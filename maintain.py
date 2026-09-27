"""Maintain daemon: the loop that makes a supply "always on".

Scraping and peer networks both produce short-lived exits. The problem is not
producing exits, it is that they rot. A proxy verified at 05:00 is a coin flip
by 06:00. So this daemon runs the whole loop continuously:

  peer pull  ──▶ import as a parcel ──▶ test + grade ──┐
  harvest     ──▶ (on a slower cadence)  ─────────────┤
                                                      ▼
                                            pool ← serve ──▶ chrome / tunnel
                                                      ▲
                                    health loop: probe, demote, cool down ──┘

and re-checks stale rows so the pool only ever serves something verified
recently. It is the difference between a pile of proxy lists and a live egress.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass

from tooling.config import load, ensure_dirs
from tooling.db import DB
from tooling.httpclient import Session
from tooling.parcel import ParcelImporter
from tooling import logging_util as lu
from recon.peer import collect as collect_peer
from recon.harvest import Harvester
from vuln.tester import Tester, our_exit_ip
from run import _build_queue

log = lu.get()


@dataclass
class Policy:
    """Cadence and policy. Every number is overridable from config."""
    peer_every: float = 900.0        # 15 min: peer networks churn fastest
    harvest_every: float = 7200.0     # 2 h: public lists are slow-moving
    test_new_every: float = 600.0     # 10 min: grade whatever arrived
    revalidate_every: float = 1800.0  # 30 min: re-check rows that went stale
    revalidate_window_h: float = 2.0   # consider anything older than this stale
    test_batch: int = 400             # cap per pass so one cycle stays short
    min_grade: str = "C"
    networks: tuple = ()              # empty = all configured adapters
    do_harvest: bool = True

    @classmethod
    def from_cfg(cls, cfg) -> "Policy":
        m = cfg.path("maintain", {}) or {}
        return cls(
            peer_every=float(m.get("peer_every", 900)),
            harvest_every=float(m.get("harvest_every", 7200)),
            test_new_every=float(m.get("test_new_every", 600)),
            revalidate_every=float(m.get("revalidate_every", 1800)),
            revalidate_window_h=float(m.get("revalidate_window_h", 2.0)),
            test_batch=int(m.get("test_batch", 400)),
            min_grade=str(m.get("min_grade", "C")),
            networks=tuple(m.get("networks", ()) or ()),
            do_harvest=bool(m.get("do_harvest", True)),
        )


class Maintainer:
    def __init__(self, cfg):
        self.cfg = cfg
        ensure_dirs(cfg)
        self.db = DB(cfg.abspath(cfg.path("paths.db")))
        self.imp = ParcelImporter(cfg, self.db)
        self.pol = Policy.from_cfg(cfg)
        self.tester: Tester | None = None
        self._next = {"peer": 0.0, "harvest": 0.0, "test": 0.0, "reval": 0.0}
        self._peer_parcels: list[int] = []

    async def _ensure_tester(self) -> Tester:
        if self.tester is None:
            me = await our_exit_ip(self.cfg)
            log.info("our exit ip: %s", me or "unknown")
            self.tester = Tester(self.cfg, self.db, me)
        return self.tester

    # ---------------------------------------------------------------- peer pull
    async def pull_peer(self) -> int:
        sess = Session(timeout=20, pool_size=2)
        try:
            batches = await collect_peer(sess, list(self.pol.networks) or None)
        finally:
            await sess.close()
        added = 0
        for b in batches:
            log.info("%s", b.summary())
            if not b.ok or not b.lines:
                continue
            # one parcel per network, so pass/fail is attributable and a bad
            # network never taints the others
            text = "\n".join(b.lines)
            res = self.imp.import_text(text, f"peer:{b.network}", "auto")
            added += res.unique
            if res.parcel_id not in self._peer_parcels:
                self._peer_parcels.append(res.parcel_id)
            log.info("   -> parcel #%d %s: parsed=%d unique=%d",
                     res.parcel_id, b.network, res.parsed, res.unique)
        return added

    # ------------------------------------------------------------------ harvest
    async def harvest(self) -> int:
        h = Harvester(self.cfg, self.db)
        try:
            stats = await h.run(quiet=True)
        finally:
            await h.close()
        return int(stats.get("written", 0))

    # --------------------------------------------------------------------- test
    async def test_new(self) -> int:
        """Grade whatever has never been tested, oldest first.

        This is the path that turns a raw peer-network pull into usable
        upstreams. Cheap to run continuously because it only touches rows with
        no test row at all.
        """
        t = await self._ensure_tester()
        ids = self.db.untested(limit=self.pol.test_batch)
        if not ids:
            return 0
        by_id = {int(r["id"]): r for r in self.db.iter_proxies(batch=100000)}
        src = [by_id[i] for i in ids if i in by_id]
        jobs = _build_queue(self.cfg, src)
        if not jobs:
            return 0
        log.info("testing %d never-tested candidates", len(jobs))
        res = await t.run(jobs, write=True, progress_every=200)
        alive = sum(1 for r in res if r.verdict in ("alive", "slow"))
        log.info("test pass: %d graded, %d alive", len(res), alive)
        return alive

    async def revalidate(self) -> int:
        """Re-verify the pool so 'alive' means 'alive recently', not 'alive in March'."""
        t = await self._ensure_tester()
        rows = self.db.live_pool(min_grade=self.pol.min_grade, limit=self.pol.test_batch)
        if not rows:
            return 0
        from vuln.tester import as_row
        jobs = [as_row(r) for r in rows]
        log.info("revalidating %d pool upstreams older than %.0fh",
                 len(jobs), self.pol.revalidate_window_h)
        res = await t.run(jobs, write=True, progress_every=100)
        alive = sum(1 for r in res if r.verdict in ("alive", "slow"))
        log.info("revalidate: %d/%d still alive", alive, len(res))
        return alive

    # --------------------------------------------------------------------- loop
    async def run(self, once: bool = False) -> None:
        log.info("maintainer starting: peer=%.0fs harvest=%.0fs test=%.0fs reval=%.0fs",
                 self.pol.peer_every, self.pol.harvest_every,
                 self.pol.test_new_every, self.pol.revalidate_every)
        # prime: get something in the pool immediately
        await self.pull_peer()
        await self.test_new()
        if once:
            return
        now = time.time()
        for k in self._next:
            self._next[k] = now
        while True:
            now = time.time()
            try:
                if now >= self._next["peer"]:
                    self._next["peer"] = now + self.pol.peer_every
                    await self.pull_peer()
                if now >= self._next["test"]:
                    self._next["test"] = now + self.pol.test_new_every
                    await self.test_new()
                if now >= self._next["reval"]:
                    self._next["reval"] = now + self.pol.revalidate_every
                    await self.revalidate()
                if self.pol.do_harvest and now >= self._next["harvest"]:
                    self._next["harvest"] = now + self.pol.harvest_every
                    n = await self.harvest()
                    log.info("harvest added %d rows", n)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("maintain cycle error: %s", e)
            await asyncio.sleep(15)

    def close(self):
        self.db.close()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="run a single pass and exit")
    ap.add_argument("--peer", action="store_true", help="peer pull only")
    a = ap.parse_args()
    cfg = load()
    m = Maintainer(cfg)

    async def go():
        if a.peer:
            n = await m.pull_peer()
            print(f"peer pull added {n} unique endpoints")
        else:
            await m.run(once=a.once)

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        pass
    finally:
        m.close()
