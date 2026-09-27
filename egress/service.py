"""The service. One process that:
  1. keeps the tested pool in memory
  2. serves the local rotating SOCKS5 + HTTP listeners (the two egress routes)
  3. exposes a small HTTP API for the browser and the UI
  4. writes a PAC file and, on request, boots Chrome or the system TUN
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from tooling.config import Cfg
from tooling.db import DB
from tooling.httpclient import Endpoint, Session
from tooling import logging_util as lu
from tooling.socks_server import ProxyServer, Rotator, Upstream
from tooling.pac import build_pac

log = lu.get()


def pool_from_db(db: DB, cfg: Cfg, min_grade: str = "B", countries: str = "",
                 exclude_dc: bool = False, limit: int = 20000) -> list[Upstream]:
    rows = db.live_pool(min_grade=min_grade, limit=limit, countries=countries, exclude_dc=exclude_dc)
    out = []
    for r in rows:
        ep = Endpoint(r["host"], r["port"], r["scheme"], r["user"] or None, r["password"] or None)
        u = Upstream(ep=ep, country=r["cc"] or "", asn=r["asn"] or "", grade=r["grade"] or "C")
        ratio = float(r["success_ratio"] or 0)
        lat = float(r["latency_ms"] or 9999)
        # score carries the tester's measured success ratio so a never-used
        # upstream still has a real rank instead of a flat default.
        u.score = round(ratio, 3)
        # Seed the live counters from the measured ratio, not a binary
        # ok/fail guess: setting ok=1 whenever ratio>=0.5 made every upstream
        # in a low-ratio pool look perfect to health(), so the rotator had no
        # signal and the weighted pick became a lottery over dead proxies.
        ok = ratio * 10
        u.ok = int(ok)
        u.fail = int(round(10 - ok))
        # last_ok must mean "when this last worked", and a db row from an
        # hour ago does not. Seeding it with tested_at made the recency decay
        # in health() floor to zero for every upstream, which is the same flat
        # ranking in a different direction. Let the live counters own it and
        # start every entry equally fresh; the health check then separates them.
        u.last_ok = time.time()
        u.meta = {"exit_ip": r["exit_ip"], "isp": r["isp"], "ratio": ratio, "latency_ms": lat,
                  "tested_at": r["tested_at"]}
        out.append(u)
    return out


class ResiService:
    def __init__(self, cfg: Cfg, min_grade: str = "B", countries: str = "", exclude_dc: bool = False,
                 auth: tuple[str, str] | None = None):
        self.cfg = cfg
        self.db = DB(cfg.abspath(cfg.path("paths.db")))
        self.host = cfg.path("egress.listen_host", "127.0.0.1")
        self.socks_port = int(cfg.path("egress.socks_port", 2080))
        self.mixed_port = int(cfg.path("egress.mixed_port", 2081))
        self.auth = auth
        self.min_grade, self.countries, self.exclude_dc = min_grade, countries, exclude_dc
        self.upstreams: list[Upstream] = []
        self.rot: Rotator | None = None
        self.socks: ProxyServer | None = None
        self.mixed: ProxyServer | None = None
        self.started = 0.0
        self.api: asyncio.Server | None = None
        self.api_port = int(cfg.path("egress.api_port", 8770))
        self.pac_port = int(cfg.path("egress.pac_port", 8771))
        # The pool refresh must be slower than the health check, or every
        # refresh resets the very counters the health check just built up.
        self.refresh_every = max(60.0, float(self.cfg.path("egress.health_check_interval", 30)) * 3)
        self._last_refresh = 0.0
        self._health_task: asyncio.Task | None = None

    def load_pool(self) -> int:
        # Carry live ok/fail/cooldown across a refresh. Rebuilding the rotator
        # from the db alone throws away everything the health loop has learned
        # and puts every upstream back on the flat seed ratio, which is what
        # made the pool oscillate instead of converging.
        prior: dict[str, Upstream] = {}
        if self.rot is not None:
            for u in self.rot.pool:
                prior[u.ep.key] = u
        self.upstreams = pool_from_db(self.db, self.cfg, self.min_grade, self.countries, self.exclude_dc)
        if prior:
            for u in self.upstreams:
                old = prior.get(u.ep.key)
                if old is None:
                    continue
                u.ok += old.ok
                u.fail += old.fail
                u.last_ok = max(u.last_ok, old.last_ok)
                if old.cooldown_until > u.cooldown_until:
                    u.cooldown_until = old.cooldown_until
        self.rot = Rotator(self.upstreams,
                           sticky_seconds=int(self.cfg.path("egress.sticky_seconds", 300)),
                           cooldown=int(self.cfg.path("egress.cooldown_seconds", 120)),
                           failover=bool(self.cfg.path("egress.failover", True)))
        self._last_refresh = time.time()
        log.info("pool loaded: %d upstreams (grade %s+, countries=%s, no-dc=%s)",
                 len(self.upstreams), self.min_grade, self.countries or "any", self.exclude_dc)
        return len(self.upstreams)

    async def start(self) -> None:
        n = self.load_pool()
        if n == 0:
            raise SystemExit("no upstreams in the pool. Run: python3 run.py harvest && python3 run.py test")
        e = self.cfg.path("egress", {})
        self.socks = ProxyServer(self.rot, self.host, self.socks_port, "socks", self.auth)
        self.mixed = ProxyServer(self.rot, self.host, self.mixed_port, "mixed", self.auth)
        await self.socks.start()
        await self.mixed.start()
        await self._start_api()
        self._health_task = asyncio.create_task(self.health_loop())
        self.started = time.time()
        log.info("listening: socks5 %s:%d   http  %s:%d   api  http://%s:%d",
                 self.host, self.socks_port, self.host, self.mixed_port, self.host, self.api_port)
        log.info("PAC: http://%s:%d/proxy.pac", self.host, self.pac_port)

    async def _start_api(self) -> None:
        self.api = await asyncio.start_server(self._api_client, self.host, self.api_port)
        pac = build_pac("socks5", self.host, self.socks_port)
        (self.cfg.abspath(self.cfg.path("paths.artifacts", "artifacts")) / "proxy.pac").write_text(pac, encoding="utf-8")

    # ------------------------------------------------------------- self-heal
    async def health_loop(self) -> None:
        """Actively re-probe the pool and demote what is actually dead.

        A harvested open-proxy pool is roughly half dead within minutes, and
        no amount of ranking fixes that: the listener keeps drawing from
        whatever the db last said. This probes a slice of the pool on an
        interval, feeds the result into the same ok/fail counters the rotator
        ranks on, and pushes anything that fails repeatedly into cooldown, so
        the pool converges on the entries that still work.
        """
        interval = float(self.cfg.path("egress.health_check_interval", 30))
        width = int(self.cfg.path("egress.healthcheck_batch", 24))
        if interval <= 0:
            return
        log.info("health loop: every %.0fs, %d probes", interval, width)
        while True:
            try:
                await asyncio.sleep(interval)
                if not self.upstreams or self.rot is None:
                    continue
                # probe the least-recently-verified slice, so the whole pool
                # gets covered over time rather than the same head forever
                ranked = self.rot._ranked()
                if not ranked:
                    continue
                batch = (ranked[-width:] if len(ranked) > width else ranked)
                judge = self.cfg.path("tester.judge_url", "http://httpbin.org/ip")
                probe = Session(timeout=12, pool_size=1)
                good = 0
                for u in batch:
                    try:
                        r = await probe.get(u.ep, judge)
                        ok = r.status == 200
                    except Exception:
                        ok = False
                    self.rot.report(u, ok, "" if ok else "healthcheck failed")
                    good += 1 if ok else 0
                await probe.close()
                if good:
                    log.info("health check: %d/%d upstreams verified good", good, len(batch))
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.debug("health loop error: %s", e)

    async def _api_client(self, reader, writer) -> None:
        from tooling.httpclient import _read_head, _parse_status
        try:
            head = await asyncio.wait_for(_read_head(reader, 8192), 5)
            first = head.split(b"\r\n", 1)[0].decode("latin-1")
            _, path, _ = (first.split(" ") + ["", "", ""])[:3]
            if not path.startswith("/"):
                path = "/"
            body = self._route(path)
            code = 200 if body is not None else 404
            if code == 200:
                if path.endswith(".pac") or path == "/proxy.pac":
                    ct = b"application/x-ns-proxy-autoconfig"
                    payload = body.encode()
                else:
                    ct = b"application/json"
                    payload = json.dumps(body, default=str).encode()
            else:
                ct, payload = b"text/plain", b"not found"
            writer.write(b"HTTP/1.1 " + str(code).encode() + b" OK\r\nContent-Type: " + ct +
                         b"\r\nContent-Length: " + str(len(payload)).encode() +
                         b"\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n" + payload)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _route(self, path: str):
        q = path.split("?", 1)
        path = q[0]
        qs = q[1] if len(q) > 1 else ""
        if path in ("/", "/api"):
            return self.status()
        if path == "/api/status":
            return self.status()
        if path == "/api/pool":
            return {"count": len(self.upstreams),
                    "upstreams": [{"proxy": u.ep.url(), "grade": u.grade, "cc": u.country, "asn": u.asn,
                                   "score": u.score, "ok": u.ok, "fail": u.fail, "in_use": u.in_use,
                                   "cooldown": round(max(0, u.cooldown_until - time.time()), 1),
                                   "meta": u.meta} for u in self.upstreams[:500]]}
        if path == "/api/stats":
            return self.db.stats()
        if path == "/api/exit":
            return self.pick_exit(qs)
        if path == "/proxy.pac":
            return build_pac("socks5", self.host, self.socks_port)
        if path == "/api/refresh":
            return {"reloaded": self.load_pool()}
        return None

    def pick_exit(self, qs: str) -> dict:
        """Hand a caller the next upstream URL — for curl -x, scripts, anything."""
        from urllib.parse import parse_qs
        p = parse_qs(qs)
        grade = (p.get("grade") or [self.min_grade])[0]
        cc = (p.get("cc") or [""])[0]
        n = int((p.get("n") or ["1"])[0])
        cands = [u for u in self.upstreams
                 if grade == "all" or u.grade <= grade
                 and (not cc or u.country.upper() == cc.upper())]
        out = []
        for _ in range(n):
            u = self.rot.pick() if self.rot else None
            if u is None:
                break
            if u in cands:
                out.append({"proxy": u.ep.url(), "grade": u.grade, "cc": u.country, "asn": u.asn})
        if not out:
            return {"error": "no upstream matches", "pool": len(self.upstreams)}
        return {"picks": out}

    def status(self) -> dict:
        return {
            "uptime_s": round(time.time() - self.started, 1) if self.started else 0,
            "pool": len(self.upstreams),
            "grades": {g: sum(1 for u in self.upstreams if u.grade == g) for g in "ABCD"},
            "countries": sorted({u.country for u in self.upstreams if u.country})[:60],
            "listeners": {"socks5": f"{self.host}:{self.socks_port}",
                          "http": f"{self.host}:{self.mixed_port}",
                          "api": f"http://{self.host}:{self.api_port}",
                          "pac": f"http://{self.host}:{self.pac_port}/proxy.pac"},
            "rotator": self.rot.stats() if self.rot else {},
            "counters": {**{k: v for k, v in (self.socks.counters.items() if self.socks else [])},
                         **{k: v for k, v in (self.mixed.counters.items() if self.mixed else [])}},
            "db": self.db.stats(),
        }

    async def loop(self) -> None:
        """Periodically re-read the pool so a fresh `test` run is picked up live."""
        while True:
            await asyncio.sleep(5)
            if time.time() - self._last_refresh > self.refresh_every:
                old = len(self.upstreams)
                self.load_pool()
                if self.rot and len(self.upstreams) != old:
                    log.info("pool refreshed: %d -> %d upstreams", old, len(self.upstreams))

    async def stop(self) -> None:
        if self._health_task:
            self._health_task.cancel()
        if self.socks:
            await self.socks.stop()
        if self.mixed:
            await self.mixed.stop()
        if self.api:
            self.api.close()
        self.db.close()
