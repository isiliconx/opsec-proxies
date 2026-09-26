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
from tooling.httpclient import Endpoint
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
        u.score = round(ratio * 2.0 + max(0.0, 2.0 - lat / 1500.0), 3)
        u.ok = 1 if ratio >= 0.5 else 0
        u.last_ok = float(r["tested_at"] or 0)
        u.meta = {"exit_ip": r["exit_ip"], "isp": r["isp"], "ratio": ratio, "latency_ms": lat}
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
        self.refresh_every = 60.0
        self._last_refresh = 0.0

    def load_pool(self) -> int:
        self.upstreams = pool_from_db(self.db, self.cfg, self.min_grade, self.countries, self.exclude_dc)
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
        self.started = time.time()
        log.info("listening: socks5 %s:%d   http  %s:%d   api  http://%s:%d",
                 self.host, self.socks_port, self.host, self.mixed_port, self.host, self.api_port)
        log.info("PAC: http://%s:%d/proxy.pac", self.host, self.pac_port)

    async def _start_api(self) -> None:
        self.api = await asyncio.start_server(self._api_client, self.host, self.api_port)
        pac = build_pac("socks5", self.host, self.socks_port)
        (self.cfg.abspath(self.cfg.path("paths.artifacts", "artifacts")) / "proxy.pac").write_text(pac, encoding="utf-8")

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
        if self.socks:
            await self.socks.stop()
        if self.mixed:
            await self.mixed.stop()
        if self.api:
            self.api.close()
        self.db.close()
