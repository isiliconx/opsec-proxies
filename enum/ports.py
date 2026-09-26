"""Stage 2 — content/port discovery over harvested candidates.

A cheap, high-yield enumeration trick for open-proxy work: probe the SAME host
on the other standard proxy ports, and probe the host's open web port for a
proxy banner. Both are bounded by the tier system and the port allowlist.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from tooling.config import Cfg
from tooling.db import DB
from tooling.httpclient import Endpoint, Session, socks5_connect, socks4_connect
from tooling.limiter import GlobalPacer
from tooling import logging_util as lu

log = lu.get()

PROXY_PORTS = [8080, 3128, 8000, 8888, 1080, 8118, 8443, 9050, 4145, 6660, 1234, 3129, 80, 443, 9000]
WEB_PORTS = [80, 443, 8080, 8000, 81, 3000, 5000, 8081, 8443, 9000]

BANNER_HINTS = ("proxy", "squid", "socks", "gateway", "forward", "upstream", "tor", "open")


@dataclass
class PortFinding:
    host: str
    port: int
    kind: str          # socks5 | socks4 | http-connect | http-banner | open
    detail: str = ""


class PortEnumerator:
    def __init__(self, cfg: Cfg, db: DB):
        self.cfg = cfg
        self.db = db
        self.sess = Session(timeout=6, pool_size=2, keepalive=False)
        self.pacer = GlobalPacer(200)
        self.findings: list[PortFinding] = []
        self.extra: list[tuple] = []

    async def probe_host(self, host: str) -> list[PortFinding]:
        found: list[PortFinding] = []
        async with self.pacer:
            for port in PROXY_PORTS:
                k = await self._probe(host, port)
                if k:
                    found.append(k)
        for f in found:
            self.extra.append((f.kind if f.kind.startswith("socks") else "http", f.host, f.port, "", "", 0))
        return found

    async def _probe(self, host: str, port: int) -> PortFinding | None:
        try:
            r, w, _ = await socks5_connect(host, port, None, None, 3.0)
            w.close()
            return PortFinding(host, port, "socks5", "socks5 greeting ok")
        except Exception:
            pass
        try:
            r, w, _ = await socks4_connect(host, port, None, 3.0)
            w.close()
            return PortFinding(host, port, "socks4", "socks4 granted")
        except Exception:
            pass
        try:
            res = await self.sess.get(None, f"http://{host}:{port}/", timeout=4)
            head = res.text(400).lower()
            if any(h in head for h in BANNER_HINTS):
                return PortFinding(host, port, "http-banner", head[:120].replace("\n", " "))
            if res.status in (400, 405, 407) or res.status >= 500:
                return PortFinding(host, port, "http-connect", f"status {res.status}")
        except Exception:
            pass
        return None

    async def run(self, hosts: list[str], limit: int = 400) -> list[PortFinding]:
        t0 = time.time()
        results = await asyncio.gather(*(self.probe_host(h) for h in hosts[:limit]),
                                       return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                self.findings.extend(r)
        if self.extra:
            self.db.upsert_proxies(self.extra, origin="enum")
        log.info("enum/ports: %d hosts probed, %d new proxy ports, %d rows in %.1fs",
                 min(len(hosts), limit), len(self.extra), len(self.extra), time.time() - t0)
        return self.findings

    async def close(self) -> None:
        await self.sess.close()
