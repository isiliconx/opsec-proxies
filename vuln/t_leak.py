"""Detector: open-relay confirmation + honeypot / TSA identification.

Two reasons this exists:
  1. A forward proxy that will relay to ANY destination is a relay, and a relay
     is the strongest possible "there is always one IP that works" primitive.
     We confirm with a CONNECT to a destination that is definitely not the judge.
  2. A public TSA that answers every port with a canned banner is not a proxy at
     all, and it is a fingerprinting trap. We identify and exclude those.
"""
from __future__ import annotations

import asyncio
import re
import time

from tooling.config import Cfg
from tooling.httpclient import (ConnectError, Endpoint, _parse_status, _read_head,
                                http_connect, socks4_connect, socks5_connect, tcp_connect, tunnel)
from tooling import logging_util as lu

log = lu.get()

# Neutral, always-up destinations used to prove relaying. Chosen because they
# don't rate-limit and speak plain HTTP.
RELAY_TARGETS = [
    ("cloudflare-trace", "cloudflare.com", 80, "/cdn-cgi/trace"),
    ("example", "example.com", 80, "/"),
    ("iana", "iana.org", 80, "/"),
    ("neverssl", "neverssl.com", 80, "/"),
    ("http", "httpbin.org", 80, "/get"),
]

# Destinations we must NEVER use as a relay proof: they would leak or mislead.
NEVER = ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "metadata.google.internal",
         "10.0.0.1", "192.168.0.1", "[::1]")


def is_tsa(banner: str, cfg: Cfg) -> bool:
    """A banner that comes back from every port, with a TSA header, is a trap."""
    marks = cfg.path("tester.classification.tsa_banner_markers", [])
    b = banner[:400].lower()
    if "tsa" in b or "transparent security agent" in b:
        return True
    for m in marks:
        if str(m).lower() in b:
            return True
    return False


def is_open_relay_banner(banner: str) -> bool:
    b = banner[:400].lower()
    return any(x in b for x in ("open proxy", "you are connected", "proxy connection", "squid",
                                "forwarding", "tunnel established", "connection established"))


class RelayProbe:
    def __init__(self, cfg: Cfg, timeout: float = 6.0):
        self.cfg = cfg
        self.timeout = timeout
        self.relay = False
        self.target = ""
        self.banner = b""
        self.tsa = False

    async def probe(self, ep: Endpoint) -> dict:
        for name, host, port, path in RELAY_TARGETS:
            if host in NEVER:
                continue
            r = await self._one(ep, host, port, path)
            if r.get("ok"):
                self.relay = True
                self.target = name
                self.banner = r.get("banner", b"")
                self.tsa = is_tsa(self.banner.decode("latin-1", "replace"), self.cfg)
                return {"verdict": "relay" if not self.tsa else "tsa", "relay": self.relay,
                        "target": name, "tsa": self.tsa, "status": r.get("status"),
                        "banner": self.banner[:200].decode("latin-1", "replace")}
        return {"verdict": "not_relay", "relay": False, "tsa": False}

    async def _one(self, ep: Endpoint, host: str, port: int, path: str) -> dict:
        reader = writer = None
        try:
            if ep.scheme in ("socks5", "socks4"):
                reader, writer, _ = await tunnel(ep, host, port, self.timeout)
            else:
                reader, writer, _ = await http_connect(ep.host, ep.port, host, port, ep.user, ep.password, self.timeout)
            if ep.scheme in ("socks5", "socks4"):
                req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                       f"Connection: close\r\n\r\n").encode()
                writer.write(req)
                await writer.drain()
            head = await asyncio.wait_for(_read_head(reader, 4096), self.timeout)
            code, reason, _h = _parse_status(head)
            return {"ok": 200 <= code < 400, "status": code, "reason": reason, "banner": head}
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:80]}"}
        finally:
            try:
                if writer:
                    writer.close()
            except Exception:
                pass


class PortSweep:
    """Does this host answer on several proxy ports with the same banner?

    That is the honeypot / TSA signature: a real open proxy answers on one port.
    """

    def __init__(self, ports=(80, 8080, 443, 1080, 3128, 8000, 9110, 8443), timeout: float = 4.0):
        self.ports = ports
        self.timeout = timeout

    async def same_banner(self, host: str) -> dict:
        banners: dict[int, str] = {}
        for p in self.ports:
            try:
                r = await tcp_connect(host, p, self.timeout)
                reader, writer = r
                head = await asyncio.wait_for(_read_head(reader, 1024), self.timeout)
                banners[p] = head[:120].decode("latin-1", "replace")
                writer.close()
            except Exception:
                continue
        if len(banners) < 3:
            return {"tsa": False, "ports": list(banners), "n": len(banners)}
        vals = list(banners.values())
        first = vals[0][:60]
        same = sum(1 for v in vals if v[:60] == first)
        return {"tsa": same >= len(vals) - 1 and same >= 3, "ports": list(banners), "n": len(banners),
                "identical": same, "sample": first}
