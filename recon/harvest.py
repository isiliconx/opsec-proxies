"""Stage 1 — recon/harvest. Pull every public open-proxy + open-residential feed,
parse all four payload shapes (text / json / html / range), normalize to Endpoint.
Writes raw bodies to data/harvest/ and rows to sqlite.
"""
from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Iterable

from tooling.config import Cfg, ensure_dirs
from tooling.db import DB
from tooling.httpclient import Endpoint, Session
from tooling.limiter import GlobalPacer, RateLimiter
from tooling import logging_util as lu
from tooling.mutator import parse_line

log = lu.get()

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT = re.compile(r"\b\d{2,5}\b")
TAGS = re.compile(r"<[^>]+>")
JSON_ROW = re.compile(r"\{[^{}]*\}", re.S)
IP_IN_JSON = re.compile(r'"ip"\s*:\s*"([^"]+)"')
PORT_IN_JSON = re.compile(r'"port"\s*:\s*"?(\d{1,5})"?')
PROTO_IN_JSON = re.compile(r'"protocols?"\s*:\s*\[?([^"\]]*)')

# ISP / CGNAT CIDRs that are resnet-shaped. Anything inside these is a candidate
# residential address rather than a cloud range; the tester confirms with geo+ASN.
RESNET_HINTS = (
    "100.64.0.0/10",      # RFC 6598 CGNAT
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "169.254.0.0/16",
)
_resnet_nets = [ipaddress.ip_network(c) for c in RESNET_HINTS]


def looks_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast


def in_resnet_hint(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _resnet_nets)


def parse_text(body: str) -> list[Endpoint]:
    out = []
    for ln in body.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        ep = parse_line(ln, "http")
        if ep:
            out.append(ep)
    return out


TOKEN = re.compile(
    r"(?:(?P<scheme>socks5|socks4|https?)://)?"
    r"(?P<user>[A-Za-z0-9._~%+-]{1,64}:[A-Za-z0-9._~%+-]{1,64}@)?"
    r"(?P<host>\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]{1,253})"
    r":(?P<port>\d{1,5})")


def parse_url_blob(body: str) -> list[Endpoint]:
    """Some feeds ship every line concatenated with no newlines at all.

    The token regex is anchored on host:port, so it recovers them either way and
    is safe to run on normal newline-delimited text too.
    """
    out: list[Endpoint] = []
    for m in TOKEN.finditer(body):
        scheme = _norm(m.group("scheme")) if m.group("scheme") else None
        ep = Endpoint(m.group("host").strip("[]"), int(m.group("port")),
                      scheme or "http", m.group("user").split(":")[0] if m.group("user") else None,
                      m.group("user").split(":")[1] if m.group("user") else None)
        if 0 < ep.port < 65536:
            out.append(ep)
    return out


def parse_crlf(body: str) -> list[Endpoint]:
    """One-per-line feeds whose newlines are CRLF or missing."""
    return parse_text(body) or parse_url_blob(body)


def _norm(s: str | None) -> str:
    s = (s or "http").lower()
    if s in ("socks5", "socks", "socks5h"):
        return "socks5"
    if s in ("socks4", "socks4a"):
        return "socks4"
    return s


def parse_html(body: str) -> list[Endpoint]:
    text = TAGS.sub(" ", body)
    text = html.unescape(text)
    out = []
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})[^\d]{0,20}(\d{2,5})", text):
        host, port = m.group(1), m.group(2)
        if parse_line(f"{host}:{port}"):
            out.append(Endpoint(host, int(port), "http"))
    for m in re.finditer(r"([a-z0-9.\-]+\.com:\d{2,5})", text, re.I):
        ep = parse_line(m.group(1), "http")
        if ep:
            out.append(ep)
    return out


def parse_json(body: str) -> list[Endpoint]:
    out = []
    try:
        data = json.loads(body)
    except Exception:
        for row in JSON_ROW.findall(body):
            ipm = IP_IN_JSON.search(row)
            pm = PORT_IN_JSON.search(row)
            if ipm and pm:
                proto = "http"
                pr = PROTO_IN_JSON.search(row)
                if pr and "socks" in pr.group(1).lower():
                    proto = "socks5"
                out.append(Endpoint(ipm.group(1), int(pm.group(1)), proto))
        return out
    rows = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else []
    for r in rows:
        if isinstance(r, str):
            ep = parse_line(r, "http")
            if ep:
                out.append(ep)
            continue
        if not isinstance(r, dict):
            continue
        host = r.get("ip") or r.get("addr") or r.get("host") or r.get("ip_address")
        port = r.get("port") or r.get("proxy_port")
        protos = r.get("protocols") or r.get("protocol") or r.get("type") or "http"
        if isinstance(protos, list):
            protos = ",".join(protos)
        if not host or not port:
            continue
        try:
            port = int(str(port).strip())
        except ValueError:
            continue
        schemes = []
        p = str(protos).lower()
        if "socks4" in p:
            schemes.append("socks4")
        if "socks5" in p or "socks" in p:
            schemes.append("socks5")
        if "http" in p or not schemes:
            schemes.append("http")
        for s in schemes:
            ep = parse_line(f"{s}://{host}:{port}", s)
            if ep:
                out.append(ep)
    return out


def parse_range(body: str) -> list[Endpoint]:
    """Expand `start-end` or `ip/prefix` lines into individual host:port pairs.

    Only used for CGNAT/ISP-shaped space. `max_lines` in config bounds it hard.
    """
    out = []
    ports = [80, 8080, 3128, 8000, 8118, 1080, 8888, 8443, 9110]
    for ln in body.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$", ln)
        if m:
            a = int(ipaddress.IPv4Address(m.group(1)))
            b = int(ipaddress.IPv4Address(m.group(2)))
            if b < a or b - a > 65536:
                continue
            for i in range(a, b + 1):
                ip = str(ipaddress.IPv4Address(i))
                for p in ports[:3]:
                    out.append(Endpoint(ip, p, "http"))
            continue
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$", ln)
        if m:
            try:
                net = ipaddress.IPv4Network(ln, strict=False)
            except Exception:
                continue
            if net.num_addresses > 4096:
                continue
            for ip in net.hosts():
                for p in ports[:3]:
                    out.append(Endpoint(str(ip), p, "http"))
    return out


def parse_body(kind: str, body: str) -> list[Endpoint]:
    if kind == "text":
        return parse_text(body)
    if kind == "crlf":
        return parse_crlf(body)
    if kind == "url":
        return parse_url_blob(body)
    if kind == "json":
        return parse_json(body)
    if kind == "html":
        return parse_html(body)
    if kind == "range":
        return parse_range(body)
    if kind == "api":
        return parse_text(body) or parse_json(body)
    return parse_text(body) or parse_url_blob(body)


class Harvester:
    def __init__(self, cfg: Cfg, db: DB):
        self.cfg = cfg
        self.db = db
        self.raw_dir = cfg.abspath(cfg.path("paths.harvest_raw", "data/harvest"))
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.sess = Session(timeout=cfg.path("harvest.timeout", 25.0), pool_size=4)
        self.pacer = GlobalPacer(int(cfg.path("harvest.concurrency", 48)))
        self.limiter = RateLimiter(per_host_rps=1.5, burst=3)
        self.stats = {"feeds": 0, "raw": 0, "parsed": 0, "written": 0, "errors": 0}

    async def run(self, only: str | None = None, quiet: bool = False) -> dict:
        sources = [s for s in self.cfg.path("harvest.sources", []) if s.get("enabled", True)]
        if only:
            sources = [s for s in sources if only in s["name"]]
        jid = self.db.start_job("harvest", len(sources))
        t0 = time.time()
        seen: dict[tuple, tuple] = {}
        tasks = [self._one(s, seen, quiet) for s in sources]
        await asyncio.gather(*tasks, return_exceptions=True)
        rows = list(seen.values())
        self.stats["written"] = self.db.upsert_proxies(rows, origin="harvest")
        self.db.finish_job(jid, len(rows), f"feeds={self.stats['feeds']} parsed={self.stats['parsed']}")
        if not quiet:
            log.info("harvest: %d feeds, %d raw bytes, %d parsed, %d new/updated rows in %.1fs -> db now %d",
                     self.stats["feeds"], self.stats["raw"], self.stats["parsed"],
                     self.stats["written"], time.time() - t0, self.db.proxy_count())
        return self.stats

    async def _one(self, src: dict, seen: dict, quiet: bool) -> None:
        async with self.pacer:
            name, url, kind = src["name"], src["url"], src.get("kind", "text")
            try:
                await self.limiter.acquire(_host(url))
                r = await self.sess.get(None, url, timeout=self.cfg.path("harvest.timeout", 25.0))
                body = r.text(20_000_000)
                self.stats["raw"] += len(body)
                (self.raw_dir / f"{name}.txt").write_text(body, encoding="utf-8", errors="replace")
                eps = parse_body(kind, body)
                cap = int(self.cfg.path("harvest.max_range_lines_per_feed", 4000))
                if kind == "range" and not self.cfg.path("harvest.allow_range_feeds", True):
                    eps = []
                if len(eps) > cap:
                    eps = eps[:cap]
                self.stats["parsed"] += len(eps)
                for ep in eps:
                    if not ep.host or not (0 < ep.port < 65536):
                        continue
                    if looks_private(ep.host) and not in_resnet_hint(ep.host):
                        continue
                    key = (ep.scheme, ep.host, ep.port, ep.user or "")
                    seen.setdefault(key, (ep.scheme, ep.host, ep.port, ep.user or "", ep.password or "",
                                          1 if looks_private(ep.host) else 0))
                self.stats["feeds"] += 1
                self.db.touch_source(name, url, kind, len(eps), f"http {r.status}")
                if not quiet:
                    log.info("  %-22s %6d endpoints (%d bytes)", name, len(eps), len(body))
            except Exception as e:
                self.stats["errors"] += 1
                self.db.touch_source(name, url, kind, 0, f"error {type(e).__name__}")
                if not quiet:
                    log.warning("  %-22s FAILED %s: %s", name, type(e).__name__, str(e)[:80])

    async def close(self) -> None:
        await self.sess.close()


def _host(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).hostname or "feed"
    except ValueError:
        return "feed"


async def main(cfg: Cfg) -> None:
    db = DB(cfg.abspath(cfg.path("paths.db")))
    h = Harvester(cfg, db)
    try:
        await h.run()
    finally:
        await h.close()
        db.close()


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tooling.config import load
    c = load()
    ensure_dirs(c)
    asyncio.run(main(c))
