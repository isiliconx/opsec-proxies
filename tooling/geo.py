"""Geo / ASN / hosting lookup with batch primary and rate-limit-aware fallback."""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, asdict

from .config import Cfg
from .httpclient import Endpoint, Session
from .limiter import RateLimiter


@dataclass
class GeoInfo:
    ip: str = ""
    country: str = ""
    cc: str = ""
    city: str = ""
    region: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    asname: str = ""
    hosting: bool = False
    proxy: bool = False
    mobile: bool = False
    source: str = ""
    checked: float = 0.0

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def is_datacenter(self) -> bool:
        return bool(self.hosting) or any(k in (self.isp + " " + self.org + " " + self.asname).lower()
                                         for k in ("hosting", "datacenter", "data center", "cloud", "vps",
                                                   "server", "colo", "idc", "amazon", "google", "microsoft",
                                                   "alibaba", "oracle", "digitalocean", "linode", "vultr",
                                                   "hetzner", "ovh", "contabo", "leaseweb", "equinix"))


class GeoResolver:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self.batch = int(cfg.path("geo.batch_size", 100))
        self.primary = cfg.path("geo.primary", "http://ip-api.com/batch")
        self.fields = cfg.path("geo.primary_fields", "status,query,country,countryCode,regionName,city,isp,org,as,asname,hosting,proxy,mobile")
        self.fallback = cfg.path("geo.fallback", "https://ipwho.is")
        # ip-api free tier: 15 req/min, 100 IPs per batch -> 1500 IPs/min ceiling
        self.limiter = RateLimiter(per_host_rps=0.25, burst=1)
        self.sess = Session(timeout=20, pool_size=2)
        self._cache: dict[str, tuple[float, GeoInfo]] = {}
        self.ttl = int(cfg.path("geo.cache_ttl_days", 14)) * 86400
        self.hits = 0
        self.misses = 0

    def cached(self, ip: str) -> GeoInfo | None:
        e = self._cache.get(ip)
        if e and e[0] > time.time():
            return e[1]
        return None

    async def bulk(self, ips: list[str]) -> dict[str, GeoInfo]:
        """Resolve a batch. Cache-first, then ip-api batches, then ipwho.is one-by-one."""
        out: dict[str, GeoInfo] = {}
        todo = []
        for ip in ips:
            c = self.cached(ip)
            if c:
                out[ip] = c
            else:
                todo.append(ip)
        self.hits += len(ips) - len(todo)
        self.misses += len(todo)
        # dedupe, keep order
        seen = set()
        uniq = [x for x in todo if not (x in seen or seen.add(x))]
        for i in range(0, len(uniq), self.batch):
            chunk = uniq[i:i + self.batch]
            got = await self._primary(chunk)
            if not got:
                got = await self._fallback_many(chunk)
            for ip, info in got.items():
                self._cache[ip] = (time.time() + self.ttl, info)
                out[ip] = info
        return out

    async def _primary(self, ips: list[str]) -> dict[str, GeoInfo]:
        body = json.dumps([{"query": ip} for ip in ips])
        try:
            await self.limiter.acquire("ip-api.com")
            r = await self.sess.post(None, self.primary, body=body,
                                     headers={"Content-Type": "application/json"}, timeout=25)
            if r.status != 200:
                return {}
            data = json.loads(r.body or b"[]")
        except Exception:
            return {}
        out = {}
        for row in data if isinstance(data, list) else []:
            if not isinstance(row, dict) or row.get("status") != "success":
                continue
            asn = row.get("as", "") or ""
            m = asn.split()[0] if asn else ""
            out[row.get("query", "")] = GeoInfo(
                ip=row.get("query", ""), country=row.get("country", ""), cc=row.get("countryCode", ""),
                city=row.get("city", ""), region=row.get("regionName", ""), isp=row.get("isp", ""),
                org=row.get("org", ""), asn=m, asname=row.get("asname", ""),
                hosting=bool(row.get("hosting")), proxy=bool(row.get("proxy")), mobile=bool(row.get("mobile")),
                source="ip-api", checked=time.time())
        return out

    async def _fallback_many(self, ips: list[str]) -> dict[str, GeoInfo]:
        sem = asyncio.Semaphore(8)
        out: dict[str, GeoInfo] = {}

        async def one(ip: str):
            async with sem:
                try:
                    await self.limiter.acquire("ipwho.is")
                    r = await self.sess.get(None, f"{self.fallback}/{ip}", timeout=12)
                    d = json.loads(r.body or b"{}")
                    if not d.get("success", True) or "ip" not in d:
                        return
                    conn = d.get("connection", {}) or {}
                    out[ip] = GeoInfo(ip=ip, country=d.get("country", ""), cc=d.get("country_code", ""),
                                      city=d.get("city", ""), region=d.get("region", ""),
                                      isp=conn.get("isp", ""), org=conn.get("org", ""),
                                      asn=str(conn.get("asn", "")), asname=conn.get("org", ""),
                                      hosting=bool(conn.get("asn_org") and "host" in str(conn.get("asn_org", "")).lower()),
                                      source="ipwho.is", checked=time.time())
                except Exception:
                    pass

        await asyncio.gather(*(one(ip) for ip in ips[:400]))
        return out
