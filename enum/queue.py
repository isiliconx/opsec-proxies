"""Stage 2 — build the test queue: tiering, filtering, variant generation."""
from __future__ import annotations

import ipaddress
import random
import time
from dataclasses import dataclass, field

from tooling.config import Cfg
from tooling.db import DB
from tooling.httpclient import Endpoint
from tooling import logging_util as lu
from tooling.mutator import case_mutate, octet_mutate, port_mutate
from recon.fingerprint import in_cloud

log = lu.get()

# Ports that are never a forward proxy for a browser, or that belong to a
# service we don't want to touch. A residential forward proxy is 8xxx/3xxx/1xxx/10xx.
GOOD_PORTS = {80, 81, 443, 631, 808, 1080, 1099, 1234, 1337, 1717, 3128, 4444, 5000, 6666, 6969,
              7000, 7080, 7090, 8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8088, 8090,
              8118, 8123, 8180, 8200, 8280, 8443, 8500, 8686, 8888, 8989, 9000, 9080, 9090, 9110,
              9200, 9443, 9800, 9981, 10000, 10264, 11211, 12345, 16080, 18091, 20000, 31337,
              4145, 4780, 6660, 6677, 6000, 6001, 3000, 3129, 4000, 4200, 4500, 8001, 8010, 8050,
              8181, 8800, 8880, 9001, 9010, 9999, 34567}
RISKY_PORTS = {22, 25, 110, 143, 993, 995, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200,
               11211, 27017, 21, 23, 53, 445, 139, 2049, 5555, 7547, 37215, 5358, 5683}

TIER_RANDOM = [i for i in range(3000, 3020)] + [i for i in range(5000, 5020)] + [i for i in range(9000, 9020)]
TIER_COMMON = [8080, 3128, 8000, 8888, 1080, 9050, 4145, 6660, 8118, 8443, 4444, 1234, 3129, 6969]
TIER_WIDE = list(range(1000, 65536))


@dataclass
class TestJob:
    ep: Endpoint
    tier: int
    reason: str = ""
    variants: list[Endpoint] = field(default_factory=list)
    row_id: int | None = None

    @property
    def sort_key(self) -> tuple:
        return (self.tier, self.ep.host, self.ep.port)


def classify_port(port: int) -> int:
    """0 = likely residential, 1 = common proxy, 2 = wide scan."""
    if port in RISKY_PORTS:
        return 3
    if port in TIER_RANDOM:
        return 0
    if port in TIER_COMMON:
        return 1
    if port in GOOD_PORTS:
        return 2
    return 2


def is_reject_port(port: int) -> bool:
    reject = {22, 25, 110, 143, 993, 995, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200,
              11211, 27017}
    return port in reject


def build_queue(cfg: Cfg, rows, include_cloud: bool = False, sample: int | None = None,
                retry_window_h: int = 6) -> list[TestJob]:
    """rows: sqlite Rows from db.iter_proxies(). Returns prioritized jobs.

    The row's id rides along on the job so the tester can persist the verdict.
    """
    reject_ports = set(cfg.path("tester.reject_ports", [])) | RISKY_PORTS
    reject_hosts = {h.lower() for h in cfg.path("tester.reject_hostnames", [])}
    out: list[TestJob] = []
    seen: set[str] = set()
    for r in rows:
        if hasattr(r, "keys"):
            host, port, scheme = r["host"], int(r["port"]), r["scheme"]
            user, pw, rid = r["user"] or "", r["password"] or "", r["id"]
        else:
            host, port, scheme = r.host, int(r.port), r.scheme
            user, pw, rid = r.user or "", r.password or "", getattr(r, "id", None)
        if port in reject_ports or host.lower() in reject_hosts:
            continue
        if not include_cloud and in_cloud(host):
            continue
        ep = Endpoint(host, port, scheme, user or None, pw or None)
        if ep.key in seen:
            continue
        seen.add(ep.key)
        out.append(TestJob(ep, classify_port(port), "queue", row_id=rid))
    if sample and len(out) > sample:
        random.shuffle(out)
        out = out[:sample]
    out.sort(key=lambda j: j.sort_key)
    return out


def variants_for(ep: Endpoint, ip_last_octet_only: bool = False) -> list[Endpoint]:
    """Retry candidates for one logical proxy when the first attempt fails."""
    out: list[Endpoint] = []
    if ep.scheme == "http":
        for s in ("socks5", "socks4", "https"):
            out.append(Endpoint(ep.host, ep.port, s, ep.user, ep.password))
    if ep.user:
        out.append(Endpoint(ep.host, ep.port, ep.scheme, None, None))
    for p in list(port_mutate(ep.port))[:2]:
        out.append(Endpoint(ep.host, p, ep.scheme, ep.user, ep.password))
    for nm in list(case_mutate(ep.host))[:1]:
        out.append(Endpoint(nm, ep.port, ep.scheme, ep.user, ep.password))
    if ip_last_octet_only:
        try:
            a = ipaddress.IPv4Address(ep.host)
            for d in (1, -1, 2):
                b = ipaddress.IPv4Address(int(a) + d)
                out.append(Endpoint(str(b), ep.port, ep.scheme, ep.user, ep.password))
        except Exception:
            pass
    uniq, seen = [], set()
    for v in out:
        if v.key not in seen and v.key != ep.key:
            seen.add(v.key)
            uniq.append(v)
    return uniq
