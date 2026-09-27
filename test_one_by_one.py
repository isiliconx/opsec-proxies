"""Test a specific set of endpoints given as host:port on the command line,
bypassing the parcel dedup so a proxy already in the pool is still re-verified
under the current cap/sample settings.

    python3 test_one_by_one.py 213.111.146.36:18080 184.75.221.82:3118 ...
    python3 test_one_by_one.py --file list.txt
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections import Counter

sys.path.insert(0, ".")

from tooling.config import load, ensure_dirs
from tooling.db import DB
from tooling.httpclient import Endpoint
from types import SimpleNamespace
from vuln.tester import Tester, our_exit_ip

ap = argparse.ArgumentParser()
ap.add_argument("targets", nargs="*", help="host:port or scheme://host:port")
ap.add_argument("--file")
ap.add_argument("--samples", type=int, default=3)
ap.add_argument("--scheme", default="auto", choices=["auto", "http", "https", "socks5", "socks4"])
a = ap.parse_args()

cfg = load()
ensure_dirs(cfg)
cfg.set_path("tester.quality_samples", a.samples)
db = DB(cfg.abspath(cfg.path("paths.db")))

raw = list(a.targets)
if a.file:
    for ln in open(a.file, encoding="utf-8", errors="replace"):
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            raw.append(ln.split()[0])


def parse(item: str):
    s = item
    if "://" in s:
        s = s.split("://", 1)[1]
    host, _, port = s.partition(":")
    return host.strip(), int(port)


async def main() -> int:
    me = await our_exit_ip(cfg)
    print(f"our exit ip: {me or 'unknown'}")
    t = Tester(cfg, db, me)
    print(f"cap={t.per_candidate_cap:.0f}s  samples={a.samples}  max_lat={t.max_lat:.0f}ms\n")
    rows = []
    for item in raw:
        host, port = parse(item)
        row = SimpleNamespace(host=host, port=port, scheme=a.scheme,
                              user=None, password=None, id=None)
        t0 = time.perf_counter()
        r = await t.test_one(row)
        wall = time.perf_counter() - t0
        rows.append(r)
        mark = "OK " if r.verdict in ("alive", "slow") else "-- "
        print(f"  {mark}{r.grade}  {r.verdict:<6} {host}:{port:<6} exit={(r.exit_ip or '-'):<16} "
              f"{r.cc or '-'} host={r.hosting} tls={r.tls_ok} {wall:>6.1f}s  {r.isp or ''}")
        if r.error and r.verdict not in ("alive", "slow"):
            print(f"        {r.error[:100]}")
    db.commit()
    print()
    print("grades:", dict(Counter(r.grade for r in rows)))
    print("alive :", sum(1 for r in rows if r.verdict in ("alive", "slow")))
    return 0


raise SystemExit(asyncio.run(main()))
