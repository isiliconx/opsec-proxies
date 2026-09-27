"""Re-test the upstreams already graded alive, to get a real success_ratio
spread. run.py test walks the whole candidate queue in queue order, which is
mostly dead entries; this walks the known-good ones instead.

    python3 retest_alive.py --n 40
"""
from __future__ import annotations

import argparse
import asyncio
import sys

sys.path.insert(0, ".")

from tooling.config import load, ensure_dirs
from tooling.db import DB
from tooling.httpclient import Endpoint
from vuln.tester import Tester, as_row, our_exit_ip

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=40)
ap.add_argument("--grade", default="C")
ap.add_argument("--samples", type=int, default=5)
a = ap.parse_args()

cfg = load()
ensure_dirs(cfg)
cfg.set_path("tester.quality_samples", a.samples)
db = DB(cfg.abspath(cfg.path("paths.db")))

rows = db.live_pool(min_grade=a.grade, limit=a.n)
print(f"re-testing {len(rows)} known-alive upstreams with {a.samples} samples each\n")


async def main() -> int:
    us = await our_exit_ip(cfg)
    t = Tester(cfg, db, us)
    ratios = []
    for r in rows:
        res = await t.test_one(as_row(r))
        if res.verdict in ("alive", "slow"):
            ratios.append((res.success_ratio, res.latency_ms, res.ep.url(), res.exit_ip))
            print(f"  {res.success_ratio:.2f}  {res.latency_ms:>6.0f}ms  {res.ep.url():<38} exit={res.exit_ip}")
    db.commit()
    print(f"\n{len(ratios)} alive")
    if ratios:
        import collections
        d = collections.Counter(round(x[0], 2) for x in ratios)
        print("ratio distribution:", dict(sorted(d.items(), reverse=True)))
        print("distinct ratios   :", len(d))
    return 0


raise SystemExit(asyncio.run(main()))
