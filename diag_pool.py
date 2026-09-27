"""Why is the listener failing? Rank the pool the way the rotator does and
show what it would pick, versus what actually works."""
import asyncio
import json
import time

from tooling.config import load, ensure_dirs
from tooling.db import DB
from tooling.httpclient import Endpoint, Session
from egress.service import pool_from_db
from tooling.socks_server import Rotator, Upstream

cfg = load()
ensure_dirs(cfg)
db = DB(cfg.abspath(cfg.path("paths.db")))


def to_upstream(r):
    g = (lambda k: r[k]) if hasattr(r, "keys") else (lambda k: r.get(k))
    return Upstream(
        ep=Endpoint(g("host"), int(g("port")), g("scheme"), g("user") or None, g("password") or None),
        score=float(g("success_ratio") or 0.0),
        country=g("cc") or "",
        asn=g("asn") or "",
        grade=g("grade") or "C",
    )


async def main():
    rows = pool_from_db(db, cfg, min_grade="C")
    print(f"pool_from_db(min_grade=C) -> {len(rows)} upstreams")
    rot = Rotator(rows, sticky_seconds=0, cooldown=1)
    hs = [u.health() for u in rows]
    print(f"health spread: min={min(hs):.2f} max={max(hs):.2f} distinct={len(set(round(h,3) for h in hs))}")

    ranked = rot._ranked()
    print(f"_ranked -> {len(ranked)} live")
    print("\ntop 15 the rotator would pick (health desc):")
    for u in ranked[:15]:
        print(f"  health={u.health():.2f} score={u.score:.2f} {u.ep.scheme}://{u.ep.host}:{u.ep.port}")

    # what the rotator actually hands out over 20 draws
    picks = []
    for _ in range(20):
        u = rot.pick(None)
        if u:
            picks.append(u.ep)
    uniq = {}
    for e in picks:
        uniq[e.key] = uniq.get(e.key, 0) + 1
    print(f"\n20 draws -> {len(uniq)} distinct upstreams")
    for k, n in sorted(uniq.items(), key=lambda x: -x[1])[:8]:
        print(f"  {n:>2}x  {k}")

    # which pool members actually work right now
    print("\ndirect probe of the top 20 ranked, 1 request each:")
    s = Session(timeout=12, keepalive=False)
    good = bad = 0
    for u in ranked[:20]:
        try:
            r = await s.get(u.ep, "https://api.ipify.org?format=json")
            ip = json.loads(r.body).get("ip")
            if ip:
                good += 1
        except Exception:
            bad += 1
    print(f"  {good} ok / {bad} failed out of 20")
    await s.close()


asyncio.run(main())
