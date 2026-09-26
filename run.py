#!/usr/bin/env python3
"""resiproxy orchestrator.

  python3 run.py setup                  create db + dirs, sanity-check deps
  python3 run.py harvest [--only NAME]   stage 1: pull every public feed
  python3 run.py test [--limit N] [--grade-only]   stage 3: verify + grade
  python3 run.py pipeline                harvest -> test -> export, one shot
  python3 run.py import FILE|dir|-       stage 2: user parcel in
  python3 run.py test-parcel ID          test one imported parcel
  python3 run.py serve [--grade B]       the rotating SOCKS/HTTP listeners
  python3 run.py chrome [urls...]        route A: Chrome only
  python3 run.py tunnel [--dry-run]      route B: whole machine
  python3 run.py pac                     write proxy.pac
  python3 run.py pick [--n 1] [--cc US]  print the next upstream URL(s)
  python3 run.py stats                   counts by grade / country
  python3 run.py export FILE             write the pool out as ip:port lines
  python3 run.py ui                      the local control panel
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tooling.config import load, ensure_dirs
from tooling.db import DB
from tooling.httpclient import Endpoint
from tooling.parcel import ParcelImporter
from tooling.pac import build_pac
from tooling import logging_util as lu
from tooling.modload import build_queue_module, ports_module
from vuln.tester import Tester, our_exit_ip
from recon.harvest import Harvester

# `enum/` is the stage directory name from the pipeline layout; load it by path
# so it does not shadow the stdlib `enum` module.
_build_queue = build_queue_module().build_queue
_PortEnumerator = ports_module().PortEnumerator


def _cfg():
    c = load()
    ensure_dirs(c)
    lu.setup(c, "resi")
    return c


# ----------------------------------------------------------------- setup
def cmd_setup(a) -> int:
    c = _cfg()
    db = DB(c.abspath(c.path("paths.db")))
    print(f"db:        {db.path}")
    print(f"config:    {c.abspath('config/target.json')}")
    print(f"artifacts: {c.abspath(c.path('paths.artifacts'))}")
    print(f"harvest:   {c.abspath(c.path('paths.harvest_raw'))}")
    try:
        import aiohttp  # noqa
        print("aiohttp:   present")
    except ImportError:
        print("aiohttp:   MISSING -> pip install aiohttp")
    ip = asyncio.run(our_exit_ip(c))
    print(f"your exit: {ip or 'unknown'}")
    print(json.dumps(db.stats(), indent=1))
    return 0


# ----------------------------------------------------------------- harvest
async def _harvest(c, only=None):
    db = DB(c.abspath(c.path("paths.db")))
    h = Harvester(c, db)
    try:
        await h.run(only=only)
    finally:
        await h.close()
        db.close()


def cmd_harvest(a) -> int:
    c = _cfg()
    asyncio.run(_harvest(c, a.only))
    return 0


# ----------------------------------------------------------------- test
async def _test(c, limit=None, since_h=0, origin=None, rows=None):
    db = DB(c.abspath(c.path("paths.db")))
    me = await our_exit_ip(c)
    print(f"[test] your exit ip: {me or 'unknown'}")
    t = Tester(c, db)
    t.tp.our_ip = me
    src = rows if rows is not None else list(db.iter_proxies(since=(time.time() - since_h * 3600) if since_h else None,
                                                            origin=origin))
    jobs = _build_queue(c, src)
    print(f"[test] {len(src)} candidates -> {len(jobs)} after port/host filter")
    if limit:
        jobs = jobs[:limit]
    t.conc = min(t.conc, max(50, len(jobs) // 2 or 50))
    try:
        await t.run(jobs)
    finally:
        await t.close()
        db.close()


def cmd_test(a) -> int:
    c = _cfg()
    asyncio.run(_test(c, a.limit, a.since, a.origin))
    return 0


# ----------------------------------------------------------------- pipeline
async def _pipeline(c, limit=None):
    db = DB(c.abspath(c.path("paths.db")))
    t0 = time.time()
    h = Harvester(c, db)
    print("=== stage 1: harvest ===")
    await h.run(quiet=False)
    await h.close()
    print("\n=== stage 2: enum (port discovery on the top hosts) ===")
    hosts = []
    for r in db.iter_proxies():
        if r["host"] not in hosts:
            hosts.append(r["host"])
        if len(hosts) >= 300:
            break
    pe = PortEnumerator(c, db)
    await pe.run(hosts, limit=300)
    await pe.close()
    print("\n=== stage 3: test + grade ===")
    me = await our_exit_ip(c)
    t = Tester(c, db)
    t.tp.our_ip = me
    jobs = _build_queue(c, list(db.iter_proxies()))
    if limit:
        jobs = jobs[:limit]
    t.conc = min(t.conc, max(50, len(jobs) // 2 or 50))
    await t.run(jobs)
    await t.close()
    st = db.stats()
    print("\n=== result ===")
    print(json.dumps(st, indent=1))
    # export the pool
    art = c.abspath(c.path("paths.artifacts"))
    (art / "pool.txt").write_text(
        "\n".join(f"{r['host']}:{r['port']}" for r in db.live_pool(min_grade="C", limit=100000)),
        encoding="utf-8")
    (art / "pool.json").write_text(json.dumps(
        [dict(r) for r in db.live_pool(min_grade="C", limit=100000)], default=str), encoding="utf-8")
    print(f"\npool written: {art / 'pool.txt'}")
    print(f"total {time.time() - t0:.0f}s")
    db.close()


def cmd_pipeline(a) -> int:
    c = _cfg()
    asyncio.run(_pipeline(c, a.limit))
    return 0


# ----------------------------------------------------------------- parcels
def cmd_import(a) -> int:
    c = _cfg()
    db = DB(c.abspath(c.path("paths.db")))
    imp = ParcelImporter(c, db)
    results = []
    if a.path == "-":
        results.append(imp.import_text(sys.stdin.read(), "stdin", a.scheme))
    elif Path(a.path).is_dir():
        results += imp.import_dir(a.path, a.scheme)
    else:
        results.append(imp.import_file(a.path, a.scheme))
    for r in results:
        print(f"parcel #{r.parcel_id} '{r.label}': parsed={r.parsed} unique={r.unique} schemes={r.schemes}")
    print(imp.report())
    if a.test:
        for r in results:
            asyncio.run(_test(c, rows=imp.parcel_rows(r.parcel_id)))
    db.close()
    return 0


def cmd_test_parcel(a) -> int:
    c = _cfg()
    db = DB(c.abspath(c.path("paths.db")))
    imp = ParcelImporter(c, db)
    rows = imp.parcel_rows(a.id)
    asyncio.run(_test(c, rows=rows))
    db.close()
    return 0


# ----------------------------------------------------------------- serve / routes
async def _serve(c, grade, countries, exclude_dc, auth):
    from egress.service import ResiService
    svc = ResiService(c, min_grade=grade, countries=countries, exclude_dc=exclude_dc, auth=auth)
    await svc.start()
    print(json.dumps(svc.status(), indent=1, default=str))
    print("\nchrome:  python3 run.py chrome")
    print("tunnel:  sudo python3 run.py tunnel --dry-run   then   sudo python3 run.py tunnel")
    print("curl:    curl -x socks5h://127.0.0.1:%d https://ipinfo.io" % svc.socks_port)
    try:
        await svc.loop()
    except KeyboardInterrupt:
        pass
    finally:
        await svc.stop()


def cmd_serve(a) -> int:
    c = _cfg()
    auth = tuple(a.auth.split(":", 1)) if a.auth else None
    asyncio.run(_serve(c, a.grade, a.countries, a.exclude_dc, auth))
    return 0


def cmd_chrome(a) -> int:
    c = _cfg()
    from egress.chrome import ChromeRunner
    port = a.port or int(c.path("egress.mixed_port", 2081))
    host = c.path("egress.listen_host", "127.0.0.1")
    urls = a.urls or ["https://ipinfo.io", "https://whatismyipaddress.com", "https://browserleaks.com/ip"]
    r = ChromeRunner(c)
    p = r.launch(f"http://{host}:{port}", urls, headless=a.headless)
    print(f"[chrome] pid={p.pid} via http://{host}:{port}")
    try:
        p.wait()
    except KeyboardInterrupt:
        r.kill()
    return 0


def cmd_tunnel(a) -> int:
    c = _cfg()
    from egress.tunnel import TunnelRunner
    r = TunnelRunner(c)
    if a.dry_run or a.dry:
        print(r.dry_run())
        return 0
    if os_geteuid() != 0 and not a.allow_no_sudo:
        print("tunnel needs root for the TUN device + killswitch. Re-run with sudo, or --dry-run.")
        return 1
    r.start()
    print(f"[tunnel] up: if={r.tun_if} engine={r.engine}. ctrl-c to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        r.stop()
    return 0


def os_geteuid() -> int:
    import os
    return os.geteuid() if hasattr(os, "geteuid") else -1


# ----------------------------------------------------------------- pac / pick / stats / export
def cmd_pac(a) -> int:
    c = _cfg()
    e = c.path("egress", {})
    art = c.abspath(c.path("paths.artifacts"))
    art.mkdir(parents=True, exist_ok=True)
    p = art / "proxy.pac"
    p.write_text(build_pac("socks5", e.get("listen_host", "127.0.0.1"), e.get("socks_port", 2080)), encoding="utf-8")
    print(f"wrote {p}  ->  point Chrome at it: Settings > System > Open your OS proxy settings")
    return 0


def cmd_pick(a) -> int:
    c = _cfg()
    db = DB(c.abspath(c.path("paths.db")))
    rows = db.live_pool(min_grade=a.grade, limit=100000, countries=a.countries, exclude_dc=a.exclude_dc)
    if not rows:
        print("no upstreams. run harvest + test first.")
        return 1
    import random
    for r in random.sample(rows, min(a.n, len(rows))):
        print(f"{r['scheme']}://{r['host']}:{r['port']}   grade={r['grade']} exit={r['exit_ip']} cc={r['cc']} asn={r['asn']} lat={r['latency_ms']:.0f}ms")
    return 0


def cmd_stats(a) -> int:
    c = _cfg()
    db = DB(c.abspath(c.path("paths.db")))
    print(json.dumps(db.stats(), indent=1))
    print()
    with db._lock:
        rows = db._conn.execute(
            "SELECT cc, COUNT(*) n, AVG(latency_ms) lat FROM tests WHERE at >= ? AND cc != '' GROUP BY cc ORDER BY n DESC LIMIT 40",
            (time.time() - 86400,)).fetchall()
    print(f"{'cc':<4}{'count':>7}{'avg ms':>9}")
    for r in rows:
        print(f"{r['cc']:<4}{r['n']:>7}{r['lat'] or 0:>9.0f}")
    return 0


def cmd_export(a) -> int:
    c = _cfg()
    db = DB(c.abspath(c.path("paths.db")))
    grade = a.grade
    rows = db.live_pool(min_grade=grade, limit=100000, countries=a.countries, exclude_dc=a.exclude_dc)
    out = Path(a.file) if a.file else c.abspath(c.path("paths.artifacts")) / "pool.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix == ".json":
        out.write_text(json.dumps([dict(r) for r in rows], default=str, indent=1), encoding="utf-8")
    else:
        out.write_text("\n".join(f"{r['scheme']}://{r['host']}:{r['port']}" for r in rows), encoding="utf-8")
    print(f"wrote {len(rows)} upstreams -> {out}")
    return 0


def cmd_ui(a) -> int:
    c = _cfg()
    from ui.server import ControlPlane
    cp = ControlPlane(c)
    try:
        asyncio.run(cp.run_forever())
    except KeyboardInterrupt:
        pass
    return 0


# ----------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(prog="resiproxy", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup")

    h = sub.add_parser("harvest"); h.add_argument("--only", default=None)

    t = sub.add_parser("test")
    t.add_argument("--limit", type=int, default=None)
    t.add_argument("--since", type=int, default=0, help="only rows seen in the last N hours")
    t.add_argument("--origin", default=None, choices=[None, "harvest", "import", "enum"])

    pl = sub.add_parser("pipeline"); pl.add_argument("--limit", type=int, default=None)

    im = sub.add_parser("import"); im.add_argument("path"); im.add_argument("--scheme", default="auto",
        choices=["auto", "http", "https", "socks4", "socks5"]); im.add_argument("--test", action="store_true")
    tp = sub.add_parser("test-parcel"); tp.add_argument("id", type=int)

    sv = sub.add_parser("serve")
    sv.add_argument("--grade", default="B", choices=["A", "B", "C", "all"])
    sv.add_argument("--countries", default="")
    sv.add_argument("--exclude-dc", action="store_true")
    sv.add_argument("--auth", default="", help="user:pass required by the local SOCKS5 listener")

    ch = sub.add_parser("chrome")
    ch.add_argument("urls", nargs="*"); ch.add_argument("--port", type=int, default=None)
    ch.add_argument("--headless", action="store_true")

    tu = sub.add_parser("tunnel"); tu.add_argument("--dry-run", "--dry", action="store_true")
    tu.add_argument("--allow-no-sudo", action="store_true")

    sub.add_parser("pac")

    pk = sub.add_parser("pick")
    pk.add_argument("--n", type=int, default=1); pk.add_argument("--grade", default="B", choices=["A", "B", "C"])
    pk.add_argument("--countries", default=""); pk.add_argument("--exclude-dc", action="store_true")

    sub.add_parser("stats")

    ex = sub.add_parser("export"); ex.add_argument("file", nargs="?", default="")
    ex.add_argument("--grade", default="B", choices=["A", "B", "C", "all"]); ex.add_argument("--countries", default="")
    ex.add_argument("--exclude-dc", action="store_true")

    sub.add_parser("ui")

    a = ap.parse_args()
    return {
        "setup": cmd_setup, "harvest": cmd_harvest, "test": cmd_test, "pipeline": cmd_pipeline,
        "import": cmd_import, "test-parcel": cmd_test_parcel, "serve": cmd_serve, "chrome": cmd_chrome,
        "tunnel": cmd_tunnel, "pac": cmd_pac, "pick": cmd_pick, "stats": cmd_stats,
        "export": cmd_export, "ui": cmd_ui,
    }[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
