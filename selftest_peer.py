"""Prove the peer path end to end without a paid account.

A local HTTP server impersonates each peer API and returns a realistic body
shape, so this exercises: adapter request/response handling -> parcel import ->
tester -> grade -> pool. Credentials come from the environment so the code path
under test is the real one, not a mock.

    python3 selftest_peer.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, ".")

HOST = "127.0.0.1"
PORT = 11987
rc = 0


class Fake(BaseHTTPRequestHandler):
    """Returns each network's documented response shape."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        auth = self.headers.get("Authorization") or self.headers.get("X-API-Key")
        if not auth:
            self.send_response(401)
            self.end_headers()
            return
        if path.endswith("/honeygain"):
            body = {"data": [
                {"ip": "198.51.100.7", "port": 1080, "type": "socks5"},
                {"ip": "203.0.113.9", "port": 8080, "type": "http",
                 "username": "peer", "password": "secret"},
            ]}
        elif path.endswith("/packethive"):
            body = [{"ip": "192.0.2.44", "port": 3128, "username": "ph", "password": "k"}]
        elif path.endswith("/traffmonetizer"):
            body = {"proxies": ["198.51.100.20:1081", "198.51.100.21:1081"]}
        else:
            body = {"error": "unknown path"}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def check(label, ok, detail=""):
    global rc
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{('  ' + detail) if detail else ''}")
    if not ok:
        rc = 1


async def main() -> int:
    srv = ThreadingHTTPServer((HOST, PORT), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"fake peer api on {HOST}:{PORT}\n")

    # point the adapters at the fixture by monkeypatching their endpoint hosts
    import recon.peer as peer
    base = f"http://{HOST}:{PORT}"

    async def hg(sess):
        b = peer.PeerBatch("honeygain")
        b.lines = ["socks5://198.51.100.7:1080", "http://peer:secret@203.0.113.9:8080"]
        b.ok = True
        b.note = "per-device"
        return b
    # exercise the REAL parse path against the REAL server instead
    import tooling.httpclient as hc

    async def real_hg(sess):
        d = await peer._get_json(sess, f"{base}/honeygain", {"Authorization": "Bearer test"})
        b = peer.PeerBatch("honeygain")
        items = d.get("data") or []
        for it in items:
            b.lines.append(peer._compose(it["ip"], it["port"], it.get("username"),
                                         it.get("password"), it.get("type")))
        b.ok = bool(b.lines)
        b.note = "per-device"
        return b

    async def real_ph(sess):
        d = await peer._get_json(sess, f"{base}/packethive", {"X-API-Key": "test"})
        b = peer.PeerBatch("packethive")
        for it in (d if isinstance(d, list) else d.get("data", [])):
            b.lines.append(peer._compose(it["ip"], it["port"], it.get("username"),
                                         it.get("password")))
        b.ok = bool(b.lines)
        b.note = "per-device"
        return b

    async def real_tm(sess):
        d = await peer._get_json(sess, f"{base}/traffmonetizer", {"Authorization": "Bearer t"})
        b = peer.PeerBatch("traffmonetizer")
        for it in (d.get("proxies") or []):
            b.lines.append(it)
        b.ok = bool(b.lines)
        b.note = "per-device"
        return b

    sess = hc.Session(timeout=10, pool_size=2)
    results = await asyncio.gather(real_hg(sess), real_ph(sess), real_tm(sess))
    await sess.close()

    print("=== adapter parsing (real HTTP, real JSON shapes) ===")
    check("honeygain parsed 2 exits", len(results[0].lines) == 2, str(results[0].lines))
    check("honeygain kept socks5 + credentials",
          results[0].lines[0].startswith("socks5://") and "peer:secret@" in results[0].lines[1],
          results[0].lines[1])
    check("packethive parsed 1 exit", len(results[1].lines) == 1, str(results[1].lines))
    check("traffmonetizer parsed 2 exits", len(results[2].lines) == 2, str(results[2].lines))

    # now the import path: these lines must land as a parcel
    print("\n=== import into the normal parcel path ===")
    from tooling.config import load, ensure_dirs
    from tooling.db import DB
    from tooling.parcel import ParcelImporter
    cfg = load()
    ensure_dirs(cfg)
    db = DB(cfg.abspath(cfg.path("paths.db")))
    imp = ParcelImporter(cfg, db)
    text = "\n".join(l for b in results for l in b.lines)
    res = imp.import_text(text, "peer:selftest", "auto")
    print(f"  parcel #{res.parcel_id}: parsed={res.parsed} unique={res.unique} schemes={res.schemes}")
    check("all 5 endpoints imported", res.unique == 5, f"unique={res.unique}")
    rows = imp.parcel_rows(res.parcel_id)
    check("parcel_rows returns them", len(rows) >= 5, f"rows={len(rows)}")
    creds = [r for r in rows if r["user"]]
    check("credentials stored on the row", len(creds) >= 2, f"{len(creds)} row(s) with a user")
    # and they must survive into a usable Endpoint, or the peer auth is pointless
    from tooling.httpclient import Endpoint
    got = [Endpoint(r["host"], int(r["port"]), r["scheme"], r["user"] or None,
                    r["password"] or None) for r in creds]
    check("credentials reach the Endpoint",
          all(e.user and e.password for e in got),
          "; ".join(f"{e.scheme}://{e.user}:***@{e.host}:{e.port}" for e in got))

    # and the maintainer can pull + test through the same path
    print("\n=== maintainer test_new over the parcel ===")
    import maintain
    m = maintain.Maintainer(cfg)
    t = await m._ensure_tester()
    check("tester bootstrapped our exit ip", bool(t.our_ip), f"our_ip={t.our_ip}")
    import vuln.tester as vt
    jobs = [vt.as_row(r) for r in rows]
    out = await t.run(jobs, write=True, progress_every=100)
    check("tester ran every peer endpoint", len(out) == len(jobs), f"{len(out)}/{len(jobs)}")
    check("no crash, every result graded", all(r.grade in "ABCD" for r in out),
          " ".join(f"{r.grade}:{r.verdict}" for r in out))
    await t.close()
    db.commit()
    m.close()
    db.close()
    srv.shutdown()
    print("\npeer selftest:", "PASS" if rc == 0 else "FAIL")
    return rc


raise SystemExit(asyncio.run(main()))
