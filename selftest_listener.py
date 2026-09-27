"""Listener-only proof. The rotator gets exactly one upstream, a loopback
relay, so every result is deterministic and no public proxy can be blamed on
the listener. Exercises: HTTP CONNECT (https), absolute-form http, failover
onto a dead upstream, and rotation across two good upstreams.

    python3 selftest_listener.py
"""
from __future__ import annotations

import asyncio
import sys
import time

sys.path.insert(0, ".")

from selftest import LocalSocks5, SOCKS_PORT  # noqa: E402
from tooling.httpclient import Endpoint, Session  # noqa: E402
from tooling.socks_server import ProxyServer, Rotator, Upstream  # noqa: E402

HOST = "127.0.0.1"
HPORT = 11181
SPORT = 11180
rc = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global rc
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{('  ' + detail) if detail else ''}")
    if not ok:
        rc = 1


async def main() -> int:
    relay = LocalSocks5(host=HOST, port=SOCKS_PORT)
    await relay.start()
    print(f"loopback upstream relay: socks5://{HOST}:{SOCKS_PORT}")

    good = [Endpoint(HOST, SOCKS_PORT, "socks5"),
            Endpoint(HOST, SOCKS_PORT, "socks5")]
    ups = [Upstream(ep=ep) for ep in good]
    dead = Upstream(ep=Endpoint(HOST, 9, "socks5"))  # discard port, never answers

    rot = Rotator(ups + [dead], sticky_seconds=0, cooldown=1, strategy="health")
    http_srv = ProxyServer(rot, HOST, HPORT, mode="http", attempts=4)
    socks_srv = ProxyServer(rot, HOST, SPORT, mode="socks5", attempts=4)
    await http_srv.start()
    await socks_srv.start()
    print(f"listeners: http {HOST}:{HPORT}   socks5 {HOST}:{SPORT}\n")

    sess = Session(timeout=20)

    # 1. HTTPS through the http listener: CONNECT + real TLS
    try:
        r = await sess.get(Endpoint(HOST, HPORT, "http"),
                           "https://api.ipify.org?format=json")
        body = r.body.decode()
        check("https via http listener (CONNECT+TLS)", r.status == 200 and '"ip"' in body, body)
    except Exception as e:
        check("https via http listener (CONNECT+TLS)", False, f"{type(e).__name__}: {e}")

    # 2. plain http through the http listener: absolute-form, no CONNECT
    try:
        r = await sess.get(Endpoint(HOST, HPORT, "http"), "http://httpbin.org/ip")
        check("http via http listener (absolute-form)", r.status == 200 and "origin" in r.text(200), r.text(60).strip())
    except Exception as e:
        check("http via http listener (absolute-form)", False, f"{type(e).__name__}: {e}")

    # 3. same through the socks5 listener
    try:
        r = await sess.get(Endpoint(HOST, SPORT, "socks5"), "https://api.ipify.org?format=json")
        check("https via socks5 listener", r.status == 200 and '"ip"' in r.body.decode(), r.body.decode())
    except Exception as e:
        check("https via socks5 listener", False, f"{type(e).__name__}: {e}")

    # 4. failover: a client that only ever draws the dead upstream must still
    #    succeed by walking to the next one
    solo = Rotator([Upstream(ep=Endpoint(HOST, 9, "socks5"))] + [Upstream(ep=good[0])],
                   sticky_seconds=0, cooldown=1)
    solo._ranked = lambda: [solo.pool[0], solo.pool[1]]  # always try dead first
    srv = ProxyServer(solo, HOST, HPORT + 10, mode="http", attempts=4)
    await srv.start()
    try:
        r = await sess.get(Endpoint(HOST, HPORT + 10, "http"), "http://httpbin.org/ip")
        check("failover past a dead upstream", r.status == 200 and "origin" in r.text(200), r.text(60).strip())
    except Exception as e:
        check("failover past a dead upstream", False, f"{type(e).__name__}: {e}")
    await srv.stop()

    # 5. rotation: repeated requests must not all pin one upstream
    before = solo.rotations if hasattr(solo, "rotations") else 0
    seen = set()
    for _ in range(6):
        try:
            r = await sess.get(Endpoint(HOST, HPORT, "http"), "http://httpbin.org/ip")
            t = r.text(200)
            if "origin" in t:
                seen.add(t.split('"')[3] if '"' in t else t)
        except Exception:
            pass
    check("rotation spreads across upstreams", rot.rotations > 1, f"rotations={rot.rotations}")

    # 6. counters show what actually happened
    c = http_srv.counters
    check("listener counters advancing", c["http_conn"] >= 4, str(c))

    await sess.close()
    await http_srv.stop()
    await socks_srv.stop()
    await relay.stop()
    print(f"\ncounters http={http_srv.counters} socks={socks_srv.counters}")
    print("\nlistener selftest:", "PASS" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
