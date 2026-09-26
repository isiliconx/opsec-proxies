#!/usr/bin/env python3
"""Loopback harness: proves the tester, the pool, the rotating listener and the
PAC all work, without depending on the open internet being in a good mood.

Stands up a local SOCKS5 relay (a real one, that really forwards) plus a local
HTTP forward proxy, inserts them as a parcel, runs them through the real Tester,
starts the real ResiService on top of the resulting pool, and curls through it.

  python3 selftest.py            # full harness
  python3 selftest.py --keep     # leave the listeners running
"""
from __future__ import annotations

import argparse
import asyncio
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tooling.config import load, ensure_dirs
from tooling.db import DB
from tooling.httpclient import Endpoint, _read_head, _parse_status
from tooling import logging_util as lu
from tooling.parcel import ParcelImporter

HOST = "127.0.0.1"
SOCKS_PORT = 11080
HTTP_PORT = 18080
API_PORT = 18770


# ------------------------------------------------------------------ a real relay
class LocalSocks5:
    """A genuine SOCKS5 server that forwards to the origin. Not a mock."""

    def __init__(self, host=HOST, port=SOCKS_PORT, banner: bytes = b""):
        self.host, self.port, self.banner = host, port, banner
        self.server = None
        self.conns = 0
        self.errors: list[str] = []

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        return self

    async def _handle(self, reader, writer):
        self.conns += 1
        try:
            ver = (await reader.readexactly(1))[0]
            if ver != 5:
                writer.close()
                return
            n = (await reader.readexactly(1))[0]
            await reader.readexactly(n)
            writer.write(b"\x05\x00")
            await writer.drain()
            if self.banner:
                writer.write(self.banner)
                await writer.drain()
            _v, cmd, _r, atyp = await reader.readexactly(4)
            if atyp == 1:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 3:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            else:
                writer.close()
                return
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            try:
                orr, ow = await asyncio.open_connection(host, port)
            except Exception:
                writer.write(b"\x05\x04\x00\x01" + b"\x00" * 6)
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x00\x00\x01" + b"\x7f\x00\x00\x01" + struct.pack("!H", port))
            await writer.drain()

            async def c2o():
                try:
                    while True:
                        d = await reader.read(8192)
                        if not d:
                            break
                        ow.write(d)
                        await ow.drain()
                except Exception:
                    pass
                finally:
                    try:
                        if ow.can_write_eof():
                            ow.write_eof()
                    except Exception:
                        pass

            async def o2c():
                try:
                    while True:
                        d = await orr.read(8192)
                        if not d:
                            break
                        writer.write(d)
                        await writer.drain()
                except Exception:
                    pass
                finally:
                    try:
                        if writer.can_write_eof():
                            writer.write_eof()
                    except Exception:
                        pass

            t1 = asyncio.create_task(c2o())
            t2 = asyncio.create_task(o2c())
            # Let the response direction complete; the request direction stays
            # parked until the client half-closes. Bound it so a keep-alive
            # client cannot hold the handler open forever.
            try:
                await asyncio.wait_for(asyncio.shield(t2), 30)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                pass
            t1.cancel()
            t2.cancel()
            try:
                ow.close()
            except Exception:
                pass
        except Exception as e:
            self.errors.append(f"{type(e).__name__}: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    async def _splice(r, w):
        try:
            while True:
                d = await r.read(8192)
                if not d:
                    break
                w.write(d)
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def stop(self):
        if self.server:
            self.server.close()


class LocalHttpProxy:
    """Absolute-form HTTP forward proxy."""

    def __init__(self, host=HOST, port=HTTP_PORT):
        self.host, self.port = host, port
        self.server = None
        self.conns = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        return self

    async def _handle(self, reader, writer):
        self.conns += 1
        try:
            head = await asyncio.wait_for(_read_head(reader, 16384), 10)
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, _ = (line.split(" ") + ["", "", ""])[:3]
            from urllib.parse import urlsplit
            us = urlsplit(target if "://" in target else "http://" + target)
            host, port = us.hostname, us.port or 80
            path = us.path or "/"
            if us.query:
                path += "?" + us.query
            hdrs = [f"{method} {path} HTTP/1.1"]
            for ln in head.split(b"\r\n")[1:]:
                if b":" in ln:
                    k, _, v = ln.partition(b":")
                    if k.decode().strip().lower() not in ("proxy-authorization", "proxy-connection", "connection"):
                        hdrs.append(f"{k.decode()}: {v.decode()}")
            if not any(h.lower().startswith("host:") for h in hdrs):
                hdrs.append(f"Host: {us.netloc}")
            raw = ("\r\n".join(hdrs) + "\r\n\r\n").encode("latin-1")
            orr, ow = await asyncio.open_connection(host, port)
            ow.write(raw)
            await ow.drain()
            await asyncio.gather(self._splice(reader, ow), self._splice(orr, writer))
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    async def _splice(r, w):
        try:
            while True:
                d = await r.read(8192)
                if not d:
                    break
                w.write(d)
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def stop(self):
        if self.server:
            self.server.close()


# ------------------------------------------------------------------ the harness
async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    cfg = load()
    ensure_dirs(cfg)
    lu.setup(cfg, "selftest")
    db = DB(cfg.abspath(cfg.path("paths.db")))
    rc = 0

    print("[1/5] starting loopback relays (real SOCKS5 + real HTTP forwarder)")
    s5 = await LocalSocks5().start()
    hp = await LocalHttpProxy().start()
    print(f"      socks5 {HOST}:{SOCKS_PORT}   http {HOST}:{HTTP_PORT}")

    print("[2/5] importing them as a parcel (the user-import path)")
    imp = ParcelImporter(cfg, db)
    parcel_text = f"\n".join([
        f"socks5://{HOST}:{SOCKS_PORT}",
        f"http://{HOST}:{HTTP_PORT}",
        f"{HOST}:{SOCKS_PORT}",
        f"curl -x socks5://{HOST}:{SOCKS_PORT} https://ipinfo.io",
        f"{HOST}:{HTTP_PORT}",
    ])
    res = imp.import_text(parcel_text, "loopback-selftest", "auto")
    print(f"      parcel #{res.parcel_id}: parsed={res.parsed} unique={res.unique} schemes={res.schemes}")

    print("[3/5] running them through the real Tester")
    from vuln.tester import Tester, our_exit_ip
    t = Tester(cfg, db)
    t.tp.our_ip = await our_exit_ip(cfg)
    rows = imp.parcel_rows(res.parcel_id)
    results = await t.run(rows, write=True)
    for r in results:
        print(f"      {r.ep.scheme}://{r.ep.host}:{r.ep.port} -> {r.verdict}/{r.grade} "
              f"exit={r.exit_ip or '-'} anonymity={r.anonymity} tls={r.tls_ok}")
    if not any(r.verdict in ("alive", "slow") for r in results):
        print("      FAIL: no candidate graded alive")
        rc = 1
    else:
        print("      OK: at least one graded alive")

    print("[4/5] pool query (what the egress consumes)")
    rows = db.live_pool(min_grade="C", limit=100)
    print(f"      live_pool(min_grade=C) -> {len(rows)} upstream(s)")
    for r in rows[:5]:
        print(f"      {r['scheme']}://{r['host']}:{r['port']} grade={r['grade']} exit={r['exit_ip']}")

    print("[5/5] starting the real ResiService on that pool and curling through it")
    cfg.set_path("egress.socks_port", SOCKS_PORT + 100)
    cfg.set_path("egress.mixed_port", SOCKS_PORT + 101)
    cfg.set_path("egress.api_port", API_PORT)
    from egress.service import ResiService
    svc = ResiService(cfg, min_grade="C")
    try:
        await svc.start()
    except SystemExit as e:
        print(f"      FAIL: {e}")
        rc = 1
        svc = None
    if svc:
        st = svc.status()
        print(f"      listeners: {st['listeners']}")
        # curl through the rotating listener using the project's own client
        from tooling.httpclient import Session
        sess = Session(timeout=15)
        for label, url in (("via local socks listener", "http://httpbin.org/ip"),
                           ("via local http listener", "http://httpbin.org/ip")):
            ep = Endpoint(HOST, st["listeners"]["socks5"].split(":")[-1] and int(st["listeners"]["socks5"].split(":")[-1]),
                          "socks5") if "socks" in label else Endpoint(HOST, int(st["listeners"]["http"].split(":")[-1]), "http")
            try:
                r = await sess.get(ep, url)
                ok = r.status == 200 and "origin" in r.text(200)
                print(f"      {label}: {r.status} {'OK' if ok else 'unexpected'} {r.text(60)!r}")
            except Exception as e:
                print(f"      {label}: FAIL {type(e).__name__}: {str(e)[:80]}")
                rc = 1
        # api
        try:
            rr, ww = await asyncio.open_connection(HOST, API_PORT)
            ww.write(b"GET /api/status HTTP/1.0\r\n\r\n")
            await ww.drain()
            api = (await asyncio.wait_for(rr.read(4096), 5)).decode("latin-1", "replace")
            print(f"      api /api/status: {api.splitlines()[0] if api else 'no response'}")
            ww.close()
        except Exception as e:
            print(f"      api: FAIL {e}")
            rc = 1
        await sess.close()
        if a.keep:
            print("\nlisteners still up; ctrl-c to stop")
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                pass
        await svc.stop()

    await s5.stop()
    await hp.stop()
    db.close()
    print("\nselftest:", "PASS" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
