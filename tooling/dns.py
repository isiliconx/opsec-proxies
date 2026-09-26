"""Minimal async DNS resolver (A / PTR) over UDP with TCP fallback. No dnspython."""
from __future__ import annotations

import asyncio
import os
import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from tooling.httpclient import tcp_connect

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
RTYPE = {v: k for k, v in TYPES.items()}
CLASS_IN = 1


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if len(b) > 63:
            raise ValueError("label too long")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _decode_name(buf: bytes, off: int) -> tuple[str, int]:
    labels = []
    jumped = False
    orig = off
    hops = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                orig = off + 2
            off = ptr
            jumped = True
            hops += 1
            if hops > 16:
                raise ValueError("name loop")
            continue
        off += 1
        labels.append(buf[off:off + n].decode("latin-1", "replace"))
        off += n
    return ".".join(labels), (orig if jumped else off)


def build_query(name: str, qtype: int, tid: int) -> bytes:
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)


def parse_response(data: bytes) -> dict:
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):
        _, off = _decode_name(data, off)
        off += 4
    out = {"rcode": rcode, "answers": [], "authority": [], "additional": []}
    for section, count in (("answers", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            if off + 10 > len(data):
                break
            name, off = _decode_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            rec = {"name": name, "type": RTYPE.get(rtype, rtype), "ttl": ttl, "data": ""}
            if rtype == TYPES["A"] and rdlen == 4:
                rec["data"] = socket.inet_ntoa(rdata)
            elif rtype == TYPES["AAAA"] and rdlen == 16:
                rec["data"] = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (TYPES["CNAME"], TYPES["PTR"], TYPES["NS"]):
                try:
                    rec["data"], _ = _decode_name(data, off - rdlen)
                except Exception:
                    rec["data"] = rdata.hex()
            elif rtype == TYPES["TXT"]:
                parts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    parts.append(rdata[i + 1:i + 1 + ln].decode("latin-1", "replace"))
                    i += 1 + ln
                rec["data"] = "".join(parts)
            elif rtype == TYPES["MX"]:
                pref = struct.unpack("!H", rdata[:2])[0]
                try:
                    mx, _ = _decode_name(data, off - rdlen + 2)
                except Exception:
                    mx = ""
                rec["data"] = f"{pref} {mx}"
            else:
                rec["data"] = rdata.hex()[:128]
            out[section].append(rec)
    return out


class Resolver:
    def __init__(self, servers: list[str] | None = None, timeout: float = 4.0, tries: int = 2,
                 workers: int = 64):
        self.servers = servers or self._system_servers()
        self.timeout = timeout
        self.tries = tries
        self._cache: dict[tuple, tuple[float, dict]] = {}
        self._neg: dict[tuple, float] = {}
        # The default loop executor has ~32 threads and asyncio.open_connection
        # resolves hostnames on it. Thousands of dead proxy hostnames would
        # otherwise serialise every TCP connect behind a full executor, so the
        # resolver and the tester's own connects get a dedicated pool.
        self._executor = ThreadPoolExecutor(max_workers=workers,
                                           thread_name_prefix="resi-dns")
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def shutdown(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    @staticmethod
    def _system_servers() -> list[str]:
        out = []
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    if ln.startswith("nameserver"):
                        p = ln.split()
                        if len(p) > 1:
                            out.append(p[1])
        except Exception:
            pass
        return out or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    async def _udp(self, server: str, q: bytes, tid: int) -> dict | None:
        try:
            r, w = await tcp_connect(server, 53, self.timeout)
        except Exception:
            return None
        try:
            w.write(q)
            await w.drain()
            data = await asyncio.wait_for(r.read(4096), self.timeout)
            if len(data) < 12:
                return None
            if struct.unpack("!H", data[:2])[0] != tid:
                return None
            return parse_response(data)
        except Exception:
            return None
        finally:
            w.close()

    async def resolve(self, name: str, rtype: str = "A", use_cache: bool = True) -> dict:
        t = rtype.upper()
        key = (name.lower(), t)
        if use_cache:
            hit = self._cache.get(key)
            if hit and hit[0] > time.time():
                return hit[1]
            if self._neg.get(key, 0) > time.time():
                return {"rcode": 3, "answers": [], "authority": [], "additional": []}
        qt = TYPES.get(t)
        if qt is None:
            return {"rcode": 16, "answers": []}
        last = {"rcode": 2, "answers": []}
        for _ in range(self.tries):
            for srv in random.sample(self.servers, len(self.servers)) or ["1.1.1.1"]:
                tid = random.randint(1, 65535)
                res = await self._udp(srv, build_query(name, qt, tid), tid)
                if res is None:
                    continue
                if res["rcode"] in (0, 3):
                    if res["rcode"] == 0 and res["answers"]:
                        self._cache[key] = (time.time() + 300, res)
                    elif res["rcode"] == 3:
                        self._neg[key] = time.time() + 60
                    return res
                last = res
        return last

    async def a(self, name: str) -> list[str]:
        r = await self.resolve(name, "A")
        return [x["data"] for x in r.get("answers", []) if x["type"] == "A" and isinstance(x["data"], str)]

    async def ptr(self, ip: str) -> str:
        try:
            packed = socket.inet_aton(ip)
        except OSError:
            return ""
        name = ".".join(str(b) for b in reversed(packed)) + ".in-addr.arpa"
        r = await self.resolve(name, "PTR")
        for a in r.get("answers", []):
            if a["type"] == "PTR":
                return a["data"].rstrip(".")
        return ""

    async def txt(self, name: str) -> list[str]:
        r = await self.resolve(name, "TXT")
        return [a["data"] for a in r.get("answers", []) if a["type"] == "TXT"]

    async def blacklist(self, ip: str, zones: list[str], resolver_ip: str | None = None) -> str:
        """Return the zone that lists ip, or '' if clean."""
        try:
            packed = socket.inet_aton(ip)
        except OSError:
            return ""
        rev = ".".join(str(b) for b in reversed(packed))
        for z in zones:
            r = await self.resolve(f"{rev}.{z}", "A", use_cache=False)
            if r.get("answers"):
                return z
        return ""
