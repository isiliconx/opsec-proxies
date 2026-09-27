"""Local SOCKS5 + HTTP mixed proxy with rotating upstream pool and health failover.

Listens on 127.0.0.1 only. Each new client TCP connection (or each N seconds for a
sticky session) is bound to the next healthy upstream. On upstream error the
connection is re-bound mid-flight so a dead proxy never reaches the client.
"""
from __future__ import annotations

import asyncio
import ipaddress
import random
import time
from dataclasses import dataclass, field

from .httpclient import (ConnectError, Endpoint, HTTPStatusError, ProxyError, Response,
                         Session, _parse_status, _read_head, http_connect, http_open,
                         socks4_connect, socks5_connect, tunnel)
import struct

# Well-known ports, and ranges that are never a browser's proxy port.
COMMON_PROXY_PORTS = {80, 81, 443, 3128, 8000, 8080, 8443, 10000, 1080, 2080, 3129, 8118, 8888, 9110, 8889}


@dataclass
class Upstream:
    ep: Endpoint
    score: float = 0.0            # higher = better
    ok: int = 0
    fail: int = 0
    last_error: str = ""
    last_ok: float = 0.0
    cooldown_until: float = 0.0
    in_use: int = 0
    country: str = ""
    asn: str = ""
    grade: str = "C"
    sticky_session: str = ""
    meta: dict = field(default_factory=dict)

    def available(self, now: float | None = None) -> bool:
        now = now or time.time()
        return self.cooldown_until <= now

    def health(self) -> float:
        total = self.ok + self.fail
        if total == 0:
            return 0.5
        return (self.ok / total) * max(0.0, 1.0 - min(1.0, (time.time() - self.last_ok) / 300.0))


class Rotator:
    """Weighted round-robin over healthy upstreams with sticky sessions."""

    def __init__(self, upstreams: list[Upstream], sticky_seconds: int = 300, cooldown: int = 120,
                 failover: bool = True, strategy: str = "health"):
        self.pool = upstreams
        self.sticky_seconds = sticky_seconds
        self.cooldown = cooldown
        self.failover = failover
        self.strategy = strategy
        self._sticky: dict[str, Upstream] = {}
        self._rr = 0
        self.rotations = 0

    def __len__(self) -> int:
        return len(self.pool)

    def _ranked(self) -> list[Upstream]:
        now = time.time()
        live = [u for u in self.pool if u.available(now)]
        if not live:
            live = list(self.pool)  # everything cooling: still try
        if self.strategy == "rr":
            self._rr += 1
            return live[self._rr % len(live):] + live[:self._rr % len(live)]
        if self.strategy == "score":
            return sorted(live, key=lambda u: -u.score)
        return sorted(live, key=lambda u: (-u.health(), -u.score, -u.last_ok))

    def pick(self, session_id: str | None = None, exclude: set[str] | None = None) -> Upstream | None:
        if not self.pool:
            return None
        exclude = exclude or set()
        if session_id:
            u = self._sticky.get(session_id)
            if u and u.available() and u.ep.key not in exclude:
                return u
        live = self._ranked()
        if not live:
            return None
        live = [u for u in live if u.ep.key not in exclude] or live
        # top 30% by health, weighted random inside it
        window = max(1, min(len(live), int(len(live) * 0.3) + 1))
        top = live[:window]
        weights = [max(0.01, u.health() * (0.5 + u.score)) for u in top]
        u = random.choices(top, weights=weights, k=1)[0]
        self.rotations += 1
        if session_id:
            self._sticky[session_id] = u
            u.sticky_session = session_id
        return u

    def report(self, u: Upstream | None, ok: bool, err: str = "", sid: str | None = None) -> None:
        if u is None:
            return
        u.in_use = max(0, u.in_use - 1)
        if ok:
            u.ok += 1
            u.last_ok = time.time()
            u.cooldown_until = 0
            u.last_error = ""
        else:
            u.fail += 1
            u.last_error = err[:120]
            # exponential cooldown on repeated failure
            pen = self.cooldown * (1 + min(4, u.fail))
            u.cooldown_until = time.time() + pen
            if sid and self._sticky.get(sid) is u:
                self._sticky.pop(sid, None)
            if not self.failover:
                u.cooldown_until = time.time() + self.cooldown * 10

    def set_sticky(self, sid: str, u: Upstream) -> None:
        self._sticky[sid] = u

    def stats(self) -> dict:
        live = sum(1 for u in self.pool if u.available())
        return {"total": len(self.pool), "healthy": live, "rotations": self.rotations,
                "sessions": len(self._sticky)}


class ProxyServer:
    """Serves SOCKS5 (with auth) and HTTP CONNECT/absolutefrom on one port.

    --socks-port 127.0.0.1:2080
    --mixed-port 127.0.0.1:2081
    """

    def __init__(self, rotator: Rotator, host: str = "127.0.0.1", port: int = 2080,
                 mode: str = "mixed", auth: tuple[str, str] | None = None,
                 session_header: str = "x-resi-session", listen_sessions: bool = True,
                 attempts: int = 4):
        self.rot = rotator
        self.host = host
        self.port = port
        self.mode = mode  # socks | http | mixed
        self.auth = auth
        self.session_header = session_header.lower()
        self.sessions: dict[str, Upstream] = {}
        self.session_header_map: dict[str, str] = {}
        self.listen_sessions = listen_sessions
        # How many distinct upstreams one client connection may walk through
        # before it gives up. Open proxies die mid-session constantly, so a
        # single bad upstream must not end a browser's connection.
        self.attempts = max(1, int(attempts))
        self.server: asyncio.Server | None = None
        self._session_pool = Session(timeout=30, pool_size=2)
        self.counters = {"socks_conn": 0, "http_conn": 0, "bind_fail": 0, "upstream_err": 0, "bytes": 0}

    # ------------------------------------------------------------- lifecycle
    async def start(self) -> None:
        self.server = await asyncio.start_server(self._client, self.host, self.port)
        return self

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
        await self._session_pool.close()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if self.mode in ("http", "mixed"):
                head = await asyncio.wait_for(_read_head(reader, 8192), 10)
                if head.startswith((b"CONNECT", b"GET ", b"POST ", b"PUT ", b"HEAD ")):
                    await self._http_server(reader, writer, head)
                    return
            if self.mode in ("socks", "socks4", "socks5", "mixed"):
                await self._socks_server(reader, writer)
                return
            writer.close()
        except (asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
            pass
        except Exception:
            pass
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass

    # ------------------------------------------------------------- SOCKS5
    async def _socks_server(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.counters["socks_conn"] += 1
        # Read the client greeting first: VER, NMETHODS, METHODS.
        head = await asyncio.wait_for(reader.readexactly(2), 10)
        ver, nmethods = head[0], head[1]
        methods = set(await asyncio.wait_for(reader.readexactly(nmethods), 10))
        if ver != 5:
            writer.close()
            return
        # Reply is exactly two bytes: VER=5, METHOD. Not a 3-byte greeting.
        if self.auth and 2 in methods:
            writer.write(b"\x05\x02")
        elif 0 in methods:
            writer.write(b"\x05\x00")
        else:
            writer.write(b"\x05\xff")
            await writer.drain()
            writer.close()
            return
        await writer.drain()
        if self.auth and 2 in methods:
            ok = await self._socks_auth(reader, writer)
            if not ok:
                writer.close()
                return
        await self._socks_request(reader, writer)

    async def _socks_auth(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """RFC 1929 username/password sub-negotiation. Returns False and replies 0x01 on mismatch."""
        try:
            hdr = await asyncio.wait_for(reader.readexactly(2), 10)
            if hdr[0] != 0x01:
                writer.write(b"\x01\x01")
                await writer.drain()
                return False
            ulen = hdr[1]
            user = (await asyncio.wait_for(reader.readexactly(ulen), 10)).decode("latin-1", "replace")
            plen = (await asyncio.wait_for(reader.readexactly(1), 10))[0]
            pw = (await asyncio.wait_for(reader.readexactly(plen), 10)).decode("latin-1", "replace")
            ok = (user, pw) == tuple(self.auth or ("", ""))
            writer.write(bytes([0x01, 0x00 if ok else 0x01]))
            await writer.drain()
            return ok
        except Exception:
            return False

    async def _socks_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ver, cmd, rsv, atyp = await asyncio.wait_for(reader.readexactly(4), 10)
        if atyp == 1:
            host = ".".join(str(b) for b in await reader.readexactly(4))
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode()
        else:
            host = socket_ntop6(await reader.readexactly(16))
        import struct as _s
        port = _s.unpack("!H", await reader.readexactly(2))[0]
        if cmd == 2:  # UDP associate: not supported, tell the client
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            writer.close()
            return
        sid = f"{host}:{port}"
        u = self.rot.pick(sid) if self.listen_sessions else self.rot.pick()
        if u is None:
            writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
            await writer.drain()
            writer.close()
            return
        u.in_use += 1
        try:
            up = await self._open_upstream(u, host, port)
            if up is None:
                writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
                await writer.drain()
                self.counters["bind_fail"] += 1
                self.rot.report(u, False, "upstream open failed", sid)
                return
            # SOCKS5 success reply: VER REP RSV ATYP BND.ADDR BND.PORT
            writer.write(b"\x05\x00\x00\x01" + b"\x7f\x00\x00\x01" + struct.pack("!H", port))
            await writer.drain()
            self.counters["bytes"] += await self._pump(u, *up, reader, writer)
            self.rot.report(u, True, sid=sid)
        except Exception as e:
            self.counters["upstream_err"] += 1
            self.counters["bind_fail"] += 1
            self.rot.report(u, False, f"{type(e).__name__}:{e}", sid)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ------------------------------------------------------------- HTTP
    async def _http_server(self, reader, writer, head: bytes) -> None:
        self.counters["http_conn"] += 1
        first, _, rest = head.partition(b"\r\n")
        method, target, _ = (first.decode("latin-1").split(" ") + ["", "", ""])[:3]
        hdrs = {}
        for ln in rest.split(b"\r\n"):
            if b":" in ln:
                k, _, v = ln.partition(b":")
                hdrs[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
        # Sticky sessions are opt-in: only an explicit X-Resi-Session header pins an
        # upstream. Keying on the origin host instead would pin every connection a
        # browser opens to that host to one upstream for the whole sticky window,
        # which is exactly what breaks multi-connection clients like Chrome.
        sid = hdrs.get(self.session_header) or None
        u = self.rot.pick(sid)
        if u is None:
            writer.write(b"HTTP/1.1 503 No upstream available\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        u.in_use += 1
        # rewrite absolute-form target to origin-form, keep headers
        if method.upper() == "CONNECT":
            c_host, _, c_port_s = target.rpartition(":")
            c_host = c_host.strip("[]") or target
            c_port = int(c_port_s) if c_port_s.isdigit() else 443
            up = None
            for _ in range(self.attempts):
                up = await self._open_upstream(u, c_host, c_port)
                if up is not None:
                    break
                self.counters["upstream_err"] += 1
                self.rot.report(u, False, "connect failed", sid)
                tried = {u.ep.key}
                nxt = self.rot.pick(sid, exclude=tried)
                if nxt is None:
                    break
                u.in_use += 1
                u = nxt
            if up is None:
                writer.write(b"HTTP/1.1 502 upstream failed\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            writer.write(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: resiproxy\r\n\r\n")
            await writer.drain()
            self.counters["bytes"] += await self._pump(u, *up, reader, writer)
            self.rot.report(u, True, sid=sid)
            writer.close()
            return
        # absolute URL: parse host, rebuild origin-form
        from urllib.parse import urlsplit
        try:
            us = urlsplit(target if "://" in target else "http://" + target)
        except ValueError:
            writer.close()
            return
        host, port = us.hostname, us.port or 80
        path = us.path or "/"
        if us.query:
            path += "?" + us.query
        out = [f"{method} {path} HTTP/1.1"]
        drop = {"proxy-authorization", "proxy-connection", "connection"}
        for k, v in hdrs.items():
            if k in drop:
                continue
            out.append(f"{k}: {v}")
        if "host" not in hdrs and host:
            out.append(f"Host: {us.netloc}")
        if self.session_header in hdrs:
            out.append(f"X-Resi-Exit: {u.ep.host}:{u.ep.port}")
        if not any(l.lower().startswith("content-length:") for l in out) and method in ("POST", "PUT", "PATCH"):
            out.append("Content-Length: 0")
        raw = ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")
        # Failover: walk up to ATTEMPT upstreams before giving up. One dead
        # upstream must not end a client connection.
        tried: set[str] = set()
        for _ in range(self.attempts):
            up = None
            try:
                up = await self._open_upstream_raw(u, host, port, raw)
                if up is None:
                    raise ConnectError("upstream open failed")
                first_resp = await asyncio.wait_for(_read_head(up[0]), 20)
                code, reason, _ = _parse_status(first_resp)
                if code >= 500:
                    raise ConnectError(f"upstream {code}")
                writer.write(first_resp)
                await writer.drain()
                self.counters["bytes"] += await self._pump(u, *up, reader, writer)
                self.rot.report(u, True, sid=sid)
                return
            except Exception as e:
                self.counters["upstream_err"] += 1
                self.rot.report(u, False, f"{type(e).__name__}:{e}", sid)
                if up is not None:
                    try:
                        up[1].close()
                    except Exception:
                        pass
                tried.add(u.ep.key)
                nxt = self.rot.pick(sid, exclude=tried)
                if nxt is None:
                    break
                u.in_use += 1
                u = nxt
        try:
            writer.write(b"HTTP/1.1 502 upstream failed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass

    # ------------------------------------------------------------- upstream plumbing
    async def _open_upstream(self, u: Upstream, host: str, port: int) -> tuple | None:
        """Open a tunnel from this server to (host,port) through upstream u."""
        try:
            if u.ep.scheme in ("socks5", "socks4"):
                r, w, _ = await tunnel(u.ep, host, port, 10)
            else:
                r, w, _ = await http_connect(u.ep.host, u.ep.port, host, port, u.ep.user, u.ep.password, 10)
            return r, w
        except Exception as e:
            self.counters.setdefault("open_err", 0)
            log.debug("upstream open failed %s: %s", u.ep, str(e)[:80])
            return None

    async def _open_upstream_raw(self, u: Upstream, host: str, port: int, first_request: bytes) -> tuple | None:
        """Open a tunnel and push the already-parsed request down it.

        A plain-HTTP request must NOT be sent as CONNECT. An http upstream wants
        the request itself in absolute-form on a bare connection; only a socks
        upstream gets a real CONNECT, with the request bytes following it.
        """
        try:
            if u.ep.scheme in ("socks5", "socks4"):
                r, w, _ = await tunnel(u.ep, host, port, 10)
                if first_request:
                    w.write(first_request)
                    await w.drain()
                return r, w
            # http/https upstream: bare connection to the proxy, no CONNECT.
            r, w, _ = await http_open(u.ep.host, u.ep.port, u.ep.user, u.ep.password, 10)
            if first_request:
                head, _, rest = first_request.partition(b"\r\n")
                parts = head.decode("latin-1").split(" ")
                if len(parts) >= 2 and not parts[1].startswith(("http://", "https://")):
                    scheme = "https" if port == 443 else "http"
                    netloc = host if port in (80, 443) else f"{host}:{port}"
                    parts[1] = f"{scheme}://{netloc}{parts[1]}"
                    head = " ".join(parts).encode("latin-1")
                w.write(head + b"\r\n" + rest)
                await w.drain()
            return r, w
        except Exception:
            return None

    async def _pump(self, u: Upstream, up_r, up_w, cli_r: asyncio.StreamReader, cli_w: asyncio.StreamWriter) -> int:
        """Bidirectional splice. Returns bytes moved."""
        total = 0

        async def c2u():
            nonlocal total
            while True:
                try:
                    data = await asyncio.wait_for(cli_r.read(16384), 120)
                except (asyncio.TimeoutError, Exception):
                    break
                if not data:
                    break
                total += len(data)
                up_w.write(data)
                await up_w.drain()

        async def u2c():
            nonlocal total
            while True:
                try:
                    data = await asyncio.wait_for(up_r.read(16384), 120)
                except Exception:
                    break
                if not data:
                    break
                total += len(data)
                cli_w.write(data)
                await cli_w.drain()

        t1 = asyncio.create_task(c2u())
        t2 = asyncio.create_task(u2c())
        try:
            await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                t.cancel()
            try:
                up_w.close()
            except Exception:
                pass
        return total


async def http_connect_pub(ep: Endpoint, host: str, port: int, timeout: float):
    from .httpclient import http_connect
    return await http_connect(ep.host, ep.port, host, port, ep.user, ep.password, timeout)


def socket_ntop6(b: bytes) -> str:
    import socket as _s
    return _s.inet_ntop(_s.AF_INET6, b)


def is_routable(host: str) -> bool:
    """Reject loopback / link-local / multicast / reserved so a proxy never dials inward."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # hostname: allow
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
