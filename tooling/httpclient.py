"""Raw asyncio HTTP/1.1 client with pluggable transport: direct, HTTP CONNECT, SOCKS4, SOCKS5.

Written against asyncio streams rather than aiohttp internals so the tester keeps
working across aiohttp releases. Gives us the raw banner bytes (needed for
residential-vs-openrelay classification) and full control of the CONNECT phase.
"""
from __future__ import annotations

import asyncio
import base64
import gzip
import ipaddress
import random
import socket
import ssl
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlsplit, unquote

CRLF = b"\r\n"

# asyncio dropped the `executor=` argument from create_connection in 3.10, so
# hostname resolution has to be done ourselves. Proxy lists are full of
# half-dead hostnames; resolving them on the default loop executor serialises
# every connect behind it. This pool keeps that off the default executor.
_EXECUTOR: "ThreadPoolExecutor | None" = None
_EXECUTOR_LOCK = threading.Lock()


def resolve_executor(workers: int = 64) -> "ThreadPoolExecutor":
    global _EXECUTOR
    with _EXECUTOR_LOCK:
        if _EXECUTOR is None:
            _EXECUTOR = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="resi-dns")
        return _EXECUTOR


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _getaddrinfo(host: str, port: int) -> list[tuple]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    # IPv4 first: open proxy lists are overwhelmingly v4.
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    return [(i[0], i[4]) for i in infos]


async def tcp_connect(host: str, port: int, timeout: float, executor=None) -> tuple:
    """Resolve (off the default executor) then connect by IP literal.

    Returns (reader, writer). Raises the last socket error on failure.
    """
    loop = asyncio.get_running_loop()
    if _is_ip(host):
        targets = [(0, (host.strip("[]"), port))]
    else:
        try:
            targets = await loop.run_in_executor(executor or resolve_executor(),
                                                  _getaddrinfo, host, port)
        except Exception as e:
            raise ConnectError(f"resolve {host}: {e}") from e
        if not targets:
            raise ConnectError(f"no address for {host}")
    last: Exception | None = None
    for family, addr in targets[:4]:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(addr[0], addr[1], family=family), timeout)
        except Exception as e:
            last = e
    raise last if last else ConnectError(f"connect {host}:{port} failed")


class ProxyError(Exception):
    pass


class ConnectError(ProxyError):
    pass


class HTTPStatusError(ProxyError):
    def __init__(self, status: int, reason: str, headers: dict, body: bytes):
        super().__init__(f"HTTP {status} {reason}")
        self.status, self.reason, self.headers, self.body = status, reason, headers, body


class Timeout(ProxyError):
    pass


# ---------------------------------------------------------------- transports


async def _read_head(reader: asyncio.StreamReader, limit: int = 65536) -> bytes:
    """Read up to the first CRLFCRLF, byte by byte so nothing after is consumed."""
    buf = bytearray()
    while len(buf) < limit:
        b = await reader.read(1)
        if not b:
            if not buf:
                raise ConnectError("eof during handshake")
            break
        buf += b
        if buf.endswith(b"\r\n\r\n") or buf.endswith(b"\n\n"):
            break
    return bytes(buf)


def _parse_status(head: bytes) -> tuple[int, str, dict]:
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines:
        raise ConnectError("empty response")
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise ConnectError(f"bad status line: {status_line[:80]!r}")
    code = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""
    hdrs: dict[str, str] = {}
    for ln in lines[1:]:
        if not ln.strip():
            continue
        k, _, v = ln.partition(b":")
        hdrs[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return code, reason, hdrs


async def socks5_connect(host: str, port: int, user: str | None, pw: str | None,
                         timeout: float, remote_dns: bool = True,
                         dst_host: str | None = None, dst_port: int = 0) -> tuple:
    reader, writer = await tcp_connect(host, port, timeout)
    banner = b""
    try:
        if user:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await writer.drain()
        # A SOCKS5 reply is VER(1) + METHOD(1), but a few servers (and a few
        # SOCKS4 servers, which is the point of the fallback) answer with a
        # single byte. Accept one or two and infer the rest.
        first = await asyncio.wait_for(reader.readexactly(1), timeout)
        banner += first
        if first[0] == 0x5A:
            raise ConnectError("socks4 rejected (91/74 reply in disguise)")
        if first[0] == 0x00:
            # SOCKS4-style: 0x00 granted
            methods = 0
        elif first[0] == 0x05:
            try:
                m = await asyncio.wait_for(reader.readexactly(1), timeout)
                banner += m
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                m = b"\x00"
            methods = m[0]
        else:
            raise ConnectError(f"not socks5: ver={first[0]}")
        if methods == 0xFF or methods == 0x5A:
            raise ConnectError(f"socks: no acceptable auth method ({methods})")
        if methods == 0x02:
            if not user:
                raise ConnectError("socks5 wants auth, none supplied")
            u = (user or "").encode()
            p = (pw or "").encode()
            writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            r = await asyncio.wait_for(reader.readexactly(2), timeout)
            banner += r
            if r[1] != 0:
                raise ConnectError(f"socks5 auth failed: {r[1]}")
        elif methods not in (0x00,):
            raise ConnectError(f"unexpected socks5 method {methods}")

        # destination: the caller-supplied one, else the proxy itself (raw probe)
        dhost = dst_host or host
        dport = dst_port or port
        if remote_dns:
            atyp = 0x03
            body = bytes([0x05, 0x01, 0x00, atyp, len(dhost)]) + dhost.encode() + struct.pack("!H", dport)
        else:
            infos = await asyncio.get_running_loop().run_in_executor(
                None, _getaddrinfo, dhost, dport)
            ip = infos[0][1][0]
            atyp = 0x01 if ":" not in ip else 0x04
            body = bytes([0x05, 0x01, 0x00, atyp]) + (ipaddress_bytes(ip)) + struct.pack("!H", dport)
        writer.write(body)
        await writer.drain()
        r = await asyncio.wait_for(reader.readexactly(4), timeout)
        banner += r
        if r[1] != 0:
            raise ConnectError(f"socks5 connect refused: rep={r[1]}")
        # drain the whole BND field: ADDR then PORT. Leaving PORT in the buffer
        # makes the next HTTP read start two bytes into garbage.
        if r[3] == 0x01:
            await asyncio.wait_for(reader.readexactly(4), timeout)
        elif r[3] == 0x04:
            await asyncio.wait_for(reader.readexactly(16), timeout)
        elif r[3] == 0x03:
            n = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
            await asyncio.wait_for(reader.readexactly(n), timeout)
        else:
            raise ConnectError(f"socks5 bad atyp in reply: {r[3]}")
        await asyncio.wait_for(reader.readexactly(2), timeout)
        return reader, writer, banner
    except Exception:
        writer.close()
        raise


def ipaddress_bytes(ip: str) -> bytes:
    if ":" in ip:
        return bytes(int(x, 16) for x in ip.split(":"))
    return bytes(int(x) for x in ip.split("."))


async def socks4_connect(host: str, port: int, user: str | None, timeout: float,
                         remote_dns: bool = True,
                         dst_host: str | None = None, dst_port: int = 0) -> tuple:
    reader, writer = await tcp_connect(host, port, timeout)
    banner = b""
    try:
        dhost = dst_host or host
        dport = dst_port or port
        writer.write(b"\x04\x01" + struct.pack("!H", dport))
        if remote_dns:
            writer.write(bytes([0, 0, 0, 1]) + b"\x00" * 4)
            writer.write(dhost.encode())
        else:
            infos = await asyncio.get_running_loop().run_in_executor(
                None, _getaddrinfo, dhost, dport)
            writer.write(ipaddress_bytes(infos[0][1][0]))
        writer.write(b"\x00" + (user or "").encode() + b"\x00")
        await writer.drain()
        head = await asyncio.wait_for(reader.readexactly(8), timeout)
        banner += head
        if head[1] != 90:
            raise ConnectError(f"socks4 refused: code={head[1]}")
        return reader, writer, banner
    except Exception:
        writer.close()
        raise


async def http_connect(host: str, port: int, dst_host: str, dst_port: int,
                       user: str | None, pw: str | None, timeout: float,
                       server_hostname: str | None = None) -> tuple:
    reader, writer = await tcp_connect(host, port, timeout)
    banner = b""
    try:
        target = dst_host if dst_port == 443 else f"{dst_host}:{dst_port}"
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        if user:
            tok = base64.b64encode(f"{user}:{pw or ''}".encode()).decode()
            lines.append(f"Proxy-Authorization: Basic {tok}")
        lines += ["Proxy-Connection: keep-alive", "User-Agent: curl/8.4.0", "Connection: keep-alive", "", ""]
        writer.write(CRLF.join(x.encode() for x in lines))
        await writer.drain()
        head = await _read_head(reader)
        banner += head
        code, reason, _ = _parse_status(head)
        if code != 200:
            raise ConnectError(f"CONNECT failed: {code} {reason}")
        return reader, writer, banner
    except Exception:
        writer.close()
        raise


async def http_open(host: str, port: int, user: str | None, pw: str | None,
                    timeout: float) -> tuple:
    """Bare connection to an http proxy, no CONNECT. For absolute-form requests."""
    reader, writer = await tcp_connect(host, port, timeout)
    try:
        if user:
            tok = base64.b64encode(f"{user}:{pw or ''}".encode()).decode()
            writer.write(f"Proxy-Authorization: Basic {tok}\r\n".encode())
            await writer.drain()
        return reader, writer, b""
    except Exception:
        writer.close()
        raise


async def direct_connect(host: str, port: int, timeout: float, executor=None) -> tuple:
    r, w = await tcp_connect(host, port, timeout, executor)
    return r, w, b""


# ---------------------------------------------------------------- endpoint


@dataclass
class Endpoint:
    host: str
    port: int
    scheme: str = "http"           # http | https | socks5 | socks4
    user: str | None = None
    password: str | None = None

    @property
    def auth(self) -> str:
        if not self.user:
            return ""
        return f"{self.user}:{self.password or ''}@"

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.user or ''}:{self.password or ''}@{self.host}:{self.port}"

    def url(self) -> str:
        return f"{self.scheme}://{self.auth}{self.host}:{self.port}"

    def __str__(self) -> str:
        return f"{self.scheme}://{self.auth}{self.host}:{self.port}"

    @staticmethod
    def parse(line: str, default_scheme: str = "http") -> "Endpoint | None":
        """Accepts 1.2.3.4:8080, scheme://h:p, user:pass@h:p, http://u:p@h:p, full proxy URLs."""
        s = line.strip()
        if not s or s.startswith("#"):
            return None
        if "://" not in s:
            s = f"{default_scheme}://{s}"
        try:
            u = urlsplit(s)
        except ValueError:
            return None
        if not u.hostname:
            return None
        port = u.port
        scheme = (u.scheme or default_scheme).lower()
        if scheme in ("socks", "socks5h", "socks5"):
            scheme = "socks5"
        if scheme in ("socks4a",):
            scheme = "socks4"
        if port is None:
            port = {"http": 80, "https": 443, "socks5": 1080, "socks4": 1080}.get(scheme, 8080)
        user = unquote(u.username) if u.username else None
        pw = unquote(u.password) if u.password else None
        return Endpoint(u.hostname.strip("[]"), int(port), scheme, user, pw)


async def tunnel(ep: Endpoint, dst_host: str, dst_port: int, timeout: float) -> tuple:
    """Open a byte tunnel to dst through ep. Returns (reader, writer, banner_bytes).

    For SOCKS the destination is the 3rd/4th arg of socks5_connect; passing
    ep.host/ep.port there would ask the proxy to connect to itself.
    """
    if ep.scheme in ("socks5",):
        return await socks5_connect(ep.host, ep.port, ep.user, ep.password, timeout,
                                    dst_host=dst_host, dst_port=dst_port)
    if ep.scheme in ("socks4",):
        return await socks4_connect(ep.host, ep.port, ep.user, timeout,
                                    dst_host=dst_host, dst_port=dst_port)
    return await http_connect(ep.host, ep.port, dst_host, dst_port, ep.user, ep.password, timeout)


# ---------------------------------------------------------------- TLS


def make_insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


SSL_CTX_INSECURE = make_insecure_ctx()


async def tls_wrap(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str,
                    timeout: float, ctx: ssl.SSLContext | None = None) -> None:
    """Upgrade an established stream to TLS in place.

    asyncio's StreamWriter.start_tls() already re-points the protocol at the new
    transport, so both the reader and the writer see the TLS stream afterwards.
    """
    ctx = ctx or SSL_CTX_INSECURE
    await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), timeout)


# ---------------------------------------------------------------- request/response


@dataclass
class Response:
    status: int
    reason: str
    headers: dict
    body: bytes
    elapsed_ms: float
    banner: bytes = b""
    raw_head: bytes = b""

    def text(self, limit: int = 4096) -> str:
        return self.body[:limit].decode("utf-8", "replace")

    def header(self, k: str, default: str = "") -> str:
        return self.headers.get(k.lower(), default)


@dataclass
class Pool:
    """One keep-alive connection, keyed by (endpoint, destination, tls)."""
    ep: Endpoint
    dst: tuple[str, int]
    key: tuple
    reader: asyncio.StreamReader = field(default=None, repr=False)
    writer: asyncio.StreamWriter = field(default=None, repr=False)
    banner: bytes = b""
    created: float = 0.0
    last_used: float = 0.0
    requests: int = 0

    def alive(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()


class Session:
    """Async session with connection pooling. Not thread-safe; one per event loop."""

    def __init__(self, timeout: float = 8.0, pool_size: int = 8, keepalive: bool = True,
                 user_agent: str | None = None, max_body: int = 262144, executor=None):
        self.timeout = timeout
        self.pool_size = pool_size
        self.keepalive = keepalive
        self.executor = executor
        self.ua = user_agent or random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        ])
        self.max_body = max_body
        self._pools: dict[tuple, list[Pool]] = {}

    async def request(self, ep: Endpoint | None, method: str, url: str, headers: dict | None = None,
                      body: bytes | None = None, timeout: float | None = None,
                      read_body: bool = True, retry: bool = True) -> Response:
        t0 = time.perf_counter()
        u = urlsplit(url)
        tls = u.scheme == "https"
        host, port = u.hostname, u.port or (443 if tls else 80)
        if not host:
            raise ProxyError(f"no host in {url}")
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        timeout = timeout or self.timeout

        hdrs = {
            "Host": u.netloc.split("@")[-1],
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive" if self.keepalive else "close",
        }
        if headers:
            hdrs.update(headers)

        p = await self._get_conn(ep, host, port, tls, timeout)
        # request line. An http proxy on a non-tls target wants absolute-form;
        # everything else (direct, socks, CONNECT) wants origin-form.
        absolute = ep is not None and ep.scheme in ("http", "https") and not tls
        target_path = url if absolute else path
        head = [f"{method} {target_path} HTTP/1.1"]
        for k, v in hdrs.items():
            head.append(f"{k}: {v}")
        if body:
            head.append(f"Content-Length: {len(body)}")
        elif method in ("POST", "PUT", "PATCH"):
            head.append("Content-Length: 0")
        raw = CRLF.join(h.encode("latin-1") for h in head) + CRLF + CRLF
        if body:
            raw += body
        try:
            p.writer.write(raw)
            await p.writer.drain()
            return await self._read_response(p, t0, read_body)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, ssl.SSLError,
                TimeoutError, asyncio.TimeoutError, ConnectError) as e:
            await self._close(p)
            # A pooled socket the peer closed while it sat idle looks alive
            # locally (is_closing() is False) but dies on first read. Retry once
            # on a fresh connection; a second failure is a real failure.
            if retry:
                return await self.request(ep, method, url, headers=headers, body=body,
                                          timeout=timeout, read_body=read_body, retry=False)
            raise ConnectError(f"io: {type(e).__name__}: {e}") from e

    async def _read_response(self, p: Pool, t0: float, read_body: bool) -> Response:
        head = await asyncio.wait_for(_read_head(p.reader), 15)
        code, reason, hdrs = _parse_status(head)
        clen = int(hdrs.get("content-length", "0") or 0)
        chunked = "chunked" in hdrs.get("transfer-encoding", "").lower()
        conn_close = hdrs.get("connection", "").lower() == "close" or code in (204, 304)
        if not read_body:
            body = b""
        elif chunked:
            body = await self._read_chunked(p.reader)
        elif clen:
            body = await asyncio.wait_for(p.reader.readexactly(min(clen, self.max_body)), 15)
        else:
            body = await self._read_to_eof(p.reader, self.max_body)
        if hdrs.get("content-encoding", "").lower().find("gzip") >= 0:
            try:
                body = gzip.decompress(body)
            except Exception:
                try:
                    body = zlib.decompress(body, 16 + zlib.MAX_WBITS)
                except Exception:
                    pass
        elif hdrs.get("content-encoding", "").lower().find("deflate") >= 0:
            try:
                body = zlib.decompress(body)
            except Exception:
                pass
        dt = (time.perf_counter() - t0) * 1000
        p.last_used = time.time()
        p.requests += 1
        if conn_close or not self.keepalive:
            await self._close(p)
        else:
            self._put(p)
        return Response(code, reason, hdrs, body, dt, p.banner, head)

    async def _read_chunked(self, r: asyncio.StreamReader) -> bytes:
        out = bytearray()
        while True:
            line = await asyncio.wait_for(r.readline(), 15)
            if not line:
                break
            try:
                n = int(line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                await asyncio.wait_for(r.readline(), 5)
                break
            out += await asyncio.wait_for(r.readexactly(n), 15)
            await asyncio.wait_for(r.readexactly(2), 5)
            if len(out) > self.max_body:
                break
        return bytes(out)

    async def _read_to_eof(self, r: asyncio.StreamReader, cap: int) -> bytes:
        out = bytearray()
        while len(out) < cap:
            chunk = await asyncio.wait_for(r.read(8192), 10)
            if not chunk:
                break
            out += chunk
        return bytes(out)

    async def _get_conn(self, ep: Endpoint | None, host: str, port: int, tls: bool, timeout: float) -> Pool:
        key = (ep.key if ep else "direct", host, port, tls)
        if self.keepalive:
            lst = self._pools.setdefault(key, [])
            while lst:
                p = lst.pop()
                if p.alive() and time.time() - p.last_used < 30:
                    return p
                await self._close(p)
        if ep is None:
            r, w, b = await direct_connect(host, port, timeout, self.executor)
        elif ep.scheme in ("socks5", "socks4"):
            r, w, b = await tunnel(ep, host, port, timeout)
        elif tls:
            # CONNECT is only for https targets; an http target through an
            # http proxy uses absolute-form, so open a plain TCP link instead.
            r, w, b = await http_connect(ep.host, ep.port, host, port, ep.user, ep.password, timeout)
        else:
            # absolute-form tunnel: we write "GET http://host/path HTTP/1.1"
            # ourselves, so a bare TCP link to the proxy is all that is needed.
            r, w, b = await direct_connect(ep.host, ep.port, timeout, self.executor)
        if tls:
            await tls_wrap(r, w, host, timeout)
        return Pool(ep or Endpoint(host, port, "direct"), (host, port), key, r, w, b, time.time(), time.time())

    def _put(self, p: Pool) -> None:
        lst = self._pools.setdefault(p.key, [])
        if len(lst) < self.pool_size and p.alive():
            lst.append(p)
        else:
            asyncio.create_task(self._close(p))

    async def _close(self, p: Pool) -> None:
        try:
            if p.writer and not p.writer.is_closing():
                p.writer.close()
                await asyncio.wait_for(p.writer.wait_closed(), 2)
        except Exception:
            pass

    async def close(self) -> None:
        for lst in self._pools.values():
            for p in lst:
                await self._close(p)
        self._pools.clear()

    # convenience
    async def get(self, ep: Endpoint | None, url: str, **kw) -> Response:
        return await self.request(ep, "GET", url, **kw)

    async def post(self, ep: Endpoint | None, url: str, body: bytes | str = b"",
                   headers: dict | None = None, **kw) -> Response:
        h = {"Content-Type": "application/json"} if isinstance(body, (bytes, str)) else {}
        if headers:
            h.update(headers)
        return await self.request(ep, "POST", url, headers=h,
                                  body=body.encode() if isinstance(body, str) else body, **kw)
