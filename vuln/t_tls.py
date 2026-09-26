"""Detector: TLS through the proxy. Confirms a real CONNECT tunnel with SNI.

A residential edge rarely does TLS; a real open proxy usually does. Either way we
record whether the tunnel upgrades, and the SNI/cert story that comes back.
"""
from __future__ import annotations

import asyncio
import ssl
import time

from tooling.httpclient import (ConnectError, Endpoint, SSL_CTX_INSECURE, Session,
                                http_connect, socks4_connect, socks5_connect, tls_wrap, tunnel)
from tooling import logging_util as lu

log = lu.get()

TLS_PROBES = [
    ("cloudflare", "cloudflare.com", 443, "/cdn-cgi/trace"),
    ("google", "www.google.com", 443, "/generate_204"),
    ("github", "github.com", 443, "/robots.txt"),
]


async def tls_probe(ep: Endpoint, host: str, port: int = 443, path: str = "/", timeout: float = 8.0):
    """Open a tunnel, upgrade to TLS, do one GET. Returns dict of evidence."""
    t0 = time.perf_counter()
    reader = writer = None
    try:
        reader, writer, _ = await tunnel(ep, host, port, timeout)
        await tls_wrap(reader, writer, host, timeout, SSL_CTX_INSECURE)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout)
        dt = (time.perf_counter() - t0) * 1000
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        status = 0
        first = head.split("\r\n", 1)[0]
        parts = first.split(" ")
        if len(parts) > 1 and parts[1].isdigit():
            status = int(parts[1])
        return {"ok": status > 0, "status": status, "latency_ms": round(dt, 1),
                "sni": host, "head": head[:300], "verdict": "tls_ok" if status > 0 else "tls_fail"}
    except Exception as e:
        return {"ok": False, "status": 0, "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                "sni": host, "error": f"{type(e).__name__}: {str(e)[:120]}",
                "verdict": "tls_refused"}
    finally:
        try:
            if writer:
                writer.close()
        except Exception:
            pass


async def tls_suite(ep: Endpoint, timeout: float = 8.0) -> dict:
    """Try three TLS origins; one success is enough. Returns aggregate evidence."""
    results = []
    for name, host, port, path in TLS_PROBES:
        r = await tls_probe(ep, host, port, path, timeout)
        r["target"] = name
        results.append(r)
        if r["ok"]:
            break
    good = [r for r in results if r["ok"]]
    return {
        "tls_ok": bool(good),
        "latency_ms": min((r["latency_ms"] for r in good), default=0),
        "attempts": results,
        "verdict": "tls_ok" if good else "tls_fail",
    }
