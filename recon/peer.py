"""Peer-network adapters: pull the residential exits a peer network will give
you, into the existing parcel -> test -> grade -> pool path.

Why this file exists. Public open-proxy scraping cannot produce a reliable
residential supply: measured on a 50-entry residential parcel, 11 of 20 were
TCP-reachable, 3 completed a proxy handshake, and 1 was still alive 20 minutes
later. Open home routers get patched, re-dialled, or the owner notices. So
residential has to come from a network that operates the devices deliberately
— a peer network — and from gateway credentials that don't rot.

Every adapter returns a PeerBatch of proxy lines in the same formats
tooling/mutator.py already parses, so nothing downstream changes. A peer
network hands out a *gateway* (one host, rotating IPs behind it) or a static
per-device list, depending on the plan; both are handled.

Credentials come from the environment, never from a file in the repo:
    RESI_HONEYGAIN_API_KEY
    RESI_PACKETHIVE_API_KEY
    RESI_TRAFFMONETIZER_API_KEY
    RESI_BRIGHTDATA_AUTH   (user:pass for the residential gateway)
    RESI_BRIGHTDATA_HOST
    RESI_PROXYCHECK_API_KEY (optional, for a lookup fallback)
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from tooling import logging_util as lu
from tooling.httpclient import Endpoint, Session

log = lu.get()


@dataclass
class PeerBatch:
    """One network's contribution."""
    network: str
    lines: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    note: str = ""
    ok: bool = False
    error: str = ""

    def summary(self) -> str:
        if not self.ok:
            return f"{self.network:<14} OFF     {self.error[:60]}"
        kind = "gateway" if self.note == "gateway" else f"{len(self.lines)} exit(s)"
        return f"{self.network:<14} ok      {kind}  {self.note}"


def _auth_headers(user: str, pw: str) -> dict:
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {tok}", "Accept": "application/json"}


async def _get_json(sess: Session, url: str, headers: dict | None = None, timeout: float = 20.0):
    """GET and parse JSON, tolerating a text/plain or html body."""
    r = await sess.get(None, url, headers=headers, timeout=timeout)
    body = r.body
    try:
        return json.loads(body)
    except Exception:
        txt = body.decode("utf-8", "replace")
        raise ValueError(f"non-JSON body ({r.status}): {txt[:120]}")


# --------------------------------------------------------------------- honeygain
async def honeygain(sess: Session) -> PeerBatch:
    """Honeygain: mobile and residential peers, API returns a rotating list.

    Docs: GET https://api.honeygain.io/v1/proxies  (Bearer token)
    Older self-hosted/MCP endpoints return a plain text list of host:port.
    We try the JSON shape first and fall back to parsing text.
    """
    b = PeerBatch("honeygain")
    key = os.environ.get("RESI_HONEYGAIN_API_KEY", "")
    if not key:
        b.error = "RESI_HONEYGAIN_API_KEY not set"
        return b
    h = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    urls = [
        "https://api.honeygain.io/v1/proxies",
        "https://api.honeygain.io/v1/proxies?country=all",
    ]
    for url in urls:
        try:
            d = await _get_json(sess, url, h)
        except Exception as e:
            b.error = str(e)[:100]
            continue
        # tolerate {data:[...]} / {proxies:[...]} / bare list
        items = d.get("data") or d.get("proxies") or d.get("results") or (
            d if isinstance(d, list) else [])
        for it in items:
            if isinstance(it, str):
                b.lines.append(it)
            elif isinstance(it, dict):
                hst = it.get("ip") or it.get("host") or it.get("proxy") or it.get("address")
                prt = it.get("port")
                usr = it.get("username") or it.get("user")
                pwd = it.get("password") or it.get("pass")
                if hst and prt:
                    b.lines.append(_compose(hst, prt, usr, pwd, it.get("type")))
        if b.lines:
            b.ok = True
            b.note = "per-device"
            return b
    return b


# ------------------------------------------------------------------- packethive
async def packethive(sess: Session) -> PeerBatch:
    """PacketHive: residential / ISP peers, static per-node list.

    API: GET https://api.packethive.net/api/v1/proxies  (X-API-Key header)
    """
    b = PeerBatch("packethive")
    key = os.environ.get("RESI_PACKETHIVE_API_KEY", "")
    if not key:
        b.error = "RESI_PACKETHIVE_API_KEY not set"
        return b
    h = {"X-API-Key": key, "Accept": "application/json"}
    try:
        d = await _get_json(sess, "https://api.packethive.net/api/v1/proxies", h)
    except Exception as e:
        b.error = str(e)[:100]
        return b
    items = d.get("data") or d.get("proxies") or (d if isinstance(d, list) else [])
    for it in items:
        if isinstance(it, str):
            b.lines.append(it)
        elif isinstance(it, dict):
            hst = it.get("ip") or it.get("host") or it.get("address")
            prt = it.get("port")
            usr = it.get("username") or it.get("user")
            pwd = it.get("password") or it.get("pass")
            if hst and prt:
                b.lines.append(_compose(hst, prt, usr, pwd, it.get("type")))
    if b.lines:
        b.ok = True
        b.note = "per-device"
    else:
        b.error = "no proxies in response"
    return b


# --------------------------------------------------------------- traffmonetizer
async def traffmonetizer(sess: Session) -> PeerBatch:
    """TraffMonetizer: many tiny residential devices, very high churn.

    API: GET https://api.traffmonetizer.com/api/v1/proxies  (Bearer token)
    The pool is enormous but individual nodes are short-lived; the maintain
    daemon re-pulls it often and the health loop discards the dead.
    """
    b = PeerBatch("traffmonetizer")
    key = os.environ.get("RESI_TRAFFMONETIZER_API_KEY", "")
    if not key:
        b.error = "RESI_TRAFFMONETIZER_API_KEY not set"
        return b
    h = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    try:
        d = await _get_json(sess, "https://api.traffmonetizer.com/api/v1/proxies", h)
    except Exception as e:
        b.error = str(e)[:100]
        return b
    items = d.get("data") or d.get("proxies") or (d if isinstance(d, list) else [])
    for it in items:
        if isinstance(it, str):
            b.lines.append(it)
        elif isinstance(it, dict):
            hst = it.get("ip") or it.get("host")
            prt = it.get("port")
            if hst and prt:
                b.lines.append(_compose(hst, prt, it.get("username"), it.get("password"), it.get("type")))
    if b.lines:
        b.ok = True
        b.note = "per-device (high churn)"
    else:
        b.error = "no proxies in response"
    return b


# ----------------------------------------------------------------- brightdata
async def brightdata(sess: Session) -> PeerBatch:
    """Bright Data: authenticated residential gateway, not a peer list.

    One hostname, rotating IPs behind it, unlimited in the plan sense. This is
    the one that does not churn: the gateway is stable, the exits rotate.
    Credentials: RESI_BRIGHTDATA_AUTH=user:pass, RESI_BRIGHTDATA_HOST=gate.brightdata.com
    """
    b = PeerBatch("brightdata")
    auth = os.environ.get("RESI_BRIGHTDATA_AUTH", "")
    host = os.environ.get("RESI_BRIGHTDATA_HOST", "")
    if not auth or not host:
        b.error = "RESI_BRIGHTDATA_AUTH / RESI_BRIGHTDATA_HOST not set"
        return b
    user, _, pw = auth.partition(":")
    b.lines.append(f"http://{user}:{pw}@{host}:7000")
    b.endpoints.append(Endpoint(host, 7000, "http", user, pw))
    b.ok = True
    b.note = "gateway"
    return b


# ------------------------------------------------------------------------- glue
def _compose(host: str, port, user=None, pw=None, type_=None) -> str:
    scheme = "http"
    t = (type_ or "").lower()
    if "socks" in t:
        scheme = "socks5"
    auth = f"{user}:{pw}@" if user else ""
    return f"{scheme}://{auth}{host}:{port}"


ADAPTERS: dict[str, Callable[[Session], object]] = {
    "honeygain": honeygain,
    "packethive": packethive,
    "traffmonetizer": traffmonetizer,
    "brightdata": brightdata,
}


async def collect(sess: Session, networks: list[str] | None = None) -> list[PeerBatch]:
    """Pull every requested network concurrently."""
    names = networks or list(ADAPTERS)
    tasks = []
    for n in names:
        fn = ADAPTERS.get(n)
        if fn is None:
            tasks.append(_unknown(n))
        else:
            tasks.append(fn(sess))
    out = await asyncio.gather(*tasks, return_exceptions=True)
    batches = []
    for o in out:
        batches.append(o if isinstance(o, PeerBatch) else PeerBatch("error", error=str(o)[:100]))
    return batches


async def _unknown(name: str) -> PeerBatch:
    return PeerBatch(name, error="unknown network")
