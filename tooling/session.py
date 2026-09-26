"""Per-identity session helper: cookie jar, pinned language, rotating UA, exit-IP cache.

One Session object == one simulated browser identity. Never share a Session across
identities, never reuse a cookie jar across a privilege change, and keep the
Accept-Language pinned for the life of the session.
"""
from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

from .config import ACCEPT_LANGS, UA_POOL
from .httpclient import Endpoint, Session

UA_BY_CC = {
    "US": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "DE": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "JP": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "BR": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "IN": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "GB": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "RU": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "FR": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "NL": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "IT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
}


@dataclass
class Identity:
    """A single simulated browser + its exit proxy."""
    name: str
    proxy: Endpoint | None = None
    ua: str = field(default_factory=lambda: random.choice(UA_POOL))
    lang: str = field(default_factory=lambda: random.choice(ACCEPT_LANGS))
    cc: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    created: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    exit_ip: str = ""
    requests: int = 0
    failures: int = 0

    def headers(self, extra: dict | None = None) -> dict[str, str]:
        h = {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": self.lang,
            "Accept-Encoding": "gzip, deflate",
            "Upgrade-Insecure-Requests": "1",
            "Dnt": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if extra:
            h.update(extra)
        return h

    def absorb(self, set_cookie: list[str] | None) -> None:
        """Store cookies per identity. Never shared across identities."""
        for sc in set_cookie or []:
            c = SimpleCookie()
            try:
                c.load(sc)
            except Exception:
                continue
            for k, morsel in c.items():
                if morsel["max-age"] == "0" or morsel["expires"] in ("Thu, 01 Jan 1970 00:00:00 GMT", ""):
                    self.cookies.pop(k, None)
                else:
                    self.cookies[k] = morsel.value

    def match_ua_to_country(self, cc: str) -> None:
        if cc in UA_BY_CC:
            self.ua = UA_BY_CC[cc]
            lang = {"US": "en-US,en;q=0.9", "DE": "de-DE,de;q=0.9,en;q=0.7", "JP": "ja-JP,ja;q=0.9,en;q=0.7",
                    "BR": "pt-BR,pt;q=0.9,en;q=0.7", "IN": "en-IN,en;q=0.9", "GB": "en-GB,en;q=0.8",
                    "RU": "ru-RU,ru;q=0.9,en;q=0.7", "FR": "fr-FR,fr;q=0.9,en;q=0.7",
                    "NL": "nl-NL,nl;q=0.9,en;q=0.7", "IT": "it-IT,it;q=0.9,en;q=0.7"}.get(cc)
            if lang:
                self.lang = lang


class SessionManager:
    def __init__(self, timeout: float = 15.0, pool_size: int = 4):
        self.sess = Session(timeout=timeout, pool_size=pool_size, keepalive=True)
        self.identities: dict[str, Identity] = {}
        self._rotate_at = 3600.0

    def new_identity(self, name: str, proxy: Endpoint | None = None, cc: str = "") -> Identity:
        ident = Identity(name=name, proxy=proxy)
        if cc:
            ident.cc = cc
            ident.match_ua_to_country(cc)
        self.identities[name] = ident
        return ident

    def rotate_identity(self, name: str) -> Identity:
        old = self.identities.pop(name, None)
        ident = self.new_identity(name, old.proxy if old else None)
        return ident

    def retire(self, name: str) -> None:
        """Drop an identity entirely: cookies gone, nothing reused."""
        self.identities.pop(name, None)

    async def fetch(self, ident: Identity, url: str, method: str = "GET", headers: dict | None = None,
                    body: bytes | str | None = None, timeout: float | None = None, read_body: bool = True):
        ident.last_used = time.time()
        ident.requests += 1
        h = ident.headers(headers)
        extra_ct = {"Content-Type": "application/json"} if body is not None else {}
        h.update(extra_ct)
        try:
            r = await self.sess.request(ident.proxy, method, url, headers=h,
                                        body=body.encode() if isinstance(body, str) else body,
                                        timeout=timeout, read_body=read_body)
            if r.header("set-cookie"):
                ident.absorb([v for v in r.headers.get("set-cookie", "").split("\x1e") if v])
            return r
        except Exception:
            ident.failures += 1
            raise

    async def close(self) -> None:
        await self.sess.close()


class ExitIPCache:
    """What IP am I exiting as, through a given proxy. Cached per proxy for 60s."""

    def __init__(self, judge_url: str = "http://httpbin.org/ip", timeout: float = 8.0):
        self.judge_url = judge_url
        self.timeout = timeout
        self.sess = Session(timeout=timeout, pool_size=1, keepalive=False)
        self._cache: dict[str, tuple[float, str]] = {}
        self.ttl = 60.0

    def get(self, ep: Endpoint) -> str | None:
        e = self._cache.get(ep.key)
        if e and e[0] > time.time():
            return e[1]
        return None

    async def probe(self, ep: Endpoint) -> str:
        c = self.get(ep)
        if c:
            return c
        for url in (self.judge_url, "https://api.ipify.org", "http://ifconfig.me/ip",
                    "https://ipinfo.io/ip", "https://icanhazip.com"):
            try:
                r = await self.sess.get(ep, url, timeout=self.timeout)
                txt = r.text(200).strip()
                if txt and _is_ip(txt):
                    self._cache[ep.key] = (time.time() + self.ttl, txt)
                    return txt
            except Exception:
                continue
        self._cache[ep.key] = (time.time() - 1, "")
        return ""

    async def close(self) -> None:
        await self.sess.close()


def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
