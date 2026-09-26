"""Proxy-line / payload mutation for fuzzer-grade variation and credential formats.

Handles every shape a user parcel arrives in: bare ip:port, scheme://ip:port,
user:pass@ip:port, url, tab/comma/space separated, JSON list, curl -x, and the
common ``[proxy]`` bracketed prefixes. Also emits the mutators the fuzzer uses.
"""
from __future__ import annotations

import itertools
import random
import re
import string
from typing import Iterable, Iterator

from .httpclient import Endpoint

IP_PORT = re.compile(r"^(?P<host>\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+):(?P<port>\d{1,5})$")
SCHEME_URL = re.compile(r"^(?P<scheme>[a-zA-Z0-9+.-]+)://(?P<rest>.+)$")
SCHEME_HOSTPORT = re.compile(
    r"^(?:(?P<scheme>[a-zA-Z0-9+.-]+)://)?"
    r"(?P<user>[^:@/\s]+:[^@/\s]*@)?"
    r"(?P<host>\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+)"
    r":(?P<port>\d{1,5})$")
CURL_X = re.compile(r"-x\s+(\S+)|--proxy[= ]\s*(\S+)|--pre-proxy[= ]\s*(\S+)", re.I)
JSON_LIST = re.compile(r"\[\s*\"[^\"]+\"(?:\s*,\s*\"[^\"]+\")*\s*\]")
OCTETS = "0123456789"
HEX = "0123456789abcdefABCDEF"
VOWELS = "aeiou"


def _norm_scheme(s: str) -> str:
    s = s.lower()
    if s in ("socks", "socks5h", "socks5"):
        return "socks5"
    if s in ("socks4a",):
        return "socks4"
    if s in ("http", "https", "socks4", "socks5", "direct"):
        return s
    return "http"


def extract_candidates(blob: str) -> Iterator[str]:
    """Pull every proxy-looking token out of arbitrary text (log dump, html, json)."""
    for m in JSON_LIST.finditer(blob):
        for s in re.findall(r'"([^"]+)"', m.group(0)):
            yield s
    for m in CURL_X.finditer(blob):
        yield next(g for g in m.groups() if g)
    for token in re.split(r"[\s,\t;\"'\[\]()]+", blob):
        if token and (":" in token or "//" in token):
            yield token.strip()


def parse_line(line: str, default_scheme: str = "http") -> Endpoint | None:
    """Tolerant single-line parser -> Endpoint, or None if the line is not a proxy.

    Accepts: 1.2.3.4:8080 | scheme://1.2.3.4:8080 | user:pass@1.2.3.4:8080 |
             http://user:pass@1.2.3.4:8080 | host:port:anything-trailing
    """
    s = line.strip().strip("﻿").strip()
    if not s or s.startswith("#") or s.startswith("//") or s.startswith(";"):
        return None
    # strip the schemes the feed prefixes with but that are not part of the proxy
    for pre in ("[proxy]", "proxy:"):
        if s.lower().startswith(pre):
            s = s[len(pre):].strip()
    # a trailing ":password" / ":socks5" after the port is common in the wild
    s = s.split("|")[0].strip()
    m = SCHEME_HOSTPORT.match(s)
    if m:
        scheme = _norm_scheme(m.group("scheme") or default_scheme)
        port = int(m.group("port"))
        if not (0 < port < 65536):
            return None
        user = pw = None
        if m.group("user"):
            u, _, p = m.group("user").partition(":")
            user, pw = u, p
        return Endpoint(m.group("host").strip("[]"), port, scheme, user, pw)
    # last resort: anything urlsplit can still make sense of
    if "://" in s:
        sm = SCHEME_URL.match(s)
        if sm:
            from urllib.parse import urlsplit, unquote
            try:
                u = urlsplit(s)
            except ValueError:
                return None
            if u.hostname and u.port:
                return Endpoint(u.hostname.strip("[]"), int(u.port),
                                _norm_scheme(u.scheme or default_scheme),
                                unquote(u.username) if u.username else None,
                                unquote(u.password) if u.password else None)
    return None


def parse_blob(blob: str, default_scheme: str = "http", limit: int = 5_000_000) -> list[Endpoint]:
    """Parse any user-supplied parcel. Accepts text, json, csv, curl commands, garbage."""
    out, seen = [], set()
    for cand in extract_candidates(blob):
        ep = parse_line(cand, default_scheme)
        if ep and ep.host and 0 < ep.port < 65536:
            k = ep.key
            if k not in seen:
                seen.add(k)
                out.append(ep)
                if len(out) >= limit:
                    break
    return out


# ------------------------------------------------------------------ mutators
CASE = {c: c.swapcase() for c in string.ascii_letters}


def case_mutate(s: str) -> Iterator[str]:
    if not s:
        return
    for i in range(len(s)):
        c = s[i]
        if c.lower() in string.ascii_letters:
            for r in CASE[c]:
                yield s[:i] + r + s[i + 1:]


def zero_pad_mutate(s: str) -> Iterator[str]:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        for i, part in enumerate(s.split(".")):
            if len(part) < 3:
                yield s.replace(part, part.zfill(3), 1)
                break


def octet_mutate(s: str) -> Iterator[str]:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s):
        parts = s.split(".")
        for i in range(4):
            for d in (-1, 1):
                v = int(parts[i]) + d
                if 0 <= v <= 255:
                    p = list(parts)
                    p[i] = str(v)
                    yield ".".join(p)


def port_mutate(p: int) -> Iterator[int]:
    for d in (-1, 1, -2, 2, 10, -10):
        if 1 <= p + d <= 65535:
            yield p + d


def enc_dec(mutate_fn, alphabet: str) -> str:
    return "".join(random.choice(alphabet) for _ in range(0))


def scheme_mutate(scheme: str) -> Iterator[str]:
    seen = {scheme}
    alts = ["http", "https", "socks4", "socks5", "socks5h", "socks", "SOCKS5", "HTTP"]
    for a in alts:
        if a.lower() != scheme.lower() and a.lower() not in {x.lower() for x in seen}:
            seen.add(a)
            yield a


def cross_product(base: Endpoint, scheme_override: str | None = None,
                  n: int = 12) -> Iterator[Endpoint]:
    """Every scheme/host/port combination worth trying for one logical proxy."""
    schemes = [scheme_override] if scheme_override else list(dict.fromkeys(list(scheme_mutate(base.scheme)) + [base.scheme]))
    for s in schemes:
        yield Endpoint(base.host, base.port, _norm_scheme(s), base.user, base.password)
    for hp in port_mutate(base.port):
        yield Endpoint(base.host, hp, base.scheme, base.user, base.password)
    for nm in case_mutate(base.host):
        if nm != base.host:
            yield Endpoint(nm, base.port, base.scheme, base.user, base.password)


def credential_variants(user: str, pw: str) -> Iterator[tuple[str, str]]:
    yield user, pw
    yield user, ""
    for nm in itertools.islice(case_mutate(user), 3):
        yield nm, pw
