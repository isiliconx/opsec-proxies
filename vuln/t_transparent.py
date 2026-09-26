"""Detector: transparency. Does the exit IP actually differ from ours, and is the
proxy rewriting the request (X-Forwarded-For injection, header stripping)?

Anonymity score:
  exit_ip != our_ip        +0.5   it forwards to a different egress
  no Via / XFF injection  +0.3   the client header is not appended
  our UA survives         +0.2   no banner rewrite
"""
from __future__ import annotations

import asyncio
import json
import re
import time

from tooling.httpclient import Endpoint, Session
from tooling import logging_util as lu

log = lu.get()

ECHOS = [
    ("ipify", "https://api.ipify.org?format=json"),
    ("httpbin", "http://httpbin.org/ip"),
    ("icanhazip", "https://icanhazip.com"),
    ("ifconfig", "https://ifconfig.me/ip"),
    ("identme", "https://ident.me"),
]

INJECT_HEADERS = ("via", "x-forwarded-for", "x-real-ip", "forwarded", "x-client-ip",
                  "x-proxy-id", "proxy-connection", "x-forwarded-host", "x-forwarded-proto")

MARKER = "resiproxy-probe-8f3c9a"


def extract_ip(text: str) -> str:
    """Pull an IP out of a judge response: bare ip, single-line json, or pretty json."""
    t = text.strip()
    if t.startswith("{"):
        try:
            d = json.loads(t)
            for k in ("ip", "origin", "query", "ipAddress"):
                if k in d and d[k]:
                    v = str(d[k]).split(",")[0].strip()
                    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", v):
                        return v
        except Exception:
            pass
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", t)
    return m.group(0) if m else ""


def anonymity_score(res_body: str, res_headers: dict, our_ip: str, req_ua: str) -> tuple[float, dict]:
    exit_ip = extract_ip(res_body)
    same = bool(exit_ip) and bool(our_ip) and exit_ip == our_ip
    injected = {h: res_headers[h] for h in INJECT_HEADERS if h in res_headers}
    ua_back = req_ua in res_body or req_ua in " ".join(res_headers.values())
    score = 0.0
    if exit_ip and not same:
        score += 0.5
    if not injected:
        score += 0.3
    if ua_back or not res_body:
        score += 0.2
    detail = {"exit_ip": exit_ip, "same_as_me": same, "injected": injected, "ua_reflected": ua_back}
    return score, detail


class TransparencyProbe:
    def __init__(self, our_ip: str, judge_url: str = "http://httpbin.org/ip", timeout: float = 8.0):
        self.our_ip = our_ip
        self.judge_url = judge_url
        self.timeout = timeout
        # one-shot judge requests through flaky relays: no keepalive, no pooling
        self.sess = Session(timeout=timeout, pool_size=1, keepalive=False)
        self.ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 {MARKER}"

    async def our_exit_ip(self) -> str:
        for name, url in ECHOS:
            try:
                r = await self.sess.get(None, url, timeout=self.timeout)
                ip = extract_ip(r.text(300))
                if ip:
                    return ip
            except Exception:
                continue
        return ""

    async def probe(self, ep: Endpoint) -> dict:
        t0 = time.perf_counter()
        attempts = []
        for name, url in ([("judge", self.judge_url)] + ECHOS):
            try:
                r = await self.sess.get(ep, url, headers={"User-Agent": self.ua,
                                                          "X-Resi-Probe": MARKER}, timeout=self.timeout)
                if r.status != 200:
                    attempts.append({"target": name, "status": r.status})
                    continue
                score, detail = anonymity_score(r.text(4000), r.headers, self.our_ip, self.ua)
                detail.update({"target": name, "status": r.status,
                               "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                               "verdict": "transparent" if detail.get("exit_ip") else "dead"})
                detail["anonymity_score"] = round(score, 2)
                return detail
            except Exception as e:
                attempts.append({"target": name, "error": f"{type(e).__name__}: {str(e)[:80]}"})
        return {"verdict": "dead", "exit_ip": "", "anonymity_score": 0.0, "attempts": attempts}

    async def close(self) -> None:
        await self.sess.close()
