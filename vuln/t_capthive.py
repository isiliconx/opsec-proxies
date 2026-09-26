"""Detector: request-capture / interception check.

Confirms a proxy is a plain forwarder (not a man-in-the-middle that rewrites the
page) and that it will not inject a script tag. One request to an echo endpoint
that reflects our marker back must come back byte-identical, modulo headers.
"""
from __future__ import annotations

import asyncio
import re
import time

from tooling.httpclient import Endpoint, Session
from tooling import logging_util as lu

log = lu.get()

MARKER = "resiproxy-capture-4b71d2"
ECHO = "http://httpbin.org/anything"


class CaptureCheck:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.sess = Session(timeout=timeout, pool_size=1, keepalive=False)

    async def check(self, ep: Endpoint) -> dict:
        """Returns whether the response reflects our exact request unmodified."""
        try:
            r = await self.sess.post(ep, ECHO,
                                     body=f"resiproxy={MARKER}",
                                     headers={"User-Agent": MARKER, "X-Resi-Mark": MARKER,
                                              "Content-Type": "text/plain"},
                                     timeout=self.timeout)
        except Exception as e:
            return {"verdict": "dead", "error": f"{type(e).__name__}: {str(e)[:80]}"}
        body = r.text(20000)
        reflected = MARKER in body
        # a rewriting proxy strips our content-type or injects <script>
        injected = bool(re.search(r"<script[^>]+(mitm|proxy|inject|brightdata|oxylabs|smartproxy|"
                                  r"scraping\s*browser|residential\s*proxy|webshare|proxymesh)",
                                  body, re.I))
        stripped = reflected and MARKER not in r.header("content-type", "")
        verdict = "clean" if (reflected and not injected) else ("intercept" if injected else "mutated")
        return {"verdict": verdict, "reflected": reflected, "injected": injected,
                "status": r.status, "server": r.header("server", ""),
                "via": r.header("via", ""), "content_type": r.header("content-type", "")}

    async def close(self) -> None:
        await self.sess.close()
