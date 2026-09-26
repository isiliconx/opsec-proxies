"""Token-bucket rate limiting: per-host, per-endpoint, global burst cap, jittered backoff."""
from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, per_host_rps: float = 2.0, burst: int = 4, max_concurrency: int = 0):
        self.per_host_rps = max(0.01, per_host_rps)
        self.burst = max(1, burst)
        self.sem = asyncio.Semaphore(max_concurrency) if max_concurrency > 0 else None
        self._tokens: dict[str, float] = defaultdict(lambda: self.burst)
        self._last: dict[str, float] = defaultdict(time.monotonic)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._global = asyncio.Semaphore(burst * 2)
        self.backoff_until: dict[str, float] = {}
        self.throttle_events: dict[str, int] = defaultdict(int)

    async def acquire(self, host: str = "global") -> None:
        if self.sem is not None:
            await self.sem.acquire()
        async with self._global:
            while True:
                blocked = self.backoff_until.get(host, 0.0)
                if blocked > time.monotonic():
                    self.throttle_events[host] += 1
                    await asyncio.sleep(min(blocked - time.monotonic(), 30) + random.uniform(0.05, 0.3))
                    continue
                now = time.monotonic()
                dt = now - self._last[host]
                self._last[host] = now
                self._tokens[host] = min(self.burst, self._tokens[host] + dt * self.per_host_rps)
                if self._tokens[host] >= 1.0:
                    self._tokens[host] -= 1.0
                    return
                await asyncio.sleep((1.0 - self._tokens[host]) / self.per_host_rps + random.uniform(0, 0.01))

    def release(self) -> None:
        if self.sem is not None:
            self.sem.release()

    def penalize(self, host: str, seconds: float) -> None:
        """Back off a host that answered 429/403/503."""
        self.backoff_until[host] = max(self.backoff_until.get(host, 0.0), time.monotonic() + seconds)
        self.throttle_events[host] += 1

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *exc) -> None:
        self.release()


class GlobalPacer:
    """Flat concurrency cap with jittered staggering so 900 tasks don't stampede."""

    def __init__(self, concurrency: int, jitter: float = 0.02):
        self.conc = max(1, concurrency)
        self.jitter = jitter
        self._sem = asyncio.Semaphore(self.conc)
        self.inflight = 0
        self.peak = 0

    async def __aenter__(self):
        await self._sem.acquire()
        self.inflight += 1
        self.peak = max(self.peak, self.inflight)
        await asyncio.sleep(random.uniform(0, self.jitter))
        return self

    async def __aexit__(self, *exc):
        self.inflight -= 1
        self._sem.release()
