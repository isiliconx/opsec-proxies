"""Stage 3 — the tester. Four passes per candidate, cheapest first:

  pass 0  TCP reachability        3s timeout, no TLS, no HTTP.  Kills ~85% of rows.
  pass 1  protocol handshake       socks5 / socks4 / http-connect, banner captured.
  pass 2  judge + anonymity        exit IP, injection headers, our-IP comparison.
  pass 3  TLS + relay + capture   only for survivors. Geo + blacklist + grade.

Grade:
  A  residential ASN, non-cloud prefix, ISP PTR, exit IP differs, TLS ok, fast, reliable
  B  usable, verified exit, one soft signal missing (or slow, or no TLS)
  C  alive but relay-ish, or datacenter ASN, or flaky
  D  alive but transparent, honeypot/TSA, or blacklisted

Every grade write carries the evidence that produced it.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Iterable

from tooling.config import Cfg
from tooling.db import DB
from tooling.dns import Resolver
from tooling.geo import GeoResolver
from tooling.httpclient import (ConnectError, Endpoint, ProxyError, Session, _parse_status,
                                _read_head, http_connect, socks4_connect, socks5_connect,
                                tcp_connect)
from tooling.limiter import GlobalPacer, RateLimiter
from tooling import logging_util as lu
from vuln.t_capthive import CaptureCheck
from vuln.t_leak import PortSweep, RelayProbe, is_tsa
from vuln.t_tls import tls_suite
from vuln.t_transparent import TransparencyProbe, extract_ip

log = lu.get()

DST_HTTP = "httpbin.org"
DST_HTTP_PORT = 80
DST_TLS = "cloudflare.com"
DST_TLS_PORT = 443


def as_row(r):
    """Normalize sqlite Row / TestJob / SimpleNamespace into one attribute object.

    Reads are attribute-based downstream so every input shape works unchanged.
    """
    from types import SimpleNamespace
    ep = getattr(r, "ep", None)
    if ep is not None:
        # TestJob / anything carrying an Endpoint
        return SimpleNamespace(host=ep.host, port=int(ep.port), scheme=ep.scheme,
                               user=ep.user or "", password=ep.password or "",
                               id=getattr(r, "row_id", None) or getattr(r, "id", None))
    if hasattr(r, "host") and hasattr(r, "port"):
        return SimpleNamespace(host=r.host, port=int(r.port), scheme=r.scheme,
                               user=r.user or "", password=r.password or "",
                               id=getattr(r, "row_id", None) or getattr(r, "id", None))
    return SimpleNamespace(host=r["host"], port=int(r["port"]), scheme=r["scheme"],
                           user=r["user"] or "", password=r["password"] or "",
                           id=r["id"] if "id" in r.keys() else None)


@dataclass
class TestResult:
    ep: Endpoint
    verdict: str = "unknown"          # alive | slow | dead | transparent | dnsfail | blocked | tsa
    grade: str = "D"
    latency_ms: float = 0.0
    exit_ip: str = ""
    anonymity: float = 0.0
    country: str = ""
    cc: str = ""
    asn: str = ""
    isp: str = ""
    hosting: bool = False
    tls_ok: bool = False
    relay: bool = False
    tsa: bool = False
    tsa_conf: float = 0.0
    capture: str = ""
    success_ratio: float = 0.0
    samples: int = 0
    ptr: str = ""
    ptr_kind: str = ""
    asn_kind: str = ""
    blacklisted: str = ""
    error: str = ""
    evidence: dict = field(default_factory=dict)

    def score(self) -> float:
        """Numeric quality used for pool ordering."""
        s = 0.0
        s += 4.0 if self.grade == "A" else 3.0 if self.grade == "B" else 2.0 if self.grade == "C" else 1.0
        s += min(2.0, self.success_ratio * 2.0)
        s += 1.0 if self.exit_ip and not self.transparent_flag() else 0.0
        s += 0.8 if self.asn_kind == "isp" else 0.0
        s += 0.6 if self.ptr_kind == "isp" else 0.0
        s += 0.4 if self.tls_ok else 0.0
        s += 0.3 if self.relay else 0.0
        s += 0.4 if self.capture == "clean" else -0.5 if self.capture == "intercept" else 0.0
        s -= 0.6 if self.hosting else 0.0
        s -= 1.5 if self.tsa else 0.0
        s -= 2.0 if self.blacklisted else 0.0
        s -= min(1.5, self.latency_ms / 3000.0)
        return round(s, 3)

    def transparent_flag(self) -> bool:
        return bool(self.evidence.get("same_as_me"))


class Tester:
    def __init__(self, cfg: Cfg, db: DB):
        self.cfg = cfg
        self.db = db
        self.conc = int(cfg.path("tester.concurrency", 900))
        self.tcp_to = float(cfg.path("tester.tcp_timeout", 3.0))
        self.http_to = float(cfg.path("tester.http_timeout", 8.0))
        self.samples = int(cfg.path("tester.quality_samples", 5))
        self.min_ratio = float(cfg.path("tester.min_success_ratio", 0.5))
        self.max_lat = float(cfg.path("tester.max_latency_ms", 6000))
        self.judge_url = cfg.path("tester.judge_url", "http://httpbin.org/ip")
        self.require_change = bool(cfg.path("tester.require_ip_change", True))
        self.bl_enabled = bool(cfg.path("tester.blacklist.enabled", True))
        self.bl_zones = cfg.path("tester.blacklist.zones", [])
        self.bl_only_better = bool(cfg.path("tester.blacklist.only_grade_b_or_better", True))
        self.class_kw = cfg.path("tester.classification", {})
        self.pacer = GlobalPacer(self.conc, jitter=0.003)
        self.geo = GeoResolver(cfg)
        self.res = Resolver()
        # hostname resolution for thousands of half-dead hosts is the real
        # bottleneck, not the sockets: give it its own thread pool and stop it
        # from competing with the default loop executor.
        self.executor = self.res._executor
        self.res.set_loop(asyncio.get_event_loop_policy().get_event_loop())
        self.geo.sess.executor = self.executor
        self.tp = TransparencyProbe("", self.judge_url, self.http_to)
        self.tp.sess.executor = self.executor
        self.capture = CaptureCheck(self.http_to)
        self.capture.sess.executor = self.executor
        self.sweep = PortSweep()
        self.judge_limiter = RateLimiter(per_host_rps=30, burst=60)
        # pass0(3s)+pass1(5s)+pass2(8s)+pass3(~25s) worst case; cap below that so
        # a half-open host cannot occupy a slot indefinitely
        self.per_candidate_cap = self.tcp_to * 2 + self.http_to * 4
        self.stats = {"tried": 0, "tcp_ok": 0, "alive": 0, "graded": {}, "A": 0, "B": 0, "C": 0, "D": 0}

    # ----------------------------------------------------------------- pass 0
    async def tcp_alive(self, ep: Endpoint) -> bool:
        try:
            r, w = await tcp_connect(ep.host, ep.port, self.tcp_to, self.executor)
            w.close()
            return True
        except Exception:
            return False

    # ----------------------------------------------------------------- pass 1
    async def handshake(self, ep: Endpoint) -> dict:
        """Try the declared scheme first, then the other two. Captures the banner."""
        order = [ep.scheme] + [s for s in ("socks5", "http", "socks4") if s != ep.scheme]
        errors = []
        for scheme in order:
            e = Endpoint(ep.host, ep.port, scheme, ep.user, ep.password)
            try:
                if scheme == "socks5":
                    r, w, banner = await socks5_connect(e.host, e.port, e.user, e.password, self.tcp_to + 1)
                elif scheme == "socks4":
                    r, w, banner = await socks4_connect(e.host, e.port, e.user, self.tcp_to + 1)
                else:
                    r, w, banner = await http_connect(e.host, e.port, DST_TLS, DST_TLS_PORT,
                                                      e.user, e.password, self.tcp_to + 2)
                w.close()
                return {"ok": True, "scheme": scheme, "banner": banner[:400].decode("latin-1", "replace"),
                        "errors": errors}
            except Exception as ex:
                errors.append(f"{scheme}:{type(ex).__name__}:{str(ex)[:60]}")
        return {"ok": False, "scheme": None, "banner": "", "errors": errors}

    # ----------------------------------------------------------------- pass 2
    async def judge(self, ep: Endpoint) -> dict:
        d = await self.tp.probe(ep)
        return d

    # ----------------------------------------------------------------- pass 3
    async def enrich(self, res: TestResult) -> TestResult:
        if res.exit_ip:
            g = await self.geo.bulk([res.exit_ip])
            gi = g.get(res.exit_ip)
            if gi:
                res.country, res.cc, res.asn, res.isp = gi.country, gi.cc, gi.asn, gi.isp
                res.hosting = gi.is_datacenter
                self.db.geo_put(gi.as_dict())
                res.asn_kind = "datacenter" if gi.is_datacenter else "isp" if gi.isp else "unknown"
            ptr = await self.res.ptr(res.exit_ip)
            res.ptr = ptr
            from recon.fingerprint import ptr_verdict
            res.ptr_kind = ptr_verdict(ptr)
            if self.bl_enabled and (not self.bl_only_better or res.grade in ("A", "B")):
                res.blacklisted = await self.res.blacklist(res.exit_ip, self.bl_zones)
        t = await tls_suite(ep=res.ep, timeout=self.http_to)
        res.tls_ok = bool(t.get("tls_ok"))
        res.evidence["tls"] = t
        if res.grade in ("A", "B"):
            rp = RelayProbe(self.cfg, timeout=self.http_to - 2)
            rl = await rp.probe(res.ep)
            res.relay = bool(rl.get("relay"))
            res.tsa = bool(rl.get("tsa"))
            res.evidence["relay"] = rl
        cc = await self.capture.check(res.ep)
        res.capture = cc.get("verdict", "")
        res.evidence["capture"] = cc
        sw = await self.sweep.same_banner(res.ep.host)
        if sw.get("tsa"):
            res.tsa = True
            res.tsa_conf = float(sw.get("identical", 0))
        res.evidence["portsweep"] = sw
        return res

    # ----------------------------------------------------------------- grading
    def grade(self, res: TestResult) -> str:
        if res.verdict == "dead" or not res.exit_ip:
            return "D"
        if res.blacklisted or res.tsa or res.capture == "intercept":
            return "D"
        residential = (res.asn_kind == "isp") or (res.ptr_kind == "isp")
        dc = res.hosting or res.asn_kind == "datacenter"
        if self.require_change and res.transparent_flag():
            return "D"   # exit ip == ours: the proxy is not actually proxying
        s = res.score()
        if residential and not dc and res.tls_ok and res.latency_ms < 2500 and s >= 8.0:
            return "A"
        if (residential and not dc) or (not dc and res.tls_ok and res.success_ratio >= 0.8):
            return "B" if s >= 5.5 else "C"
        if dc:
            return "C" if s >= 3.0 else "D"
        return "C" if s >= 3.0 else "D"

    # ----------------------------------------------------------------- driver
    async def test_one(self, row) -> TestResult:
        ep = Endpoint(row.host, int(row.port), row.scheme, row.user or None, row.password or None)
        res = TestResult(ep=ep)
        self.stats["tried"] += 1
        if not await self.tcp_alive(ep):
            res.verdict, res.error = "dead", "tcp timeout/refused"
            return res
        self.stats["tcp_ok"] += 1
        hs = await self.handshake(ep)
        if not hs["ok"]:
            res.verdict, res.error = "dead", "; ".join(hs.get("errors", []))[:200]
            res.evidence["handshake"] = hs
            return res
        res.evidence["handshake"] = hs
        res.ep = Endpoint(ep.host, ep.port, hs["scheme"], ep.user, ep.password)
        banner = hs.get("banner", "")
        if is_tsa(banner, self.cfg):
            res.verdict, res.tsa, res.error = "tsa", True, "TSA banner"
            return res
        if any(k in banner.lower() for k in self.class_kw.get("relay_banner_keywords", [])):
            res.evidence["relay_banner"] = True
        # quality samples
        t0 = time.perf_counter()
        oks = 0
        for i in range(self.samples):
            try:
                await self.judge_limiter.acquire("judge")
                d = await self.judge(res.ep)
                if d.get("exit_ip"):
                    oks += 1
                    res.exit_ip = d["exit_ip"]
                    res.anonymity = d.get("anonymity_score", 0.0)
                    res.evidence.setdefault("judge", d)
                    res.latency_ms = d.get("latency_ms", 0.0)
                    break
            except Exception:
                pass
        res.samples = self.samples
        res.success_ratio = oks / max(1, self.samples)
        if not res.exit_ip:
            res.verdict, res.error = "dead", "no exit ip from judge"
            return res
        res.latency_ms = res.latency_ms or ((time.perf_counter() - t0) * 1000)
        res.verdict = "alive" if res.latency_ms < self.max_lat else "slow"
        res.grade = "C"       # provisional until enriched
        await self.enrich(res)
        res.grade = self.grade(res)
        return res

    async def run(self, rows: Iterable, write: bool = True, progress_every: int = 500,
                  on_result=None) -> list[TestResult]:
        rows = [as_row(r) for r in rows]
        t0 = time.time()
        results: list[TestResult] = []
        self.stats = {"tried": 0, "tcp_ok": 0, "alive": 0, "graded": {}, "A": 0, "B": 0, "C": 0, "D": 0}
        sem = asyncio.Semaphore(self.conc)

        async def one(row):
            async with sem:
                t_start = time.perf_counter()
                try:
                    # hard wall-clock cap per candidate: no single host can
                    # hold a slot through every stage's timeout in series
                    r = await asyncio.wait_for(self.test_one(row), self.per_candidate_cap)
                except (asyncio.TimeoutError, TimeoutError):
                    r = TestResult(ep=Endpoint(row.host, int(row.port), row.scheme),
                                   verdict="dead", error=f"exceeded {self.per_candidate_cap}s cap")
                except Exception as e:
                    r = TestResult(ep=Endpoint(row.host, int(row.port), row.scheme),
                                   verdict="dead", error=f"{type(e).__name__}: {str(e)[:100]}")
                r.evidence["wall_ms"] = round((time.perf_counter() - t_start) * 1000)
                if r.verdict in ("alive", "slow"):
                    self.stats["alive"] += 1
                self.stats[r.grade] = self.stats.get(r.grade, 0) + 1
                self.stats["graded"][r.grade] = self.stats["graded"].get(r.grade, 0) + 1
                if write:
                    self._write(row.id, r)
                if on_result:
                    on_result(r)
                return r

        batch = 400
        for i in range(0, len(rows), batch):
            chunk = rows[i:i + batch]
            results.extend(await asyncio.gather(*(one(r) for r in chunk)))
            done = min(i + batch, len(rows))
            if done % progress_every < batch or done == len(rows):
                el = time.time() - t0
                rate = done / max(el, 0.001)
                log.info("tested %d/%d  tcp_ok=%d alive=%d A=%d B=%d C=%d D=%d  %.0f/s  eta %.0fs",
                         done, len(rows), self.stats["tcp_ok"], self.stats["alive"],
                         self.stats.get("A", 0), self.stats.get("B", 0), self.stats.get("C", 0),
                         self.stats.get("D", 0), rate, (len(rows) - done) / max(rate, 0.001))
        self.stats["elapsed"] = round(time.time() - t0, 1)
        log.info("test done: %d rows, %d tcp-ok, %d alive, grades A=%d B=%d C=%d D=%d in %.1fs",
                 self.stats["tried"], self.stats["tcp_ok"], self.stats["alive"],
                 self.stats.get("A", 0), self.stats.get("B", 0), self.stats.get("C", 0),
                 self.stats.get("D", 0), self.stats["elapsed"])
        return results

    def _write(self, proxy_id: int | None, r: TestResult) -> None:
        if proxy_id is None:
            return
        ev = json.dumps(r.evidence, default=str)[:4000] if self.cfg.path("opsec.persist_raw_bodies", False) \
            else json.dumps({k: v for k, v in r.evidence.items() if k in ("judge", "relay", "portsweep", "handshake")},
                            default=str)[:1500]
        self.db.add_test(proxy_id, verdict=r.verdict, grade=r.grade, latency_ms=r.latency_ms,
                         exit_ip=r.exit_ip, country=r.country, cc=r.cc, asn=r.asn, isp=r.isp,
                         hosting=1 if r.hosting else 0, tls_ok=1 if r.tls_ok else 0,
                         success_ratio=r.success_ratio, samples=r.samples, error=r.error[:300],
                         evidence=ev)

    async def close(self) -> None:
        await self.tp.close()
        await self.capture.close()
        self.res.shutdown()


class Factory(TransparencyProbe):
    """Bootstraps TransparencyProbe with our real exit IP before testing starts."""
    pass


async def our_exit_ip(cfg: Cfg) -> str:
    tp = TransparencyProbe("", cfg.path("tester.judge_url", "http://httpbin.org/ip"),
                           float(cfg.path("tester.http_timeout", 8.0)))
    try:
        ip = await tp.our_exit_ip()
        return ip
    finally:
        await tp.close()
