"""Fingerprint + the passives the harvester needs: ASN map, PTR names, cloud ranges.

The point is to tell a real resnet edge from a cloud VPS before spending test
budget on it: ISP-flagged ASN, non-hosting, a PTR that looks like a real access
network, and not inside a published cloud prefix.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from tooling.config import Cfg
from tooling.dns import Resolver
from tooling import logging_util as lu

log = lu.get()

# Published cloud prefixes (partial, enough to kill obvious VPS noise).
CLOUD_PREFIXES = [
    "3.0.0.0/8", "13.32.0.0/15", "13.224.0.0/14", "15.177.0.0/16", "18.128.0.0/9", "18.176.0.0/13",
    "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/12", "35.196.0.0/14", "35.200.0.0/13",
    "52.0.0.0/8", "54.64.0.0/11", "54.128.0.0/12", "54.176.0.0/12", "54.192.0.0/11", "54.224.0.0/11",
    "63.32.0.0/14", "64.233.160.0/19", "66.249.64.0/19",
    "3.64.0.0/12", "18.153.0.0/16", "18.156.0.0/14", "18.176.0.0/13", "18.184.0.0/13",
    "20.0.0.0/8", "23.20.0.0/14", "23.96.0.0/13", "31.13.24.0/21",
    "40.64.0.0/10", "51.4.0.0/15", "51.8.0.0/16", "51.12.0.0/15", "51.20.0.0/14", "51.103.0.0/16",
    "52.0.0.0/8",
    "64.227.0.0/16", "66.220.144.0/20", "69.171.224.0/19", "70.132.0.0/18",
    "74.125.0.0/16", "77.75.72.0/21", "77.88.0.0/18",
    "80.158.0.0/15", "82.0.0.0/15",
    "91.198.174.0/24", "92.123.0.0/16", "93.184.216.0/24",
    "95.140.224.0/20", "103.21.244.0/22",
    "104.16.0.0/12", "104.196.0.0/14", "104.244.40.0/21",
    "129.250.0.0/16", "130.211.0.0/16", "131.0.0.0/16", "132.145.0.0/16", "134.209.0.0/16",
    "142.250.0.0/15", "143.110.0.0/16", "146.190.0.0/16",
    "157.240.0.0/16", "157.245.0.0/16", "157.248.0.0/16",
    "159.65.0.0/16", "159.89.0.0/16", "159.203.0.0/16",
    "161.35.0.0/16", "162.159.0.0/16", "164.90.0.0/16", "164.92.0.0/16",
    "165.22.0.0/16", "165.227.0.0/16", "165.232.0.0/16",
    "167.71.0.0/16", "167.99.0.0/16", "167.172.0.0/16",
    "170.64.0.0/16", "172.64.0.0/13", "172.64.128.0/17", "172.104.0.0/15", "172.217.0.0/16",
    "173.245.48.0/20", "173.254.0.0/16",
    "174.129.0.0/16", "178.62.0.0/16", "178.128.0.0/16", "179.48.0.0/16",
    "184.72.0.0/15", "185.60.216.0/22", "188.114.96.0/20",
    "192.30.252.0/22", "193.32.126.0/24", "195.20.224.0/19",
    "198.41.128.0/17", "199.16.156.0/21", "199.232.0.0/16", "204.79.197.0/24",
    "208.67.108.0/22", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
    "2606:4700::/32", "2a00:1450::/32", "2404:6800::/32",
]
_cnets = [ipaddress.ip_network(p, strict=False) for p in CLOUD_PREFIXES]

# PTR shapes that read like an ISP access network rather than a datacentre.
ISP_PTR = re.compile(
    r"(?:^|[\.\-])(?:cpe|cust|client|res|resi|residential|dyn|dynamic|pppoe|ppp|pool|adsl|"
    r"vdsl|dsl|cable|fiber|fibre|fttx|hfc|docsis|cable-modem|"
    r"dhcp|fixed|broadband|bb|isp|is|internet|net|network|hub|node|edge|"
    r"user|home|lan|wifi|wireless|dsl|adsl2|netcologne|unitymedia|telia|"
    r"comcast|xfinity|spectrum|cox|att|verizon|centurylink|charter|optus|telstra|rogers|vodafone|"
    r"orange|bt|sky|virgin|o2|three|lyca|swisscom|salt|telia|deutsche|"
    r"kddi|softbank|auone|ocn|nuro|jcom|biglobe|"
    r"relay|broadband|ispproxy|resiprox|residential|proxy-?pool|exit-node|"
    r"socks|http-proxy|openproxy|freeproxy)",
    re.I)
DC_PTR = re.compile(r"(cloud|hosting|vps|server|datacenter|data-?center|amazonaws|googleusercontent|"
                    r"linode|digitalocean|ovh|netcup|hetzner|contabo|digital|azure|"
                    r"colocation|dedi|leaseweb|m247|choopa|contabo|vultr|linode|"
                    r"oracle|alibaba|aliyun|tencent|huaweicloud|kimsufi|"
                    r"reverse|ptr|in-addr|unused|assigned|static|dedicated|node-?js)", re.I)

ISP_ASN_HINT = re.compile(
    r"(broadband|cable|satellite|fiber|telecom|telco|mobile|wireless|isp|"
    r"communications|telecommunication|wireline|cable|"
    r"comcast|spectrum|xfinity|cox|verizon|at&t|centurylink|charter|optus|"
    r"telstra|rogers|vodafone|orange|bt|sky|deutsche|telekom|"
    r"kddi|softbank|au|orange|jcom|telefonica|Claro|"
    r"vivo|oi|telefonica|movistar|entel|wow|"
    r"shaw|viper|frontier|altice|suddenlink|cableone|mediacom|bree|"
    r"windstream|sonnet|frontier|sparklight|lumen)", re.I)


def in_cloud(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _cnets)


def ptr_verdict(ptr: str) -> str:
    if not ptr:
        return "none"
    if DC_PTR.search(ptr):
        return "datacenter"
    if ISP_PTR.search(ptr):
        return "isp"
    return "neutral"


def asn_verdict(ispa: str, asname: str, org: str) -> str:
    blob = " ".join(x for x in (ispa, asname, org) if x)
    if not blob:
        return "unknown"
    if re.search(r"(hosting|datacenter|data center|cloud|vps|server|colo|idc|"
                 r"amazon|google|microsoft|alibaba|oracle|digitalocean|linode|vultr|"
                 r"hetzner|ovh|contabo|leaseweb|equinix|choopa|m247|dedi|"
                 r"cisco|linode|conoha|zenlayer|contabo)", blob, re.I):
        return "datacenter"
    if ISP_ASN_HINT.search(blob):
        return "isp"
    return "unknown"


@dataclass
class Fingerprint:
    ip: str
    in_cloud: bool = False
    ptr: str = ""
    ptr_kind: str = "none"
    asn_kind: str = "unknown"
    score: float = 0.0
    notes: str = ""


class Fingerprinter:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self.res = Resolver()
        self._ptr: dict[str, tuple[float, str]] = {}

    async def ptr(self, ip: str) -> str:
        c = self._ptr.get(ip)
        if c and c[0] > time.time():
            return c[1]
        p = await self.ptr_lookup(ip)
        self._ptr[ip] = (time.time() + 3600, p)
        return p

    async def ptr_lookup(self, ip: str) -> str:
        try:
            packed = socket.inet_aton(ip)
        except OSError:
            return ""
        name = ".".join(str(b) for b in reversed(packed)) + ".in-addr.arpa"
        r = await self.resolve(name, "PTR")
        for a in r.get("answers", []):
            if a["type"] == "PTR":
                return a["data"].rstrip(".")
        return ""

    async def one(self, ip: str, asn_blob: str = "") -> Fingerprint:
        fp = Fingerprint(ip=ip)
        fp.in_cloud = in_cloud(ip)
        fp.ptr = await self.ptr(ip)
        fp.ptr_kind = ptr_verdict(fp.ptr)
        fp.asn_kind = asn_verdict(asn_blob, asn_blob, asn_blob)
        s = 0.0
        notes = []
        if fp.asn_kind == "isp":
            s += 0.45; notes.append("asn=isp")
        if fp.ptr_kind == "isp":
            s += 0.3; notes.append(f"ptr={fp.ptr[:40]}")
        if not fp.in_cloud:
            s += 0.15; notes.append("no-cloud-prefix")
        if fp.asn_kind == "datacenter":
            s -= 0.5; notes.append("asn=dc")
        if fp.ptr_kind == "datacenter":
            s -= 0.3; notes.append("ptr=dc")
        if fp.in_cloud:
            s -= 0.25; notes.append("cloud-prefix")
        fp.score = max(0.0, min(1.0, s))
        fp.notes = ",".join(notes)
        return fp

    async def many(self, ips: list[str], asn_map: dict[str, str] | None = None,
                   conc: int = 60) -> dict[str, Fingerprint]:
        asn_map = asn_map or {}
        sem = asyncio.Semaphore(conc)
        out: dict[str, Fingerprint] = {}

        async def one(ip: str):
            async with sem:
                try:
                    out[ip] = await self.one(ip, asn_map.get(ip, ""))
                except Exception:
                    out[ip] = Fingerprint(ip=ip)

        await asyncio.gather(*(one(i) for i in ips[:1500]))
        return out
