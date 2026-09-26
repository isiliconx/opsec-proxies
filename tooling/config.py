"""Config loading. JSON, dot-access, recursive default merge, no yaml dependency."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "target.json"

DEFAULTS: dict[str, Any] = {
    "paths": {"db": "data/resi.db", "harvest_raw": "data/harvest", "artifacts": "artifacts"},
    "harvest": {"concurrency": 48, "timeout": 25.0, "retries": 1, "allow_range_feeds": True,
                "max_range_lines_per_feed": 4000, "sources": []},
    "tester": {"concurrency": 900, "tcp_timeout": 3.0, "http_timeout": 8.0, "quality_samples": 5,
               "judge_url": "http://httpbin.org/ip", "geo_verify_url": "http://ip-api.com/json/?fields=query",
               "require_ip_change": True, "min_success_ratio": 0.5, "max_latency_ms": 6000,
               "reject_ports": [], "reject_hostnames": [], "blacklist": {"enabled": True, "zones": [],
                                                                        "resolver": "1.1.1.1", "only_grade_b_or_better": True},
               "classification": {"dc_asn_keywords": [], "relay_banner_keywords": [], "resnet_banner_keywords": [],
                                  "public_tsa_ports": [], "tsa_banner_markers": []}},
    "geo": {"batch_size": 100, "primary": "http://ip-api.com/batch", "primary_fields": "status,message,query,country,countryCode,regionName,city,isp,org,as,asname,hosting,proxy,mobile",
            "fallback": "https://ipwho.is", "cache_ttl_days": 14},
    "egress": {"listen_host": "127.0.0.1", "socks_port": 2080, "mixed_port": 2081, "api_port": 8770, "pac_port": 8771,
               "failover": True, "sticky_seconds": 300, "cooldown_seconds": 120, "health_check_interval": 30,
               "browser": {"binary": "", "user_data_dir": "data/chrome-profile", "extra_args": []},
               "tunnel": {"engine": "sing-box", "interface": "resi0", "mtu": 1500, "strict_route": True,
                          "block_local_networks": True, "startup_command": "",
                          "killswitch": {"enabled": True, "linux": "nft", "macos": "pf", "windows": "netsh"}}},
    "ui": {"bind": "127.0.0.1", "port": 8770, "open_browser": True, "auth_token": ""},
    "opsec": {"persist_raw_bodies": False, "scrub_logs": True, "max_log_age_days": 7,
              "user_agent_pool": "data/ua.txt", "no_credential_persist": True},
}


class Cfg(dict):
    """dict with a.get_path("egress.tunnel.interface") accessor."""

    def path(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def set_path(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        cur: Any = self
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = value

    @property
    def root(self) -> Path:
        return ROOT

    def abspath(self, rel: str | os.PathLike) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else ROOT / p


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


_cache: Cfg | None = None


def load(reload: bool = False, path: str | Path | None = None) -> Cfg:
    """Load config/target.json merged over DEFAULTS. Cached."""
    global _cache
    if _cache is not None and not reload and path is None:
        return _cache
    p = Path(path) if path else CONFIG_PATH
    user: dict = {}
    if p.exists():
        try:
            user = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise SystemExit(f"[config] {p} is not valid JSON: {e}")
    merged = Cfg(_merge(DEFAULTS, user))
    for k in list(user.keys()):
        if k.startswith("_"):
            merged.pop(k, None)
    if path is None:
        _cache = merged
    return merged


def ensure_dirs(cfg: Cfg) -> None:
    # paths.db is a FILE (data/resi.db); only its parent directory is created.
    for rel in ("data", "artifacts", "inbox", cfg.path("paths.harvest_raw")):
        cfg.abspath(rel).mkdir(parents=True, exist_ok=True)
    cfg.abspath(cfg.path("paths.db")).parent.mkdir(parents=True, exist_ok=True)


UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

ACCEPT_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9,en;q=0.7", "fr-FR,fr;q=0.9,en;q=0.7",
                "es-ES,es;q=0.9,en;q=0.7", "pt-BR,pt;q=0.9,en;q=0.7", "ja-JP,ja;q=0.9,en;q=0.7",
                "nl-NL,nl;q=0.9,en;q=0.7", "it-IT,it;q=0.9,en;q=0.7", "ru-RU,ru;q=0.9,en;q=0.7"]


def random_headers(cfg: Cfg | None = None, lang: str | None = None) -> dict[str, str]:
    """One coherent browser header set. Language pinned per-session by the caller."""
    import random
    ua = random.choice(UA_POOL)
    al = lang or random.choice(ACCEPT_LANGS)
    h = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": al,
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Dnt": "1",
        "Connection": "keep-alive",
    }
    if "Firefox/" in ua:
        for k in list(h):
            if k.startswith("Sec-Ch") or k.startswith("Sec-Fetch"):
                h.pop(k)
        h["Sec-GPC"] = "1"
    return h
