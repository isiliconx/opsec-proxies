"""Scrubbed local logger. No target payload bodies, rotating, age-purged."""
from __future__ import annotations

import logging
import logging.handlers
import re
import sys
import time
from pathlib import Path

_SCRUB = [
    (re.compile(r"(authorization|cookie|set-cookie|proxy-authorization|x-api-key|api[_-]?key|token|password|passwd|secret)(\s*[:=]\s*)(\S+)", re.I), r"\1\2<redacted>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b"), "<proxy>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<email>"),
]

_cfg = None
_configured = False


def _scrub(s: str) -> str:
    for rx, rep in _SCRUB:
        s = rx.sub(rep, s)
    return s


class ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _scrub(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


def setup(cfg=None, name: str = "resi") -> logging.Logger:
    """Configure once. Creates artifacts/resi.log with size+time rotation."""
    global _cfg, _configured
    _cfg = cfg
    log = logging.getLogger(name)
    if _configured:
        return log
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s", "%H:%M:%S")
    f = ScrubFilter()
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    sh.addFilter(f)
    log.addHandler(sh)
    try:
        art = cfg.abspath(cfg.path("paths.artifacts", "artifacts")) if cfg else Path("artifacts")
        art.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.TimedRotatingFileHandler(art / "resi.log", when="D", backupCount=7, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.addFilter(f)
        log.addHandler(fh)
        _purge_old(art)
    except Exception:
        pass
    _configured = True
    return log


def _purge_old(art: Path) -> None:
    try:
        maxage = int(_cfg.path("opsec.max_log_age_days", 7)) if _cfg else 7
    except Exception:
        maxage = 7
    cutoff = time.time() - maxage * 86400
    for p in art.glob("resi.log*"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
        except Exception:
            pass


def get(name: str = "resi") -> logging.Logger:
    return logging.getLogger(name)
