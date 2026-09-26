"""User parcels. Drop your own scraped residential proxies in, get them tested
into the same pool as the harvested ones, tagged by origin=import.

Accepted formats (auto-detected, mixed files are fine):
  host:port
  scheme://host:port
  user:pass@host:port
  http://user:pass@host:port
  socks5://user:pass@host:port:extra
  one per line / comma / space / tab separated
  a JSON array of strings
  a copy-pasted `curl -x ...` command
  a whole html page or log file (candidates are extracted)
  csv with a proxy column

Nothing is written to disk beyond the sqlite row + your original file copy.
Credentials live only in the db, never in a log (the logger scrubs them).
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from tooling.config import Cfg
from tooling.db import DB
from tooling.httpclient import Endpoint
from tooling import logging_util as lu
from tooling.mutator import parse_blob, parse_line

log = lu.get()

CSV_HINTS = ("proxy", "proxies", "ip", "host", "endpoint", "url", "server", "addr")


@dataclass
class ParcelResult:
    parcel_id: int
    label: str
    total_lines: int
    parsed: int
    skipped: int
    schemes: dict
    unique: int
    sample: list[str]


def detect_scheme(text: str) -> str:
    low = text.lower()
    if "socks5://" in low or "socks://" in low:
        return "socks5"
    if "socks4://" in low:
        return "socks4"
    if "https://" in low and "://" in low and "http://" not in low:
        return "https"
    return "http"


class ParcelImporter:
    def __init__(self, cfg: Cfg, db: DB):
        self.cfg = cfg
        self.db = db
        self.inbox = cfg.root / "inbox"
        self.inbox.mkdir(parents=True, exist_ok=True)

    def import_text(self, text: str, label: str = "pasted", scheme: str = "auto",
                    save_as: str | None = None) -> ParcelResult:
        default_scheme = scheme if scheme != "auto" else detect_scheme(text)
        eps = parse_blob(text, default_scheme)
        # de-dup preserving order
        uniq, seen = [], set()
        for ep in eps:
            if ep.key in seen:
                continue
            seen.add(ep.key)
            uniq.append(ep)
        schemes: dict[str, int] = {}
        for e in uniq:
            schemes[e.scheme] = schemes.get(e.scheme, 0) + 1
        lines = sum(1 for _ in text.splitlines())
        pid = self.db.add_parcel(label, save_as, len(uniq), scheme, "")
        if uniq:
            self.db.upsert_proxies(
                [(e.scheme, e.host, e.port, e.user or "", e.password or "",
                  1 if _is_private(e.host) else 0) for e in uniq],
                origin="import", parcel_id=pid)
        log.info("parcel '%s': %d parsed / %d unique (schemes %s) -> parcel_id=%d",
                 label, len(eps), len(uniq), schemes, pid)
        return ParcelResult(pid, label, lines, len(eps), max(0, lines - len(eps)), schemes,
                            len(uniq), [str(e) for e in uniq[:8]])

    def import_file(self, path: str | Path, label: str = "", scheme: str = "auto") -> ParcelResult:
        p = Path(path)
        raw = p.read_text(encoding="utf-8", errors="replace")
        label = label or p.stem
        dest = self.inbox / p.name
        if p.resolve() != dest.resolve():
            shutil.copy2(p, dest)
        r = self.import_text(raw, label, scheme, str(dest))
        self.db.set_parcel_status(r.parcel_id, "pending")
        return r

    def import_dir(self, directory: str | Path, scheme: str = "auto") -> list[ParcelResult]:
        out = []
        d = Path(directory)
        for p in sorted(d.iterdir()):
            if p.is_file() and p.suffix.lower() in (".txt", ".csv", ".json", ".list", ".dat", ""):
                out.append(self.import_file(p, scheme=scheme))
        return out

    def parcel_rows(self, pid: int):
        return self.db.parcel_proxies(pid)

    async def test_parcel(self, pid: int, tester, write_back: bool = True) -> dict:
        rows = self.parcel_rows(pid)
        self.db.set_parcel_status(pid, "testing")
        passed = failed = 0
        for r in await tester.run(rows, write=write_back):
            if r.grade in ("A", "B", "C"):
                passed += 1
            else:
                failed += 1
        self.db.set_parcel_status(pid, "done", passed, failed)
        log.info("parcel %d tested: %d usable / %d rejected of %d", pid, passed, failed, len(rows))
        return {"parcel_id": pid, "total": len(rows), "passed": passed, "failed": failed}

    def list_parcels(self) -> list[dict]:
        return self.db.list_parcels()

    def report(self) -> str:
        ps = self.db.list_parcels()
        if not ps:
            return "no parcels imported yet"
        lines = ["parcels:"]
        for p in ps:
            lines.append(f"  #{p['id']:<3} {p['label'][:28]:<28} {p['count']:>6} proxies  "
                         f"status={p['status']} passed={p['passed']} failed={p['failed']}")
        return "\n".join(lines)


def _is_private(host: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


if __name__ == "__main__":
    import sys
    from tooling.config import load
    cfg = load()
    lu.setup(cfg, "parcel")
    db = DB(cfg.abspath(cfg.path("paths.db")))
    imp = ParcelImporter(cfg, db)
    if len(sys.argv) < 2:
        print(imp.report())
        print("\nusage: python3 -m tooling.parcel <file|txt->  |  drop files in inbox/")
        sys.exit(0)
    arg = sys.argv[1]
    if arg == "-":
        r = imp.import_text(sys.stdin.read(), "pasted")
    elif Path(arg).is_dir():
        for r in imp.import_dir(arg):
            print(r)
    else:
        r = imp.import_file(arg)
    print(f"parcel #{r.parcel_id} '{r.label}': parsed={r.parsed} unique={r.unique} schemes={r.schemes}")
    print("sample:", *r.sample, sep="\n  ")
