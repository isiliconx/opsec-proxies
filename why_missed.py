"""Why did the harvest miss these? Cross-reference a parcel's ports against
the queue's port classifier and the config's reject list.

    python3 why_missed.py inbox/residential-parcel.txt
"""
from __future__ import annotations

import re
import sys
from collections import Counter

sys.path.insert(0, ".")

from tooling.modload import load  # noqa: E402

queue = load("enum/queue.py", "resi_enum_queue")
from tooling.config import load  # noqa: E402

cfg = load()
cfg_reject = set(cfg.path("tester.reject_ports", []) or [])
risky = queue.RISKY_PORTS
reject_all = cfg_reject | risky

LINE = re.compile(r"(?:(https?)://)?([\w.\-]+):(\d+)")


def main(path: str) -> None:
    text = open(path, encoding="utf-8", errors="replace").read()
    entries = []
    for m in LINE.finditer(text):
        entries.append((m.group(1) or "http", m.group(2), int(m.group(3))))
    print(f"{len(entries)} endpoints in {path}\n")

    tiers = Counter()
    verdict = Counter()
    dropped = []
    for scheme, host, port in entries:
        if port in reject_all:
            verdict["REJECTED by queue (risky/config)"] += 1
            dropped.append((host, port, "risky/config"))
            continue
        t = queue.classify_port(port)
        tiers[f"tier {t}"] += 1
        if queue.is_reject_port(port):
            verdict["REJECTED by is_reject_port"] += 1
            dropped.append((host, port, "is_reject_port"))
        elif t >= 90:
            verdict["tier 90 = never tested last"] += 1
        else:
            verdict["TESTED"] += 1

    print("port tiers:", dict(tiers))
    print()
    print("what would happen to them:")
    for k, v in verdict.most_common():
        print(f"  {v:>3}  {k}")
    if dropped:
        print(f"\ndropped before testing ({len(dropped)}):")
        for host, port, why in dropped:
            print(f"  {host}:{port}  {why}")
    print()
    print("GOOD_PORTS sample:", sorted(queue.GOOD_PORTS)[:24], "...")
    print("TIER_RANDOM     :", sorted(queue.TIER_RANDOM)[:24], "...")
    print("config reject   :", sorted(cfg_reject))
    print()
    print("=== ports in this list that are NOT in GOOD_PORTS ===")
    ports = sorted({p for _, _, p in entries})
    unknown = [p for p in ports if p not in queue.GOOD_PORTS]
    print(" ", unknown)


main(sys.argv[1] if len(sys.argv) > 1 else "inbox/residential-parcel.txt")
