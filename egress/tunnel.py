"""Route B — take the whole machine's traffic through the pool.

Two mechanisms, chosen by what the OS has:

  sing-box   a real TUN device. Creates `resi0`, sets the default route into it,
             and runs a local SOCKS inbound that the sing-box *outbound* dials.
             Linux/macOS/Windows (wintun). This is the real VPN-grade path.
  tun2socks  a userspace TUN that hands the default route to a SOCKS5 listener.
             Works everywhere without kernel modules.

Both dial OUR local SOCKS listener, which is already rotating verified
residential exits, so sing-box never needs to know about the pool.

Killswitch: installed before the route goes up, removed after it comes down.
  Linux   nftables: drop forward/output except the TUN + the local listener
  macOS   pf: block all egress except the TUN interface
  Windows netsh: firewall rule blocking all outbound except the TUN

--dry-run prints the exact commands and writes nothing.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from tooling.config import Cfg
from tooling import logging_util as lu

log = lu.get()

PLAT = platform.system().lower()   # linux | darwin | windows


def which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


# ------------------------------------------------------------------ sing-box


def singbox_config(cfg: Cfg, listen_host: str, socks_port: int, tun_if: str, mtu: int) -> dict:
    return {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "interface_name": tun_if, "mtu": mtu,
             "strict_route": True, "stack": "system", "auto_route": True,
             "route_exclude_address": ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16",
                                       "172.16.0.0/12", "169.254.0.0/16", "100.64.0.0/10"]
             if cfg.path("egress.tunnel.block_local_networks", True) else [],
             "endpoint_independent_nat": False},
            {"type": "socks", "tag": "socks-in", "listen": listen_host, "listen_port": socks_port},
        ],
        "outbounds": [
            {"type": "socks", "tag": "to-resi", "server": listen_host, "server_port": socks_port,
             "version": "5"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"inbound": ["socks-in"], "outbound": "to-resi"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": "to-resi",
            "auto_detect_interface": True,
        },
    }


# ------------------------------------------------------------------ killswitch


@dataclass
class Command:
    argv: list[str]
    sudo: bool = False

    def render(self) -> str:
        return ("sudo " if self.sudo else "") + " ".join(self.argv)


def killswitch_up(cfg: Cfg, tun_if: str) -> list[Command]:
    kind = cfg.path("egress.tunnel.killswitch.linux", "nft")
    if PLAT == "linux":
        w = which("nft") or which("iptables")
        if not w:
            return []
        if "nft" in w:
            return [Command([w, "add", "table", "inet", "resiproxy"]),
                    Command([w, "add", "chain", "inet", "resiproxy", "output", "{", "type", "filter",
                             "hook", "output", "priority", "0", ";", "policy", "drop", ";"]),
                    Command([w, "add", "chain", "inet", "resiproxy", "forward", "{", "type", "filter",
                             "hook", "forward", "priority", "0", ";", "policy", "drop", ";"]),
                    Command([w, "add", "rule", "inet", "resiproxy", "output", "oifname", f'"{tun_if}"', "accept"], True),
                    Command([w, "add", "rule", "inet", "resiproxy", "output", "ip", "daddr", "127.0.0.0/8", "accept"], True),
                    Command([w, "add", "rule", "inet", "resiproxy", "output", "ip", "daddr", "100.64.0.0/10", "accept"], True),
                    Command([w, "add", "rule", "inet", "resiproxy", "output", "ct", "state", "established,related", "accept"], True),
                    Command([w, "add", "rule", "inet", "resiproxy", "forward", "oifname", f'"{tun_if}"', "accept"], True)]
        return [Command([w, "-I", "OUTPUT", "1", "!", "-o", tun_if, "-d", "127.0.0.0/8", "-j", "DROP"], True),
                Command([w, "-I", "FORWARD", "1", "!", "-o", tun_if, "-j", "DROP"], True)]
    if PLAT == "darwin":
        return [Command(["/sbin/pfctl", "-a", "resiproxy", "-f", "-"], True)]
    if PLAT == "windows":
        return [Command(["netsh", "advfirewall", "add", "rule", "name=resiproxy-killswitch",
                         "dir=out", "action=block", "enable=yes"])]
    return []


def killswitch_down(cfg: Cfg) -> list[Command]:
    if PLAT == "linux":
        w = which("nft")
        if w:
            return [Command([w, "delete", "table", "inet", "resiproxy"], True)]
        w = which("iptables")
        if w:
            return [Command([w, "-D", "OUTPUT", "!", "-o", "tun0", "-d", "127.0.0.0/8", "-j", "DROP"], True),
                    Command([w, "-D", "FORWARD", "!", "-o", "tun0", "-j", "DROP"], True)]
    if PLAT == "darwin":
        return [Command(["/sbin/pfctl", "-a", "resiproxy", "-F", "all"], True),
                Command(["/sbin/pfctl", "-a", "resiproxy", "-X"], True)]
    if PLAT == "windows":
        return [Command(["netsh", "advfirewall", "delete", "rule", "name=resiproxy-killswitch"])]
    return []


PFD_RULES = """anchor "resiproxy"
block out
pass out on resi0
pass out route-to lo0
pass out proto icmp
pass out to 127.0.0.0/8
pass in on resi0
"""


# ------------------------------------------------------------------ runner


class TunnelRunner:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self.tun_if = cfg.path("egress.tunnel.interface", "resi0")
        self.mtu = int(cfg.path("egress.tunnel.mtu", 1500))
        self.engine = cfg.path("egress.tunnel.engine", "sing-box")
        self.proc: subprocess.Popen | None = None
        self.up: list[Command] = []
        self.conf_path: Path | None = None

    def plan(self) -> tuple[list[str], str, list[Command], list[Command]]:
        host = self.cfg.path("egress.listen_host", "127.0.0.1")
        socks = int(self.cfg.path("egress.socks_port", 2080))
        up = killswitch_up(self.cfg, self.tun_if)
        down = killswitch_down(self.cfg)
        if self.engine == "sing-box":
            binp = which("sing-box") or "sing-box"
            conf = singbox_config(self.cfg, host, socks, self.tun_if, self.mtu)
            return ([binp, "run", "-c", "<generated>"], json.dumps(conf, indent=2), up, down)
        binp = which("tun2socks") or "tun2socks"
        return ([binp, "-device", self.tun_if, "-proxy", f"socks5://{host}:{socks}",
                 "-mtu", str(self.mtu), "-auto-route", "-strict-route", "-dns-proxy",
                 f"socks5://{host}:{socks}"], "", up, down)

    def dry_run(self) -> str:
        argv, conf, up, down = self.plan()
        lines = [f"# resiproxy tunnel plan ({PLAT}, engine={self.engine})",
                 f"# local rotating SOCKS listener: {self.cfg.path('egress.listen_host')}:{self.cfg.path('egress.socks_port')}",
                 "", "## killswitch UP"]
        lines += [f"  {c.render()}" for c in up]
        lines += ["", "## TUN"] + [f"  {a}" for a in argv]
        if conf:
            lines += ["", "## sing-box config"] + ["  " + l for l in conf.splitlines()]
        lines += ["", "## killswitch DOWN"] + [f"  {c.render()}" for c in down]
        lines += ["", "## needed binaries"]
        for b in (which("sing-box"), which("tun2socks"), which("nft"), which("ip")):
            lines.append(f"  {b or 'MISSING'}")
        return "\n".join(lines)

    def start(self) -> None:
        argv, conf, up, down = self.plan()
        if self.engine == "sing-box":
            binp = argv[0]
            if not which("sing-box") and not Path(binp).exists():
                raise SystemExit("sing-box not found. Install: "
                                 "linux: bash <(curl -fsSL https://sing-box.app/install.sh) ; "
                                 "macOS: brew install sing-box ; windows: winget install SagerNet.SingBox")
            art = self.cfg.abspath(self.cfg.path("paths.artifacts", "artifacts"))
            art.mkdir(parents=True, exist_ok=True)
            self.conf_path = art / "singbox.json"
            self.conf_path.write_text(conf, encoding="utf-8")
            self.up = up
            for c in up:
                self._run(c)
            self.proc = subprocess.Popen([binp, "run", "-c", str(self.conf_path)],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            if not which("tun2socks"):
                raise SystemExit("tun2socks not found. Install with your package manager, or "
                                 "switch egress.tunnel.engine to sing-box in config/target.json")
            self.up = up
            for c in up:
                self._run(c)
            self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info("tunnel up: engine=%s if=%s pid=%s", self.engine, self.tun_if,
                 self.proc.pid if self.proc else "-")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=6)
            except Exception:
                self.proc.kill()
        self.proc = None
        for c in reversed(self.up):
            self._run(c)
        self.up = []
        log.info("tunnel down, killswitch removed")

    @staticmethod
    def _run(c: Command) -> None:
        try:
            if c.sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
                subprocess.run(["sudo", "-n"] + c.argv, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(c.argv, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            log.warning("killswitch cmd failed: %s (%s)", c.render()[:60], type(e).__name__)


if __name__ == "__main__":
    from tooling.config import load
    c = load()
    lu.setup(c, "tunnel")
    r = TunnelRunner(c)
    if "--dry-run" in sys.argv:
        print(r.dry_run())
    else:
        r.start()
        print(f"[tunnel] up on {r.tun_if} via {r.engine}; ctrl-c to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            r.stop()
