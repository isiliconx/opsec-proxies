"""Route A — Chrome (and any Chromium) pointed at the local rotating proxy.

Nothing else changes: no extension, no PAC inside the profile, no system
settings. The browser simply has its proxy set to 127.0.0.1:<mixed_port>, and
that listener binds each connection to a verified residential upstream. Kill
switch is the process itself: close the listener and the browser is direct.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from tooling.config import Cfg
from tooling import logging_util as lu

log = lu.get()

CHROME_NAMES = {
    "linux": ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"],
    "darwin": ["Google Chrome", "Chromium"],
    "win32": ["chrome.exe", "msedge.exe"],
}
MAC_APP = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def find_browser(cfg: Cfg) -> str | None:
    configured = cfg.path("egress.browser.binary", "")
    if configured and Path(configured).exists():
        return configured
    plat = sys.platform
    if plat == "darwin":
        if Path(MAC_APP).exists():
            return MAC_APP
        for n in CHROME_NAMES["darwin"]:
            p = Path(f"/Applications/{n}.app/Contents/MacOS/{n}")
            if p.exists():
                return str(p)
    if plat == "win32":
        for base in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                     os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
                     os.environ.get("LOCALAPPDATA", "")):
            for n in CHROME_NAMES["win32"]:
                p = Path(base) / n
                if p.exists():
                    return str(p)
        return None
    for n in CHROME_NAMES["linux"]:
        p = shutil.which(n)
        if p:
            return p
    return None


def build_argv(cfg: Cfg, proxy_url: str, urls: Iterable[str], profile: Path,
               headless: bool = False, no_sandbox: bool = False) -> list[str]:
    binary = cfg.path("egress.browser.binary", "") or find_browser(cfg) or "google-chrome"
    ud = str(profile)
    args = [binary, f"--user-data-dir={ud}", f"--proxy-server={proxy_url}"]
    args += ["--no-first-run", "--no-default-browser-check", "--password-store=basic",
             "--disable-features=Translate,OptimizationHints", "--disable-background-networking",
             "--disable-component-update", "--disable-sync", "--dns-prefetch-disable",
             "--safebrowsing-disable-auto-update", "--metrics-recording-only",
             "--disable-features=OptimizationGuideModelDownloading"]
    for extra in cfg.path("egress.browser.extra_args", []) or []:
        args.append(extra)
    if headless:
        args.append("--headless=new")
    if no_sandbox or os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        args.append("--no-sandbox")
    args += list(urls)
    return args


class ChromeRunner:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self.proc: subprocess.Popen | None = None

    def launch(self, proxy_url: str, urls: Iterable[str] | None = None,
               headless: bool = False, wait: bool = False) -> subprocess.Popen:
        urls = list(urls or ["https://ipinfo.io", "https://whatismyipaddress.com"])
        profile = self.cfg.abspath(self.cfg.path("egress.browser.user_data_dir", "data/chrome-profile"))
        profile.mkdir(parents=True, exist_ok=True)
        argv = build_argv(self.cfg, proxy_url, urls, profile, headless)
        log.info("launching: %s", " ".join(argv[:6]) + f" ... (+{len(urls)} urls)")
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if wait:
            try:
                self.proc.wait(timeout=30)
            except Exception:
                pass
        return self.proc

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None


if __name__ == "__main__":
    cfg = load()
    lu.setup(cfg, "chrome")
    port = int(cfg.path("egress.mixed_port", 2081))
    host = cfg.path("egress.listen_host", "127.0.0.1")
    urls = sys.argv[1:] or ["https://ipinfo.io"]
    r = ChromeRunner(cfg)
    p = r.launch(f"http://{host}:{port}", urls)
    print(f"[chrome] pid={p.pid} proxy=http://{host}:{port} urls={urls}")
    try:
        p.wait()
    except KeyboardInterrupt:
        r.kill()
