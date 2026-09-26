"""Local UI + control plane. Binds 127.0.0.1 only.

Serves ui/index.html, the same JSON API the service exposes, and adds the three
write endpoints the UI needs: import a parcel, start the listeners, boot Chrome
or the system TUN. Everything is same-origin, token-gated if you set one.
"""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
import webbrowser
from http import HTTPStatus
from pathlib import Path
from typing import Any

from tooling.config import Cfg
from tooling.db import DB
from tooling import logging_util as lu
from tooling.parcel import ParcelImporter
from egress.chrome import ChromeRunner
from egress.service import ResiService
from egress.tunnel import TunnelRunner
from vuln.tester import Tester

log = lu.get()
UI_DIR = Path(__file__).resolve().parent


class ControlPlane:
    def __init__(self, cfg: Cfg):
        self.cfg = cfg
        self.bind = cfg.path("ui.bind", "127.0.0.1")
        self.port = int(cfg.path("ui.port", 8770))
        self.token = cfg.path("ui.auth_token", "")
        self.db = DB(cfg.abspath(cfg.path("paths.db")))
        self.service = ResiService(cfg)
        self.importer = ParcelImporter(cfg, self.db)
        self.chrome = ChromeRunner(cfg)
        self.tunnel = TunnelRunner(cfg)
        self.tester: Tester | None = None
        self.server: asyncio.Server | None = None
        self.tunnel_proc = None
        self.serving = False

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._client, self.bind, self.port)
        log.info("UI on http://%s:%d", self.bind, self.port)

    # -------------------------------------------------------------- routing
    async def _client(self, reader, writer) -> None:
        from tooling.httpclient import _read_head
        try:
            head = await asyncio.wait_for(_read_head(reader, 16384), 10)
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            method, path, _ = (line.split(" ") + ["", "", ""])[:3]
            headers = {}
            for ln in head.split(b"\r\n")[1:]:
                if b":" in ln:
                    k, _, v = ln.partition(b":")
                    headers[k.decode().strip().lower()] = v.decode().strip()
            body = b""
            n = int(headers.get("content-length", "0") or 0)
            if n:
                body = await asyncio.wait_for(reader.readexactly(n), 30)
            code, ctype, payload = await self._route(method, path, headers, body)
        except Exception as e:
            code, ctype, payload = 500, "text/plain", f"{type(e).__name__}: {e}".encode()
        try:
            writer.write(b"HTTP/1.1 " + str(code).encode() + b" " +
                         HTTPStatus(code).phrase.encode() + b"\r\nContent-Type: " + ctype.encode() +
                         b"\r\nContent-Length: " + str(len(payload)).encode() +
                         b"\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n" + payload)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _authed(self, headers: dict) -> bool:
        if not self.token:
            return True
        return headers.get("x-resi-token", "") == self.token

    async def _route(self, method: str, path: str, headers: dict, body: bytes) -> tuple[int, str, bytes]:
        p, _, qs = path.partition("?")
        if p == "/" or p == "/index.html":
            return 200, "text/html; charset=utf-8", (UI_DIR / "index.html").read_bytes()
        if p == "/proxy.pac":
            from tooling.pac import build_pac
            e = self.cfg.path("egress", {})
            return 200, "application/x-ns-proxy-autoconfig", \
                build_pac("socks5", e.get("listen_host", "127.0.0.1"), e.get("socks_port", 2080)).encode()
        if p == "/api/status":
            return self._j(self._status())
        if p == "/api/stats":
            return self._j(self.db.stats())
        if p == "/api/pool":
            return self._j(self._pool(qs))
        if p == "/api/parcels":
            return self._j({"parcels": self.db.list_parcels()})
        if p == "/api/tunnel-plan":
            return 200, "text/plain", self.tunnel.dry_run().encode()
        if p == "/api/import" and method == "POST":
            if not self._authed(headers):
                return 403, "text/plain", b"bad token"
            return self._import(body)
        if p.startswith("/api/act/") and method == "POST":
            if not self._authed(headers):
                return 403, "text/plain", b"bad token"
            return self._act(p.rsplit("/", 1)[-1])
        return 404, "text/plain", b"not found"

    @staticmethod
    def _j(obj: Any) -> tuple[int, str, bytes]:
        return 200, "application/json", json.dumps(obj, default=str).encode()

    def _status(self) -> dict:
        s = self.service.status() if self.serving else {}
        s["db"] = self.db.stats()
        s["tunnel"] = {"up": self.tunnel_proc is not None, "engine": self.tunnel.engine,
                       "if": self.tunnel.tun_if}
        s["chrome"] = {"running": self.chrome.proc is not None and self.chrome.proc.poll() is None}
        return s

    def _pool(self, qs: str) -> dict:
        from urllib.parse import parse_qs
        from tooling.httpclient import Endpoint
        from tooling.socks_server import Upstream
        p = parse_qs(qs)
        grade = (p.get("grade") or ["B"])[0]
        cc = (p.get("cc") or [""])[0]
        nodc = (p.get("nodc") or [""])[0] in ("1", "true", "yes")
        rows = self.db.live_pool(min_grade=grade, limit=8000, countries=cc, exclude_dc=nodc)
        ups = []
        for r in rows:
            ups.append({"proxy": f"{r['scheme']}://{r['host']}:{r['port']}", "grade": r["grade"],
                        "cc": r["cc"], "asn": r["asn"], "score": round(float(r["success_ratio"] or 0) * 2, 2),
                        "meta": {"exit_ip": r["exit_ip"], "isp": r["isp"],
                                 "latency_ms": float(r["latency_ms"] or 0),
                                 "ratio": float(r["success_ratio"] or 0)}})
        return {"count": len(ups), "upstreams": ups}

    def _import(self, body: bytes) -> tuple[int, str, bytes]:
        try:
            d = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return 400, "text/plain", b"bad json"
        text = d.get("text", "")
        label = d.get("label") or "pasted"
        scheme = d.get("scheme") or "auto"
        want_test = bool(d.get("test"))
        if not text.strip():
            return 400, "text/plain", b"empty"
        save = None
        inbox = self.cfg.root / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        save = inbox / f"{label.strip().replace('/', '_') or 'parcel'}-{int(time.time())}.txt"
        save.write_text(text, encoding="utf-8", errors="replace")
        r = self.importer.import_text(text, label, scheme, str(save))
        msg = {"parcel_id": r.parcel_id, "parsed": r.parsed, "unique": r.unique, "schemes": r.schemes}
        if want_test:
            self.tester = self.tester or Tester(self.cfg, self.db)
            res = asyncio.create_task(self._test_parcel(r.parcel_id))
            msg["testing"] = True
            res.add_done_callback(lambda t: log.info("parcel test finished: %s", t.exception() or "ok"))
        return self._j(msg)

    async def _test_parcel(self, pid: int) -> None:
        self.tester = self.tester or Tester(self.cfg, self.db)
        await self.tester.run(self.importer.parcel_rows(pid), write=True)

    def _act(self, what: str) -> tuple[int, str, bytes]:
        if what == "serve":
            if self.serving:
                return self._j({"serving": True, "note": "already running"})
            asyncio.create_task(self.service.start())
            self.serving = True
            return self._j({"serving": True, "socks": self.service.socks_port, "http": self.service.mixed_port})
        if what == "chrome":
            host = self.cfg.path("egress.listen_host", "127.0.0.1")
            port = self.service.mixed_port or int(self.cfg.path("egress.mixed_port", 2081))
            urls = ["https://ipinfo.io", "https://whatismyipaddress.com", "https://browserleaks.com/ip"]
            p = self.chrome.launch(f"http://{host}:{port}", urls)
            return self._j({"chrome_pid": p.pid, "proxy": f"http://{host}:{port}", "urls": urls})
        if what == "tunnel-dry":
            return 200, "text/plain", self.tunnel.dry_run().encode()
        if what == "tunnel":
            if self.tunnel_proc:
                self.tunnel.stop()
                self.tunnel_proc = None
                return self._j({"tunnel": "down"})
            self.tunnel.start()
            self.tunnel_proc = True
            return self._j({"tunnel": "up", "engine": self.tunnel.engine, "if": self.tunnel.tun_if})
        if what == "stop":
            self.tunnel.stop()
            self.chrome.kill()
            return self._j({"stopped": True})
        return 404, "text/plain", b"unknown action"

    async def run_forever(self) -> None:
        await self.start()
        if self.cfg.path("ui.open_browser", True):
            try:
                webbrowser.open(f"http://{self.bind}:{self.port}")
            except Exception:
                pass
        while True:
            await asyncio.sleep(3600)


if __name__ == "__main__":
    from tooling.config import load
    c = load()
    lu.setup(c, "ui")
    cp = ControlPlane(c)
    try:
        asyncio.run(cp.run_forever())
    except KeyboardInterrupt:
        pass
