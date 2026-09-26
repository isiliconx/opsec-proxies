"""PAC generator: routes host patterns through the local rotating proxy."""
from __future__ import annotations

TEMPLATE = """// resiproxy auto-generated PAC  (regenerated on every pool change)
var PROXY = "PROTO://HOST:PORT";
var DIRECT = "DIRECT";
var SESSION = "__resi_session_" + (new Date().getTime() % 100000);

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (isPlainHost(host)) return DIRECT;
  if (dnsDomainIs(host, "localhost")) return DIRECT;
  if (isInNet(host, "127.0.0.0", "255.0.0.0")) return DIRECT;
  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return DIRECT;
  if (isInNet(host, "192.168.0.0", "255.255.0.0")) return DIRECT;
  if (isInNet(host, "172.16.0.0", "255.240.0.0")) return DIRECT;
  if (isInNet(host, "169.254.0.0", "255.255.0.0")) return DIRECT;   // link-local / metadata
  if (isInNet(host, "100.64.0.0", "255.192.0.0")) return DIRECT;    // CGNAT: keep local traffic home
  if (BYPASS.length) {
    for (var i = 0; i < BYPASS.length; i++) {
      if (shExpMatch(host, BYPASS[i])) return DIRECT;
    }
  }
  // PROXY carries the sticky session id so one browser tab keeps one exit IP
  return PROXY + "; " + PROXY;
}

function isPlainHost(host) {
  return !host || host.indexOf(".") === -1 || (/^[0-9.]+$/.test(host));
}
"""


def build_pac(proto: str = "socks5", host: str = "127.0.0.1", port: int = 2080,
              bypass: list[str] | None = None) -> str:
    b = bypass or []
    if not b:
        b = ["*.local", "*.lan", "*.internal", "*.home.arpa"]
    js = TEMPLATE.replace("PROTO", proto).replace("HOST", host).replace("PORT", str(port))
    return js.replace("BYPASS", js_array(b))


def js_array(items: list[str]) -> str:
    return "[" + ", ".join('"' + x.replace('"', '\\"') + '"' for x in items) + "]"


def build_pac_file(cfg) -> str:
    e = cfg.path("egress", {})
    proto = "socks5" if e.get("socks_port") else "http"
    port = e.get("socks_port", 2080)
    return build_pac(proto, e.get("listen_host", "127.0.0.1"), port)
