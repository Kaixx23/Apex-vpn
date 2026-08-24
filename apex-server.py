#!/usr/bin/env python3
"""Apex VPN — live mihomo YAML subscription server.

- GET /            → small HTML status page (auto-refreshes every 60s)
- GET /apex-vpn.yaml → freshly generated minimal mihomo YAML (1:1 from the link)
- GET /quota.txt   → plain-text quota/STATUS line
- GET /healthz     → 200 OK

Each request re-fetches the provider link (5-minute cache) so the quota
and node list are always current — just like refreshing in Shadowrocket.
"""
import base64
import os
import re
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import yaml

PROVIDER_URL = os.environ.get("PROVIDER_URL", "").strip()
if not PROVIDER_URL:
    raise SystemExit("PROVIDER_URL environment variable is required (set it in Render dashboard -> Environment)")
CACHE_TTL = 300  # seconds
_cache = {"ts": 0.0, "status": "", "nodes": 0, "yaml_b": b""}


def build():
    """Fetch the provider link and build the current YAML + status."""
    raw = urllib.request.urlopen(
        urllib.request.Request(PROVIDER_URL, headers={"User-Agent": "Shadowrocket/2.2.32"}),
        timeout=30,
    ).read()
    text = raw.decode().strip()
    try:
        text = base64.b64decode(text).decode("utf-8")
    except Exception:
        pass  # already plain
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    status_line = next((l for l in lines if l.startswith("STATUS=")), "")
    links = [l for l in lines if l.startswith("vless://")]

    proxies = []
    for link in links:
        p = urllib.parse.urlsplit(link)
        uuid, _, hostport = p.netloc.rpartition("@")
        server, _, port = hostport.partition(":")
        q = urllib.parse.parse_qs(p.query)
        g = lambda k: q.get(k, [""])[0]
        name = urllib.parse.unquote(p.fragment or (server + ":" + port))
        net = g("type") or "tcp"
        security = g("security")
        proxy = {
            "name": name, "type": "vless", "server": server, "port": int(port),
            "uuid": uuid, "network": net, "udp": True,
        }
        if security in ("tls", "reality"):
            proxy["tls"] = True
        if g("flow"):
            proxy["flow"] = g("flow")
        if g("sni"):
            proxy["servername"] = g("sni")
        if g("fp"):
            proxy["client-fingerprint"] = g("fp")
        if net == "ws":
            opts = {}
            if g("path"):
                opts["path"] = g("path")
            if g("host"):
                opts["headers"] = {"Host": g("host")}
            if opts:
                proxy["ws-opts"] = opts
        if security == "reality":
            ropts = {}
            if g("pbk"):
                ropts["public-key"] = g("pbk")
            if g("sid"):
                ropts["short-id"] = g("sid")
            if ropts:
                proxy["reality-opts"] = ropts
        proxies.append(proxy)

    names = [p["name"] for p in proxies]
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "global",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxy-groups": [{"name": "Apex VPN", "type": "select", "proxies": names}],
        "proxies": proxies,
    }
    header = (
        "# Apex VPN — auto-generated from subscription (live quota below)\n"
        + ("# " + status_line + "\n" if status_line else "")
        + f"# {len(proxies)} nodes · refreshed {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
    )
    yb = header.encode("utf-8") + yaml.safe_dump(
        config, allow_unicode=True, sort_keys=False, default_flow_style=False, width=1000
    ).encode("utf-8")
    _cache.update(ts=time.time(), status=status_line, nodes=len(proxies), yaml_b=yb)
    return _cache


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body: bytes, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        try:
            if path == "/healthz":
                self._send(200, "text/plain", b"ok")
                return
            if time.time() - _cache["ts"] > CACHE_TTL or not _cache["yaml_b"]:
                c = build()
            else:
                c = _cache
            if path in ("/apex-vpn.yaml", "/config.yaml", "/"):
                if path == "/":
                    status = c["status"].replace("STATUS=", "")
                    m = re.search(r"↑:([\d.]+)GB,↓:([\d.]+)GB,TOT:([\d.]+)GB.*?Expires:([\d-]+)", status)
                    if m:
                        up, down, tot = float(m.group(1)), float(m.group(2)), float(m.group(3))
                        exp = m.group(4)
                        left = max(tot - up - down, 0)
                        pct = min(100.0, (tot - left) / tot * 100) if tot else 0
                        quota_html = f"""
<div class="big">{left:,.2f} <span>GB left</span></div>
<div class="bar"><div class="fill" style="width:{pct:.1f}%"></div></div>
<div class="grid">
  <div><b>{tot:,.0f} GB</b><span>total plan</span></div>
  <div><b>{up + down:,.2f} GB</b><span>used</span></div>
  <div><b>↑ {up:,.2f}</b><span>uploaded</span></div>
  <div><b>↓ {down:,.2f}</b><span>downloaded</span></div>
</div>
<div class="exp">💡 Expires: <b>{exp}</b></div>"""
                    else:
                        quota_html = f'<div class="big">{status or "status unavailable"}</div>'
                    html = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Apex VPN — your data</title>
<style>body{{font-family:-apple-system,-apple-system,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;padding:20px}}
.card{{background:#1e293b;border-radius:16px;padding:24px;max-width:440px;width:100%}}
h1{{font-size:20px;margin:0 0 6px}}
.big{{font-size:42px;font-weight:800;color:#34d399;text-align:center;margin:14px 0 4px}}
.big span{{font-size:20px;color:#94a3b8;font-weight:600}}
.bar{{height:12px;background:#334155;border-radius:8px;overflow:hidden;margin:14px 0 18px}}
.fill{{height:100%;background:linear-gradient(90deg,#34d399,#2563eb)}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
.grid div{{background:#0f172a;border-radius:10px;padding:10px 12px}}
.grid b{{display:block;font-size:17px}} .grid span{{font-size:12px;color:#94a3b8}}
.exp{{margin-top:14px;color:#fbbf24;font-size:15px;text-align:center}}
a{{display:inline-block;margin-top:18px;width:100%;background:#2563eb;color:#fff;text-decoration:none;
padding:14px;border-radius:11px;font-size:16px;text-align:center;font-weight:600}}
.dim{{color:#64748b;font-size:12px;margin-top:12px;text-align:center;line-height:1.5}}</style>
</head><body><div class="card">
<h1>⚡ Apex VPN — live</h1>
<div class="dim" style="text-align:center;margin-bottom:0">updated {time.strftime('%H:%M UTC', time.gmtime())} · auto-refreshes every 60s</div>
{quota_html}
<div class="dim">{c['nodes']} nodes available</div>
<a href="/apex-vpn.yaml">⬇️ Get latest YAML config</a>
</div></body></html>"""
                    self._send(200, "text/html; charset=utf-8", html.encode("utf-8"))
                else:
                    self._send(200, "text/yaml; charset=utf-8", c["yaml_b"])
            elif path == "/quota.txt":
                self._send(200, "text/plain; charset=utf-8", c["status"].encode("utf-8"))
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(502, "text/plain", f"upstream error: {e}".encode())

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8899"))
    print(f"Apex VPN subscription server on :{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
