#!/usr/bin/env python3
"""Apex VPN — multi-client quota site (one site, any number of clients).

Each client pastes their own subscription link once → gets their own
permanent personal quota URL (the link is encoded IN the URL, so the
server stores nothing — perfect for free Render).

Routes:
  /                  → paste-your-link page
  /?link=...         → validates + redirects to the personal page
  /q/<encoded>       → personal live quota page + personal link + YAML button
  /q/<encoded>/yaml  → freshly generated mihomo YAML for that client
  /healthz           → ok
"""
import base64
import os
import re
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import yaml

CACHE_TTL = 300  # seconds per client link
_cache = {}


def b64e(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode()


def b64d(s: str) -> str:
    return base64.urlsafe_b64decode(s.encode()).decode()


def fetch_subscription(url):
    raw = urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "Shadowrocket/2.2.32"}),
        timeout=30,
    ).read()
    text = raw.decode().strip()
    try:
        text = base64.b64decode(text).decode("utf-8")
    except Exception:
        pass
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    status = next((l for l in lines if l.startswith("STATUS=")), "")
    links = [l for l in lines if re.match(r"^[a-z0-9+.-]+://", l)]
    return status, links


def parse_vless(link):
    p = urllib.parse.urlsplit(link)
    uuid, _, hostport = p.netloc.rpartition("@")
    server, _, port = hostport.partition(":")
    q = urllib.parse.parse_qs(p.query)
    g = lambda k: q.get(k, [""])[0]
    name = urllib.parse.unquote(p.fragment or (server + ":" + port))
    net = g("type") or "tcp"
    security = g("security")
    proxy = {"name": name, "type": "vless", "server": server, "port": int(port),
             "uuid": uuid, "network": net, "udp": True}
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
    return proxy


def get_data(url):
    hit = _cache.get(url)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit
    status, links = fetch_subscription(url)
    proxies = [parse_vless(l) for l in links if l.startswith("vless://")]
    entry = (time.time(), status, links, proxies)
    _cache[url] = entry
    return entry


def build_yaml(status, proxies):
    names = [p["name"] for p in proxies]
    config = {
        "mixed-port": 7890, "allow-lan": False, "mode": "global",
        "log-level": "info", "external-controller": "127.0.0.1:9090",
        "proxy-groups": [{"name": "Apex VPN", "type": "select", "proxies": names}],
        "proxies": proxies,
    }
    header = (
        "# Apex VPN — generated for your account (live quota below)\n"
        + ("# " + status + "\n" if status else "")
        + f"# {len(proxies)} nodes · refreshed {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
    )
    return header.encode() + yaml.safe_dump(
        config, allow_unicode=True, sort_keys=False, default_flow_style=False, width=1000
    ).encode()


PAGE_BASE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>__TITLE__</title>
<style>body{font-family:-apple-system,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;padding:20px}
.card{background:#1e293b;border-radius:16px;padding:24px;max-width:460px;width:100%}
h1{font-size:21px;margin:0 0 6px}
.sub{color:#94a3b8;font-size:13px;text-align:center;margin-bottom:16px}
.big{font-size:42px;font-weight:800;color:#34d399;text-align:center;margin:10px 0 4px}
.big span{font-size:20px;color:#94a3b8;font-weight:600}
.bar{height:12px;background:#334155;border-radius:8px;overflow:hidden;margin:14px 0 18px}
.fill{height:100%;background:linear-gradient(90deg,#34d399,#2563eb)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid div{background:#0f172a;border-radius:10px;padding:10px 12px}
.grid b{display:block;font-size:17px}.grid span{font-size:12px;color:#94a3b8}
.exp{margin-top:14px;color:#fbbf24;font-size:15px;text-align:center}
.btn{display:block;margin-top:14px;background:#2563eb;color:#fff;text-decoration:none;
padding:14px;border-radius:11px;font-size:16px;text-align:center;font-weight:600}
.btn.gray{background:#334155}
textarea{width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #334155;color:#e2e8f0;
border-radius:10px;padding:12px;font-size:15px;height:84px;margin-bottom:10px}
input[type=submit]{width:100%;background:#34d399;color:#0f172a;font-weight:700;border:0;
padding:14px;border-radius:11px;font-size:16px}
.me{background:#0f172a;border-radius:10px;padding:12px;margin-top:16px}
.me .t{font-size:13px;color:#94a3b8;margin-bottom:6px}
.me .u{font-size:13px;word-break:break-all;color:#93c5fd}
.steps{margin-top:16px;font-size:14px;line-height:1.8;color:#cbd5e1}
.err{color:#f87171;font-size:15px;text-align:center;line-height:1.6;margin:10px 0}
.dim{color:#64748b;font-size:12px;margin-top:14px;text-align:center;line-height:1.5}</style>
</head><body><div class="card">__BODY__</div></body></html>"""


def home_page():
    body = """<h1>⚡ Apex VPN — check your data</h1>
<div class="sub">paste your subscription link · 10 seconds</div>
<form method="get" action="/">
<textarea name="link" placeholder="Paste your subscription link here (the one you use in Shadowrocket)"></textarea>
<input type="submit" value=" Show my quota">
</form>
<div class="steps">1️⃣ Paste the link your seller gave you<br>
2️⃣ Tap <b>Show my quota</b><br>
3️⃣ You'll get <b>your own personal link</b> — save it. Next time you just tap it.<br><br>
⬇️ The page also gives you your latest VPN config file (for Clash).</div>
<div class="dim">Your link stays on your device — it is only used to fetch your live quota.</div>"""
    return PAGE_BASE.replace("__TITLE__", "Apex VPN").replace("__BODY__", body)


def quota_page(enc, status, proxies, nodes_total, page_url, origin):
    m = re.search(r"↑:([\d.]+)GB,↓:([\d.]+)GB,TOT:([\d.]+)GB.*?Expires:([\d-]+)", status)
    if m:
        up, down, tot = float(m.group(1)), float(m.group(2)), float(m.group(3))
        exp = m.group(4)
        left = max(tot - up - down, 0)
        pct = min(100.0, (tot - left) / tot * 100) if tot else 0
        quota = f"""<div class="big">{left:,.2f} <span>GB left</span></div>
<div class="bar"><div class="fill" style="width:{pct:.1f}%"></div></div>
<div class="grid">
  <div><b>{tot:,.0f} GB</b><span>total plan</span></div>
  <div><b>{up + down:,.2f} GB</b><span>used</span></div>
  <div><b>↑ {up:,.2f}</b><span>uploaded</span></div>
  <div><b>↓ {down:,.2f}</b><span>downloaded</span></div>
</div>
<div class="exp">💡 Expires: <b>{exp}</b></div>"""
    else:
        quota = f'<div class="err">Quota text not recognized.<br>{status or "No status from provider."}</div>'
    body = f"""<h1>⚡ Apex VPN — your data</h1>
<div class="sub">updated {time.strftime('%H:%M UTC', time.gmtime())} · auto-refreshes every 60s</div>
{quota}
<div class="dim" style="text-align:center;margin-top:10px">{len(proxies)} of {nodes_total} nodes ready in config</div>
<div class="me"><div class="t">🔗 YOUR personal link — save it (this is the one you tap from now on):</div>
<div class="u" id="pl">{page_url}</div></div>
<button class="btn gray" style="margin-top:8px" onclick="copyLink()">📋 Copy my personal link</button>
<a class="btn" href="/q/{enc}/yaml">⬇️ Get my latest VPN config (YAML)</a>
<div class="dim" id="copied" style="display:none;color:#4ade80;text-align:center">✅ copied — save it in Notes or your browser bookmarks</div>
<script>function copyLink(){{var t=document.getElementById('pl').textContent;
function ok(){{document.getElementById('copied').style.display='block'}}
if(navigator.clipboard){{navigator.clipboard.writeText(t).then(ok)}}else{{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();ok()}}}}</script>"""
    return PAGE_BASE.replace("__TITLE__", "Apex VPN — your data").replace("__BODY__", body)


def error_page(msg):
    body = f"""<h1>⚡ Apex VPN</h1>
<div class="err">{msg}</div>
<a class="btn" href="/">← Paste a link</a>
<div class="dim">If your plan was renewed, use the NEW link your seller gave you.</div>"""
    return PAGE_BASE.replace("__TITLE__", "Apex VPN — error").replace("__BODY__", body)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, ctype, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = self.path.split("?")
        path = parts[0]
        query = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
        try:
            if path == "/healthz":
                self._send(200, "text/plain", b"ok")
            elif path == "/":
                link = (query.get("link", [""])[0]).strip()
                if link:
                    if not re.match(r"^https?://", link):
                        self._send(200, "text/html; charset=utf-8",
                                   error_page("That doesn't look like a link — it should start with http or https.").encode())
                        return
                    enc = b64e(link)
                    self.send_response(302)
                    self.send_header("Location", f"/q/{enc}")
                    self.end_headers()
                else:
                    self._send(200, "text/html; charset=utf-8", home_page().encode())
            elif path.startswith("/q/") and path.endswith("/yaml"):
                enc = path[3:-5]
                url = b64d(enc)
                ts, status, links, proxies = get_data(url)
                if not proxies:
                    self._send(200, "text/plain; charset=utf-8",
                               "No VLESS nodes found in that link - cannot build a YAML config.".encode())
                    return
                self._send(200, "text/yaml; charset=utf-8", build_yaml(status, proxies))
            elif path.startswith("/q/"):
                enc = path[3:]
                url = b64d(enc)
                ts, status, links, proxies = get_data(url)
                page_url = self.headers.get("Host", "")
                full = f"https://{page_url}/q/{enc}"
                html = quota_page(enc, status, proxies, len(links), full, "")
                self._send(200, "text/html; charset=utf-8", html.encode())
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(200, "text/html; charset=utf-8",
                       error_page("Couldn't read that link — it may be invalid or expired.<br>(" + str(e).replace('<', '&lt;') + ")").encode())

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8899"))
    print(f"Apex VPN multi-client site on :{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
