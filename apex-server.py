#!/usr/bin/env python3
"""Apex VPN — multi-client quota site + seller tool.

Routes:
  /                    → SELLER TOOL: paste link(s) + brand → yaml download
                         + client quota link + ready-to-send message (POST)
  /client              → client self-service paste page
  /client?link=...     → 302 to the client's personal page
  /q/<encoded>         → client's personal live quota page
  /dl/<encoded>?brand= → freshly generated branded mihomo YAML download
  /healthz             → ok
"""
import base64
import html
import json
import os
import re
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import yaml

CACHE_TTL = 300  # seconds per client link
MAX_BATCH = 20
_cache = {}


def b64e(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode()


def b64d(s: str) -> str:
    return base64.urlsafe_b64decode(s.encode()).decode()


def slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", s.lower()).strip("-")
    return s or "apex-vpn"


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


def build_yaml(status, proxies, brand="Apex VPN"):
    names = [p["name"] for p in proxies]
    config = {
        "mixed-port": 7890, "allow-lan": False, "mode": "global",
        "log-level": "info", "external-controller": "127.0.0.1:9090",
        "proxy-groups": [{"name": brand, "type": "select", "proxies": names}],
        "proxies": proxies,
    }
    header = (
        f"# {brand} — generated for your account (live quota below)\n"
        + (("# " + status + "\n") if status else "")
        + f"# {len(proxies)} nodes · refreshed {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
    )
    return header.encode() + yaml.safe_dump(
        config, allow_unicode=True, sort_keys=False, default_flow_style=False, width=1000
    ).encode()


def quota_summary(status):
    m = re.search(r"↑:([\d.]+)GB,↓:([\d.]+)GB,TOT:([\d.]+)GB.*?Expires:([\d-]+)", status)
    if not m:
        return None
    up, down, tot = float(m.group(1)), float(m.group(2)), float(m.group(3))
    return {"up": up, "down": down, "tot": tot, "left": max(tot - up - down, 0), "exp": m.group(4)}


PAGE_BASE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
__REFRESH__
<title>__TITLE__</title>
<style>body{font-family:-apple-system,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;align-items:flex-start;padding:24px 16px}
.card{background:#1e293b;border-radius:16px;padding:24px;max-width:480px;width:100%;margin:0 auto 14px;box-shadow:0 12px 32px rgba(0,0,0,.35)}
h1{font-size:21px;margin:0 0 6px}
h2{font-size:17px;margin:0 0 8px}
.sub{color:#94a3b8;font-size:13px;text-align:center;margin-bottom:16px}
.big{font-size:42px;font-weight:800;color:#34d399;text-align:center;margin:10px 0 4px}
.big span{font-size:20px;color:#94a3b8;font-weight:600}
.bar{height:12px;background:#334155;border-radius:8px;overflow:hidden;margin:14px 0 18px}
.fill{height:100%;background:linear-gradient(90deg,#34d399,#2563eb)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid div{background:#0f172a;border-radius:10px;padding:10px 12px}
.grid b{display:block;font-size:17px}.grid span{font-size:12px;color:#94a3b8}
.exp{margin-top:14px;color:#fbbf24;font-size:15px;text-align:center}
.btn{display:block;margin-top:10px;background:#2563eb;color:#fff;text-decoration:none;border:0;cursor:pointer;
padding:13px;border-radius:11px;font-size:15px;text-align:center;font-weight:600;width:100%;box-sizing:border-box}
.btn.gray{background:#334155}.btn.green{background:#34d399;color:#0f172a}
label{display:block;font-size:14px;margin:12px 0 6px;color:#cbd5e1}
input[type=text],textarea{width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #334155;color:#e2e8f0;
border-radius:10px;padding:12px;font-size:15px}
textarea{height:110px}
input[type=submit]{width:100%;margin-top:14px;background:#34d399;color:#0f172a;font-weight:700;border:0;
padding:14px;border-radius:11px;font-size:16px}
.me{background:#0f172a;border-radius:10px;padding:12px;margin-top:10px}
.me .t{font-size:13px;color:#94a3b8;margin-bottom:6px}
.me .u{font-size:13px;word-break:break-all;color:#93c5fd}
.err{color:#f87171;font-size:15px;text-align:center;line-height:1.6;margin:10px 0}
.dim{color:#64748b;font-size:12px;margin-top:14px;text-align:center;line-height:1.5}
.ok{color:#4ade80;font-size:13px;text-align:center;margin-top:8px}
.row{border-top:1px solid #334155;margin-top:18px;padding-top:14px}
.msg{font-size:13px;color:#cbd5e1;background:#0f172a;border-radius:10px;padding:12px;line-height:1.6;white-space:pre-wrap}
.steps{margin-top:16px;font-size:14px;line-height:1.8;color:#cbd5e1}
</style></head><body><div class="card">__BODY__</div></body></html>"""


def render(title, body, refresh=False):
    ref = '<meta http-equiv="refresh" content="60">' if refresh else ""
    return PAGE_BASE.replace("__REFRESH__", ref).replace("__TITLE__", title).replace("__BODY__", body)


def seller_page():
    body = """<h1>⚡ Apex VPN — Seller Tool</h1>
<div class="sub">paste provider link(s) → get client yaml + quota link + message</div>
<form method="post" action="/tool">
<label>Your brand name (shown in the yaml + client pages)</label>
<input type="text" name="brand" value="Apex VPN" maxlength="40">
<label>Provider link(s) — one per line (up to 20)</label>
<textarea name="links" placeholder="https://provider.example/api/sub?token=…&#10;https://provider.example/api/sub?token=…"></textarea>
<input type="submit" value="⚡ Generate client packs">
</form>
<div class="steps">For each link you get:<br>
⬇️ the branded .yaml to attach · 🔗 the client's personal quota link · 📋 a ready-to-send message.<br>
Send all three to your client — done.</div>
<div class="dim"> Share with clients: <b style="color:#93c5fd">this site's main link</b> (without /tool)<br>
🔒 This /tool page is yours — don't share it.</div>"""
    return render("Apex VPN — Seller Tool", body)


def client_page():
    body = """<h1>⚡ Apex VPN — check your data</h1>
<div class="sub">paste your subscription link · 10 seconds</div>
<form method="get" action="/">
<label>Your subscription link (the one you use in Shadowrocket)</label>
<textarea name="link" placeholder="Paste your subscription link here"></textarea>
<input type="submit" value=" Show my quota">
</form>
<div class="steps">1️⃣ Paste the link your seller gave you<br>
2️⃣ Tap <b>Show my quota</b><br>
3️⃣ You'll get <b>your own personal link</b> — save it. Next time you just tap it.<br><br>
⬇️ The page also gives you your latest VPN config file (for Clash).</div>
<div class="dim">Your link stays on your device — it is only used to fetch your live quota.</div>"""
    return render("Apex VPN — check your data", body)


def client_page_body(enc, status, proxies, nodes_total, full_url):
    s = quota_summary(status)
    if s:
        pct = min(100.0, (s["tot"] - s["left"]) / s["tot"] * 100) if s["tot"] else 0
        quota = f"""<div class="big">{s['left']:,.2f} <span>GB left</span></div>
<div class="bar"><div class="fill" style="width:{pct:.1f}%"></div></div>
<div class="grid">
  <div><b>{s['tot']:,.0f} GB</b><span>total plan</span></div>
  <div><b>{s['up'] + s['down']:,.2f} GB</b><span>used</span></div>
  <div><b>↑ {s['up']:,.2f}</b><span>uploaded</span></div>
  <div><b>↓ {s['down']:,.2f}</b><span>downloaded</span></div>
</div>
<div class="exp">💡 Expires: <b>{html.escape(s['exp'])}</b></div>"""
    else:
        quota = f'<div class="err">Quota text not recognized.<br>{html.escape(status) or "No status from provider."}</div>'
    body = f"""<h1>⚡ Apex VPN — your data</h1>
<div class="sub">updated {time.strftime('%H:%M UTC', time.gmtime())} · auto-refreshes every 60s</div>
{quota}
<div class="dim" style="text-align:center;margin-top:10px">{len(proxies)} of {nodes_total} nodes ready in config</div>
<div class="me"><div class="t">🔗 YOUR personal link — save it (this is the one you tap from now on):</div>
<div class="u" id="pl">{html.escape(full_url)}</div></div>
<button class="btn gray" style="margin-top:8px" onclick="copyLink()">📋 Copy my personal link</button>
<a class="btn" href="/dl/{enc}">⬇️ Get my latest VPN config (YAML)</a>
<div class="ok" id="copied" style="display:none">✅ copied — save it in Notes or bookmarks</div>
<script>function copyLink(){{var t=document.getElementById('pl').textContent;
function ok(){{document.getElementById('copied').style.display='block'}}
if(navigator.clipboard){{navigator.clipboard.writeText(t).then(ok)}}else{{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();ok()}}}}</script>"""
    return render("Apex VPN — your data", body, refresh=True)


def error_page(msg):
    body = f"""<h1>⚡ Apex VPN</h1>
<div class="err">{msg}</div>
<a class="btn" href="/">← Paste a link</a>
<div class="dim">If your plan was renewed, use the NEW link your seller gave you.</div>"""
    return render("Apex VPN — error", body)


def results_page(brand, rows, host):
    slug = slugify(brand)
    parts = [f"""<h1>⚡ {html.escape(brand)} — client packs</h1>
<div class="sub">{len(rows)} link(s) · generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</div>"""]
    data_attr = []
    for i, r in enumerate(rows):
        if r.get("error"):
            parts.append(f"""<div class="row"><h2>Link {i + 1}</h2>
<div class="err">❌ {html.escape(r["error"])}</div></div>""")
            continue
        s = r["summary"]
        full = f"https://{host}/q/{r['enc']}"
        dl = f"/dl/{r['enc']}?brand={urllib.parse.quote(brand)}"
        if s:
            stat = f"<div class='big' style='font-size:30px'>{s['left']:,.2f} <span>GB left</span></div><div class='dim' style='text-align:center'>expires {html.escape(s['exp'])}</div>"
        else:
            stat = f"<div class='dim' style='text-align:center'>no quota text · {len(r['proxies'])} nodes found</div>"
        msg = (f"Hi! Here's your {brand} VPN setup 🚀\n\n"
               f"1) VPN config: import the attached {slug}.yaml file (Clash Verge / Fugu / mihomo → New profile → from file)\n"
               f"2) Check your data anytime: {full}\n\n"
               f"If your plan renews, open that link and paste your new subscription.")
        data_attr.append((i + 1, msg.replace("</", "<\\/")))
        parts.append(f"""<div class="row"><h2>Link {i + 1} — {len(r['proxies'])} nodes</h2>
{stat}
<a class="btn green" href="{dl}">⬇️ Download {html.escape(slug)}.yaml</a>
<div class="me"><div class="t">🔗 Client's quota link:</div><div class="u" id="pl{i + 1}">{html.escape(full)}</div></div>
<div style="display:flex;gap:8px">
<button class="btn gray" style="flex:1;margin-top:8px" onclick="cp('pl{i + 1}','cop{i + 1}')">📋</button>
<button class="btn gray" style="flex:1;margin-top:8px" onclick="cm('m{i + 1}')">📋 Message</button>
</div>
<div class="ok" id="cop{i + 1}" style="display:none">✅ link copied</div>
<div class="msg" id="m{i + 1}" style="display:none">{html.escape(msg)}</div>
<div class="ok" id="copm{i + 1}" style="display:none">✅ message copied — paste it to your client</div></div>""")
    js = "<script>" + "var M=" + json.dumps({n: m for n, m in data_attr}) + ";"
    js += """function cp(id,ok){var t=document.getElementById(id).textContent;function d(){document.getElementById(ok).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}
function cm(k){var el=document.getElementById(k);el.style.display='block';var t=el.textContent;
setTimeout(function(){document.getElementById('copm'+k.slice(1)).style.display='block'},50);
function d(){document.getElementById('copm'+k.slice(1)).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}
</script>"""
    parts.append(js)
    parts.append('<div class="dim">⬇️ attach the yaml file + send the copied message to your client. Their quota link keeps working forever (auto-updates).</div>')
    return render(f"{brand} — client packs", "".join(parts))


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

    def _host(self):
        return self.headers.get("Host", "localhost").split(":")[0]

    def do_GET(self):
        parts = self.path.split("?")
        path = parts[0]
        query = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
        try:
            if path == "/healthz":
                self._send(200, "text/plain", b"ok")
            elif path == "/tool":
                self._send(200, "text/html; charset=utf-8", seller_page().encode())
            elif path == "/":
                link = (query.get("link", [""])[0]).strip()
                if link:
                    if not re.match(r"^https?://", link):
                        self._send(200, "text/html; charset=utf-8",
                                   error_page("That doesn't look like a link — it should start with http or https.").encode())
                        return
                    self.send_response(302)
                    self.send_header("Location", f"/q/{b64e(link)}")
                    self.end_headers()
                else:
                    self._send(200, "text/html; charset=utf-8", client_page().encode())
            elif path.startswith("/dl/"):
                enc = path[4:]
                url = b64d(enc)
                brand = (query.get("brand", ["Apex VPN"])[0]).strip()[:40] or "Apex VPN"
                ts, status, links, proxies = get_data(url)
                if not proxies:
                    self._send(200, "text/plain; charset=utf-8",
                               "No VLESS nodes found in that link - cannot build a YAML config.".encode())
                    return
                body = build_yaml(status, proxies, brand)
                self._send(200, "text/yaml; charset=utf-8", body,
                           {"Content-Disposition": f'attachment; filename="{slugify(brand)}.yaml"'})
            elif path.startswith("/q/"):
                enc = path[3:]
                url = b64d(enc)
                ts, status, links, proxies = get_data(url)
                full = f"https://{self._host()}/q/{enc}"
                self._send(200, "text/html; charset=utf-8",
                           client_page_body(enc, status, proxies, len(links), full).encode())
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(200, "text/html; charset=utf-8",
                       error_page("Couldn't read that link — it may be invalid or expired.<br>(" + html.escape(str(e)) + ")").encode())

    def do_POST(self):
        if self.path.split("?")[0] != "/tool":
            self._send(404, "text/plain", b"not found")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = urllib.parse.parse_qs(self.rfile.read(length).decode())
            brand = (data.get("brand", ["Apex VPN"])[0]).strip()[:40] or "Apex VPN"
            links_text = data.get("links", [""])[0]
            links = [l.strip() for l in links_text.splitlines()
                     if l.strip().startswith(("http://", "https://"))][:MAX_BATCH]
            if not links:
                self._send(200, "text/html; charset=utf-8",
                           error_page("No valid links found — each should start with http or https (one per line).").encode())
                return
            rows = []
            for link in links:
                enc = b64e(link)
                try:
                    ts, status, all_links, proxies = get_data(link)
                    if not proxies:
                        rows.append({"enc": enc, "error": "link opened but no VLESS nodes found", "proxies": []})
                    else:
                        rows.append({"enc": enc, "status": status, "summary": quota_summary(status), "proxies": proxies})
                except Exception as e:
                    rows.append({"enc": enc, "error": f"could not read link ({e})"})
            self._send(200, "text/html; charset=utf-8",
                       results_page(brand, rows, self._host()).encode())
        except Exception as e:
            self._send(200, "text/html; charset=utf-8",
                       error_page("Something went wrong generating your packs: " + html.escape(str(e))).encode())

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8899"))
    print(f"Apex VPN site (seller tool + client pages) on :{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
