#!/usr/bin/env python3
"""Apex VPN — multi-client quota site + seller tool.

Security:
  - Client personal links use AES-256-GCM encrypted tokens (apx.*).
    The provider link is NEVER visible in the URL, page, or history.
    Key comes from the APX_KEY env var (64 hex chars, Render dashboard).
    Without it the site falls back to legacy base64 links.

Routes:
  /                        → CLIENT page (paste link, POST) — share this
  /tool                    → SELLER tool (yours, don't share)
  /q/<token>?brand=        → client's personal live quota page
  /dl/<token>?brand=       → branded mihomo YAML download (attachment)
  /sub/<token>?brand=      → branded plain mihomo YAML (Clash auto-update)
  /share/<token>?brand=    → rebranded subscription, PLAIN vless list
                             (Shadowrocket paste, v2rayN/NG, NekoBox, Hiddify)
  /share/<token>/sr?brand= → rebranded subscription, BASE64 (classic Shadowrocket)
  /healthz                 → ok (keep-alive ping)
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CACHE_TTL = 300  # seconds per provider link
MAX_BATCH = 20
DEFAULT_BRAND = "Sblaze VPN"
_cache = {}

_env_key = os.environ.get("APX_KEY", "").strip()
KEY = bytes.fromhex(_env_key) if len(_env_key) == 64 else None


def b64e(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode()


def b64d(s: str) -> str:
    return base64.urlsafe_b64decode(s.encode()).decode()


def make_token(url: str) -> str:
    if not KEY:
        return b64e(url)
    nonce = os.urandom(12)
    ct = AESGCM(KEY).encrypt(nonce, url.encode(), None)
    return "apx." + base64.urlsafe_b64encode(nonce + ct).decode()


def read_token(tok: str) -> str:
    if tok.startswith("apx."):
        if not KEY:
            raise ValueError("personal link needs the APX_KEY setting on the server")
        raw = base64.urlsafe_b64decode(tok[4:].encode())
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(KEY).decrypt(nonce, ct, None).decode()
    return b64d(tok)


def slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", s.lower()).strip("-")
    return s or "vpn"


def clean_brand(v: str) -> str:
    v = (v or "").strip()[:40]
    return v or DEFAULT_BRAND


# ---------- subscription fetch + yaml build ----------

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


def rebrand_link(link: str, brand: str) -> str:
    """Replace only the display name (#fragment) of any scheme:// link.
    The original fragment is already percent-encoded — keep it as-is and
    prepend the (quoted) brand so nothing gets double-encoded."""
    if "#" in link:
        base, fragment = link.split("#", 1)
        return base + "#" + urllib.parse.quote(brand, safe="") + fragment
    return link + "#" + urllib.parse.quote(brand, safe="")


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


def build_yaml(status, proxies, brand):
    branded = [{**p, "name": f"{brand} {p['name']}"} for p in proxies]
    names = [p["name"] for p in branded]
    config = {
        "mixed-port": 7890, "allow-lan": False, "mode": "global",
        "log-level": "info", "external-controller": "127.0.0.1:9090",
        "proxy-groups": [{"name": brand, "type": "select", "proxies": names}],
        "proxies": branded,
    }
    header = (
        f"# {brand} — generated for your account (live quota below)\n"
        + (("# " + status + "\n") if status else "")
        + f"# {len(branded)} nodes · refreshed {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
    )
    return header.encode() + yaml.safe_dump(
        config, allow_unicode=True, sort_keys=False, default_flow_style=False, width=1000
    ).encode()


def build_share(status, links, brand):
    """Rebranded plain-text subscription (all apps can import it)."""
    out = [status] if status else []
    out.extend(rebrand_link(l, brand) for l in links)
    return "\n".join(out) + "\n"


def quota_summary(status):
    m = re.search(r"↑:([\d.]+)GB,↓:([\d.]+)GB,TOT:([\d.]+)GB.*?Expires:([\d-]+)", status)
    if not m:
        return None
    up, down, tot = float(m.group(1)), float(m.group(2)), float(m.group(3))
    return {"up": up, "down": down, "tot": tot, "left": max(tot - up - down, 0), "exp": m.group(4)}


# ---------- pages ----------

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
padding:14px;border-radius:11px;font-size:16px;cursor:pointer}
.me{background:#0f172a;border-radius:10px;padding:12px;margin-top:10px}
.me .t{font-size:13px;color:#94a3b8;margin-bottom:6px;line-height:1.5}
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


COPY_JS = """<script>function cp(id,ok){var t=document.getElementById(id).textContent.trim();
function d(){document.getElementById(ok).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}
else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}</script>"""


def seller_page():
    body = f"""<h1>⚡ {html.escape(DEFAULT_BRAND)} — Seller Tool</h1>
<div class="sub">paste provider link(s) → rebranded share link + Clash auto-update + quota link + yaml + message</div>
<form method="post" action="/tool">
<label>Your brand name (shown everywhere — nodes, yaml, pages, share links)</label>
<input type="text" name="brand" value="{html.escape(DEFAULT_BRAND)}" maxlength="40">
<label>Provider link(s) — one per line (up to 20)</label>
<textarea name="links" placeholder="https://provider.example/api/sub?token=…&#10;https://provider.example/api/sub?token=…"></textarea>
<input type="submit" value="⚡ Generate client packs">
</form>
<div class="steps">For each link you get:<br>
✨ rebranded share link (works in Shadowrocket / v2rayNG / NekoBox / Hiddify)<br>
🔄 Clash auto-update link · 🔗 private quota link · ⬇️ branded yaml · 📋 ready-to-send message.</div>
<div class="dim"> Only need a rebranded link (no packs)? → <a href="/rebrand" style="color:#93c5fd">Link Rebranding page</a><br>
Share with clients: <b style="color:#93c5fd">this site's main link</b> (without /tool)<br>
🔒 This /tool page is yours — don't share it.</div>"""
    return render("Seller Tool", body)


def rebrand_page():
    body = f"""<h1>⚡ Link Rebranding</h1>
<div class="sub">paste a provider link → get YOUR branded link back</div>
<form method="post" action="/rebrand">
<label>Your brand name (shown on every node)</label>
<input type="text" name="brand" value="{html.escape(DEFAULT_BRAND)}" maxlength="40">
<label>Provider link(s) — one per line</label>
<textarea name="links" placeholder="https://provider.example/api/sub?token=…&#10;https://provider.example/api/sub?token=…"></textarea>
<input type="submit" value="✨ Rebrand link(s)">
</form>
<div class="steps">You get back a rebranded subscription link:<br>
• works in Shadowrocket / v2rayNG / NekoBox / Hiddify / v2rayN<br>
• every node shows <b>your brand name</b><br>
• same nodes, same details — just your name on it<br><br>
💡 Need the full client pack (quota link + auto-update + yaml + message)? Use the <a href="/tool" style="color:#93c5fd">Seller Tool (/tool)</a>.</div>
<div class="dim">🔒 This page is for the seller — don't share it.</div>"""
    return render("Link Rebranding", body)


def rebrand_results(brand, rows, host):
    parts = [f"""<h1>⚡ Rebranded as {html.escape(brand)}</h1>
<div class="sub">{len(rows)} link(s) · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</div>"""]
    for i, r in enumerate(rows):
        n = i + 1
        if r.get("error"):
            parts.append(f"""<div class="row"><h2>Link {n}</h2>
<div class="err">❌ {html.escape(r["error"])}</div></div>""")
            continue
        s = r["summary"]
        share = f"https://{host}/share/{r['enc']}?brand={urllib.parse.quote(brand)}"
        share_sr = f"https://{host}/share/{r['enc']}/sr?brand={urllib.parse.quote(brand)}"
        dl = f"/share/{r['enc']}?brand={urllib.parse.quote(brand)}&file=1"
        if s:
            stat = f"<div class='dim' style='text-align:center'>{s['left']:,.2f} GB left · expires {html.escape(s['exp'])}</div>"
        else:
            stat = f"<div class='dim' style='text-align:center'>{len(r['links_all'])} nodes</div>"
        parts.append(f"""<div class="row"><h2>Link {n}</h2>
{stat}
<a class="btn green" href="{dl}">⬇️ Download rebranded subscription (.txt)</a>
<div class="me"><div class="t">✨ Rebranded link — use this in any app (Shadowrocket / v2rayNG / NekoBox / Hiddify):</div>
<div class="u" id="sp{n}">{html.escape(share)}</div></div>
<div class="me"><div class="t">📱 Shadowrocket (classic base64):</div>
<div class="u" id="ssr{n}">{html.escape(share_sr)}</div></div>
<div style="display:flex;gap:8px">
<button class="btn gray" style="flex:1;margin-top:8px" onclick="cp('sp{n}','cosp{n}')">📋 Copy link</button>
<button class="btn gray" style="flex:1;margin-top:8px" onclick="cp('ssr{n}','cossr{n}')">📋 Copy SR</button>
</div>
<div class="ok" id="cosp{n}" style="display:none">✅ copied</div>
<div class="ok" id="cossr{n}" style="display:none">✅ copied</div></div>""")
    parts.append("""<script>function cp(id,ok){var t=document.getElementById(id).textContent.trim();
function d(){document.getElementById(ok).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}
else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}</script>""")
    parts.append('<div class="dim">Send this rebranded link to your client — nodes appear under your brand, details unchanged, updates live.</div>')
    return render(f"Rebranded as {brand}", "".join(parts))


def client_page():
    body = """<h1>⚡ Your VPN — check your data</h1>
<div class="sub">paste your subscription link · 10 seconds</div>
<form method="post" action="/">
<label>Your subscription link (the one you use in Shadowrocket)</label>
<textarea name="link" placeholder="Paste your subscription link here"></textarea>
<input type="submit" value=" Show my quota">
</form>
<div class="steps">1️⃣ Paste the link your seller gave you<br>
2️⃣ Tap <b>Show my quota</b><br>
3️⃣ You'll get <b>your own personal link</b> — save it. Next time you just tap it.<br><br>
⬇️ The page also gives you your VPN links for every app + config file.</div>
<div class="dim">🔒 Your subscription link is only used to fetch your quota — your personal link contains no readable details from it.</div>"""
    return render("Check your data", body)


def client_page_body(enc, status, proxies, nodes_total, links, host, brand):
    qs = f"?brand={urllib.parse.quote(brand)}"
    full_url = f"https://{host}/q/{enc}{qs}"
    sub_url = f"https://{host}/sub/{enc}{qs}"
    share_url = f"https://{host}/share/{enc}{qs}"
    share_sr_url = f"https://{host}/share/{enc}/sr{qs}"
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
    body = f"""<h1>⚡ {html.escape(brand)} — your data</h1>
<div class="sub">updated {time.strftime('%H:%M UTC', time.gmtime())} · auto-refreshes every 60s</div>
{quota}
<div class="dim" style="text-align:center;margin-top:10px">{len(proxies)} of {nodes_total} nodes ready in config</div>
<div class="me"><div class="t">🔗 YOUR personal link — save it (this is the one you tap from now on):</div>
<div class="u" id="pl">{html.escape(full_url)}</div></div>
<button class="btn gray" style="margin-top:8px" onclick="cp('pl','cop1')">📋 Copy my personal link</button>
<div class="ok" id="cop1" style="display:none">✅ copied — save it in Notes or bookmarks</div>
<div class="me" style="margin-top:14px"><div class="t">✨ VPN in your app (Shadowrocket / v2rayNG / NekoBox / Hiddify): add this subscription link — nodes appear as <b>{html.escape(brand)}</b>:</div>
<div class="u" id="sp">{html.escape(share_url)}</div></div>
<button class="btn green" style="margin-top:8px" onclick="cp('sp','cosp')">📋 Copy VPN link (all apps)</button>
<div class="ok" id="cosp" style="display:none">✅ copied</div>
<div class="me" style="margin-top:14px"><div class="t">🔄 CLASH auto-update (Verge / Fugu / mihomo): Profiles → New → remote URL → paste this. Nodes &amp; quota update automatically, forever:</div>
<div class="u" id="su">{html.escape(sub_url)}</div></div>
<button class="btn gray" style="margin-top:8px" onclick="cp('su','cop2')">📋 Copy Clash auto-update link</button>
<div class="ok" id="cop2" style="display:none">✅ copied</div>
<a class="btn" href="/dl/{enc}{qs}">⬇️ Get my latest VPN config (YAML file)</a>
<div class="dim" style="margin-top:10px">Shadowrocket (classic): use the base64 variant<br>
<span style="color:#93c5fd">{html.escape(share_sr_url)}</span></div>
<div class="dim">🔒 Your links contain no readable details from your subscription — keep them private anyway.</div>
{COPY_JS}"""
    return render(f"{brand} — your data", body, refresh=True)


def error_page(msg):
    body = f"""<h1>⚡ VPN</h1>
<div class="err">{msg}</div>
<a class="btn" href="/">← Paste a link</a>
<div class="dim">If your plan was renewed, use the NEW link your seller gave you.</div>"""
    return render("Error", body)


def results_page(brand, rows, host):
    slug = slugify(brand)
    parts = [f"""<h1>⚡ {html.escape(brand)} — client packs</h1>
<div class="sub">{len(rows)} link(s) · generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</div>"""]
    for i, r in enumerate(rows):
        n = i + 1
        if r.get("error"):
            parts.append(f"""<div class="row"><h2>Link {n}</h2>
<div class="err">❌ {html.escape(r["error"])}</div></div>""")
            continue
        s = r["summary"]
        full = f"https://{host}/q/{r['enc']}?brand={urllib.parse.quote(brand)}"
        sub = f"https://{host}/sub/{r['enc']}?brand={urllib.parse.quote(brand)}"
        share = f"https://{host}/share/{r['enc']}?brand={urllib.parse.quote(brand)}"
        share_sr = f"https://{host}/share/{r['enc']}/sr?brand={urllib.parse.quote(brand)}"
        dl = f"/dl/{r['enc']}?brand={urllib.parse.quote(brand)}"
        if s:
            stat = f"<div class='big' style='font-size:30px'>{s['left']:,.2f} <span>GB left</span></div><div class='dim' style='text-align:center'>expires {html.escape(s['exp'])}</div>"
        else:
            stat = f"<div class='dim' style='text-align:center'>no quota text · {len(r['proxies'])} vless nodes</div>"
        no_yaml = r.get("no_yaml")
        if no_yaml:
            stat += "<div class='err' style='font-size:13px'>⚠️ No VLESS nodes — the rebranded share link (below) still works in all apps, but the YAML file needs VLESS nodes.</div>"
        dl_btn = "" if no_yaml else f'<a class="btn green" href="{dl}">⬇️ Download {html.escape(slug)}.yaml</a>'
        msg = (f"Hi! Here's your {brand} setup 🚀\n\n"
               f"1) VPN — add this subscription link in your app (Shadowrocket / v2rayNG / NekoBox / Hiddify):\n{share}\n"
               f"   Clash (Verge/Fugu/mihomo) users — use this instead, it auto-updates:\n{sub}\n"
               f"   (If your app needs a file: import the attached {slug}.yaml)\n\n"
               f"2) Check your data anytime (live): {full}\n\n"
               f"If your plan renews: open {full} and paste your new subscription link.")
        parts.append(f"""<div class="row"><h2>Link {n} — {len(r['proxies'])} nodes</h2>
{stat}
{dl_btn}
<div class="me"><div class="t">✨ Rebranded share link (all apps):</div><div class="u" id="sp{n}">{html.escape(share)}</div></div>
<div class="me"><div class="t">📱 Shadowrocket (classic base64):</div><div class="u" id="ssr{n}">{html.escape(share_sr)}</div></div>
<div class="me"><div class="t">🔄 Clash auto-update link:</div><div class="u" id="su{n}">{html.escape(sub)}</div></div>
<div class="me"><div class="t">🔗 Client's private quota link:</div><div class="u" id="pl{n}">{html.escape(full)}</div></div>
<div style="display:flex;gap:8px">
<button class="btn gray" style="flex:1;margin-top:8px" onclick="cp('sp{n}','cosp{n}')">📋 Share</button>
<button class="btn gray" style="flex:1;margin-top:8px" onclick="cp('su{n}','cosp2{n}')">📋 Clash</button>
</div>
<div class="ok" id="cosp{n}" style="display:none">✅ share link copied</div>
<div class="ok" id="cosp2{n}" style="display:none">✅ clash link copied</div>
<button class="btn" onclick="cm('m{n}','copm{n}')">📋 Copy ready-to-send message</button>
<div class="msg" id="m{n}" style="display:none">{html.escape(msg)}</div>
<div class="ok" id="copm{n}" style="display:none">✅ message copied — send it with the yaml file</div></div>""")
    js = ("<script>function cp(id,ok){var t=document.getElementById(id).textContent.trim();"
          "function d(){document.getElementById(ok).style.display='block'}"
          "if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}"
          "else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}"
          "function cm(k,ok){var el=document.getElementById(k);el.style.display='block';var t=el.textContent;"
          "function d(){document.getElementById(ok).style.display='block'}"
          "if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}"
          "else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}</script>")
    parts.append(js)
    parts.append('<div class="dim">⬇️ attach the yaml + send the copied message. All links keep working and auto-refresh forever.</div>')
    return render(f"{brand} — client packs", "".join(parts))


# ---------- HTTP ----------

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

    def _brand(self, parts):
        qs = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
        return clean_brand(qs.get("brand", [""])[0])

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return urllib.parse.parse_qs(self.rfile.read(length).decode())

    def _yaml_response(self, enc, brand, as_attachment):
        url = read_token(enc)
        ts, status, links, proxies = get_data(url)
        if not proxies:
            self._send(400, "text/plain; charset=utf-8",
                       "No VLESS nodes found in that link - cannot build a YAML config.".encode())
            return
        body = build_yaml(status, proxies, brand)
        extra = {"Content-Disposition": f'attachment; filename="{slugify(brand)}.yaml"'} if as_attachment else None
        self._send(200, "text/yaml; charset=utf-8", body, extra)

    def _share_response(self, enc, brand, as_base64, download=False):
        url = read_token(enc)
        ts, status, links, proxies = get_data(url)
        if not links:
            self._send(400, "text/plain; charset=utf-8",
                       "No nodes found in that link.".encode())
            return
        text = build_share(status, links, brand)
        if as_base64:
            body = base64.b64encode(text.encode()).decode().encode()
        else:
            body = text.encode()
        extra = None
        if download:
            fn = "sblaze-vpn" + (".b64" if as_base64 else ".txt")
            extra = {"Content-Disposition": f'attachment; filename="{fn}"'}
        self._send(200, "text/plain; charset=utf-8", body, extra)

    def do_GET(self):
        parts = self.path.split("?")
        path = parts[0]
        try:
            if path == "/healthz":
                self._send(200, "text/plain", b"ok")
            elif path == "/tool":
                self._send(200, "text/html; charset=utf-8", seller_page().encode())
            elif path == "/":
                self._send(200, "text/html; charset=utf-8", client_page().encode())
            elif path == "/rebrand":
                self._send(200, "text/html; charset=utf-8", rebrand_page().encode())
            elif path.startswith("/dl/"):
                self._yaml_response(path[4:], self._brand(parts), True)
            elif path.startswith("/sub/"):
                self._yaml_response(path[5:], self._brand(parts), False)
            elif path.startswith("/share/") and path.endswith("/sr"):
                qs = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
                self._share_response(path[7:-3], self._brand(parts), True, qs.get("file", [""])[0] == "1")
            elif path.startswith("/share/"):
                qs = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
                self._share_response(path[7:], self._brand(parts), False, qs.get("file", [""])[0] == "1")
            elif path.startswith("/q/"):
                enc = path[3:]
                brand = self._brand(parts)
                url = read_token(enc)
                ts, status, links, proxies = get_data(url)
                self._send(200, "text/html; charset=utf-8",
                           client_page_body(enc, status, proxies, len(links), links, self._host(), brand).encode())
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(200, "text/html; charset=utf-8",
                       error_page("Couldn't read that link — it may be invalid or expired.<br>(" + html.escape(str(e)) + ")").encode())

    def do_POST(self):
        p = self.path.split("?")[0]
        try:
            data = self._read_body()
            if p == "/tool":
                brand = clean_brand(data.get("brand", [""])[0])
                links_text = data.get("links", [""])[0]
                links = [l.strip() for l in links_text.splitlines()
                         if l.strip().startswith(("http://", "https://"))][:MAX_BATCH]
                if not links:
                    self._send(200, "text/html; charset=utf-8",
                               error_page("No valid links found — each should start with http or https (one per line).").encode())
                    return
                rows = []
                for link in links:
                    enc = make_token(link)
                    try:
                        ts, status, all_links, proxies = get_data(link)
                        if not all_links:
                            rows.append({"enc": enc, "error": "link opened but contained no nodes"})
                        elif not proxies:
                            rows.append({"enc": enc, "status": status, "summary": quota_summary(status), "proxies": [], "no_yaml": True})
                        else:
                            rows.append({"enc": enc, "status": status, "summary": quota_summary(status), "proxies": proxies})
                    except Exception as e:
                        rows.append({"enc": enc, "error": f"could not read link ({e})"})
                self._send(200, "text/html; charset=utf-8",
                           results_page(brand, rows, self._host()).encode())
            elif p == "/rebrand":
                brand = clean_brand(data.get("brand", [""])[0])
                links_text = data.get("links", [""])[0]
                links = [l.strip() for l in links_text.splitlines()
                         if l.strip().startswith(("http://", "https://"))][:MAX_BATCH]
                if not links:
                    self._send(200, "text/html; charset=utf-8",
                               error_page("No valid links found — each should start with http or https (one per line).").encode())
                    return
                rows = []
                for link in links:
                    enc = make_token(link)
                    try:
                        ts, status, all_links, proxies = get_data(link)
                        if not all_links:
                            rows.append({"enc": enc, "error": "link opened but contained no nodes"})
                        else:
                            rows.append({"enc": enc, "status": status, "summary": quota_summary(status),
                                         "proxies": proxies, "links_all": all_links})
                    except Exception as e:
                        rows.append({"enc": enc, "error": f"could not read link ({e})"})
                self._send(200, "text/html; charset=utf-8",
                           rebrand_results(brand, rows, self._host()).encode())
            elif p == "/":
                link = (data.get("link", [""])[0]).strip()
                if not link:
                    self._send(200, "text/html; charset=utf-8", client_page().encode())
                    return
                if not re.match(r"^https?://", link):
                    self._send(200, "text/html; charset=utf-8",
                               error_page("That doesn't look like a link — it should start with http or https.").encode())
                    return
                get_data(link)  # validate now so bad links error out here
                self.send_response(302)
                self.send_header("Location", f"/q/{make_token(link)}")
                self.end_headers()
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(200, "text/html; charset=utf-8",
                       error_page("Couldn't read that link — it may be invalid or expired.<br>(" + html.escape(str(e)) + ")").encode())

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8899"))
    mode = "encrypted tokens" if KEY else "FALLBACK base64 (set APX_KEY!)"
    print(f"Apex VPN site on :{port} [{mode}]")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
