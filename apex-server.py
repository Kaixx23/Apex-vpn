#!/usr/bin/env python3
"""SP VPN — client link hub (rebranding, quota, auto-update).

Routes:
  /                        → CLIENT page (paste link, POST) — share this
  /tool                    → SELLER tool (full client packs, don't share)
  /rebrand                 → REBRANDING page (paste link → your branded link)
  /q/<token>?brand=        → client's personal live quota page
  /all/<brand>?t=<token>   → ONE LINK: auto-detects the app (User-Agent) and
                             serves mihomo YAML for Clash-type apps, base64
                             SR-format subscription for everything else
  /sub/<token>?brand=      → plain mihomo YAML (Clash auto-update profile)
  /share/<token>?brand=    → rebranded subscription, PLAIN list (all apps)
  /share/<token>/sr?brand= → rebranded subscription, BASE64 (classic Shadowrocket)
  /sr/<brand>?t=<token>    → clean Shadowrocket link (name = last path segment)
  /healthz                 → ok (keep-alive ping)

Security: tokens are AES-256-GCM encrypted (apx.*) when APX_KEY env is set,
otherwise legacy base64 fallback.
"""
import base64
import html
import os
import re
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CACHE_TTL = 300
MAX_BATCH = 20
DEFAULT_BRAND = "SP VPN"
_cache = {}

_env_key = os.environ.get("APX_KEY", "").strip()
KEY = bytes.fromhex(_env_key) if len(_env_key) == 64 else None

# ---------- name translation (Chinese provider names → English) ----------
INFO_PREFIX = [
    ("距离下次重置剩余", "Reset in"),
    ("剩余流量", "Remaining"),
    ("套餐到期", "Expires"),
    ("到期时间", "Expires"),
    ("流量到期", "Expires"),
    ("剩余流量：", "Remaining: "),
    ("剩余", "Remaining"),
    ("到期", "Expires"),
]
COUNTRY = {
    "日本": "Japan", "新加坡": "Singapore", "香港": "Hong Kong", "台湾": "Taiwan",
    "韩国": "Korea", "美国": "USA", "英国": "UK", "德国": "Germany", "法国": "France",
    "加拿大": "Canada", "澳大利亚": "Australia", "中国": "China", "泰国": "Thailand",
    "越南": "Vietnam", "印度": "India", "俄罗斯": "Russia", "荷兰": "Netherlands",
    "瑞典": "Sweden", "芬兰": "Finland", "挪威": "Norway", "意大利": "Italy",
    "西班牙": "Spain", "瑞士": "Switzerland", "奥地利": "Austria", "葡萄牙": "Portugal",
    "迪拜": "Dubai", "土耳其": "Turkey", "巴西": "Brazil", "墨西哥": "Mexico",
}
CARRIER = {
    "移联": "Mobile", "移动": "Mobile", "联通": "Unicom", "电信": "Telecom",
    "家宽": "Home", "机房": "IDC", "广电": "Cable", "教育网": "Edu", "三线": "Tri-line",
    "原生": "Native",
}


def translate_name(name: str) -> str:
    n = name
    for zh, en in INFO_PREFIX:
        if n.startswith(zh):
            rest = n[len(zh):].lstrip("：: ").strip()
            n = en + " " + rest
            break
    for zh, en in COUNTRY.items():
        n = n.replace(zh, en)
    for zh, en in CARRIER.items():
        n = n.replace(zh, en)
    n = n.replace("天", " days").replace("小时", " hours").replace("分钟", " min")
    return re.sub(r"\s{2,}", " ", n).strip()


# ---------- tokens ----------

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


NODE_SCHEMES = ("vless://", "vmess://", "ss://", "trojan://", "hysteria2://",
                "hy2://", "tuic://", "ssd://", "socks5://")


def _is_node_link(line: str) -> bool:
    return line.lower().startswith(NODE_SCHEMES)


# ---------- subscription fetch ----------

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
    """Translate a node link's display name to English (no brand prefix —
    the brand is carried by the subscription's REMARK instead).
    Works for any scheme:// link (vless/vmess/ss/trojan/hysteria2/…)."""
    if "#" in link:
        base, fragment = link.split("#", 1)
        old = urllib.parse.unquote(fragment)
        new = translate_name(old) or brand
    else:
        base = link
        new = brand
    return base + "#" + urllib.parse.quote(new, safe="")


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
    if url.startswith("direct:"):
        # a node link (vless://vmess://…) pasted directly — nothing to fetch
        blob = url[7:]
        links = [l.strip() for l in blob.splitlines() if l.strip()]
        status = ""
        proxies = [parse_vless(l) for l in links if l.startswith("vless://")]
        entry = (time.time(), status, links, proxies)
        _cache[url] = entry
        return entry
    hit = _cache.get(url)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit
    status, links = fetch_subscription(url)
    proxies = [parse_vless(l) for l in links if l.startswith("vless://")]
    entry = (time.time(), status, links, proxies)
    _cache[url] = entry
    return entry


def build_yaml(status, proxies, brand):
    branded = [{**p, "name": (translate_name(p["name"]) or f"{brand} {i+1}")} for i, p in enumerate(proxies)]
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
    out = []
    if status:
        out.append(status)
    out.append("[General]")
    out.append(f"REMARK={brand}")
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
<style>
:root{--bg:#0b1220;--card:#141d31;--card2:#0e1626;--line:rgba(148,163,184,.14);--text:#e8eef8;--dim:#8ea0ba;--green:#34d399;--blue:#60a5fa}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:radial-gradient(1100px 500px at 50% -120px,rgba(37,99,235,.28),transparent),var(--bg);
color:var(--text);display:flex;justify-content:center;align-items:flex-start;padding:28px 16px;min-height:100vh}
.card{background:linear-gradient(180deg,#17233c,#121a2c);border:1px solid var(--line);
border-radius:22px;padding:26px;max-width:460px;width:100%;box-shadow:0 24px 60px rgba(0,0,0,.55)}
h1{font-size:22px;margin:0 0 4px;font-weight:800;letter-spacing:.2px;text-align:center}
h2{font-size:16px;margin:0 0 8px}
.sub{color:var(--dim);font-size:13px;text-align:center;margin:4px 0 18px;line-height:1.5}
.big{font-size:46px;font-weight:800;text-align:center;margin:16px 0 2px;
background:linear-gradient(90deg,#34d399,#60a5fa);-webkit-background-clip:text;background-clip:text;color:transparent}
.big span{font-size:17px;font-weight:600;color:var(--dim);-webkit-text-fill-color:var(--dim)}
.bar{height:14px;background:#0c1424;border:1px solid var(--line);border-radius:10px;overflow:hidden;margin:16px 0 18px}
.fill{height:100%;background:linear-gradient(90deg,#34d399,#60a5fa);border-radius:10px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid div{background:var(--card2);border:1px solid var(--line);border-radius:13px;padding:12px 13px}
.grid b{display:block;font-size:16px;font-weight:700}
.grid span{font-size:12px;color:var(--dim)}
.exp{margin-top:14px;color:#fbbf24;font-size:14px;text-align:center;font-weight:700}
.btn{display:block;margin-top:10px;background:linear-gradient(90deg,#2563eb,#4f46e5);color:#fff;
text-decoration:none;border:0;cursor:pointer;padding:14px;border-radius:13px;font-size:15px;
text-align:center;font-weight:700;width:100%;box-shadow:0 8px 20px rgba(37,99,235,.25)}
.btn.gray{background:#1b2740;border:1px solid var(--line);color:var(--text);box-shadow:none}
.btn.green{background:linear-gradient(90deg,#059669,#10b981);box-shadow:0 8px 20px rgba(16,185,129,.22)}
label{display:block;font-size:14px;margin:14px 0 7px;color:#c4d0e2;font-weight:600}
input[type=text],textarea{width:100%;background:var(--card2);border:1px solid var(--line);
color:var(--text);border-radius:13px;padding:13px;font-size:15px;outline:none}
input[type=text]:focus,textarea:focus{border-color:rgba(96,165,250,.5)}
textarea{height:112px;resize:vertical}
input[type=submit]{width:100%;margin-top:16px;background:linear-gradient(90deg,#059669,#10b981);
color:#fff;font-weight:800;border:0;padding:15px;border-radius:13px;font-size:16px;cursor:pointer}
.me{background:var(--card2);border:1px solid var(--line);border-radius:13px;padding:12px 13px;margin-top:10px}
.me .t{font-size:13px;color:var(--dim);margin-bottom:7px;line-height:1.55}
.me .u{font-size:13px;word-break:break-all;color:var(--blue);line-height:1.5}
.err{color:#f87171;font-size:15px;text-align:center;line-height:1.6;margin:10px 0}
.dim{color:var(--dim);font-size:12px;margin-top:14px;text-align:center;line-height:1.6}
.ok{color:var(--green);font-size:13px;text-align:center;margin-top:8px;font-weight:600}
.row{border-top:1px solid var(--line);margin-top:20px;padding-top:16px}
.msg{font-size:13px;color:#cdd8e8;background:var(--card2);border:1px solid var(--line);
border-radius:13px;padding:13px;line-height:1.65;white-space:pre-wrap}
.steps{margin-top:18px;font-size:14px;line-height:1.85;color:#c4d0e2}
.note{margin-top:12px;background:rgba(96,165,250,.08);border:1px solid rgba(96,165,250,.25);
border-radius:13px;padding:12px 13px;font-size:13px;color:#bfdbfe;line-height:1.6}
</style></head><body><div class="card">__BODY__</div></body></html>"""


def render(title, body, refresh=False):
    ref = '<meta http-equiv="refresh" content="60">' if refresh else ""
    return PAGE_BASE.replace("__REFRESH__", ref).replace("__TITLE__", title).replace("__BODY__", body)


COPY_JS = """<script>function cp(id,ok){var t=document.getElementById(id).textContent.trim();
function d(){document.getElementById(ok).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}
else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}
function cpText(txt,ok){function d(){document.getElementById(ok).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(txt).then(d)}
else{var x=document.createElement('textarea');x.value=txt;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}</script>"""


def seller_page():
    body = f"""<h1>⚡ {html.escape(DEFAULT_BRAND)} — Seller Tool</h1>
<div class="sub">full client packs — links for every app, quota, auto-update &amp; message</div>
<form method="post" action="/tool">
<label>Brand name (shown on every node &amp; link)</label>
<input type="text" name="brand" value="{html.escape(DEFAULT_BRAND)}" maxlength="40">
<label>Provider link(s) — one per line (up to 20)</label>
<textarea name="links" placeholder="https://provider.example/api/sub?token=…"></textarea>
<input type="submit" value="⚡ Generate client packs">
</form>
<div class="steps">Each client gets: ✨ ONE link for all apps (auto-detects their app) ·
🔗 live quota link · 📋 ready-to-send message</div>
<div class="dim">Only need a quick rebrand? → <a href="/rebrand" style="color:var(--blue)">Link Rebranding page</a><br>
Share with clients: <b style="color:var(--blue)">this site's main link</b> (without /tool)<br>
🔒 This /tool page is yours — don't share it.</div>"""
    return render(f"{DEFAULT_BRAND} — Seller Tool", body)


def rebrand_page():
    body = f"""<h1>⚡ Link Rebranding</h1>
<div class="sub">paste a provider link → get back YOUR branded link</div>
<form method="post" action="/rebrand">
<label>Brand name (shown on every node)</label>
<input type="text" name="brand" value="{html.escape(DEFAULT_BRAND)}" maxlength="40">
<label>Provider link(s) — one per line</label>
<textarea name="links" placeholder="https://provider.example/api/sub?token=…"></textarea>
<input type="submit" value="✨ Rebrand link(s)">
</form>
<div class="steps">You get back a rebranded subscription — named <b>{html.escape(DEFAULT_BRAND)}</b> (remark),
nodes show clean English names: <b>🇯🇵Japan•Mobile01</b>, <b>🇸🇬Singapore•Telecom01</b>, …<br><br>
💡 Need full client packs (quota + auto-update + message)? → <a href="/tool" style="color:var(--blue)">Seller Tool</a></div>
<div class="dim">🔒 Seller page — don't share.</div>"""
    return render(f"{DEFAULT_BRAND} — Link Rebranding", body)


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
3️⃣ You'll get <b>your own personal link</b> — save it. Next time you just tap it.</div>
<div class="dim">🔒 Your subscription link is only used to fetch your quota — your personal link contains no readable details from it.</div>"""
    return render("Check your data", body)


def client_page_body(enc, status, proxies, nodes_total, host, brand):
    qs = f"?brand={urllib.parse.quote(brand)}"
    full_url = f"https://{host}/q/{enc}{qs}"
    sub_url = f"https://{host}/sub/{enc}{qs}"
    share_url = f"https://{host}/share/{enc}{qs}"
    sr_url = f"https://{host}/sr/{urllib.parse.quote(brand)}?t={enc}"
    all_url = f"https://{host}/all/{urllib.parse.quote(brand)}?t={enc}"
    s = quota_summary(status)
    if s:
        pct = min(100.0, (s["tot"] - s["left"]) / s["tot"] * 100) if s["tot"] else 0
        quota = f"""<div class="big">{s['left']:,.2f} <span>GB left</span></div>
<div class="bar"><div class="fill" style="width:{pct:.1f}%"></div></div>
<div class="grid">
  <div><b>{s['tot']:,.0f} GB</b><span>total plan</span></div>
  <div><b>{s['up'] + s['down']:,.2f} GB</b><span>used</span></div>
  <div><b>↑ {s['up']:,.2f} GB</b><span>uploaded</span></div>
  <div><b>↓ {s['down']:,.2f} GB</b><span>downloaded</span></div>
</div>
<div class="exp">💡 Expires: {html.escape(s['exp'])}</div>"""
    else:
        quota = f'<div class="err">Quota text not recognized.<br>{html.escape(status) or "No status from provider."}</div>'
    body = f"""<h1>⚡ {html.escape(brand)}</h1>
<div class="sub">your live data · updates every 60s</div>
{quota}
<div class="dim" style="text-align:center;margin-top:12px">{len(proxies)} of {nodes_total} nodes ready</div>
<div class="me"><div class="t">🔗 <b>YOUR personal link</b> — save it, this is what you tap from now on:</div>
<div class="u" id="pl">{html.escape(full_url)}</div></div>
<button class="btn gray" style="margin-top:8px" onclick="cp('pl','cop1')">📋 Copy my personal link</button>
<div class="ok" id="cop1" style="display:none">✅ copied — save in Notes or bookmarks</div>
<div class="me" style="margin-top:14px"><div class="t">✨ <b>ONE VPN LINK — works in all apps</b> (Shadowrocket, v2rayNG, NekoBox, Hiddify, Clash — auto-detects your app, named <b>{html.escape(brand)}</b>, clean English node names):</div>
<div class="u" id="al">{html.escape(all_url)}</div></div>
<button class="btn green" style="margin-top:8px" onclick="cp('al','copa')">📋 Copy my VPN link (all apps)</button>
<div class="ok" id="copa" style="display:none">✅ copied — add it in your VPN app, done</div>
<div class="me" style="margin-top:14px"><div class="t">If your app can't auto-detect, use the one for it:<br>
📱 Shadowrocket: <span style="color:var(--blue)">{html.escape(sr_url)}</span><br>
🔄 Clash (Verge/Fugu/mihomo): <span style="color:var(--blue)">{html.escape(sub_url)}</span><br>
📡 v2rayN / NekoBox / Hiddify: <span style="color:var(--blue)">{html.escape(share_url)}</span></div></div>
<div class="dim">🔒 Your links contain no readable details from your subscription — keep them private.</div>
{COPY_JS}"""
    return render(f"{brand} — your data", body, refresh=True)


def error_page(msg):
    body = f"""<h1>⚡ VPN</h1>
<div class="err">{msg}</div>
<a class="btn" href="/">← Paste a link</a>
<div class="dim">If your plan was renewed, use the NEW link your seller gave you.</div>"""
    return render("Error", body)


def results_page(brand, rows, host):
    parts = [f"""<h1>⚡ {html.escape(brand)} — client packs</h1>
<div class="sub">{len(rows)} link(s) · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</div>"""]
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
        sr = f"https://{host}/sr/{urllib.parse.quote(brand)}?t={r['enc']}"
        allink = f"https://{host}/all/{urllib.parse.quote(brand)}?t={r['enc']}"
        if s:
            stat = f"<div class='big' style='font-size:30px'>{s['left']:,.2f} <span>GB left</span></div><div class='dim' style='text-align:center'>expires {html.escape(s['exp'])}</div>"
        else:
            stat = f"<div class='dim' style='text-align:center'>{len(r['links_all'])} nodes</div>"
        msg = (f"Here's your {brand} setup 🚀\n\n"
               f"1) VPN — add this ONE link in your app (works in Shadowrocket, v2rayNG, NekoBox, Hiddify & Clash, it auto-detects your app and arrives named \"{brand}\"):\n{allink}\n\n"
               f"   If your app can't auto-detect — Shadowrocket: {sr}\n"
               f"   Clash (Verge/Fugu): {sub}\n\n"
               f"2) Check your data anytime (live):\n{full}\n\n"
               f"If your plan renews: open {full} and paste your new subscription link.")
        parts.append(f"""<div class="row"><h2>Link {n} — {len(r['proxies'])} nodes</h2>
{stat}
<div class="me"><div class="t">✨ <b>ONE LINK — all apps</b> (auto-detects Shadowrocket / v2rayNG / NekoBox / Hiddify / Clash):</div><div class="u" id="al{n}">{html.escape(allink)}</div></div>
<button class="btn green" style="margin-top:8px" onclick="cp('al{n}','copa{n}')">📋 Copy the one link</button>
<div class="ok" id="copa{n}" style="display:none">✅ copied — that's the VPN link for your client</div>
<div class="me" style="margin-top:14px"><div class="t">Fallback app-specific links:<br>
📱 Shadowrocket: <span style="color:var(--blue)">{html.escape(sr)}</span><br>
🔄 Clash: <span style="color:var(--blue)">{html.escape(sub)}</span><br>
📡 v2rayN/NekoBox/Hiddify: <span style="color:var(--blue)">{html.escape(share)}</span></div></div>
<div class="me"><div class="t">🔗 <b>Client's private quota</b> link:</div><div class="u" id="pl{n}">{html.escape(full)}</div></div>
<button class="btn" onclick="cm('m{n}','copm{n}')">📋 Copy ready-to-send message</button>
<div class="msg" id="m{n}" style="display:none">{html.escape(msg)}</div>
<div class="ok" id="copm{n}" style="display:none">✅ message copied — send it to your client</div></div>""")
    parts.append("""<script>function cm(k,ok){var el=document.getElementById(k);el.style.display='block';var t=el.textContent;
function d(){document.getElementById(ok).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}
else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}</script>""")
    parts.append('<div class="dim">All links keep working and auto-refresh forever. Send the message to your client.</div>')
    return render(f"{brand} — client packs", "".join(parts))


def rebrand_results(brand, rows, host):
    parts = [f"""<h1>⚡ Rebranded as {html.escape(brand)}</h1>
<div class="sub">{len(rows)} link(s) · English node names · {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</div>"""]
    for i, r in enumerate(rows):
        n = i + 1
        if r.get("error"):
            parts.append(f"""<div class="row"><h2>Link {n}</h2>
<div class="err">❌ {html.escape(r["error"])}</div></div>""")
            continue
        s = r["summary"]
        share = f"https://{host}/share/{r['enc']}?brand={urllib.parse.quote(brand)}"
        sr = f"https://{host}/sr/{urllib.parse.quote(brand)}?t={r['enc']}"
        allink = f"https://{host}/all/{urllib.parse.quote(brand)}?t={r['enc']}"
        dl = f"/share/{r['enc']}?brand={urllib.parse.quote(brand)}&file=1"
        if s:
            stat = f"<div class='dim' style='text-align:center;font-size:14px'>🚀 {s['left']:,.2f} GB left · expires {html.escape(s['exp'])}</div>"
        else:
            stat = f"<div class='dim' style='text-align:center'>{len(r['links_all'])} nodes</div>"
        parts.append(f"""<div class="row"><h2>Link {n}</h2>
{stat}
<div class="me"><div class="t">✨ <b>ONE LINK — works in all apps</b> (Shadowrocket, v2rayNG, NekoBox, Hiddify, Clash — it auto-detects the app and serves the right format, named <b>{html.escape(brand)}</b>):</div>
<div class="u" id="al{n}">{html.escape(allink)}</div></div>
<button class="btn green" style="margin-top:8px" onclick="cp('al{n}','copa{n}')">📋 Copy the one link (send this to your client)</button>
<div class="ok" id="copa{n}" style="display:none">✅ copied — that's all your client needs for the VPN</div>
<div class="me" style="margin-top:14px"><div class="t">Fallback app-specific links (only if a client's app can't auto-detect):<br>
📱 Shadowrocket: <span style="color:var(--blue)">{html.escape(sr)}</span><br>
🔄 Clash: <span style="color:var(--blue)">{html.escape(f"https://{host}/sub/{r['enc']}?brand={urllib.parse.quote(brand)}")}</span><br>
 Plain list (v2rayN/NekoBox/Hiddify): <span style="color:var(--blue)">{html.escape(share)}</span></div></div>
<a class="btn gray" href="{dl}">⬇️ Download rebranded subscription (.txt) — offline backup</a>
<div class="note">📱 The one link arrives in Shadowrocket already named <b>{html.escape(brand)}</b> — clients add it, nothing to rename. The .txt is the offline backup (paste into Shadowrocket → same name).</div></div>""")
    parts.append("""<script>function cp(id,ok){var t=document.getElementById(id).textContent.trim();
function d(){document.getElementById(ok).style.display='block'}
if(navigator.clipboard){navigator.clipboard.writeText(t).then(d)}
else{var x=document.createElement('textarea');x.value=t;document.body.appendChild(x);x.select();document.execCommand('copy');x.remove();d()}}</script>""")
    parts.append('<div class="dim">Send this link to your client — the subscription is named under your brand, nodes show clean English names, details unchanged, updates live.</div>')
    return render(f"Rebranded as {brand}", "".join(parts))


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

    def _yaml_response(self, enc, brand):
        url = read_token(enc)
        ts, status, links, proxies = get_data(url)
        if not proxies:
            self._send(400, "text/plain; charset=utf-8",
                       "No VLESS nodes found in that link.".encode())
            return
        self._send(200, "text/yaml; charset=utf-8", build_yaml(status, proxies, brand))

    def _share_response(self, enc, brand, as_base64, download=False):
        url = read_token(enc)
        ts, status, links, proxies = get_data(url)
        if not links:
            self._send(400, "text/plain; charset=utf-8",
                       "No nodes found in that link.".encode())
            return
        text = build_share(status, links, brand)
        body = base64.b64encode(text.encode()).decode().encode() if as_base64 else text.encode()
        extra = None
        if download:
            fn = slugify(brand) + (".b64" if as_base64 else ".txt")
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
            elif path == "/rebrand":
                self._send(200, "text/html; charset=utf-8", rebrand_page().encode())
            elif path == "/":
                self._send(200, "text/html; charset=utf-8", client_page().encode())
            elif path.startswith("/sub/"):
                self._yaml_response(path[5:], self._brand(parts))
            elif path.startswith("/share/") and path.endswith("/sr"):
                qs = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
                self._share_response(path[7:-3], self._brand(parts), True, qs.get("file", [""])[0] == "1")
            elif path.startswith("/share/"):
                qs = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
                self._share_response(path[7:], self._brand(parts), False, qs.get("file", [""])[0] == "1")
            elif path.startswith("/sr/"):
                # clean Shadowrocket link: /sr/SP%20VPN?t=<token>
                # SR's default name = last path segment → shows as "SP VPN"
                qs = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
                tok = qs.get("t", [""])[0]
                if not tok:
                    self._send(400, "text/plain", b"missing ?t= parameter")
                    return
                seg = urllib.parse.unquote(path[4:])
                brand = clean_brand(qs.get("brand", [""])[0] or seg)
                self._share_response(tok, brand, True)
            elif path.startswith("/all/"):
                # ONE link for ALL apps: auto-detects the requesting app
                # (User-Agent) and serves the right format:
                #   Clash-type  → mihomo YAML
                #   everything else (Shadowrocket, v2rayN/NG, NekoBox,
                #   Hiddify, FoXray…) → base64 SR-format subscription
                qs = urllib.parse.parse_qs(parts[1]) if len(parts) > 1 else {}
                tok = qs.get("t", [""])[0]
                if not tok:
                    self._send(400, "text/plain", b"missing ?t= parameter")
                    return
                seg = urllib.parse.unquote(path[5:])
                brand = clean_brand(qs.get("brand", [""])[0] or seg)
                url = read_token(tok)
                ts, status, links, proxies = get_data(url)
                if not links:
                    self._send(400, "text/plain; charset=utf-8",
                               "No nodes found in that link.".encode())
                    return
                ua = (self.headers.get("User-Agent") or "").lower()
                if any(k in ua for k in ("clash", "mihomo", "fugu", "streisand", "nyanpasu")):
                    if not proxies:
                        self._send(400, "text/plain; charset=utf-8",
                                   "Clash needs VLESS nodes; none found in this link.".encode())
                        return
                    self._send(200, "text/yaml; charset=utf-8", build_yaml(status, proxies, brand))
                else:
                    text = build_share(status, links, brand)
                    self._send(200, "text/plain; charset=utf-8",
                               base64.b64encode(text.encode()).decode().encode())
            elif path.startswith("/q/"):
                enc = path[3:]
                brand = self._brand(parts)
                url = read_token(enc)
                ts, status, links, proxies = get_data(url)
                self._send(200, "text/html; charset=utf-8",
                           client_page_body(enc, status, proxies, len(links), self._host(), brand).encode())
            else:
                self._send(404, "text/plain", b"not found")
        except Exception as e:
            self._send(200, "text/html; charset=utf-8",
                       error_page("Couldn't read that link — it may be invalid or expired.<br>(" + html.escape(str(e)) + ")").encode())

    def _collect_links(self, data):
        links_text = data.get("links", [""])[0]
        out = []
        for l in links_text.splitlines():
            l = l.strip()
            if not l:
                continue
            low = l.lower()
            if low.startswith(("http://", "https://")) or _is_node_link(l):
                out.append(l)
        return out[:MAX_BATCH]

    def _fetch_rows(self, links):
        rows = []
        for link in links:
            key = ("direct:" + link) if _is_node_link(link) else link
            enc = make_token(key)
            try:
                ts, status, all_links, proxies = get_data(key)
                if not all_links:
                    rows.append({"enc": enc, "error": "link opened but contained no nodes"})
                else:
                    rows.append({"enc": enc, "status": status, "summary": quota_summary(status),
                                 "proxies": proxies, "links_all": all_links})
            except Exception as e:
                rows.append({"enc": enc, "error": f"could not read link ({e})"})
        return rows

    def do_POST(self):
        p = self.path.split("?")[0]
        try:
            data = self._read_body()
            if p in ("/tool", "/rebrand"):
                brand = clean_brand(data.get("brand", [""])[0])
                links = self._collect_links(data)
                if not links:
                    self._send(200, "text/html; charset=utf-8",
                               error_page("No valid links found — each should start with http or https (one per line).").encode())
                    return
                rows = self._fetch_rows(links)
                page = results_page if p == "/tool" else rebrand_results
                self._send(200, "text/html; charset=utf-8", page(brand, rows, self._host()).encode())
            elif p == "/":
                link = (data.get("link", [""])[0]).strip()
                if not link:
                    self._send(200, "text/html; charset=utf-8", client_page().encode())
                    return
                if not re.match(r"^https?://", link):
                    self._send(200, "text/html; charset=utf-8",
                               error_page("That doesn't look like a link — it should start with http or https.").encode())
                    return
                get_data(link)
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
    print(f"SP VPN hub on :{port} [{mode}]")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
