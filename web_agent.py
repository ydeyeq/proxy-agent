#!/usr/bin/env python3
"""
Local web UI for checking SOCKS5 proxies against IPQualityScore.

- API key field is ALWAYS visible (eye/eye-slash toggle; prefilled from session or saved .env).
- On submit, the pasted key is saved to per-user .env so it persists across launches.
- Drops ALL proxies for any IP that appears more than once (only unique-IP proxies remain).
- Displays proxies as host:port:login:password (login/password blank if none).
- Verdict colors: 0 -> green ✓, 1–20 -> orange ✓, >20 -> red ✗.
- Copy textarea for proxies with fraud_score ≤ 20.
- Saves CSV + two TXT files to outbox/: *_proxies_eq0.txt and *_proxies_le20.txt.
- Uses a stable per-user data folder (see user_data_root()) so packaging is safe.
- Binds ONLY to 127.0.0.1 (do not expose publicly).
"""

import os
import re
import json
import sqlite3
import threading
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

from flask import Flask, request, redirect, url_for, render_template_string, send_from_directory, session
import requests
import pandas as pd
from dotenv import load_dotenv

# ---------------- Paths & Config ----------------
def user_data_root() -> Path:
    """Cross-platform per-user data directory."""
    if sys.platform == "darwin":  # macOS
        base = Path.home() / "Library" / "Application Support" / "ProxyAgent"
    elif sys.platform.startswith("win"):  # Windows
        base = Path(os.environ.get("APPDATA", str(Path.home()))) / "ProxyAgent"
    else:  # Linux/other
        base = Path.home() / ".local" / "share" / "ProxyAgent"
    base.mkdir(parents=True, exist_ok=True)
    return base

ROOT    = user_data_root()                     # per-user app data root
OUTBOX  = ROOT / "outbox"                      # outputs live here
DB_PATH = ROOT / "ip_cache.sqlite3"            # cache db lives here

IPIFY_URL   = "https://api.ipify.org?format=json"
IPQS_BASE   = "https://ipqualityscore.com/api/json/ip"
BATCH_SIZE  = 50                # parallelism for proxy/IP checks
REQ_TIMEOUT = 15                # seconds per HTTP request
CACHE_MAX_AGE_DAYS = 7          # re-check IPQS after this many days

DB_LOCK = threading.RLock()     # thread-safety for SQLite
# ------------------------------------------------

# Load .env from per-user data folder; GUI key overrides this.
load_dotenv(dotenv_path=ROOT / ".env")
ENV_API_KEY = os.getenv("IPQS_API_KEY", "").strip()

app = Flask(__name__, static_folder=None)
app.secret_key = os.urandom(16)  # for session storage


# ---------- Helpers ----------
def _utcnow():
    return datetime.now(timezone.utc)

def ensure_dirs():
    OUTBOX.mkdir(exist_ok=True)

def db_conn():
    # Single connection used by app; allow cross-thread access; guard with lock.
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    with DB_LOCK:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_cache(
                ip TEXT PRIMARY KEY,
                fraud_score INTEGER,
                raw_json TEXT,
                checked_at TEXT
            )
        """)
    return conn

CONN = None  # global DB connection (initialized at start)

def cache_get(conn, ip):
    with DB_LOCK:
        cur = conn.execute("SELECT fraud_score, raw_json, checked_at FROM ip_cache WHERE ip=?", (ip,))
        row = cur.fetchone()
    if not row:
        return None
    fraud_score, raw_json, checked_at = row
    try:
        when = datetime.fromisoformat(checked_at)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
    except Exception:
        when = datetime(1970, 1, 1, tzinfo=timezone.utc)
    age_days = int((_utcnow() - when).total_seconds() // 86400)
    return {"fraud_score": fraud_score, "raw": json.loads(raw_json) if raw_json else {}, "age_days": age_days}

def cache_put(conn, ip, fraud_score, raw_json):
    with DB_LOCK:
        conn.execute(
            "INSERT OR REPLACE INTO ip_cache(ip, fraud_score, raw_json, checked_at) VALUES(?,?,?,?)",
            (ip, int(fraud_score) if fraud_score is not None else None,
             json.dumps(raw_json)[:20000],
             _utcnow().isoformat())
        )
        conn.commit()

def normalize_proxy(line: str) -> str:
    s = line.strip()
    if not s:
        return ""
    if s.startswith("socks5://"):
        return s
    # Allow plain host:port or user:pass@host:port
    return "socks5://" + s

# Parse "socks5://[user[:pass]@]host:port" OR "host:port" OR "user:pass@host:port"
# Return tuple (host, port, user, password)
def parse_proxy_to_parts(proxy_url: str):
    s = proxy_url.strip()
    if s.startswith("socks5://"):
        s = s[len("socks5://"):]
    # Now s is "[user[:pass]@]host:port" or "host:port"
    user = password = ""
    if "@" in s:
        creds, addr = s.split("@", 1)
        if ":" in creds:
            user, password = creds.split(":", 1)
        else:
            user = creds
        s = addr
    # s should be host:port
    if s.startswith("["):
        # IPv6 like [2001:db8::1]:1080
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
        if not m:
            return ("", "", user, password)
        host, port = m.group(1), m.group(2)
    else:
        if ":" not in s:
            return (s, "", user, password)
        host, port = s.rsplit(":", 1)
    return (host, port, user, password)

def format_proxy_hostport_userpass(proxy_url: str) -> str:
    host, port, user, pwd = parse_proxy_to_parts(proxy_url)
    host = host or ""
    port = port or ""
    user = user or ""
    pwd  = pwd or ""
    return f"{host}:{port}:{user}:{pwd}"

def get_ip_via_proxy(proxy_url: str):
    """Return (ok, ip_or_error)."""
    proxies = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get(IPIFY_URL, proxies=proxies, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            ip = r.json().get("ip")
            if ip:
                return True, ip
            return False, "no ip in response"
        return False, f"status {r.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"error: {e}"

def query_ipqs(api_key: str, ip: str):
    """Return dict with IPQS response."""
    url = f"{IPQS_BASE}/{api_key}/{ip}"
    try:
        r = requests.get(url, params={"strictness": 0}, timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return {"success": False, "message": f"status {r.status_code}", "_body": r.text[:400]}
    except requests.exceptions.RequestException as e:
        return {"success": False, "message": str(e)}

def verdict_icon(fraud_score):
    """Return HTML icon based on fraud_score."""
    if fraud_score is None or fraud_score == "":
        return '<span style="color:#999">?</span>'
    try:
        fs = int(fraud_score)
    except Exception:
        return '<span style="color:#999">?</span>'
    if fs == 0:
        return '<span style="color:#0a8a0a;font-weight:bold;">✓</span>'   # green
    if 1 <= fs <= 20:
        return '<span style="color:#e67e00;font-weight:bold;">✓</span>'   # orange
    return '<span style="color:#c32020;font-weight:bold;">✗</span>'       # red

def save_env_api_key(key: str):
    """Persist API key in per-user data dir so it survives restarts."""
    env_path = ROOT / ".env"
    try:
        env_path.write_text(f"IPQS_API_KEY={key}\n", encoding="utf-8")
    except Exception:
        pass

def clear_saved_api_key():
    try:
        (ROOT / ".env").unlink(missing_ok=True)
    except TypeError:
        p = ROOT / ".env"
        if p.exists():
            p.unlink()


def process_paste_and_build_rows(conn, api_key: str, text: str):
    """
    Accepts raw pasted text (one proxy per line).
    Returns: (rows_list, csv_filename, txt_eq0_filename, txt_le20_filename,
              dropped_dupe_count, kept_count, copy_payload)
    Behavior: if an exit IP appears more than once, DROP ALL proxies for that IP.
              Only proxies whose resolved IP is unique remain.
    """
    raw = [l for l in (s.strip() for s in text.splitlines()) if l]
    proxies = [normalize_proxy(l) for l in raw]
    if not proxies:
        raise ValueError("No proxies provided.")

    # 1) Resolve proxies -> IPs (batched threads)
    proxy_to_result = {}
    with ThreadPoolExecutor(max_workers=BATCH_SIZE) as ex:
        fut = {ex.submit(get_ip_via_proxy, p): p for p in proxies}
        for f in as_completed(fut):
            p = fut[f]
            ok, val = f.result()
            proxy_to_result[p] = (ok, val)

    # 2) Build IP -> proxies map
    ip_to_proxies = defaultdict(list)
    for proxy, (ok, val) in proxy_to_result.items():
        if ok:
            ip_to_proxies[val].append(proxy)

    # 3) Identify unique-IP proxies ONLY
    kept = []  # list of (proxy_url, ip, formatted)
    dropped_dupes = 0
    for ip, plist in ip_to_proxies.items():
        if len(plist) == 1:
            p = plist[0]
            kept.append((p, ip, format_proxy_hostport_userpass(p)))
        else:
            dropped_dupes += len(plist)

    kept_count = len(kept)

    # 4) IPQS lookup ONCE per kept unique IP
    unique_kept_ips = [ip for _, ip, _ in kept]
    ip_to_ipqs = {}
    def lookup_or_cache(ip):
        cached = cache_get(conn, ip)
        if cached and cached["age_days"] < CACHE_MAX_AGE_DAYS:
            data = cached["raw"]
            if "fraud_score" not in data:
                data["fraud_score"] = cached["fraud_score"]
            return ip, data, True
        data = query_ipqs(api_key, ip)
        fraud_score = data.get("fraud_score")
        if fraud_score is not None:
            cache_put(conn, ip, fraud_score, data)
        return ip, data, False

    with ThreadPoolExecutor(max_workers=BATCH_SIZE) as ex:
        fut2 = {ex.submit(lookup_or_cache, ip): ip for ip in unique_kept_ips}
        for f in as_completed(fut2):
            ip, data, _ = f.result()
            ip_to_ipqs[ip] = data

    # 5) Build rows for UI/CSV using ONLY kept unique-IP proxies
    rows = []
    list_le20 = []  # formatted proxies with fraud_score ≤ 20
    list_eq0  = []  # formatted proxies with fraud_score == 0

    for proxy_url, ip, formatted in kept:
        info = ip_to_ipqs.get(ip, {})
        fraud_score = info.get("fraud_score") if isinstance(info, dict) else None
        ok, _ = proxy_to_result.get(proxy_url, (True, ip))
        icon_html = verdict_icon(fraud_score)

        # collect for copy/download lists
        try:
            fs_int = int(fraud_score) if fraud_score is not None and fraud_score != "" else None
        except Exception:
            fs_int = None

        if fs_int is not None and fs_int <= 20:
            list_le20.append(formatted)
        if fs_int == 0:
            list_eq0.append(formatted)

        rows.append({
            "proxy_formatted": formatted,
            "resolved_ip": ip,
            "proxy_ok": "✅" if ok else "❌",
            "ipqs_success": "✅" if not (isinstance(info, dict) and info.get("success") is False) else "❌",
            "fraud_score": fs_int if fs_int is not None else "",
            "verdict_icon": icon_html,
            "ipqs_message": info.get("message") if isinstance(info, dict) else ""
        })

    # 6) Save files
    df = pd.DataFrame(rows, columns=[
        "proxy_formatted","resolved_ip","proxy_ok","ipqs_success","fraud_score","ipqs_message"
    ])
    timestamp = _utcnow().strftime("%Y%m%d_%H%M%S")
    csv_name      = f"{timestamp}_results.csv"
    txt_eq0_name  = f"{timestamp}_proxies_eq0.txt"
    txt_le20_name = f"{timestamp}_proxies_le20.txt"
    df.to_csv(OUTBOX / csv_name, index=False, encoding="utf-8")

    # write lists
    with (OUTBOX / txt_eq0_name).open("w", encoding="utf-8") as f:
        for line in list_eq0:
            f.write(line + "\n")
    with (OUTBOX / txt_le20_name).open("w", encoding="utf-8") as f:
        for line in list_le20:
            f.write(line + "\n")

    # textarea payload for copy
    copy_payload = "\n".join(list_le20)

    return rows, csv_name, txt_eq0_name, txt_le20_name, dropped_dupes, kept_count, copy_payload


# ---------- HTML ----------
INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Proxy Agent (Local)</title>
  <style>
    body { font-family: -apple-system, system-ui, Arial, sans-serif; margin: 32px; }
    input, textarea { width: 100%; max-width: 1100px; box-sizing: border-box; }
    textarea { font-family: monospace; }
    .btn { padding: 8px 14px; border: 1px solid #ccc; border-radius: 6px; background: #f6f6f6; cursor: pointer; }
    .btn:hover { background: #eee; }
    table { border-collapse: collapse; margin-top: 24px; width: 100%; max-width: 1100px; }
    th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; vertical-align: top; }
    th { background: #fafafa; }
    .muted { color: #666; font-size: 0.9em; }
    .files a { text-decoration: none; }
    .note { margin: 10px 0; padding: 8px 12px; background:#f9f9f9; border:1px solid #eee; border-radius:6px; }
    .flex { display:flex; gap:10px; align-items:center; flex-wrap: wrap; }
    .row { display:flex; gap:8px; align-items:center; max-width:1100px; }
    .row input[type="password"], .row input[type="text"] { flex: 1 1 auto; }
    .iconbtn { padding: 6px 8px; border: 1px solid #ccc; border-radius: 6px; background: #fff; cursor: pointer; min-width:40px;}
    .iconbtn:hover { background:#f6f6f6; }
    .icon { display:block; width:20px; height:20px; }
    code { white-space: pre-wrap; }
  </style>
</head>
<body>
  <h2>Proxy Agent (Local)</h2>
  <p class="muted">Data folder: <code>{{ data_dir }}</code></p>

  <form method="post" action="{{ url_for('submit') }}">
    <p><strong>IPQS API Key</strong></p>
    <div class="row">
      <input id="apiKey" type="password" name="api_key" placeholder="Paste your IPQS API key" value="{{ api_key_prefill }}" autocomplete="off">
      <button class="iconbtn" type="button" onclick="toggleEye()" title="Show/Hide API key" aria-label="Show or hide API key">
        <!-- Eye (open) icon. We toggle to 'slash' in JS -->
        <svg id="eyeIcon" class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      </button>
    </div>
    <p class="muted">New key overrides session/saved key. <a href="{{ url_for('reset_key') }}">Clear session key</a> · <a href="{{ url_for('reset_saved_key') }}">Clear saved key</a></p>

    <p><strong>Paste SOCKS5 proxies (one per line)</strong></p>
    <textarea name="proxies" rows="12" placeholder="socks5://1.2.3.4:1080
socks5://user:pass@5.6.7.8:1080
7.7.7.7:1080
user:pass@8.8.8.8:1080"></textarea><br><br>
    <button class="btn" type="submit">Submit & Process</button>
  </form>
  <p class="muted">Plain <code>host:port</code> or <code>user:pass@host:port</code> are OK — we'll auto-prefix <code>socks5://</code>. Batch size = {{ batch_size }}. Only unique-IP proxies are kept; all duplicates (by IP) are removed.</p>

  {% if note %}
    <div class="note">{{ note }}</div>
  {% endif %}

  {% if rows %}
    <h3>Results ({{ rows|length }} rows) — verdicts: <span style="color:#0a8a0a;font-weight:bold;">✓</span>=0, <span style="color:#e67e00;font-weight:bold;">✓</span>≤20, <span style="color:#c32020;font-weight:bold;">✗</span>>20</h3>
    <table>
      <thead>
        <tr>
          <th>Proxy (host:port:login:password)</th>
          <th>Resolved IP</th>
          <th>Proxy OK</th>
          <th>IPQS OK</th>
          <th>Fraud Score</th>
          <th>Verdict</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>
          <td><code>{{ r.proxy_formatted }}</code></td>
          <td>{{ r.resolved_ip }}</td>
          <td>{{ r.proxy_ok }}</td>
          <td>{{ r.ipqs_success }}</td>
          <td>{{ r.fraud_score }}</td>
          <td>{{ r.verdict_icon | safe }}</td>
          <td>{{ r.ipqs_message }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <h3>Copy proxies with fraud score ≤ 20</h3>
    <div class="flex">
      <button class="btn" type="button" onclick="copyLe20()">Copy to clipboard</button>
      <span class="muted">Format: <code>host:port:login:password</code></span>
    </div>
    <textarea id="le20" rows="8">{{ copy_payload }}</textarea>

    {% if csv_name and txt_eq0_name and txt_le20_name %}
    <p class="files">
      CSV: <a href="{{ url_for('download', filename=csv_name) }}">{{ csv_name }}</a> |
      =0 TXT: <a href="{{ url_for('download', filename=txt_eq0_name) }}">{{ txt_eq0_name }}</a> |
      ≤20 TXT: <a href="{{ url_for('download', filename=txt_le20_name) }}">{{ txt_le20_name }}</a>
    </p>
    {% endif %}
  {% endif %}

  <h3>Recent outputs</h3>
  <ul class="files">
    {% for name, t in files %}
      <li>{{ t }} — <a href="{{ url_for('download', filename=name) }}">{{ name }}</a></li>
    {% else %}
      <li>(none yet)</li>
    {% endfor %}
  </ul>

  <script>
    function toggleEye() {
      const el = document.getElementById('apiKey');
      const icon = document.getElementById('eyeIcon');
      const eye = `<svg id="eyeIcon" class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>`;
      const slash = `<svg id="eyeIcon" class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#333" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20C5 20 1 12 1 12a20.29 20.29 0 0 1 5.09-5.91"/>
        <path d="M9.88 9.88a3 3 0 0 0 4.24 4.24"/>
        <line x1="1" y1="1" x2="23" y2="23"/>
      </svg>`;
      if (el.type === 'password') {
        el.type = 'text';
        icon.outerHTML = slash;
      } else {
        el.type = 'password';
        icon.outerHTML = eye;
      }
    }
    function copyLe20() {
      const ta = document.getElementById('le20');
      ta.select();
      ta.setSelectionRange(0, 99999);
      const ok = document.execCommand('copy');
      if (ok) {
        alert('Copied!');
      } else if (navigator.clipboard) {
        navigator.clipboard.writeText(ta.value).then(() => alert('Copied!'));
      }
    }
  </script>
</body>
</html>
"""

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def index():
    ensure_dirs()
    files = sorted([p for p in OUTBOX.iterdir() if p.is_file()],
                   key=lambda p: p.stat().st_mtime, reverse=True)[:20]
    files_with_time = [(p.name, datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")) for p in files]
    api_key_prefill = (session.get("api_key") or ENV_API_KEY or "")
    return render_template_string(
        INDEX_HTML,
        rows=None, csv_name=None, txt_eq0_name=None, txt_le20_name=None, files=files_with_time,
        batch_size=BATCH_SIZE, note=None, copy_payload="", api_key_prefill=api_key_prefill,
        data_dir=str(ROOT)
    )

@app.route("/reset-key", methods=["GET"])
def reset_key():
    session.pop("api_key", None)
    return redirect(url_for("index"))

@app.route("/reset-saved-key", methods=["GET"])
def reset_saved_key():
    clear_saved_api_key()
    return redirect(url_for("index"))

@app.route("/submit", methods=["POST"])
def submit():
    pasted_key = (request.form.get("api_key") or "").strip()
    if pasted_key:
        session["api_key"] = pasted_key
        save_env_api_key(pasted_key)  # persist for next launches

    api_key = session.get("api_key") or ENV_API_KEY

    text = request.form.get("proxies", "")
    files = sorted([p for p in OUTBOX.iterdir() if p.is_file()],
                   key=lambda p: p.stat().st_mtime, reverse=True)[:20]
    files_with_time = [(p.name, datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")) for p in files]
    api_key_prefill = session.get("api_key") or ENV_API_KEY or ""

    if not api_key:
        return render_template_string(
            INDEX_HTML,
            rows=None, csv_name=None, txt_eq0_name=None, txt_le20_name=None, files=files_with_time,
            batch_size=BATCH_SIZE, note="Missing IPQS API key. Paste it above.", copy_payload="",
            api_key_prefill=api_key_prefill, data_dir=str(ROOT)
        )
    if not text.strip():
        return render_template_string(
            INDEX_HTML,
            rows=None, csv_name=None, txt_eq0_name=None, txt_le20_name=None, files=files_with_time,
            batch_size=BATCH_SIZE, note="Please paste at least one proxy.", copy_payload="",
            api_key_prefill=api_key_prefill, data_dir=str(ROOT)
        )

    try:
        (rows, csv_name, txt_eq0_name, txt_le20_name,
         dropped_dupes, kept_count, copy_payload) = process_paste_and_build_rows(CONN, api_key, text)
        note = f"Processed. Removed {dropped_dupes} proxies because their exit IPs were duplicated. Kept {kept_count} unique-IP proxies."
        if kept_count == 0:
            note += " (All proxies shared duplicated IPs; nothing left after filtering.)"
    except Exception as e:
        rows = [{
            "proxy_formatted": "",
            "resolved_ip": "",
            "proxy_ok": "❌",
            "ipqs_success": "",
            "fraud_score": "",
            "verdict_icon": '<span style="color:#999">?</span>',
            "ipqs_message": f"Error: {e}"
        }]
        csv_name = txt_eq0_name = txt_le20_name = None
        copy_payload = ""
        note = "There was an error during processing."

    files = sorted([p for p in OUTBOX.iterdir() if p.is_file()],
                   key=lambda p: p.stat().st_mtime, reverse=True)[:20]
    files_with_time = [(p.name, datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")) for p in files]
    api_key_prefill = session.get("api_key") or ENV_API_KEY or ""

    return render_template_string(
        INDEX_HTML,
        rows=rows, csv_name=csv_name, txt_eq0_name=txt_eq0_name, txt_le20_name=txt_le20_name,
        files=files_with_time, batch_size=BATCH_SIZE, note=note, copy_payload=copy_payload,
        api_key_prefill=api_key_prefill, data_dir=str(ROOT)
    )

@app.route("/outbox/<path:filename>")
def download(filename):
    return send_from_directory(OUTBOX, filename, as_attachment=True)

# ---------- Entrypoint ----------
def start_app():
    ensure_dirs()
    global CONN
    CONN = db_conn()
    app.run(host="127.0.0.1", port=5000, debug=False)

if __name__ == "__main__":
    print("Starting web agent. Open http://127.0.0.1:5000")
    start_app()