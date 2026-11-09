#!/usr/bin/env python3
"""Local server for the site, with an administrator who can save text edits straight into the page.

    python3 server.py                  serve public/ at http://127.0.0.1:8123
    python3 server.py --set-password   choose a new admin password

On the page, type "edit" (or open /#admin) and sign in. "Save to site" rewrites
public/index.html; the version it replaces is kept in backups/.
Only public/ is served, so admin.json (the password hash) and backups/ are never exposed.
"""
import argparse
import getpass
import hashlib
import hmac
import http.cookies
import http.server
import json
import os
import secrets
import shutil
import sys
import threading
import time
from datetime import datetime
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
PAGE = PUBLIC / "index.html"
CONFIG = ROOT / "admin.json"
BACKUPS = ROOT / "backups"
KEEP_BACKUPS = 30
SESSION_SECONDS = 12 * 3600
MAX_BODY = 8 * 1024 * 1024
COOKIE = "site_admin"
ITERATIONS = 310_000
MAX_FAILS, FAIL_WINDOW = 5, 600          # 5 wrong passwords in 10 minutes locks sign-in for a while

lock = threading.Lock()
sessions = {}                            # token -> expiry (unix seconds)
failures = []                            # timestamps of recent wrong passwords


# ---------- password ----------
def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return {"salt": salt.hex(), "hash": digest.hex(), "iterations": ITERATIONS}


def password_ok(password, cfg):
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(cfg["salt"]), cfg["iterations"])
    return hmac.compare_digest(digest.hex(), cfg["hash"])


def write_config(cfg):
    tmp = CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg))
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG)


def load_config():
    if CONFIG.exists():
        return json.loads(CONFIG.read_text())
    password = secrets.token_urlsafe(9)
    cfg = hash_password(password)
    write_config(cfg)
    print(f"\n  Admin password created: {password}\n"
          f"  Change it any time with: python3 server.py --set-password\n", flush=True)
    return cfg


def set_password():
    if not sys.stdin.isatty():
        sys.exit("Run this in a terminal: python3 server.py --set-password")
    first = getpass.getpass("New admin password (8+ characters): ")
    if len(first) < 8:
        sys.exit("Too short; nothing changed.")
    if getpass.getpass("Again: ") != first:
        sys.exit("They didn't match; nothing changed.")
    write_config(hash_password(first))
    print("Admin password updated. Restart the server to sign out existing sessions.")


# ---------- saving ----------
def back_up_page():
    BACKUPS.mkdir(exist_ok=True)
    name = f"index-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
    shutil.copy2(PAGE, BACKUPS / name)
    old = sorted(BACKUPS.glob("index-*.html"))
    for p in old[:-KEEP_BACKUPS]:
        p.unlink()
    return name


def save_page(html):
    tmp = ROOT / ".index.html.saving"
    tmp.write_text(html, encoding="utf-8")
    os.replace(tmp, PAGE)


class Handler(http.server.SimpleHTTPRequestHandler):
    server_version = "SiteAdmin/1"

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    # ----- helpers -----
    def reply(self, status, data, cookie=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def token(self):
        jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar[COOKIE].value if COOKIE in jar else None

    def is_admin(self):
        t = self.token()
        with lock:
            exp = sessions.get(t)
            if exp and exp > time.time():
                return True
            sessions.pop(t, None)
        return False

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("too large")
        return json.loads(self.rfile.read(length) or b"{}")

    # ----- routes -----
    def do_GET(self):
        if self.path.split("?")[0] == "/api/session":
            return self.reply(200, {"admin": self.is_admin()})
        if self.path.startswith("/api/"):
            return self.reply(404, {"error": "Not found."})
        return super().do_GET()

    def do_POST(self):
        path = self.path.split("?")[0]
        # Only this page may call the API: same origin, JSON body (which a cross-site form can't send).
        origin = self.headers.get("Origin")
        if origin and origin != f"http://{self.headers.get('Host')}":
            return self.reply(403, {"error": "Requests must come from this site."})
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            return self.reply(415, {"error": "Expected JSON."})
        try:
            data = self.read_json()
        except ValueError:
            return self.reply(400, {"error": "That request couldn't be read."})

        if path == "/api/login":
            now = time.time()
            with lock:
                failures[:] = [t for t in failures if now - t < FAIL_WINDOW]
                locked_out = len(failures) >= MAX_FAILS
            if locked_out:
                return self.reply(429, {"error": "Too many wrong passwords. Wait a few minutes, then try again."})
            password = data.get("password")
            if not isinstance(password, str) or not password_ok(password, self.server.cfg):
                with lock:
                    failures.append(now)
                time.sleep(0.8)
                return self.reply(401, {"error": "That password didn't work."})
            t = secrets.token_urlsafe(32)
            with lock:
                sessions[t] = now + SESSION_SECONDS
            cookie = f"{COOKIE}={t}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"
            return self.reply(200, {"admin": True}, cookie)

        if path == "/api/logout":
            with lock:
                sessions.pop(self.token(), None)
            return self.reply(200, {"admin": False}, f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")

        if path == "/api/save":
            if not self.is_admin():
                return self.reply(401, {"error": "Sign in again to save."})
            html = data.get("html")
            if (not isinstance(html, str) or not html.lstrip()[:15].lower().startswith("<!doctype html")
                    or any(m not in html for m in ('id="launch"', 'id="admin"', "<script>"))):
                return self.reply(400, {"error": "That doesn't look like the whole page, so nothing was saved."})
            with lock:
                backup = back_up_page()
                save_page(html)
            return self.reply(200, {"ok": True, "backup": backup,
                                    "savedAt": datetime.now().isoformat(timespec="seconds")})

        return self.reply(404, {"error": "Not found."})


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8123)
    ap.add_argument("--set-password", action="store_true")
    args = ap.parse_args()
    if args.set_password:
        return set_password()
    if not PAGE.exists():
        sys.exit(f"Missing {PAGE}")
    httpd = http.server.ThreadingHTTPServer((args.host, args.port), partial(Handler, directory=str(PUBLIC)))
    httpd.cfg = load_config()
    print(f"Serving {PUBLIC} at http://{args.host}:{args.port}  (type \"edit\" on the page to sign in)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
