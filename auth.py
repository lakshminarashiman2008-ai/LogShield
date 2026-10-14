"""Admin-only authentication for LogShield.

There is deliberately NO sign-up. Administrator accounts are provisioned from the
command line (see manage_admins.py) and stored in a separate SQLite file with
salted PBKDF2 password hashes. Plain-text passwords are never stored.

Sessions survive a browser refresh: after signing in, a random token is stored in a
browser cookie and (as a SHA-256 hash only) in the database. On refresh the token is
read back with st.context.cookies (Streamlit 1.37+) and checked server-side.
"""
from __future__ import annotations

import hashlib
import hmac
import html as html_lib
import json
import math
import secrets
import sqlite3
import time
from functools import lru_cache
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

AUTH_DB_PATH = Path(__file__).resolve().with_name("logshield_admins.db")
PBKDF2_ITERATIONS = 600_000
MAX_FAILURES = 5              # failed attempts before a temporary lockout
LOCKOUT_SECONDS = 5 * 60      # lockout length
SESSION_SECONDS = 8 * 60 * 60 # how long a sign-in lasts (survives refreshes)
MIN_PASSWORD_LENGTH = 10
COOKIE_NAME = "logshield_session"


# ----------------------------- Storage ---------------------------------------
def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(AUTH_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                username_key  TEXT PRIMARY KEY,
                username      TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username_key TEXT PRIMARY KEY,
                failures     INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash   TEXT PRIMARY KEY,
                username_key TEXT NOT NULL,
                expires_at   REAL NOT NULL
            );
            """
        )
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))


# ----------------------------- Passwords -------------------------------------
def hash_password(password: str, *, salt: bytes | None = None, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(candidate, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """Used for unknown usernames so response time doesn't reveal which usernames exist."""
    return hash_password("logshield-dummy-password")


# ----------------------------- Admin management (used by the CLI) ------------
def _key(username: str) -> str:
    return username.strip().casefold()


def admin_count() -> int:
    with _connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0])


def list_admins() -> list[dict]:
    with _connect() as conn:
        return [dict(r) for r in conn.execute("SELECT username, created_at FROM admins ORDER BY username_key")]


def add_admin(username: str, password: str) -> None:
    username = username.strip()
    if not username or len(username) > 64:
        raise ValueError("Username must be 1-64 characters.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM admins WHERE username_key = ?", (_key(username),)).fetchone():
            raise ValueError(f"Admin '{username}' already exists.")
        conn.execute(
            "INSERT INTO admins(username_key, username, password_hash, created_at) VALUES (?, ?, ?, datetime('now'))",
            (_key(username), username, hash_password(password)),
        )


def set_admin_password(username: str, password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    with _connect() as conn:
        cur = conn.execute("UPDATE admins SET password_hash = ? WHERE username_key = ?", (hash_password(password), _key(username)))
        if cur.rowcount == 0:
            raise ValueError(f"Admin '{username}' does not exist.")
        conn.execute("DELETE FROM login_attempts WHERE username_key = ?", (_key(username),))
        conn.execute("DELETE FROM sessions WHERE username_key = ?", (_key(username),))  # sign out everywhere


def remove_admin(username: str) -> None:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM admins WHERE username_key = ?", (_key(username),))
        if cur.rowcount == 0:
            raise ValueError(f"Admin '{username}' does not exist.")
        conn.execute("DELETE FROM login_attempts WHERE username_key = ?", (_key(username),))
        conn.execute("DELETE FROM sessions WHERE username_key = ?", (_key(username),))


# ----------------------------- Login logic -----------------------------------
def _seconds_locked(conn: sqlite3.Connection, key: str) -> int:
    row = conn.execute("SELECT locked_until FROM login_attempts WHERE username_key = ?", (key,)).fetchone()
    return max(0, math.ceil(row["locked_until"] - time.time())) if row else 0


def _record_failure(conn: sqlite3.Connection, key: str) -> None:
    row = conn.execute("SELECT failures, locked_until FROM login_attempts WHERE username_key = ?", (key,)).fetchone()
    failures = (row["failures"] if row else 0) + 1
    locked_until = 0.0
    if failures >= MAX_FAILURES:
        locked_until, failures = time.time() + LOCKOUT_SECONDS, 0
    conn.execute(
        "INSERT INTO login_attempts(username_key, failures, locked_until) VALUES (?, ?, ?) "
        "ON CONFLICT(username_key) DO UPDATE SET failures = excluded.failures, locked_until = excluded.locked_until",
        (key, failures, locked_until),
    )


def authenticate(username: str, password: str) -> tuple[str | None, str]:
    """Return (admin username, "") on success or (None, error message) on failure."""
    key = _key(username)[:128]
    if not key or not password:
        return None, "Enter both your username and password."
    with _connect() as conn:
        remaining = _seconds_locked(conn, key)
        if remaining:
            return None, f"Too many failed attempts. Try again in {math.ceil(remaining / 60)} minute(s)."
        row = conn.execute("SELECT username, password_hash FROM admins WHERE username_key = ?", (key,)).fetchone()
        valid = verify_password(password, row["password_hash"] if row else _dummy_hash())
        if row and valid:
            conn.execute("DELETE FROM login_attempts WHERE username_key = ?", (key,))
            return row["username"], ""
        _record_failure(conn, key)
    # One generic message so the page never reveals whether a username exists.
    return None, "Incorrect username or password."


# ----------------------------- Persistent sessions ---------------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(username: str) -> str:
    """Create a server-side session and return the secret token (only its hash is stored)."""
    token = secrets.token_urlsafe(32)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO sessions(token_hash, username_key, expires_at) VALUES (?, ?, ?)",
            (_hash_token(token), _key(username), time.time() + SESSION_SECONDS),
        )
    return token


def get_session(token: str | None) -> tuple[str, float] | None:
    """Return (admin username, expiry timestamp) for a valid token, else None."""
    if not token:
        return None
    digest = _hash_token(token)
    with _connect() as conn:
        row = conn.execute(
            "SELECT a.username AS username, s.expires_at AS expires_at FROM sessions s "
            "JOIN admins a ON a.username_key = s.username_key WHERE s.token_hash = ?",
            (digest,),
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] <= time.time():
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
            return None
        return row["username"], float(row["expires_at"])


def end_session(token: str | None) -> None:
    if token:
        with _connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))


def _cookie_token() -> str | None:
    try:
        return st.context.cookies.get(COOKIE_NAME)
    except Exception:  # older Streamlit without st.context.cookies
        return None


def _run_js(js: str) -> None:
    components.html(f"<script>{js}</script>", height=0)


def _set_cookie_js(token: str) -> str:
    return (
        "const p = window.parent; const secure = p.location.protocol === 'https:' ? '; Secure' : '';"
        f"p.document.cookie = {json.dumps(COOKIE_NAME)} + '=' + {json.dumps(token)} + '; path=/; max-age={SESSION_SECONDS}; SameSite=Lax' + secure;"
    )


def _clear_cookie_js() -> str:
    return f"window.parent.document.cookie = {json.dumps(COOKIE_NAME)} + '=; path=/; max-age=0; SameSite=Lax';"


# ----------------------------- UI --------------------------------------------
LOGIN_CSS = """
<style>
/* No navigation before sign-in */
[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"], [data-testid="collapsedControl"] { display:none !important; }
.block-container { max-width: 1100px; }
.lg-brand { display:flex; align-items:center; gap:12px; margin-bottom:18px; }
.lg-logo { width:46px; height:46px; border-radius:13px; display:flex; align-items:center; justify-content:center; font-size:1.5rem; color:#031316;
           background:linear-gradient(135deg,#20e5ed,#53edc2); box-shadow:0 6px 18px rgba(32,229,237,.3); }
.lg-name { font-family:'Space Grotesk',sans-serif; font-size:1.45rem; font-weight:700; color:#eaffff; line-height:1.1; }
.lg-name span { color:var(--cyan); }
.lg-sub { font-family:'JetBrains Mono',monospace; font-size:.62rem; letter-spacing:.16em; color:#6f9ea4; text-transform:uppercase; margin-top:3px; }
.lg-title { font-family:'Space Grotesk',sans-serif; font-size:1.7rem; font-weight:600; letter-spacing:-.03em; margin:6px 0 4px 0;
            background:linear-gradient(90deg,#e7fbfc 0%,#8ff5f0 55%,#53edc2 100%); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; width:fit-content; }
.lg-desc { color:#8db4b9; font-size:.92rem; margin-bottom:14px; }
.lg-foot { color:#6f9ea4; font-size:.78rem; line-height:1.5; margin-top:14px; }
[data-testid="stFormSubmitButton"] button { width:100%; border-radius:10px; border:1px solid #16818a; background:linear-gradient(100deg,#0c5961,#08747c);
                                           color:white; font-weight:600; padding:.55rem 1rem; }
[data-testid="stFormSubmitButton"] button:hover { border-color:var(--cyan); color:white; }
[data-testid="stTextInput"] label p { color:#bfe6ea !important; font-size:.84rem; }
</style>
"""


def _render_login(notice: str = "") -> None:
    st.markdown(LOGIN_CSS, unsafe_allow_html=True)
    _, middle, _ = st.columns([1, 1.15, 1])
    with middle:
        with st.container(border=True):
            st.markdown(
                '<div class="lg-brand"><div class="lg-logo">◈</div><div><div class="lg-name">Log<span>Shield</span></div>'
                '<div class="lg-sub">Authentication monitoring</div></div></div>'
                '<div class="lg-title">Administrator sign in</div>'
                '<div class="lg-desc">Sign in to review authentication logs and incidents.</div>',
                unsafe_allow_html=True,
            )
            if notice:
                st.info(notice)
            if admin_count() == 0:
                st.warning("No administrator accounts exist yet. Create the first one from the server with `python manage_admins.py add <username>`.")
            with st.form("login_form", clear_on_submit=False):
                username = st.text_input("Username", key="login_username", autocomplete="username")
                password = st.text_input("Password", type="password", key="login_password", autocomplete="current-password")
                submitted = st.form_submit_button("Sign in")
            if submitted:
                admin, error = authenticate(username, password)
                if admin:
                    token = create_session(admin)
                    st.session_state.pop("login_password", None)
                    st.session_state.auth_user = admin
                    st.session_state.auth_time = time.time()
                    st.session_state.auth_token = token
                    st.session_state["_cookie_set"] = token  # written to the browser on the next run
                    st.rerun()
                else:
                    st.error(error)
            st.markdown(
                '<div class="lg-foot">Access is limited to administrators. Accounts can’t be created here; '
                'ask an existing administrator if you need access.</div>',
                unsafe_allow_html=True,
            )


def require_admin() -> str:
    """Gate for the whole app: returns the signed-in admin's name, or shows the login page and stops."""
    init_auth_db()

    # 1) Already signed in during this browser session.
    user = st.session_state.get("auth_user")
    if user and time.time() - st.session_state.get("auth_time", 0) <= SESSION_SECONDS:
        pending = st.session_state.pop("_cookie_set", None)
        if pending:
            _run_js(_set_cookie_js(pending))  # remember this sign-in across refreshes
        return user

    notice = ""
    if user:  # session expired
        end_session(st.session_state.get("auth_token"))
        st.session_state.clear()
        notice = "Your session expired. Please sign in again."
    elif not st.session_state.get("_cookie_clear"):
        # 2) Page was refreshed: restore the sign-in from the browser cookie.
        token = _cookie_token()
        restored = get_session(token)
        if restored:
            st.session_state.auth_user = restored[0]
            st.session_state.auth_time = restored[1] - SESSION_SECONDS  # keep the original expiry
            st.session_state.auth_token = token
            return restored[0]

    if st.session_state.pop("_cookie_clear", None):
        _run_js(_clear_cookie_js())  # just signed out: remove the cookie from the browser
    _render_login(notice)
    st.stop()


def render_sign_out(user: str) -> None:
    """Sidebar account block: who is signed in, plus a sign-out button styled like the nav buttons."""
    initial = html_lib.escape((user[:1] or "A").upper())
    st.sidebar.markdown(
        f'<div class="sb-label">Account</div>'
        f'<div class="sb-user"><span class="sb-avatar">{initial}</span><span>{html_lib.escape(user)}</span></div>',
        unsafe_allow_html=True,
    )
    if st.sidebar.button("Sign out", icon=":material/logout:", key="nav_signout", use_container_width=True):
        for token in {st.session_state.get("auth_token"), _cookie_token()}:
            end_session(token)  # invalidate server-side so the old cookie can never log in again
        st.session_state.clear()  # also drops any loaded events/alerts from this session
        st.session_state["_cookie_clear"] = True
        st.rerun()