from __future__ import annotations

import html as html_lib
import io
import math
import re
import json
from datetime import date, datetime, time as dtime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from auth import require_admin, render_sign_out
from detector import analyze_events
from validator import validate_csv
from history_store import initialize_db, content_digest, prior_account_history, save_analysis, list_analyses, get_analysis_incidents, persistent_accounts, delete_analysis

try:
    from detector import DEFAULT_SETTINGS
except ImportError:
    DEFAULT_SETTINGS = {}
try:
    from detector import validate_settings
except ImportError:
    validate_settings = None

def make_favicon():
    """Small gradient diamond mark drawn in code, so the tab needs no emoji or image file."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return None
    size = 128
    grad = Image.new("RGBA", (size, size))
    px = grad.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * size)
            px[x, y] = (int(32 + 51 * t), int(229 + 8 * t), int(237 - 43 * t), 255)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=30, fill=255)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    img.paste(grad, (0, 0), mask)
    d, c = ImageDraw.Draw(img), size // 2
    d.polygon([(c, 24), (size - 24, c), (c, size - 24), (24, c)], fill=(3, 19, 22, 255))
    d.polygon([(c, 46), (size - 46, c), (c, size - 46), (46, c)], fill=(32, 229, 237, 255))
    return img

st.set_page_config(
    page_title="LogShield — Auth Watchtower",
    page_icon=make_favicon(),
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------- Theme -----------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    :root {
      --bg: #031316; --panel: #061e22; --panel2: #08272b;
      --border: #11515a; --cyan: #20e5ed; --mint: #53edc2;
      --text: #e7fbfc; --muted: #8db4b9; --pink: #ff557b;
      --amber: #ffc857; --blue: #35c9ff;
    }
    html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
    .stApp { background: radial-gradient(ellipse at 75% 0%, #073238 0%, var(--bg) 48%); color: var(--text); }
    /* Keep the page header from clipping the eyebrow / first panels */
    .block-container { padding-top: 4rem !important; }
    [data-testid="stSidebar"] { background: #041a1e; border-right: 1px solid var(--border); }
    [data-testid="stSidebar"] * { color: var(--text); }
    h1,h2,h3 { font-family: 'Space Grotesk', sans-serif !important; letter-spacing: -0.03em; }
    h1 { color: var(--text); font-size: 2.05rem !important; }
    h2 { font-size: 1.25rem !important; }
    p, label, .stCaption { color: var(--muted); }
    [data-testid="stMetric"] { background: linear-gradient(135deg, #08272c, #061c20); border: 1px solid var(--border); border-radius: 15px; padding: 16px 18px; min-height: 118px; }
    [data-testid="stMetricLabel"] { color: #9cc8cc !important; }
    [data-testid="stMetricValue"] { color: var(--text) !important; font-family: 'Space Grotesk', sans-serif; }
    [data-testid="stMetricDelta"] { color: var(--mint) !important; }
    div[data-testid="stVerticalBlockBorderWrapper"] { border-color: var(--border) !important; border-radius: 15px; }
    /* Panel headings: tighter, consistent spacing */
    div[data-testid="stVerticalBlockBorderWrapper"] h3 { padding: 0 0 .15rem 0 !important; margin: 0 !important; }
    .hero { padding: 8px 0 16px 0; }
    .eyebrow { color: var(--cyan); text-transform: uppercase; font-size: .75rem; letter-spacing: .15em; font-weight: 700; }
    .muted { color: var(--muted); }
    .pill { display:inline-block; border:1px solid #16818a; background:#07353a; color:#6df4f0; padding:5px 10px; border-radius:999px; font-size:.76rem; }
    .alert-note { border:1px solid #6c5a21; background:#2a2410; padding:12px 15px; border-radius:12px; color:#ffdc7c; }
    .sidebar-brand { font-family:'Space Grotesk',sans-serif; font-size:1.45rem; font-weight:700; color:#eaffff; }
    .sidebar-brand span { color:var(--cyan); }
    .small-card { background: #062126; border: 1px solid #10464d; border-radius: 12px; padding: 14px; }
    div.stButton > button { border-radius: 10px; border: 1px solid #16818a; background: linear-gradient(100deg,#0c5961,#08747c); color: white; font-weight: 600; }
    div.stButton > button:hover { border-color: var(--cyan); color: white; }
    div[data-baseweb="select"] > div, div[data-baseweb="input"] > div, textarea { background-color:#061e22 !important; border-color:#14525a !important; }
    [data-testid="stDataFrame"] { border:1px solid var(--border); border-radius:12px; overflow:hidden; }
    /* Upload box: compact and content-sized (no big empty gap under the file chip) */
    [data-testid="stFileUploader"] { margin-bottom: .5rem; }
    [data-testid="stFileUploaderDropzone"] { min-height: 0 !important; padding: 10px 12px !important; align-items: center; }
    [data-testid="stFileUploaderDropzoneInstructions"] { padding: 0 !important; }
    [data-testid="stFileUploaderDropzone"] button { padding: 4px 12px !important; min-height: 32px !important; }
    [data-testid="stFileUploaderFile"] { padding: 2px 0 !important; }
    hr { border-color:#123e44; }
    /* Hide the anchor/link icon Streamlit adds beside every heading */
    [data-testid="stHeaderActionElements"], [data-testid="stHeadingActionElements"], .stHeading a, h1 a, h2 a, h3 a { display:none !important; }

    /* Motion */
    @keyframes fadeUp { from { opacity:0; transform:translateY(14px); } to { opacity:1; transform:none; } }
    @keyframes slideIn { from { opacity:0; transform:translateX(-14px); } to { opacity:1; transform:none; } }
    @keyframes rowIn { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:none; } }
    @keyframes pulse { 0% { box-shadow:0 0 0 0 rgba(83,237,194,.55); } 70% { box-shadow:0 0 0 8px rgba(83,237,194,0); } 100% { box-shadow:0 0 0 0 rgba(83,237,194,0); } }
    .block-container { animation:fadeUp .5s ease backwards; }
    div[data-testid="stVerticalBlockBorderWrapper"] { animation:fadeUp .55s ease backwards; }
    .alert-note, .uchip, .sigcard { animation:fadeUp .45s ease backwards; }
    .mcard, .racc { animation:fadeUp .6s ease backwards; transition:transform .25s ease, border-color .25s ease, box-shadow .25s ease; }
    .mcard:hover, .racc:hover { transform:translateY(-4px); border-color:#1b747b; box-shadow:0 12px 28px rgba(0,0,0,.35), 0 0 0 1px rgba(32,229,237,.12); }
    .mcard:nth-child(2), .racc:nth-child(2) { animation-delay:.08s; } .mcard:nth-child(3), .racc:nth-child(3) { animation-delay:.16s; }
    .mcard:nth-child(4), .racc:nth-child(4) { animation-delay:.24s; } .racc:nth-child(5) { animation-delay:.32s; } .racc:nth-child(6) { animation-delay:.4s; }
    .ltable tbody tr { animation:rowIn .4s ease backwards; }
    .ltable tbody tr:nth-child(1){animation-delay:.03s} .ltable tbody tr:nth-child(2){animation-delay:.06s} .ltable tbody tr:nth-child(3){animation-delay:.09s}
    .ltable tbody tr:nth-child(4){animation-delay:.12s} .ltable tbody tr:nth-child(5){animation-delay:.15s} .ltable tbody tr:nth-child(6){animation-delay:.18s}
    .ltable tbody tr:nth-child(7){animation-delay:.21s} .ltable tbody tr:nth-child(8){animation-delay:.24s} .ltable tbody tr:nth-child(9){animation-delay:.27s}
    .ltable tbody tr:nth-child(10){animation-delay:.3s}
    div.stButton > button, [data-testid="stFormSubmitButton"] button { transition:transform .2s ease, box-shadow .2s ease, border-color .2s ease; }
    div.stButton > button:hover, [data-testid="stFormSubmitButton"] button:hover { transform:translateY(-2px); box-shadow:0 8px 20px rgba(32,229,237,.18); }
    .pulse { display:inline-block; width:8px; height:8px; border-radius:50%; background:#53edc2; animation:pulse 2s infinite; }

    /* Sidebar */
    [data-testid="stSidebar"] > div:first-child { background:linear-gradient(180deg,#05232b 0%,#031a1e 60%,#021215 100%); }
    .sb-brand { display:flex; align-items:center; gap:12px; padding:6px 2px 4px 2px; animation:slideIn .5s ease backwards; }
    .sb-logo { width:42px; height:42px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:1.4rem; color:#031316; background:linear-gradient(135deg,#20e5ed,#53edc2); box-shadow:0 6px 18px rgba(32,229,237,.3); }
    .sb-name { font-family:'Space Grotesk',sans-serif; font-size:1.35rem; font-weight:700; color:#eaffff; line-height:1.1; }
    .sb-name span { color:var(--cyan); }
    .sb-sub { font-family:'JetBrains Mono',monospace; font-size:.6rem; letter-spacing:.16em; color:#6f9ea4; text-transform:uppercase; margin-top:3px; }
    .sb-label { font-family:'JetBrains Mono',monospace; font-size:.62rem; letter-spacing:.18em; color:#5d8a90; text-transform:uppercase; margin:22px 0 8px 6px; }
    [data-testid="stSidebar"] div.stButton > button { width:100%; justify-content:flex-start; text-align:left; background:transparent; border:1px solid transparent; color:#9cc8cc; padding:.72rem 1rem; border-radius:12px; font-weight:500; box-shadow:none; animation:slideIn .5s ease backwards; transition:all .25s ease; }
    [data-testid="stSidebar"] div.stButton > button p { color:inherit; text-align:left; width:100%; }
    [data-testid="stSidebar"] div.stButton > button:hover { background:#082a30; color:#e7fbfc; border-color:#12454b; transform:translateX(5px); box-shadow:none; }
    [data-testid="stSidebar"] div.stButton > button[kind="primary"], [data-testid="stSidebar"] div.stButton > button[data-testid="stBaseButton-primary"] { background:linear-gradient(90deg,rgba(32,229,237,.18),rgba(32,229,237,.03)); color:#eaffff; border-color:#14525a; box-shadow:inset 3px 0 0 #20e5ed; }
    /* Uniform sidebar buttons: same height, left-aligned, icons in one fixed-width column */
    [data-testid="stSidebar"] div.stButton { margin-bottom:.2rem; }
    [data-testid="stSidebar"] div.stButton > button { min-height:3rem; padding:0 1rem; display:flex; align-items:center; justify-content:flex-start; gap:.75rem; }
    [data-testid="stSidebar"] div.stButton > button > div { display:flex; align-items:center; justify-content:flex-start; gap:.75rem; width:100%; }
    [data-testid="stSidebar"] div.stButton > button [data-testid="stMarkdownContainer"] { flex:1; text-align:left; }
    [data-testid="stSidebar"] div.stButton > button p { margin:0; font-size:.95rem; line-height:1.2; }
    [data-testid="stSidebar"] div.stButton > button [data-testid="stIconMaterial"] { font-size:1.5rem !important; width:1.5rem; height:1.5rem; flex:0 0 1.5rem; color:#20e5ed; }
    [data-testid="stSidebar"] div.stButton > button:hover [data-testid="stIconMaterial"] { color:#53edc2; }
    /* Account block */
    .sb-user { display:flex; align-items:center; gap:10px; margin:0 2px 10px 2px; color:#cdeff5; font-size:.9rem; font-weight:600; }
    .sb-avatar { width:30px; height:30px; border-radius:50%; display:flex; align-items:center; justify-content:center; background:linear-gradient(135deg,#20e5ed,#53edc2); color:#031316 !important; font-weight:700; font-size:.85rem; }
    /* Invisible helper iframe used to write/clear the login cookie */
    [data-testid="stElementContainer"]:has(iframe[height="0"]) { position:absolute; height:0; overflow:hidden; margin:0; padding:0; }
    .st-key-nav_Dashboard button { animation-delay:.05s !important; } .st-key-nav_Incident_History button { animation-delay:.12s !important; }
    .st-key-nav_Repeat_Accounts button { animation-delay:.19s !important; } .st-key-nav_Settings button { animation-delay:.26s !important; }
    .sb-card { background:#061f24; border:1px solid #11464d; border-radius:14px; padding:14px; margin-top:26px; animation:fadeUp .6s .3s ease backwards; }
    .sb-status { display:flex; align-items:center; gap:9px; color:#cdeff5; font-size:.85rem; font-weight:600; }
    .sb-stats { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:12px; }
    .sb-stats div { background:#04181c; border:1px solid #0f3a40; border-radius:10px; padding:8px 10px; }
    .sb-stats b { display:block; font-family:'Space Grotesk',sans-serif; font-size:1.2rem; color:#e7fbfc; line-height:1.1; }
    .sb-stats span { font-family:'JetBrains Mono',monospace; font-size:.58rem; letter-spacing:.12em; color:#6f9ea4; text-transform:uppercase; }
    .sb-note { color:#6f9ea4; font-size:.78rem; line-height:1.45; margin:12px 2px 10px 2px; }

    /* Settings */
    [data-testid="stForm"] { border:none !important; padding:0 !important; background:transparent !important; }
    .sgh { display:flex; align-items:center; gap:14px; margin-bottom:10px; }
    .sgt { font-family:'Space Grotesk',sans-serif; font-size:1.1rem; font-weight:600; color:#e7fbfc; }
    .sgd { color:#8db4b9; font-size:.86rem; margin-top:2px; }
    [data-testid="stNumberInput"] label p, [data-testid="stTextInput"] label p, [data-testid="stToggle"] label p { color:#bfe6ea !important; font-size:.84rem; }

    h1 { background:linear-gradient(90deg,#e7fbfc 0%,#8ff5f0 55%,#53edc2 100%); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; width:fit-content; }
    .sset { font-family:'JetBrains Mono',monospace; font-size:.66rem; letter-spacing:.14em; color:#8db4b9; text-transform:uppercase; margin:14px 0 6px 0; }

    /* Metric cards */
    .mgrid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin:10px 0 14px 0; }
    .mcard { background:linear-gradient(160deg,#0c2a30,#071d21); border:1px solid #123e44; border-radius:18px; padding:20px 22px 22px 22px; }
    .mtop { display:flex; justify-content:space-between; align-items:center; }
    .mlabel { font-family:'JetBrains Mono',monospace; font-size:.72rem; letter-spacing:.14em; color:#a9cdd2; text-transform:uppercase; }
    .micon { width:40px; height:40px; border-radius:11px; display:flex; align-items:center; justify-content:center; }
    .micon svg { width:20px; height:20px; }
    .mval { display:flex; align-items:center; gap:12px; margin-top:14px; flex-wrap:wrap; }
    .mnum { font-family:'Space Grotesk',sans-serif; font-size:2.7rem; font-weight:600; line-height:1; color:#cdeff5; }
    .mchip { font-family:'JetBrains Mono',monospace; font-size:.76rem; padding:4px 10px; border-radius:8px; white-space:nowrap; }
    .mdesc { color:#a9cdd2; font-size:.95rem; line-height:1.4; margin-top:10px; min-height:2.7em; }
    .mbar { display:flex; gap:3px; height:8px; border-radius:99px; overflow:hidden; background:#0b2a2f; margin-top:16px; }
    .mbar span { transform-origin:left; animation:mgrow .9s cubic-bezier(.22,.8,.3,1) both; }
    @keyframes mgrow { from { transform:scaleX(0); } to { transform:scaleX(1); } }
    /* Upload info */
    .utiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(90px,1fr)); gap:8px; margin:10px 0 8px 0; }
    .utile { background:#061c20; border:1px solid #12454b; border-radius:10px; padding:8px 12px; }
    .utile b { display:block; font-family:'Space Grotesk',sans-serif; font-size:1.25rem; color:#dffbfc; line-height:1.2; }
    .utile span { font-family:'JetBrains Mono',monospace; font-size:.62rem; letter-spacing:.12em; color:#8db4b9; text-transform:uppercase; }
    .usec { font-family:'JetBrains Mono',monospace; font-size:.66rem; letter-spacing:.14em; color:#8db4b9; text-transform:uppercase; margin:12px 0 6px 0; }
    .uchip { display:inline-block; font-size:.74rem; padding:3px 10px; margin:0 6px 6px 0; border-radius:999px; border:1px solid #14525a; background:#07262b; color:#bfe6ea; }
    .uchip.ok { border-color:#1f6f5c; background:#0a2e2a; color:#7cf0c8; }
    .uchip.bad { border-color:#7a2a3a; background:#2a1018; color:#ff8fa8; }
    .uok { color:#7cf0c8; font-size:.85rem; margin-top:8px; }
    /* Repeat accounts */
    .rgrid { display:grid; grid-template-columns:repeat(auto-fill,minmax(360px,1fr)); gap:16px; margin-top:10px; }
    .racc { background:linear-gradient(160deg,#0c2a30,#071d21); border:1px solid #123e44; border-radius:18px; padding:18px 20px; }
    .racc.hot { border-color:#6b2433; box-shadow:0 0 0 1px #33141c inset; }
    .rhead { display:flex; justify-content:space-between; align-items:center; gap:10px; }
    .rname { font-family:'JetBrains Mono',monospace; font-size:1.05rem; font-weight:600; color:#e7fbfc; word-break:break-all; }
    .rbadges { margin:10px 0 4px 0; display:flex; gap:8px; flex-wrap:wrap; }
    .rbadge { font-family:'JetBrains Mono',monospace; font-size:.72rem; padding:4px 10px; border-radius:8px; background:#0f3a44; color:#8fdcff; }
    .rbadge.red { background:#33141c; color:#ff8fa8; }
    .rstrip { display:flex; gap:5px; flex-wrap:wrap; margin:12px 0 6px 0; }
    .rdot { width:11px; height:11px; border-radius:50%; display:inline-block; flex:0 0 11px; background:#35c9ff; }
    .rdot.f { background:#ff557b; box-shadow:0 0 8px rgba(255,85,123,.5); }
    .rrow { display:flex; align-items:center; gap:10px; padding:7px 0; border-top:1px solid #0e3237; font-size:.8rem; }
    .rwhen { font-family:'JetBrains Mono',monospace; color:#8db4b9; font-size:.72rem; white-space:nowrap; }
    .rfile { flex:1; color:#cdeff5; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .rtag { font-size:.72rem; color:#8db4b9; white-space:nowrap; }
    .rtag.f { color:#ff8fa8; }
    .rmore { color:#5d8a90; font-size:.74rem; padding-top:6px; }
    /* Incident table */
    .ltable-wrap { max-height:470px; overflow:auto; border:1px solid #123e44; border-radius:14px; background:#051a1e; margin-top:6px; }
    .ltable { width:100%; min-width:1150px; border-collapse:separate; border-spacing:0; font-size:.84rem; color:#dffbfc; }
    .ltable th { position:sticky; top:0; z-index:1; background:#08272b; text-align:left; padding:12px 14px; font-family:'JetBrains Mono',monospace; font-size:.66rem; letter-spacing:.14em; color:#8db4b9; text-transform:uppercase; border-bottom:1px solid #123e44; white-space:nowrap; }
    .ltable td { padding:12px 14px; border-bottom:1px solid #0e3237; vertical-align:top; }
    .ltable tr:last-child td { border-bottom:none; }
    .ltable tbody tr:hover td { background:#08262b; }
    .ltable .idx { color:#5d8a90; font-family:'JetBrains Mono',monospace; font-size:.76rem; }
    .ltable .rule { font-weight:600; min-width:170px; }
    .ltable .mono { font-family:'JetBrains Mono',monospace; font-size:.78rem; color:#bfe6ea; white-space:nowrap; }
    .ltable .clamp { display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; max-width:340px; color:#9cc8cc; line-height:1.45; }
    .sev { display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:999px; font-size:.74rem; font-weight:600; white-space:nowrap; }
    .sev::before { content:''; width:6px; height:6px; border-radius:50%; background:currentColor; }
    .sev.high { background:#33141c; color:#ff7a90; border:1px solid #6b2433; }
    .sev.medium { background:#33290f; color:#ffc857; border:1px solid #6c5a21; }
    .sev.low { background:#0c2e2a; color:#53edc2; border:1px solid #1f6f5c; }
    .sev.other { background:#0f2f3a; color:#8fdcff; border:1px solid #1f5d73; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ----------------------------- Admin login gate ------------------------------
# Nothing below this line runs until an administrator has signed in.
admin_user = require_admin()

# ----------------------------- Session state --------------------------------
if "page" not in st.session_state:
    st.session_state.page = "Dashboard"
if "analyses" not in st.session_state:
    st.session_state.analyses = []
if "current_alerts" not in st.session_state:
    st.session_state.current_alerts = pd.DataFrame()
if "current_events" not in st.session_state:
    st.session_state.current_events = pd.DataFrame()
if "current_filename" not in st.session_state:
    st.session_state.current_filename = ""
if "settings" not in st.session_state:
    st.session_state.settings = dict(DEFAULT_SETTINGS) if isinstance(DEFAULT_SETTINGS, dict) else {}

# Persistent history lives in SQLite beside this app; raw uploaded CSV rows are never stored.
initialize_db()

# ----------------------------- Lab holidays ----------------------------------
# Stored in a small JSON file beside the app so holidays survive restarts.
HOLIDAY_FILE = Path(__file__).resolve().with_name("lab_holidays.json")

def load_holidays() -> dict[str, str]:
    try:
        data = json.loads(HOLIDAY_FILE.read_text(encoding="utf-8"))
        return {str(k): str(v or "") for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}

def save_holidays(holidays: dict[str, str]) -> None:
    HOLIDAY_FILE.write_text(json.dumps(dict(sorted(holidays.items())), indent=2, ensure_ascii=False), encoding="utf-8")

def holiday_text(iso: str, label: str = "") -> str:
    try:
        nice = datetime.fromisoformat(iso).strftime("%a %d %b %Y")
    except ValueError:
        nice = iso
    return f"{nice} · {label}" if label else nice

# ----------------------------- Helpers ---------------------------------------
def nav_button(label: str, icon: str) -> None:
    active = st.session_state.page == label
    if st.sidebar.button(label, icon=icon, key=f"nav_{label}", use_container_width=True, type="primary" if active else "secondary"):
        st.session_state.page = label
        st.rerun()

def first_existing(frame: pd.DataFrame, names: list[str], default: Any = None):
    for name in names:
        if name in frame.columns:
            return frame[name]
    return default

def safe_count(frame: pd.DataFrame, names: list[str]) -> int:
    series = first_existing(frame, names)
    if series is None:
        return 0
    return int(series.nunique()) if hasattr(series, "nunique") else 0

_MISSING = {"", "—", "-", "nan", "none", "nat", "<na>"}

def alert_column(frame: pd.DataFrame, names: list[str], fallback: str = "") -> pd.Series:
    """First usable value across all alias columns, row by row; blanks and placeholders count as missing."""
    result = pd.Series([fallback] * len(frame), index=frame.index, dtype=object)
    filled = pd.Series(False, index=frame.index)
    for name in names:
        if name not in frame.columns:
            continue
        col = frame[name]
        if isinstance(col, pd.DataFrame):
            col = col.iloc[:, 0]
        col = col.where(col.notna(), "").astype(str).str.strip()
        usable = ~col.str.lower().isin(_MISSING) & ~filled
        result[usable] = col[usable]
        filled |= usable
    return result

def humanize_rule(value: Any) -> str:
    text = str(value)
    mapping = {
        "R1": "Repeated failures followed by success",
        "R2": "Login outside lab hours",
        "R3": "Consecutive failed logins",
        "R4": "Repeated failed logins over time",
        "R5": "Failed logins across multiple accounts",
        "R6": "One account across multiple computers",
        "H1": "Previously flagged account observed again",
        "MULTI": "Multiple-account failure pattern",
    }
    if text.strip().upper() in mapping:
        return mapping[text.strip().upper()]
    # Replace a leading rule identifier while retaining any descriptive suffix.
    match = re.match(r"^R([1-6])\s*[-:—]?\s*(.*)$", text.strip(), flags=re.I)
    if match:
        description = match.group(2).strip()
        return description if description else mapping.get("R" + match.group(1), text)
    return text

def normalized_alerts(frame: pd.DataFrame) -> pd.DataFrame:
    if frame is None or frame.empty:
        return pd.DataFrame(columns=[
            "Severity", "Rule", "Account", "Computer", "Start time",
            "End time", "Event IDs", "Evidence", "Recommendation"
        ])
    aliases = {
        "Severity": ["severity", "Severity"],
        "Rule": ["rule_name", "rule_id", "rule", "Rule", "detection_rule"],
        "Account": ["account", "accounts", "Account"],
        "Computer": ["computer", "Computer"],
        "Start time": ["start_time", "timestamp", "Start time"],
        "End time": ["end_time", "End time"],
        "Event IDs": ["event_ids", "event_id", "Event IDs"],
        "Evidence": ["evidence", "description", "Evidence"],
        "Recommendation": ["recommendation", "recommended_action", "Recommendation"],
    }
    out = pd.DataFrame(index=frame.index)
    for target, candidates in aliases.items():
        out[target] = alert_column(frame, candidates)
    out["Rule"] = out["Rule"].map(humanize_rule)
    return out.reset_index(drop=True)

DONUT_COLORS = ["#ff4d4f", "#ff8c42", "#ffd166", "#e85d75", "#ffb36b", "#d95f59", "#f97316", "#fb7185"]

def donut_html(counts: pd.DataFrame) -> str:
    """Self-contained animated donut (SVG + CSS). Segments draw in one after another; hover shows details."""
    total = int(counts["Incidents"].sum())
    radius, stroke = 70, 22
    circ = 2 * math.pi * radius
    gap = 3 if len(counts) > 1 else 0
    segments, legend, cum = [], [], 0.0
    for i, row in enumerate(counts.itertuples(index=False)):
        name = html_lib.escape(str(row[0]))
        value = int(row[1])
        frac = value / total if total else 0
        seg_len = max(frac * circ - gap, 0.5)
        color = DONUT_COLORS[i % len(DONUT_COLORS)]
        pct = f"{frac * 100:.1f}%"
        segments.append(
            f'<circle class="seg" data-i="{i}" data-name="{name}" data-val="{value}" data-pct="{pct}" '
            f'cx="100" cy="100" r="{radius}" stroke="{color}" '
            f'style="--len:{seg_len:.2f};--off:{-cum:.2f};animation-delay:{0.15 + i * 0.28:.2f}s"/>'
        )
        legend.append(
            f'<div class="row" data-i="{i}" data-name="{name}" data-val="{value}" data-pct="{pct}" style="animation-delay:{0.25 + i * 0.28:.2f}s">'
            f'<span class="dot" style="background:{color}"></span><span class="nm">{name}</span>'
            f'<span class="ct">{value} · {pct}</span></div>'
        )
        cum += frac * circ
    return f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@600;700&display=swap');
  html, body {{ margin:0; background:transparent; font-family:'DM Sans',sans-serif; color:#dffbfc; }}
  .wrap {{ display:flex; flex-direction:column; align-items:center; gap:14px; padding:4px; box-sizing:border-box; }}
  .chart {{ position:relative; width:200px; height:200px; flex:0 0 200px; }}
  svg {{ width:100%; height:100%; transform:rotate(-90deg); overflow:visible; }}
  .track {{ fill:none; stroke:#0b2f35; stroke-width:{stroke}; }}
  .seg {{ fill:none; stroke-width:{stroke}; stroke-dasharray:0 {circ:.2f}; stroke-dashoffset:var(--off);
         animation:draw .9s cubic-bezier(.22,.8,.3,1) forwards; cursor:pointer;
         transition:stroke-width .2s ease, opacity .2s ease, filter .2s ease; }}
  @keyframes draw {{ to {{ stroke-dasharray:var(--len) {circ:.2f}; }} }}
  .chart.hovering .seg {{ opacity:.35; }}
  .chart.hovering .seg.on {{ opacity:1; stroke-width:{stroke + 5}; filter:drop-shadow(0 0 6px rgba(255,255,255,.25)); }}
  .center {{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; pointer-events:none; padding:0 46px; }}
  .center .v {{ font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:2.1rem; line-height:1; animation:pop .6s .2s both; }}
  .center .l {{ color:#8db4b9; font-size:.7rem; margin-top:6px; line-height:1.2; }}
  @keyframes pop {{ from {{ opacity:0; transform:scale(.6); }} to {{ opacity:1; transform:scale(1); }} }}
  .legend {{ width:100%; max-width:440px; max-height:172px; overflow-y:auto; display:flex; flex-direction:column; gap:7px; padding-right:4px; box-sizing:border-box; scrollbar-width:thin; scrollbar-color:#14525a transparent; }}
  .row {{ display:flex; align-items:center; gap:9px; padding:7px 10px; border:1px solid #12454b; background:#061c20; border-radius:9px;
         font-size:.76rem; opacity:0; transform:translateX(12px); flex:0 0 auto; animation:slide .5s ease forwards; transition:border-color .2s, background .2s; cursor:pointer; }}
  .row:hover, .row.on {{ border-color:#20e5ed; background:#082a2f; }}
  @keyframes slide {{ to {{ opacity:1; transform:none; }} }}
  .dot {{ width:10px; height:10px; border-radius:50%; flex:0 0 10px; }}
  .nm {{ flex:1; color:#dffbfc; }}
  .ct {{ color:#8db4b9; white-space:nowrap; font-variant-numeric:tabular-nums; }}
</style>
<div class="wrap">
  <div class="chart" id="chart">
    <svg viewBox="0 0 200 200"><circle class="track" cx="100" cy="100" r="{radius}"/>{''.join(segments)}</svg>
    <div class="center"><div class="v" id="cv">{total}</div><div class="l" id="cl">Total incidents</div></div>
  </div>
  <div class="legend">{''.join(legend)}</div>
</div>
<script>
  const chart = document.getElementById('chart'), cv = document.getElementById('cv'), cl = document.getElementById('cl');
  const segs = document.querySelectorAll('.seg'), rows = document.querySelectorAll('.row');
  function on(i, el) {{
    chart.classList.add('hovering');
    segs.forEach(s => s.classList.toggle('on', s.dataset.i === i));
    rows.forEach(r => r.classList.toggle('on', r.dataset.i === i));
    cv.textContent = el.dataset.val; cl.textContent = el.dataset.name + ' · ' + el.dataset.pct;
  }}
  function off() {{
    chart.classList.remove('hovering');
    segs.forEach(s => s.classList.remove('on')); rows.forEach(r => r.classList.remove('on'));
    cv.textContent = '{total}'; cl.textContent = 'Total incidents';
  }}
  [...segs, ...rows].forEach(el => {{ el.addEventListener('mouseenter', () => on(el.dataset.i, el)); el.addEventListener('mouseleave', off); }});
</script>
"""

def run_analysis(uploaded_file) -> None:
    try:
        raw_bytes = uploaded_file.getvalue()
        digest = content_digest(raw_bytes)
        validation = validate_csv(io.BytesIO(raw_bytes))
    except Exception as exc:
        st.error(f"Could not validate this CSV: {exc}")
        return
    errors = getattr(validation, "errors", []) or []
    warnings = getattr(validation, "warnings", []) or []
    if errors:
        st.error("CSV validation failed. Fix the issues below before analysis.")
        for error in errors:
            st.write(f"• {error}")
        for warning in warnings:
            st.warning(warning)
        return
    events = getattr(validation, "data", None)
    if events is None:
        st.error("The validator did not return normalized event data.")
        return
    for warning in warnings:
        st.warning(str(warning))
    try:
        try:
            alerts = analyze_events(events, {**st.session_state.settings, "holidays": load_holidays()})
        except TypeError:
            alerts = analyze_events(events)
        if not isinstance(alerts, pd.DataFrame):
            alerts = pd.DataFrame(alerts)
    except Exception as exc:
        st.error(f"Analysis could not be completed: {exc}")
        st.caption("If this persists, check the function signature in detector.py.")
        return

    # H1: current accounts that appeared in incidents from an earlier distinct run.
    account_values = events["account"].dropna().astype(str).str.strip().unique().tolist() if "account" in events else []
    history = prior_account_history(account_values)
    history_rows = []
    for account in account_values:
        record = history.get(account.casefold())
        if record:
            history_rows.append({
                "incident_id": f"H1-{len(history_rows)+1:03d}", "rule_id": "H1",
                "rule": "Previously flagged account observed again", "severity": "Medium",
                "account": account, "computer": "Multiple / see source logs",
                "start_time": "—", "end_time": "—", "event_ids": "Not inferred from historical data",
                "evidence": f"This account appeared in incident records from {record['run_count']} earlier distinct analysis run(s). Latest prior record: {record['last_seen']}. This is context for review, not proof of current suspicious activity.",
                "recommendation": "Review current events and verify whether the prior and current activity are expected.",
                "signal": "historical_repeat_account",
            })
    if history_rows:
        alerts = pd.concat([alerts, pd.DataFrame(history_rows)], ignore_index=True, sort=False)
    account_counts = events["account"].astype(str).str.strip().value_counts().to_dict() if "account" in events else {}
    saved = save_analysis(content_hash=digest, filename=uploaded_file.name, event_count=len(events), alerts=alerts, account_counts=account_counts)
    st.session_state.current_events = events.copy()
    st.session_state.current_alerts = alerts.copy()
    st.session_state.current_filename = uploaded_file.name
    st.session_state.current_analysis_id = saved.get("analysis_id")
    st.session_state.analyses.insert(0, {
        "analysis_id": saved.get("analysis_id"), "filename": uploaded_file.name,
        "analyzed_at": saved.get("analyzed_at", datetime.now().strftime("%Y-%m-%d %H:%M")),
        "events": len(events), "alerts": len(alerts), "data": alerts.copy(),
    })
    st.session_state.analyses = st.session_state.analyses[:20]
    if saved.get("duplicate"):
        st.warning("This exact CSV was already analyzed. SQLite history was not duplicated; the results are shown again for review.")
    else:
        st.success(f"Analysis complete: {len(events):,} events checked, {len(alerts):,} current and historical review signal(s) raised.")

def forget_session_results(analysis_id: int | None = None) -> None:
    """Drop in-memory results for one deleted analysis (or all of them) so they don't linger on screen."""
    if analysis_id is None or st.session_state.get("current_analysis_id") == analysis_id:
        st.session_state.current_events = pd.DataFrame()
        st.session_state.current_alerts = pd.DataFrame()
        st.session_state.current_filename = ""
        st.session_state.current_analysis_id = None
    if analysis_id is None:
        st.session_state.analyses = []
    else:
        st.session_state.analyses = [a for a in st.session_state.analyses if a.get("analysis_id") != analysis_id]

def _sev_class(value: str) -> str:
    v = str(value).lower()
    if v in ("high", "critical", "critical review"):
        return "high"
    if v == "medium":
        return "medium"
    if v == "low":
        return "low"
    return "other"

def _cell(value: Any) -> str:
    return html_lib.escape(str(value)) if str(value).strip() else ""

def incident_table_html(view: pd.DataFrame) -> str:
    rows = []
    for n, (_, r) in enumerate(view.iterrows(), start=1):
        start_t, end_t = str(r["Start time"]).strip(), str(r["End time"]).strip()
        window = f"{start_t} → {end_t}" if start_t and end_t else start_t or end_t
        sev = f'<span class="sev {_sev_class(r["Severity"])}">{_cell(r["Severity"])}</span>' if str(r["Severity"]).strip() else ""
        evidence, rec = str(r["Evidence"]), str(r["Recommendation"])
        rows.append(
            f'<tr><td class="idx">{n:02d}</td><td>{sev}</td><td class="rule">{_cell(r["Rule"])}</td>'
            f'<td class="mono">{_cell(r["Account"])}</td><td class="mono">{_cell(r["Computer"])}</td>'
            f'<td class="mono">{_cell(window)}</td><td class="mono">{_cell(r["Event IDs"])}</td>'
            f'<td><div class="clamp" title="{html_lib.escape(evidence)}">{_cell(evidence)}</div></td>'
            f'<td><div class="clamp" title="{html_lib.escape(rec)}">{_cell(rec)}</div></td></tr>'
        )
    head = "".join(f"<th>{h}</th>" for h in ["#", "Severity", "Rule", "Account", "Computer", "Time window", "Event IDs", "Evidence", "Recommendation"])
    return f'<div class="ltable-wrap"><table class="ltable"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'

def show_incident_table(alerts: pd.DataFrame, key_prefix: str = "incidents") -> None:
    view = normalized_alerts(alerts)
    if view.empty:
        st.info("No incidents to display. Run an analysis or adjust the filters.")
        return
    sevs = sorted(view["Severity"].replace("", "Unrated").unique().tolist())
    f1, f2 = st.columns([3, 2])
    query = f1.text_input("Search incidents", key=f"{key_prefix}_q", placeholder="🔍  Search account, computer, rule or evidence", label_visibility="collapsed")
    chosen = f2.multiselect("Severity filter", sevs, default=sevs, key=f"{key_prefix}_sev_{'|'.join(sevs)}", placeholder="Filter by severity", label_visibility="collapsed")
    shown = view
    if chosen:
        shown = shown[shown["Severity"].replace("", "Unrated").isin(chosen)]
    if query.strip():
        q = query.strip().lower()
        shown = shown[shown.apply(lambda r: q in " ".join(map(str, r.values)).lower(), axis=1)]
    st.caption(f"Showing {len(shown):,} of {len(view):,} review signals · hover truncated text for the full note")
    if shown.empty:
        st.info("No incidents match these filters.")
    else:
        st.markdown(incident_table_html(shown), unsafe_allow_html=True)
    st.download_button("⬇ Download incidents CSV", data=shown.to_csv(index=False).encode("utf-8"),
                       file_name="logshield_incidents.csv", mime="text/csv", key=f"{key_prefix}_download")

REQUIRED_COLS = ["event_id", "timestamp", "account", "computer", "event"]
RULE_CHIPS = ["Failures then success", "Outside lab hours", "Consecutive failures", "Failures over time", "Multi-account failures", "One account, many computers", "Repeat offenders"]

def upload_info_html(uploaded) -> str:
    """Fills the upload panel: quick file stats, column check, and what the detector covers."""
    out = []
    df = None
    if uploaded is not None:
        try:
            df = pd.read_csv(io.BytesIO(uploaded.getvalue()))
        except Exception:
            df = None
    lowered = {str(c).strip().lower(): c for c in df.columns} if df is not None else {}
    if df is not None:
        tiles = [("Rows", f"{len(df):,}"), ("Columns", f"{len(df.columns)}")]
        if "account" in lowered:
            tiles.append(("Accounts", f"{df[lowered['account']].nunique():,}"))
        if "computer" in lowered:
            tiles.append(("Computers", f"{df[lowered['computer']].nunique():,}"))
        out.append('<div class="utiles">' + "".join(f'<div class="utile"><b>{v}</b><span>{k}</span></div>' for k, v in tiles) + "</div>")
        missing = [c for c in REQUIRED_COLS if c not in lowered]
        if missing:
            out.append('<div class="usec">Required columns</div>' + "".join(f'<span class="uchip bad">✕ {c}</span>' for c in missing))
        else:
            out.append('<div class="uok">✓ All required columns found</div>')
    else:
        out.append('<div class="usec">Required columns</div>' + "".join(f'<span class="uchip">{c}</span>' for c in REQUIRED_COLS))
    out.append('<div class="usec">Checks run on every upload</div>' + "".join(f'<span class="uchip">{c}</span>' for c in RULE_CHIPS))
    return "".join(out)

ICONS = {
    "db": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>',
    "shield": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M12 8v5M12 16.5v.01"/></svg>',
    "users": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><path d="M16 4.6a3.5 3.5 0 010 6.8M18 14.4c2 .7 3.5 2.4 3.5 5.6"/></svg>',
    "alert": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M12 5v9M12 19v.01"/></svg>',
}

ICONS.update({
    "clock": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    "layers": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></svg>',
    "net": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8 7.5l3 8M16 7.5l-3 8M8.5 6h7"/></svg>',
    "sliders": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h8M18 6h2M4 12h2M12 12h8M4 18h10M20 18h0"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/></svg>',
})

def _bar(segments: list[tuple[float, str]]) -> str:
    parts = "".join(f'<span style="flex:{c};background:{col}"></span>' for c, col in segments if c > 0)
    return f'<div class="mbar">{parts}</div>'

def _account_set(series: pd.Series) -> set[str]:
    found: set[str] = set()
    for value in series.dropna().astype(str):
        for part in re.split(r"[,;|]", value):
            part = part.strip()
            if part and part != "—":
                found.add(part)
    return found

def _card(label, icon, icon_bg, icon_fg, value, chip, chip_bg, chip_fg, desc, bar) -> str:
    chip_html = f'<span class="mchip" style="background:{chip_bg};color:{chip_fg}">{html_lib.escape(chip)}</span>' if chip else ""
    return (
        f'<div class="mcard"><div class="mtop"><span class="mlabel">{label}</span>'
        f'<span class="micon" style="background:{icon_bg};color:{icon_fg}">{ICONS[icon]}</span></div>'
        f'<div class="mval"><span class="mnum">{value}</span>{chip_html}</div>'
        f'<div class="mdesc">{html_lib.escape(desc)}</div>{bar}</div>'
    )

def metric_cards_html(events: pd.DataFrame, alerts: pd.DataFrame) -> str:
    view = normalized_alerts(alerts)
    sev = view["Severity"].astype(str).str.lower() if not view.empty else pd.Series([], dtype=str)
    crit = int(sev.isin(["critical", "critical review"]).sum())
    high_only = int((sev == "high").sum())
    med = int((sev == "medium").sum())
    low = max(len(sev) - crit - high_only - med, 0)
    hist = int((view["Rule"] == "Previously flagged account observed again").sum()) if not view.empty else 0
    current = len(view) - hist
    rules = int(view["Rule"].nunique()) if not view.empty else 0

    flagged = _account_set(alerts["account"]) if "account" in alerts.columns else (_account_set(alerts["accounts"]) if "accounts" in alerts.columns else set())
    total_accounts = int(events["account"].nunique()) if "account" in events.columns else 0
    affected = len(flagged)
    computers = int(events["computer"].nunique()) if "computer" in events.columns else 0
    flagged_events = int(events["account"].astype(str).str.strip().isin(flagged).sum()) if "account" in events.columns else 0
    rest_events = max(len(events) - flagged_events, 0)

    cards = [
        _card("Events analyzed", "db", "#13323a", "#8fdcff", f"{len(events):,}",
              f"{computers} computers" if computers else "", "#0f3a44", "#8fdcff",
              f"{flagged_events:,} events involve accounts named in findings",
              _bar([(rest_events, "#8fdcff"), (flagged_events, "#b0245a")])),
        _card("Review signals", "shield", "#3a1a2c", "#ff8fa8", f"{len(alerts):,}",
              f"{rules} rule{'s' if rules != 1 else ''}", "#3a1a2c", "#ff8fa8",
              f"{current} current • {hist} historical • Human triage required",
              _bar([(current, "#8fdcff"), (hist, "#b0245a")])),
        _card("Accounts in findings", "users", "#13323a", "#8fdcff", f"{affected:,}",
              f"of {total_accounts} total" if total_accounts else "", "#0f3a44", "#8fdcff",
              "Distinct accounts named in review signals",
              _bar([(affected, "#8ff0b0"), (max(total_accounts - affected, 0), "transparent")])),
        _card("High severity", "alert", "#3a1d1d", "#ff8f8f", f"{crit + high_only:,}",
              f"{crit} Critical", "#3a1d1d", "#ff8f8f",
              f"{high_only} High • {med} Medium • {low} Low • Needs analyst sign-off",
              _bar([(crit, "#ff9a8b"), (high_only, "#b0245a"), (med, "#ffc857"), (low, "#53edc2")])),
    ]
    return '<div class="mgrid">' + "".join(cards) + "</div>"

def repeat_accounts_html(items: list[dict[str, Any]]) -> str:
    cards = []
    for it in items:
        sev = f'<span class="sev {_sev_class(it["max_severity"])}">{html_lib.escape(it["max_severity"])}</span>' if it["max_severity"] else ""
        timeline = it["timeline"]
        strip = "".join(
            f'<span class="rdot {"f" if t["flagged"] else ""}" title="{html_lib.escape(str(t["filename"]))} · {html_lib.escape(str(t["analyzed_at"]))}"></span>'
            for t in timeline)
        rows = ""
        for t in timeline[::-1][:5]:
            tag = f'Flagged · {t["incidents"]} signal{"s" if t["incidents"] != 1 else ""}' if t["flagged"] else "Seen, not flagged"
            rows += (f'<div class="rrow"><span class="rdot {"f" if t["flagged"] else ""}"></span>'
                     f'<span class="rwhen">{html_lib.escape(str(t["analyzed_at"])[:16])}</span>'
                     f'<span class="rfile" title="{html_lib.escape(str(t["filename"]))}">{html_lib.escape(str(t["filename"]))}</span>'
                     f'<span class="rtag {"f" if t["flagged"] else ""}">{tag}</span></div>')
        more = f'<div class="rmore">+{len(timeline) - 5} earlier log(s)</div>' if len(timeline) > 5 else ""
        rules = "".join(f'<span class="uchip">{html_lib.escape(humanize_rule(r))}</span>' for r in it["rules"][:4])
        hot = " hot" if it["flagged_logs"] >= 2 else ""
        red = " red" if it["flagged_logs"] >= 2 else ""
        cards.append(
            f'<div class="racc{hot}"><div class="rhead"><span class="rname">{html_lib.escape(it["account"])}</span>{sev}</div>'
            f'<div class="rbadges"><span class="rbadge{red}">Flagged in {it["flagged_logs"]} log{"s" if it["flagged_logs"] != 1 else ""}</span>'
            f'<span class="rbadge">Seen in {it["logs_seen"]} logs</span><span class="rbadge">{it["incidents"]} signal{"s" if it["incidents"] != 1 else ""}</span></div>'
            f'<div class="rstrip">{strip}</div><div style="margin:8px 0 4px 0">{rules}</div>{rows}{more}</div>')
    return '<div class="rgrid">' + "".join(cards) + "</div>"

# ----------------------------- Sidebar ---------------------------------------
with st.sidebar:
    st.markdown('<div class="sb-brand"><div class="sb-logo">◈</div><div><div class="sb-name">Log<span>Shield</span></div><div class="sb-sub">Authentication monitoring</div></div></div><div class="sb-label">Navigate</div>', unsafe_allow_html=True)
    nav_button("Dashboard", ":material/dashboard:")
    nav_button("Incident History", ":material/history:")
    nav_button("Repeat Accounts", ":material/group:")
    nav_button("Settings", ":material/settings:")
    try:
        _logs_n = len(list_analyses(limit=1000))
        _repeat_n = len(persistent_accounts())
    except Exception:
        _logs_n, _repeat_n = 0, 0
    st.markdown(
        f'<div class="sb-card"><div class="sb-status"><span class="pulse"></span>Monitoring ready</div>'
        f'<div class="sb-stats"><div><b>{_logs_n}</b><span>Logs</span></div><div><b>{_repeat_n}</b><span>Repeat accts</span></div></div></div>'
        '<div class="sb-note">Suspicious patterns are signals for review, not proof of intrusion.</div>'
        '<span class="pill">● Human review only</span>', unsafe_allow_html=True)
    render_sign_out(admin_user)

page = st.session_state.page

# ----------------------------- Dashboard -------------------------------------
if page == "Dashboard":
    st.markdown('<div class="hero"><div class="eyebrow">Authentication telemetry / Overview</div></div>', unsafe_allow_html=True)
    st.title("Security Overview")
    st.caption("Evidence-led authentication monitoring · human review only")
    events = st.session_state.current_events
    alerts = st.session_state.current_alerts
    evaluated = not events.empty and bool(st.session_state.current_filename)

    left, right = st.columns(2, gap="large")
    with left:
        with st.container(border=True, height=560):
            st.subheader("Incident Distribution")
            st.caption("By detection rule · updates after evaluation")
            if evaluated and not alerts.empty:
                chart_data = normalized_alerts(alerts)
                chart_data = chart_data[chart_data["Rule"].astype(str).str.strip().ne("")]
                counts = chart_data["Rule"].value_counts().rename_axis("Detection rule").reset_index(name="Incidents")
                if not counts.empty:
                    components.html(donut_html(counts), height=395)
                else:
                    st.info("No incidents to chart for this evaluation.")
            else:
                st.markdown("<div style='height:300px;display:flex;align-items:center;justify-content:center'><div style='text-align:center'><div style='font-size:3.3rem;color:#1b747b'>◉</div><b style='color:#dffbfc'>AWAITING LOG DATA</b><p style='color:#8db4b9'>Upload and evaluate a CSV to populate this chart with real findings.</p></div></div>", unsafe_allow_html=True)
    with right:
        with st.container(border=True, height=560):
            st.subheader("Upload Log Files")
            st.caption("CSV format · authorized or synthetic authentication logs")
            uploaded = st.file_uploader("Choose a CSV file", type=["csv"], key="dashboard_csv_upload", help="Required columns: event_id, timestamp, account, computer, event.")
            if uploaded is None:
                st.markdown("<div style='border:1px dashed #1b747b;border-radius:12px;padding:14px 10px;text-align:center;background:#061b1f;margin:4px 0 8px 0'><div style='font-size:1.8rem;color:#20e5ed;line-height:1.2'>⇧</div><b style='color:#dffbfc'>No file uploaded yet</b><p style='color:#8db4b9;margin:2px 0 0 0'>Choose a CSV above to begin security analysis.</p></div>", unsafe_allow_html=True)
                st.caption("Raw CSV rows are processed in memory and are not saved to the history database.")
            else:
                st.markdown(f"**Selected:** `{uploaded.name}` · {uploaded.size:,} bytes")
                if st.button("Evaluate Logs", type="primary", key="dashboard_run_analysis", use_container_width=True):
                    run_analysis(uploaded)
                    st.rerun()
            st.markdown(upload_info_html(uploaded), unsafe_allow_html=True)

    if evaluated:
        st.markdown("")
        st.markdown(metric_cards_html(events, alerts), unsafe_allow_html=True)
        try:
            _persist = persistent_accounts()
        except Exception:
            _persist = []
        _cur = {str(a).strip().casefold() for a in events["account"].dropna().unique()} if "account" in events.columns else set()
        _hits = [x for x in _persist if x["key"] in _cur]
        if _hits:
            st.markdown(f'<div class="alert-note">⚠ {len(_hits)} account(s) in this log were flagged in an earlier upload and keep reappearing across logs. Open <b>Repeat Accounts</b> in the sidebar to review them.</div>', unsafe_allow_html=True)
        with st.container(border=True):
            activity_title, activity_meta = st.columns([3, 1])
            activity_title.subheader("Log Analysis Summary")
            activity_title.caption(f"Evaluation complete · {st.session_state.current_filename}")
            activity_meta.markdown(f'<div style="text-align:right;padding-top:8px"><span class="pill">{len(alerts):,} REVIEW SIGNALS</span></div>', unsafe_allow_html=True)
            if alerts.empty:
                st.success("No configured detection rules were triggered. This does not guarantee that all activity is safe.")
            else:
                nview = normalized_alerts(alerts).head(8)
                for _, row in nview.iterrows():
                    severity = str(row["Severity"]).lower()
                    color = "#ff4d4f" if severity in ("high", "critical", "critical review") else "#ff8c42" if severity == "medium" else "#ffd166"
                    meta = " · ".join(x for x in [f"Account: {html_lib.escape(str(row['Account']))}" if row["Account"] else "", f"Computer: {html_lib.escape(str(row['Computer']))}" if row["Computer"] else ""] if x)
                    meta_html = f"<br><span style='color:#8db4b9;font-size:.86rem'>{meta}</span>" if meta else ""
                    ev_html = f"<br><span style='color:#8db4b9;font-size:.84rem'>{html_lib.escape(str(row['Evidence']))}</span>" if row["Evidence"] else ""
                    sev_html = f"<span style='color:{color};font-weight:700'>{html_lib.escape(str(row['Severity']))}</span> &nbsp; " if row["Severity"] else ""
                    card = f"<div class='sigcard' style='border:1px solid #12454b;border-left:4px solid {color};background:#061c20;border-radius:9px;padding:12px 15px;margin:8px 0'>{sev_html}<span style='color:#dffbfc;font-weight:600'>{html_lib.escape(str(row['Rule']))}</span>{meta_html}{ev_html}</div>"
                    st.markdown(card, unsafe_allow_html=True)
                if len(alerts) > 8:
                    st.caption(f"Showing 8 of {len(alerts):,} review signals. See Incidents for Review below for all details.")
        with st.container(border=True):
            st.subheader("Incidents for Review")
            st.caption("Check the evidence and history context before drawing conclusions.")
            show_incident_table(alerts, "dashboard")
    else:
        st.info("Upload a CSV and select **Evaluate Logs**. The detailed analysis will appear below these two panels after successful evaluation.")

# ----------------------------- Analyze Logs (legacy state) -------------------
elif page == "Analyze Logs":
    # Backward compatibility for a session that retained the old page selection.
    st.session_state.page = "Dashboard"
    st.session_state.show_upload = True
    st.rerun()

# ----------------------------- History ---------------------------------------
elif page == "Incident History":
    st.title("Incident History")
    st.caption("Persistent SQLite history across app restarts. Only analysis metadata and incident records are stored; raw uploaded CSVs are not saved.")
    if st.session_state.get("hist_msg"):
        st.success(st.session_state.pop("hist_msg"))
    history_rows = list_analyses(limit=100)
    if not history_rows:
        st.info("No saved analyses yet. Upload and evaluate a CSV from the Dashboard.")
    else:
        hist = pd.DataFrame([{
            "Analysis ID": item["id"], "Analyzed at": item["analyzed_at"],
            "Source file": item["filename"], "Events": item["event_count"], "Review signals": item["alert_count"],
        } for item in history_rows])
        st.dataframe(hist, use_container_width=True, hide_index=True)
        options = {f"#{item['id']} · {item['analyzed_at']} — {item['filename']}": item["id"] for item in history_rows}
        selected = st.selectbox("View a saved analysis", list(options.keys()))
        show_incident_table(get_analysis_incidents(options[selected]), "history")

        # ---- Delete history (admin only; the whole app is behind the login gate)
        hv = st.session_state.get("hist_ver", 0)
        sel_id = options[selected]
        with st.container(border=True):
            st.subheader("Delete history")
            st.caption(f"Removes the analysis selected above ({selected}) and its incidents. This can't be undone.")
            ok_one = st.checkbox("I understand this can't be undone", key=f"hist_ok_one_{hv}")
            if st.button("Delete this analysis", key=f"hist_del_one_{hv}", disabled=not ok_one):
                delete_analysis(sel_id)
                forget_session_results(sel_id)
                st.session_state.hist_msg = f"Deleted analysis #{sel_id}."
                st.session_state.hist_ver = hv + 1
                st.rerun()

# ----------------------------- Repeat accounts -------------------------------
elif page == "Repeat Accounts":
    st.title("Repeat Accounts")
    st.caption("Accounts flagged in a previously uploaded log that keep appearing in other logs · review prompts, not proof of intrusion")
    items = persistent_accounts()
    logs_tracked = len(list_analyses(limit=1000))
    if not items:
        st.info("No persistent accounts yet. An account shows up here once it was flagged in one uploaded log and also appears in at least one other log.")
        st.caption(f"{logs_tracked} log(s) tracked so far.")
    else:
        multi = sum(1 for x in items if x["flagged_logs"] >= 2)
        st.markdown('<div class="mgrid">' + "".join([
            _card("Persistent accounts", "users", "#13323a", "#8fdcff", f"{len(items):,}", "", "#0f3a44", "#8fdcff",
                  "Flagged in an earlier log and present in other uploads",
                  _bar([(multi, "#ff9a8b"), (len(items) - multi, "#8fdcff")])),
            _card("Flagged in 2+ logs", "alert", "#3a1d1d", "#ff8f8f", f"{multi:,}", "Recurring", "#3a1d1d", "#ff8f8f",
                  "Accounts with real findings in more than one upload",
                  _bar([(multi, "#ff9a8b"), (max(len(items) - multi, 0), "transparent")])),
            _card("Logs tracked", "db", "#13323a", "#8fdcff", f"{logs_tracked:,}", "", "#0f3a44", "#8fdcff",
                  "Distinct uploads in the history database", _bar([(1, "#8fdcff")])),
        ]) + "</div>", unsafe_allow_html=True)
        f1, f2 = st.columns([3, 2])
        query = f1.text_input("Search accounts", key="repeat_q", placeholder="🔍  Search account or rule", label_visibility="collapsed")
        only_multi = f2.checkbox("Only accounts flagged in 2+ logs", key="repeat_multi")
        shown = [x for x in items if (not only_multi or x["flagged_logs"] >= 2)
                 and (not query.strip() or query.strip().lower() in (x["account"] + " " + " ".join(x["rules"])).lower())]
        st.caption(f"Showing {len(shown):,} of {len(items):,} persistent account(s) · red dots = log where the account was flagged, blue = seen without findings")
        if shown:
            st.markdown(repeat_accounts_html(shown), unsafe_allow_html=True)
            export = pd.DataFrame([{
                "Account": x["account"], "Logs seen": x["logs_seen"], "Logs flagged": x["flagged_logs"],
                "Signals": x["incidents"], "Highest severity": x["max_severity"],
                "Rules": "; ".join(humanize_rule(r) for r in x["rules"]), "First seen": x["first_seen"], "Last seen": x["last_seen"],
            } for x in shown])
            st.download_button("⬇ Download repeat accounts CSV", data=export.to_csv(index=False).encode("utf-8"),
                               file_name="logshield_repeat_accounts.csv", mime="text/csv", key="repeat_download")
        else:
            st.info("No accounts match these filters.")
    st.caption("For this view LogShield stores account IDs and per-log event counts only. Logs analysed before this feature count where the account was flagged.")

# ----------------------------- Settings --------------------------------------
elif page == "Settings":
    st.markdown('<div class="hero"><div class="eyebrow">Detector configuration / Settings</div></div>', unsafe_allow_html=True)
    st.title("Detection Settings")
    st.caption("The essentials are up front · fine-tuning is tucked away under Advanced")
    current = st.session_state.settings
    if st.session_state.pop("settings_saved", False):
        st.success("Settings saved for this session. Run a new analysis to apply them.")
    if not current:
        st.warning("No DEFAULT_SETTINGS dictionary was exported by detector.py. The detector's current defaults remain active.")
        st.code("DEFAULT_SETTINGS = {...}", language="python")
        st.caption("Expose the detector's supported settings before adding controls here; avoid inventing setting keys.")
    else:
        ver = st.session_state.get("settings_ver", 0)

        def _int(key, default=0):
            try:
                return int(current.get(key, default))
            except (TypeError, ValueError):
                return default

        def num(container, key, label, help=None, minimum=1):
            return container.number_input(label, value=_int(key), min_value=minimum, step=1, key=f"set_{ver}_{key}", help=help)

        # ---- Lab holidays (saved immediately, independent of the Save button below)
        holidays_now = load_holidays()
        hver = st.session_state.get("hol_ver", 0)
        with st.container(border=True):
            st.subheader("Lab holidays")
            st.caption("Days the lab is closed. Any successful login on these days is flagged for review, even during normal hours.")
            h1, h2, h3 = st.columns([2, 2, 1])
            picked = h1.date_input("Day or range", value=(date.today(), date.today()), key=f"hol_pick_{hver}", help="Pick one day, or click two dates for a range.")
            hol_label = h2.text_input("Label (optional)", placeholder="e.g. Diwali", key=f"hol_label_{hver}")
            h3.markdown("<div style='height:1.85rem'></div>", unsafe_allow_html=True)
            if h3.button("Add", key=f"hol_add_{hver}", use_container_width=True):
                days = [picked] if isinstance(picked, date) else list(picked)
                if not days:
                    st.warning("Pick a day first.")
                else:
                    start_d, end_d = days[0], days[-1]
                    if (end_d - start_d).days > 366:
                        st.error("Pick a range of up to one year.")
                    else:
                        for offset in range((end_d - start_d).days + 1):
                            holidays_now[(start_d + timedelta(days=offset)).isoformat()] = hol_label.strip()
                        save_holidays(holidays_now)
                        st.session_state.hol_ver = hver + 1
                        st.rerun()
            if holidays_now:
                st.markdown("".join(f'<span class="uchip">{html_lib.escape(holiday_text(k, v))}</span>' for k, v in sorted(holidays_now.items())), unsafe_allow_html=True)
                r1, r2 = st.columns([4, 1])
                to_remove = r1.multiselect("Remove holidays", options=sorted(holidays_now), format_func=lambda k: holiday_text(k, holidays_now.get(k, "")),
                                           key=f"hol_remove_{hver}", placeholder="Choose days to remove")
                r2.markdown("<div style='height:1.85rem'></div>", unsafe_allow_html=True)
                if r2.button("Remove", key=f"hol_rm_{hver}", use_container_width=True) and to_remove:
                    save_holidays({k: v for k, v in holidays_now.items() if k not in to_remove})
                    st.session_state.hol_ver = hver + 1
                    st.rerun()
            else:
                st.caption("No holidays set yet.")

        with st.form("settings_form"):
            updated: dict[str, Any] = {}

            with st.container(border=True):
                st.subheader("Core rules")
                c1, c2 = st.columns(2)
                if "failure_success_threshold" in current:
                    updated["failure_success_threshold"] = num(c1, "failure_success_threshold", "Failures before a success is flagged", "A success after this many failures on the same account and computer is raised for review.")
                if "failure_success_window_minutes" in current:
                    updated["failure_success_window_minutes"] = num(c2, "failure_success_window_minutes", "…within (minutes)")
                if "lab_opening_hour" in current and "lab_closing_hour" in current:
                    c3, c4 = st.columns(2)
                    opens = c3.time_input("Lab opens", value=dtime(_int("lab_opening_hour", 8), _int("lab_opening_minute")), key=f"set_{ver}_opens", help="Successful logins outside lab hours are flagged.")
                    closes = c4.time_input("Lab closes", value=dtime(_int("lab_closing_hour", 18), _int("lab_closing_minute")), key=f"set_{ver}_closes")
                    updated.update({"lab_opening_hour": opens.hour, "lab_opening_minute": opens.minute,
                                    "lab_closing_hour": closes.hour, "lab_closing_minute": closes.minute})
                if "deduplicate_overlapping_alerts" in current:
                    updated["deduplicate_overlapping_alerts"] = st.toggle(
                        "Merge overlapping alerts into one incident", value=bool(current["deduplicate_overlapping_alerts"]),
                        key=f"set_{ver}_dedupe", help="Alerts that share the same event evidence are combined.")

            with st.expander("Advanced thresholds"):
                if "consecutive_medium_threshold" in current:
                    st.markdown('<div class="sset">Consecutive failed logins · severity steps</div>', unsafe_allow_html=True)
                    a1, a2, a3 = st.columns(3)
                    updated["consecutive_medium_threshold"] = num(a1, "consecutive_medium_threshold", "Medium at")
                    updated["consecutive_high_threshold"] = num(a2, "consecutive_high_threshold", "High at")
                    updated["consecutive_critical_threshold"] = num(a3, "consecutive_critical_threshold", "Critical at")
                if "cross_account_window_minutes" in current:
                    st.markdown('<div class="sset">Many accounts failing on one computer</div>', unsafe_allow_html=True)
                    b1, b2, b3 = st.columns(3)
                    updated["cross_account_window_minutes"] = num(b1, "cross_account_window_minutes", "Window (min)")
                    updated["cross_account_min_accounts"] = num(b2, "cross_account_min_accounts", "Accounts", minimum=2)
                    updated["cross_account_min_failures"] = num(b3, "cross_account_min_failures", "Failures")
                if "cross_machine_window_minutes" in current:
                    st.markdown('<div class="sset">One account failing on many computers</div>', unsafe_allow_html=True)
                    d1, d2, d3 = st.columns(3)
                    updated["cross_machine_window_minutes"] = num(d1, "cross_machine_window_minutes", "Window (min)")
                    updated["cross_machine_min_computers"] = num(d2, "cross_machine_min_computers", "Computers", minimum=2)
                    updated["cross_machine_min_failures"] = num(d3, "cross_machine_min_failures", "Failures")
                windows = current.get("rolling_windows") if isinstance(current.get("rolling_windows"), list) else []
                new_thresholds: list[int] = []
                if windows:
                    st.markdown('<div class="sset">Failures over time · alert at</div>', unsafe_allow_html=True)
                    for col, w in zip(st.columns(len(windows)), windows):
                        new_thresholds.append(col.number_input(f"In {w.get('label', '')}", value=int(w.get("threshold", 1)), min_value=1, step=1,
                                                               key=f"set_{ver}_roll_{w.get('minutes')}"))

            b_save, b_reset, _sp = st.columns([1, 1, 2])
            save = b_save.form_submit_button("Save settings", type="primary", use_container_width=True)
            reset = b_reset.form_submit_button("Reset to defaults", use_container_width=True)

        if reset:
            st.session_state.settings = dict(DEFAULT_SETTINGS)
            st.session_state.settings_ver = ver + 1
            st.session_state.settings_saved = True
            st.rerun()
        if save:
            candidate = dict(current)
            candidate.update(updated)
            if windows:
                candidate["rolling_windows"] = [{**w, "threshold": int(t)} for w, t in zip(windows, new_thresholds)]
            try:
                if validate_settings is not None:
                    candidate = validate_settings(candidate)
            except (ValueError, KeyError, TypeError) as exc:
                st.error(f"These settings were not saved: {exc}")
            else:
                st.session_state.settings = candidate
                st.session_state.settings_saved = True
                st.rerun()
    st.markdown('<div class="alert-note">LogShield supports analyst review only. It does not block accounts or prove malicious intent.</div>', unsafe_allow_html=True)