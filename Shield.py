from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from detector import analyze_events
from validator import validate_csv

try:
    from detector import DEFAULT_SETTINGS
except ImportError:
    DEFAULT_SETTINGS = {}

st.set_page_config(
    page_title="LogShield | Security Overview",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------- Theme -----------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
    :root {
      --bg: #031316; --panel: #061e22; --panel2: #08272b;
      --border: #11515a; --cyan: #20e5ed; --mint: #53edc2;
      --text: #e7fbfc; --muted: #8db4b9; --pink: #ff557b;
      --amber: #ffc857; --blue: #35c9ff;
    }
    html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
    .stApp { background: radial-gradient(ellipse at 75% 0%, #073238 0%, var(--bg) 48%); color: var(--text); }
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
    hr { border-color:#123e44; }
    </style>
    """,
    unsafe_allow_html=True,
)

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

# ----------------------------- Helpers ---------------------------------------
def nav_button(label: str, icon: str) -> None:
    if st.sidebar.button(f"{icon}  {label}", key=f"nav_{label}", use_container_width=True):
        st.session_state.page = label

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

def alert_column(frame: pd.DataFrame, names: list[str], fallback: str = "—") -> pd.Series:
    series = first_existing(frame, names)
    if series is None:
        return pd.Series([fallback] * len(frame), index=frame.index)
    return series.fillna(fallback).astype(str)

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
    return out.reset_index(drop=True)

def run_analysis(uploaded_file) -> None:
    try:
        uploaded_file.seek(0)
        validation = validate_csv(uploaded_file)
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
        # Detection thresholds are held in session state for the Settings page.
        # Existing detector settings are passed only when the signature supports it.
        try:
            alerts = analyze_events(events, st.session_state.settings)
        except TypeError:
            alerts = analyze_events(events)
        if not isinstance(alerts, pd.DataFrame):
            alerts = pd.DataFrame(alerts)
    except Exception as exc:
        st.error(f"Analysis could not be completed: {exc}")
        st.caption("If this persists, check the function signature in detector.py.")
        return

    st.session_state.current_events = events.copy()
    st.session_state.current_alerts = alerts.copy()
    st.session_state.current_filename = uploaded_file.name
    st.session_state.analyses.insert(0, {
        "filename": uploaded_file.name,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "events": len(events),
        "alerts": len(alerts),
        "data": alerts.copy(),
    })
    st.session_state.analyses = st.session_state.analyses[:20]
    st.success(f"Analysis complete: {len(events):,} events checked and {len(alerts):,} alerts raised.")

def show_incident_table(alerts: pd.DataFrame, key_prefix: str = "incidents") -> None:
    view = normalized_alerts(alerts)
    if view.empty:
        st.info("No incidents to display. Run an analysis or adjust the filters.")
        return
    view.insert(0, "#", range(1, len(view) + 1))
    st.dataframe(view, use_container_width=True, hide_index=True, height=340)
    csv = view.to_csv(index=False).encode("utf-8")
    st.download_button("⬇ Download incidents CSV", data=csv, file_name="logshield_incidents.csv",
                       mime="text/csv", key=f"{key_prefix}_download")

# ----------------------------- Sidebar ---------------------------------------
with st.sidebar:
    st.markdown('<div class="sidebar-brand">◈ Log<span>Shield</span></div>', unsafe_allow_html=True)
    st.caption("AUTHENTICATION MONITORING")
    st.markdown("---")
    nav_button("Dashboard", "▦")
    nav_button("Analyze Logs", "▤")
    nav_button("Incident History", "◷")
    nav_button("Settings", "⚙")
    st.markdown("---")
    st.markdown('<span class="pill">● Human review only</span>', unsafe_allow_html=True)
    st.caption("Suspicious patterns are signals for review, not proof of intrusion.")

page = st.session_state.page

# ----------------------------- Dashboard -------------------------------------
if page == "Dashboard":
    st.markdown('<div class="hero"><div class="eyebrow">Authentication telemetry / Overview</div></div>', unsafe_allow_html=True)
    title_col, status_col = st.columns([3, 1])
    with title_col:
        st.title("Security Overview")
        st.caption("Authentication telemetry and incident review")
    with status_col:
        st.markdown('<div style="text-align:right;padding-top:14px"><span class="pill">● SYSTEM READY</span></div>', unsafe_allow_html=True)

    events = st.session_state.current_events
    alerts = st.session_state.current_alerts
    demo = events.empty
    if demo:
        st.info("Preview mode: upload a synthetic CSV in **Analyze Logs** to replace these illustrative empty-state metrics with real analysis results.")
    high = 0
    if not alerts.empty and "severity" in alerts.columns:
        high = int(alerts["severity"].astype(str).str.lower().isin(["high", "critical"]).sum())
    affected = safe_count(alerts, ["account", "accounts"])
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events analyzed", f"{len(events):,}", help="Events in the most recent successful analysis.")
    c2.metric("Incidents detected", f"{len(alerts):,}", help="Alerts produced by the configured rules.")
    c3.metric("Accounts affected", f"{affected:,}", help="Unique accounts represented in the alerts.")
    c4.metric("High severity", f"{high:,}", help="Alerts marked high or critical by the detector.")

    left, right = st.columns([1.0, 1.25], gap="medium")
    with left:
        with st.container(border=True):
            st.subheader("Login Event Distribution")
            if not events.empty and "event" in events.columns:
                dist = events["event"].astype(str).str.lower().value_counts().rename_axis("Event").reset_index(name="Count")
                fig = px.pie(dist, names="Event", values="Count", hole=.68,
                             color_discrete_sequence=["#53edc2", "#20cde5", "#ffc857", "#ff557b"])
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#dffbfc", margin=dict(l=5,r=5,t=10,b=5),
                    legend=dict(orientation="h", yanchor="bottom", y=-.12, xanchor="center", x=.5),
                    height=300,
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.markdown("### <span style='color:#20e5ed'>◉</span> No event data yet", unsafe_allow_html=True)
                st.caption("Your event distribution chart will appear here after analysis.")
    with right:
        with st.container(border=True):
            st.subheader("Recent Security Activity")
            if alerts.empty:
                st.caption("No alerts yet. Analyze a synthetic CSV to populate this feed.")
            else:
                nview = normalized_alerts(alerts).head(6)
                for _, row in nview.iterrows():
                    severity = str(row["Severity"]).lower()
                    color = "#ff557b" if severity in ("high", "critical") else "#ffc857" if severity == "medium" else "#20e5ed"
                    st.markdown(
                        f"""<div style="border:1px solid #12454b;border-left:3px solid {color};background:#061c20;border-radius:9px;padding:10px 12px;margin:7px 0">
                        <span style="color:{color};font-weight:700">{row['Severity']}</span>
                        &nbsp; <span style="color:#dffbfc">{row['Rule']}</span><br>
                        <span style="color:#8db4b9;font-size:0.83rem">{row['Account']} · {row['Computer']} · {row['Start time']}</span>
                        </div>""", unsafe_allow_html=True
                    )

    st.markdown("")
    with st.container(border=True):
        title_col, button_col = st.columns([3, 1])
        title_col.subheader("Incidents for Review")
        title_col.caption("Review supporting evidence before drawing conclusions.")
        if button_col.button("Analyze new logs →", use_container_width=True):
            st.session_state.page = "Analyze Logs"
            st.rerun()
        show_incident_table(alerts, "dashboard")

# ----------------------------- Analyze Logs ----------------------------------
elif page == "Analyze Logs":
    st.title("Analyze Logs")
    st.caption("Upload a synthetic authentication CSV, validate it, and run the detection rules.")
    with st.container(border=True):
        uploaded = st.file_uploader("Choose a CSV file", type=["csv"], help="Expected columns include event_id, timestamp, account, computer, and event.")
        st.caption("Use synthetic or authorized logs only. CSV validity does not prove authenticity or completeness.")
        if uploaded is not None:
            st.write(f"Selected file: **{uploaded.name}** · {uploaded.size:,} bytes")
            if st.button("Run Security Analysis", type="primary", use_container_width=True):
                run_analysis(uploaded)
    if not st.session_state.current_alerts.empty or not st.session_state.current_events.empty:
        st.markdown("### Latest analysis")
        a, b, c = st.columns(3)
        a.metric("Events analyzed", f"{len(st.session_state.current_events):,}")
        b.metric("Alerts detected", f"{len(st.session_state.current_alerts):,}")
        c.metric("Source file", st.session_state.current_filename or "—")
        show_incident_table(st.session_state.current_alerts, "analysis")

# ----------------------------- History ---------------------------------------
elif page == "Incident History":
    st.title("Incident History")
    st.caption("Previous analyses in this active session. History resets when the app session is cleared.")
    if not st.session_state.analyses:
        st.info("No analysis history yet. Upload a CSV in Analyze Logs to begin.")
    else:
        hist = pd.DataFrame([{
            "Analyzed at": item["analyzed_at"],
            "Source file": item["filename"],
            "Events": item["events"],
            "Alerts": item["alerts"],
        } for item in st.session_state.analyses])
        st.dataframe(hist, use_container_width=True, hide_index=True)
        choices = [f"{item['analyzed_at']} — {item['filename']}" for item in st.session_state.analyses]
        selected = st.selectbox("View an analysis", choices)
        idx = choices.index(selected)
        show_incident_table(st.session_state.analyses[idx]["data"], "history")

# ----------------------------- Settings --------------------------------------
elif page == "Settings":
    st.title("Detection Settings")
    st.caption("Adjust available detector settings. Changes apply to future analyses in this session.")
    current = st.session_state.settings
    if not current:
        st.warning("No DEFAULT_SETTINGS dictionary was exported by detector.py. The detector's current defaults remain active.")
        st.code("DEFAULT_SETTINGS = {...}", language="python")
        st.caption("Expose the detector's supported settings before adding controls here; avoid inventing setting keys.")
    else:
        with st.form("settings_form"):
            updated = {}
            for key, value in current.items():
                label = key.replace("_", " ").title()
                if isinstance(value, bool):
                    updated[key] = st.checkbox(label, value=value)
                elif isinstance(value, int):
                    updated[key] = st.number_input(label, value=value, step=1)
                elif isinstance(value, float):
                    updated[key] = st.number_input(label, value=value)
                elif isinstance(value, str):
                    updated[key] = st.text_input(label, value=value)
                else:
                    st.caption(f"{label}: {value} (not editable in this form)")
                    updated[key] = value
            saved = st.form_submit_button("Save settings", use_container_width=True)
            if saved:
                st.session_state.settings = updated
                st.success("Settings saved for this session. Run a new analysis to apply them.")
    st.markdown("---")
    st.markdown('<div class="alert-note">LogShield supports analyst review only. It does not block accounts or prove malicious intent.</div>', unsafe_allow_html=True)
