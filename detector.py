"""Explainable authentication-log detection for Cyber Sentinels."""
from __future__ import annotations
from datetime import time
from typing import Any
import pandas as pd

DEFAULT_SETTINGS: dict[str, Any] = {
    "failure_success_threshold": 3,
    "failure_success_window_minutes": 10,
    "lab_opening_hour": 8, "lab_opening_minute": 0,
    "lab_closing_hour": 18, "lab_closing_minute": 0,
    # Lab holidays: {"YYYY-MM-DD": "optional label"}. Any successful login on these days is flagged.
    "holidays": {},
    "consecutive_medium_threshold": 5,
    "consecutive_high_threshold": 8,
    "consecutive_critical_threshold": 10,
    "rolling_windows": [
        {"label": "10 minutes", "minutes": 10, "threshold": 5},
        {"label": "1 hour", "minutes": 60, "threshold": 10},
        {"label": "24 hours", "minutes": 1440, "threshold": 20},
    ],
    "cross_account_window_minutes": 10,
    "cross_account_min_accounts": 3,
    "cross_account_min_failures": 6,
    "cross_machine_window_minutes": 10,
    "cross_machine_min_computers": 3,
    "cross_machine_min_failures": 5,
    "deduplicate_overlapping_alerts": True,
}
RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical Review": 4}
REQUIRED = {"event_id", "timestamp", "account", "computer", "event"}

def get_settings(settings=None):
    cfg = dict(DEFAULT_SETTINGS)
    if settings:
        cfg.update(settings)
    cfg["rolling_windows"] = [dict(x) for x in cfg.get("rolling_windows", [])]
    return cfg

def _normalize_holidays(raw) -> dict[str, str]:
    """Accept None, a list/set of dates, or a {date: label} mapping; return {ISO date: label}."""
    if not raw:
        return {}
    items = raw.items() if isinstance(raw, dict) else [(x, "") for x in raw]
    out: dict[str, str] = {}
    for day, label in items:
        try:
            iso = pd.Timestamp(day).date().isoformat()
        except (ValueError, TypeError):
            raise ValueError(f"Invalid holiday date: {day!r}")
        out[iso] = str(label or "").strip()
    return dict(sorted(out.items()))

def validate_settings(settings=None):
    cfg = get_settings(settings)
    positive = [
        "failure_success_threshold", "failure_success_window_minutes",
        "consecutive_medium_threshold", "consecutive_high_threshold",
        "consecutive_critical_threshold", "cross_account_window_minutes",
        "cross_account_min_accounts", "cross_account_min_failures",
        "cross_machine_window_minutes", "cross_machine_min_computers",
        "cross_machine_min_failures",
    ]
    for key in positive:
        cfg[key] = int(cfg[key])
        minimum = 2 if key in {"cross_account_min_accounts", "cross_machine_min_computers"} else 1
        if cfg[key] < minimum:
            raise ValueError(f"Setting '{key}' must be at least {minimum}.")
    if not (cfg["consecutive_medium_threshold"] < cfg["consecutive_high_threshold"] < cfg["consecutive_critical_threshold"]):
        raise ValueError("Consecutive severity thresholds must increase: medium < high < critical.")
    for prefix in ("lab_opening", "lab_closing"):
        h, m = int(cfg[f"{prefix}_hour"]), int(cfg[f"{prefix}_minute"])
        if not 0 <= h <= 23 or not 0 <= m <= 59:
            raise ValueError(f"Invalid {prefix} time.")
        cfg[f"{prefix}_hour"], cfg[f"{prefix}_minute"] = h, m
    cfg["holidays"] = _normalize_holidays(cfg.get("holidays"))
    labels = set()
    for item in cfg["rolling_windows"]:
        item["minutes"], item["threshold"] = int(item["minutes"]), int(item["threshold"])
        item["label"] = str(item.get("label", f'{item["minutes"]} minutes'))
        if item["minutes"] < 1 or item["threshold"] < 1:
            raise ValueError("Rolling-window minutes and thresholds must be positive.")
        if item["label"] in labels:
            raise ValueError(f"Duplicate rolling-window label: {item['label']}")
        labels.add(item["label"])
    return cfg

def _clock(cfg, prefix):
    return time(cfg[f"{prefix}_hour"], cfg[f"{prefix}_minute"])

def _alert(rule_id, rule, severity, account, computer, start, end, ids, explanation, recommendation, signal, department_case=None):
    return {
        "incident_id": None, "rule_id": rule_id, "rule": rule, "severity": severity,
        "account": account, "computer": computer, "start_time": pd.Timestamp(start).isoformat(),
        "end_time": pd.Timestamp(end).isoformat(), "event_ids": list(dict.fromkeys(map(str, ids))),
        "event_count": len(set(map(str, ids))), "explanation": explanation,
        "recommendation": recommendation, "signal": signal,
        "department_case": department_case, "signals": [],
    }

def _merge_single_scope_alerts(alerts):
    """Merge single-account/computer alerts only when they share event evidence."""
    out = []
    for a in sorted(alerts, key=lambda x: (x["start_time"], x["rule_id"])):
        match = None
        if a["account"] is not None and a["computer"] is not None:
            for old in reversed(out):
                if old["account"] == a["account"] and old["computer"] == a["computer"] and set(old["event_ids"]) & set(a["event_ids"]):
                    match = old
                    break
        if match is None:
            a = dict(a)
            if not a["signals"]:
                a["signals"] = [{"rule_id": a["rule_id"], "rule": a["rule"], "explanation": a["explanation"], "recommendation": a["recommendation"]}]
            out.append(a)
            continue
        match["event_ids"] = list(dict.fromkeys(match["event_ids"] + a["event_ids"]))
        match["event_count"] = len(match["event_ids"])
        match["start_time"] = min(match["start_time"], a["start_time"])
        match["end_time"] = max(match["end_time"], a["end_time"])
        if RANK.get(a["severity"], 0) > RANK.get(match["severity"], 0):
            match["severity"] = a["severity"]
        match["signals"].append({"rule_id": a["rule_id"], "rule": a["rule"], "explanation": a["explanation"], "recommendation": a["recommendation"]})
        match["rule_id"], match["rule"] = "MULTI", "Multiple detection signals"
        match["explanation"] = "Multiple rules flagged overlapping authentication events."
        match["recommendation"] = "Review the combined event timeline and verify the activity with the authorized account owner or lab administrator."
    return out

def _out_columns():
    return ["incident_id", "rule_id", "rule", "severity", "account", "computer", "start_time", "end_time",
            "event_ids", "event_count", "explanation", "recommendation", "signal", "department_case", "signals"]

def analyze_events(df: pd.DataFrame, settings: dict[str, Any] | None = None) -> pd.DataFrame:
    """Analyze validated synthetic events; returns explainable alerts for human review."""
    cfg = validate_settings(settings)
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    if df.empty:
        return pd.DataFrame(columns=_out_columns())
    w = df.copy()
    w["timestamp"] = pd.to_datetime(w["timestamp"], errors="coerce")
    if w["timestamp"].isna().any():
        raise ValueError("Invalid timestamps found; validate the CSV before analysis.")
    for col in ("event_id", "account", "computer", "event"):
        if w[col].isna().any():
            raise ValueError(f"Missing values in '{col}'; validate the CSV before analysis.")
        w[col] = w[col].astype(str).str.strip()
    w["event"] = w["event"].str.lower()
    invalid = sorted(set(w.loc[~w["event"].isin(["success", "failure"]), "event"]))
    if invalid:
        raise ValueError("Unsupported event values: " + ", ".join(invalid))
    w = w.sort_values(["timestamp", "event_id"], kind="stable").reset_index(drop=True)
    alerts = []
    fails, successes = w[w.event == "failure"], w[w.event == "success"]

    # R1: repeated failures followed by success for the same account and computer.
    threshold = cfg["failure_success_threshold"]
    window = pd.Timedelta(minutes=cfg["failure_success_window_minutes"])
    for (account, computer), g in w.groupby(["account", "computer"], sort=False):
        streak = []
        for _, row in g.iterrows():
            if row.event == "failure":
                streak = [x for x in streak if row.timestamp - x.timestamp <= window]
                streak.append(row)
            else:
                relevant = [x for x in streak if pd.Timedelta(0) <= row.timestamp - x.timestamp <= window]
                if len(relevant) >= threshold:
                    alerts.append(_alert("R1", "Repeated failures followed by success", "High", account, computer,
                        relevant[0].timestamp, row.timestamp, [x.event_id for x in relevant] + [row.event_id],
                        f"{len(relevant)} failed login(s) were followed by success within {cfg['failure_success_window_minutes']} minutes.",
                        "Verify the successful login with the account owner and review the supporting failed attempts.",
                        "failure_then_success", row.get("department_case")))
                streak = []

    # R2: successful login on a lab holiday, or outside lab hours; opening inclusive, closing exclusive.
    opening, closing = _clock(cfg, "lab_opening"), _clock(cfg, "lab_closing")
    holidays = cfg["holidays"]
    for _, row in successes.iterrows():
        day = row.timestamp.date().isoformat()
        if day in holidays:
            label = f" ({holidays[day]})" if holidays[day] else ""
            alerts.append(_alert("R2", "Successful login outside lab hours", "Medium", row.account, row.computer,
                row.timestamp, row.timestamp, [row.event_id],
                f"Successful login on {day}{label}, which is configured as a lab holiday.",
                "Confirm whether access on a lab holiday was authorized with the lab administrator.",
                "lab_holiday", row.get("department_case")))
            continue
        t = row.timestamp.time()
        in_hours = opening <= t < closing if opening < closing else (t >= opening or t < closing)
        if not in_hours:
            alerts.append(_alert("R2", "Successful login outside lab hours", "Medium", row.account, row.computer,
                row.timestamp, row.timestamp, [row.event_id],
                f"Successful login at {t.strftime('%H:%M:%S')} is outside configured lab hours {opening:%H:%M}–{closing:%H:%M}.",
                "Confirm whether access was authorized at this time with the lab administrator.",
                "outside_lab_hours", row.get("department_case")))

    # R3: consecutive failure streak, reset by any success.
    med, high, critical = (cfg["consecutive_medium_threshold"], cfg["consecutive_high_threshold"], cfg["consecutive_critical_threshold"])
    for (account, computer), g in w.groupby(["account", "computer"], sort=False):
        streak = []
        def emit_streak(rows):
            count = len(rows)
            if count < med:
                return
            severity = "Critical Review" if count >= critical else "High" if count >= high else "Medium"
            alerts.append(_alert("R3", "Consecutive failed-login streak", severity, account, computer,
                rows[0].timestamp, rows[-1].timestamp, [x.event_id for x in rows],
                f"{count} consecutive failed logins occurred without a successful login between them.",
                "Verify the sequence with the lab administrator; do not assume malicious intent.",
                "consecutive_failures", rows[-1].get("department_case")))
        for _, row in g.iterrows():
            if row.event == "failure":
                streak.append(row)
            else:
                emit_streak(streak)
                streak = []
        emit_streak(streak)

    # R4: rolling failure volume, scoped to account + computer.
    for win in cfg["rolling_windows"]:
        duration, threshold = pd.Timedelta(minutes=win["minutes"]), win["threshold"]
        for (account, computer), g in fails.groupby(["account", "computer"], sort=False):
            rows = list(g.sort_values("timestamp", kind="stable").to_dict("records"))
            left = 0
            already_alerted = False
            for right, row in enumerate(rows):
                while left <= right and row["timestamp"] - rows[left]["timestamp"] > duration:
                    left += 1
                current = rows[left:right + 1]
                if len(current) < threshold:
                    already_alerted = False
                    continue
                if already_alerted:
                    continue
                already_alerted = True
                alerts.append(_alert("R4", f"Repeated failures in rolling window ({win['label']})",
                    "High" if len(current) >= 2 * threshold else "Medium", account, computer,
                    current[0]["timestamp"], row["timestamp"], [x["event_id"] for x in current],
                    f"{len(current)} failures occurred within {win['label']}; configured threshold is {threshold}.",
                    "Verify the account activity and compare this time window with expected lab usage.",
                    f"rolling_{win['minutes']}m", row.get("department_case")))

    # R5: multiple accounts failing on one computer in a short window.
    duration = pd.Timedelta(minutes=cfg["cross_account_window_minutes"])
    for computer, g in fails.groupby("computer", sort=False):
        rows = list(g.sort_values("timestamp", kind="stable").to_dict("records"))
        left, emitted = 0, False
        for right, row in enumerate(rows):
            while left <= right and row["timestamp"] - rows[left]["timestamp"] > duration:
                left += 1
                emitted = False
            current = rows[left:right + 1]
            if len(current) >= cfg["cross_account_min_failures"] and len({x["account"] for x in current}) >= cfg["cross_account_min_accounts"] and not emitted:
                emitted = True
                alerts.append(_alert("R5", "Failure burst across multiple accounts on one computer", "Medium", None, str(computer),
                    current[0]["timestamp"], row["timestamp"], [x["event_id"] for x in current],
                    f"{len(current)} failures affecting {len({x['account'] for x in current})} accounts occurred on this computer within {cfg['cross_account_window_minutes']} minutes.",
                    "Check whether this burst matches scheduled lab activity before escalation.", "cross_account_burst"))

    # R6: one account failing across multiple computers in a short window.
    duration = pd.Timedelta(minutes=cfg["cross_machine_window_minutes"])
    for account, g in fails.groupby("account", sort=False):
        rows = list(g.sort_values("timestamp", kind="stable").to_dict("records"))
        left, emitted = 0, False
        for right, row in enumerate(rows):
            while left <= right and row["timestamp"] - rows[left]["timestamp"] > duration:
                left += 1
                emitted = False
            current = rows[left:right + 1]
            if len(current) >= cfg["cross_machine_min_failures"] and len({x["computer"] for x in current}) >= cfg["cross_machine_min_computers"] and not emitted:
                emitted = True
                alerts.append(_alert("R6", "Failure burst for one account across multiple computers", "Medium", str(account), None,
                    current[0]["timestamp"], row["timestamp"], [x["event_id"] for x in current],
                    f"{len(current)} failures across {len({x['computer'] for x in current})} computers occurred within {cfg['cross_machine_window_minutes']} minutes.",
                    "Verify whether the account was expected to use these computers during this period.", "cross_machine_burst"))

    if cfg["deduplicate_overlapping_alerts"]:
        alerts = _merge_single_scope_alerts(alerts)
    alerts.sort(key=lambda x: (x["start_time"], x["rule_id"], str(x["account"] or ""), str(x["computer"] or "")))
    for i, a in enumerate(alerts, 1):
        a["incident_id"] = f"CS-{i:04d}"
    return pd.DataFrame(alerts, columns=_out_columns())