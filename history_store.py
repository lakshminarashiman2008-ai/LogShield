"""SQLite persistence and cross-analysis history signals for LogShield.

Only analysis metadata, incident evidence and per-log account appearance counts are
stored. Uploaded raw CSV rows are never written to the database. History signals are
review prompts, not accusations.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

DB_PATH = Path(__file__).resolve().with_name("logshield_history.db")

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4, "critical review": 4}


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path or DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_db(db_path: str | Path | None = None) -> None:
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_hash TEXT NOT NULL UNIQUE,
                filename TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                alert_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
                rule TEXT,
                severity TEXT,
                account TEXT,
                account_key TEXT,
                computer TEXT,
                start_time TEXT,
                end_time TEXT,
                event_ids TEXT,
                evidence TEXT,
                recommendation TEXT,
                is_history_signal INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_account_key ON incidents(account_key);
            CREATE INDEX IF NOT EXISTS idx_incidents_analysis_id ON incidents(analysis_id);
            -- Which accounts were present in each uploaded log (IDs + counts only, no raw rows).
            CREATE TABLE IF NOT EXISTS account_appearances (
                analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
                account_key TEXT NOT NULL,
                account TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (analysis_id, account_key)
            );
            CREATE INDEX IF NOT EXISTS idx_appearances_account_key ON account_appearances(account_key);
            """
        )
        # Lightweight schema migration for databases created by earlier prototypes.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(incidents)")}
        if "account_key" not in cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN account_key TEXT")
            conn.execute("UPDATE incidents SET account_key = lower(trim(account)) WHERE account IS NOT NULL")
        if "is_history_signal" not in cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN is_history_signal INTEGER NOT NULL DEFAULT 0")


def content_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def prior_account_history(accounts: list[str], db_path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Return prior non-history incident counts keyed by normalized account."""
    keys = sorted({str(a).strip().casefold() for a in accounts if str(a).strip()})
    if not keys:
        return {}
    placeholders = ",".join("?" for _ in keys)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT account_key, COUNT(DISTINCT analysis_id) AS run_count,
                       MAX(a.analyzed_at) AS last_seen
                FROM incidents i JOIN analyses a ON a.id = i.analysis_id
                WHERE i.account_key IN ({placeholders}) AND i.is_history_signal = 0
                  AND i.account_key IS NOT NULL
                GROUP BY i.account_key""",
            keys,
        ).fetchall()
    return {r["account_key"]: {"run_count": int(r["run_count"]), "last_seen": r["last_seen"]} for r in rows}


def save_analysis(
    *, content_hash: str, filename: str, event_count: int, alerts: pd.DataFrame,
    account_counts: Mapping[str, int] | None = None,
    analyzed_at: str | None = None, db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Persist metadata and incident rows; do not store raw events. Hash prevents duplicate runs.

    account_counts maps account ID -> number of events in this log. It powers the
    "Repeat Accounts" view and contains no other event content.
    """
    analyzed_at = analyzed_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _connect(db_path) as conn:
        existing = conn.execute("SELECT id, analyzed_at FROM analyses WHERE content_hash = ?", (content_hash,)).fetchone()
        if existing:
            return {"saved": False, "duplicate": True, "analysis_id": int(existing["id"]), "analyzed_at": existing["analyzed_at"]}
        cursor = conn.execute(
            "INSERT INTO analyses(content_hash, filename, analyzed_at, event_count, alert_count) VALUES (?, ?, ?, ?, ?)",
            (content_hash, filename, analyzed_at, int(event_count), int(len(alerts))),
        )
        analysis_id = int(cursor.lastrowid)

        # Per-log account appearances (case-insensitive merge, first spelling kept for display).
        merged: dict[str, list[Any]] = {}
        for name, count in (account_counts or {}).items():
            name = str(name).strip()
            if not name:
                continue
            slot = merged.setdefault(name.casefold(), [name, 0])
            slot[1] += int(count)
        for key, (name, count) in merged.items():
            conn.execute(
                "INSERT OR REPLACE INTO account_appearances(analysis_id, account_key, account, event_count) VALUES (?, ?, ?, ?)",
                (analysis_id, key, name, count),
            )

        for _, row in alerts.iterrows():
            def val(*names: str, default: str = "") -> str:
                """Return a safely serialized scalar from an alert row.

                pandas.isna() returns an array for list/array-like cells, so only
                use its result as a condition when it is a single boolean value.
                """
                for name in names:
                    if name not in row.index:
                        continue
                    value = row[name]
                    if value is None:
                        continue

                    # Serialize collection-valued evidence before checking missingness.
                    if isinstance(value, (list, dict, tuple, set)):
                        return json.dumps(value, ensure_ascii=False, default=str)
                    # Numpy arrays and pandas Series/Index may also occur in cells.
                    if hasattr(value, "tolist") and not isinstance(value, (str, bytes)):
                        value = value.tolist()
                        return json.dumps(value, ensure_ascii=False, default=str)

                    try:
                        missing = pd.isna(value)
                        if isinstance(missing, bool) and missing:
                            continue
                        # numpy.bool_ is not always a built-in bool.
                        if getattr(missing, "ndim", None) == 0 and bool(missing):
                            continue
                    except (TypeError, ValueError):
                        # Non-scalar / unusual values are still safe to stringify.
                        pass
                    return str(value)
                return default
            account = val("account", "Account", default="")
            is_history = val("rule_id", default="").upper() == "H1" or "historical warning" in val("rule", "Rule").casefold()
            conn.execute(
                """INSERT INTO incidents(analysis_id, rule, severity, account, account_key, computer,
                   start_time, end_time, event_ids, evidence, recommendation, is_history_signal)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (analysis_id, val("rule", "rule_name", "Rule"), val("severity", "Severity"), account,
                 account.strip().casefold() if account else None,
                 val("computer", "Computer"), val("start_time", "Start time"), val("end_time", "End time"),
                 val("event_ids", "event_id", "Event IDs"), val("evidence", "explanation", "Evidence"),
                 val("recommendation", "Recommendation"), int(is_history)),
            )
    return {"saved": True, "duplicate": False, "analysis_id": analysis_id, "analyzed_at": analyzed_at}


def list_analyses(db_path: str | Path | None = None, limit: int = 100) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, filename, analyzed_at, event_count, alert_count FROM analyses ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [dict(r) for r in rows]


def get_analysis_incidents(analysis_id: int, db_path: str | Path | None = None) -> pd.DataFrame:
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT rule, severity, account, computer, start_time, end_time, event_ids, evidence, recommendation
               FROM incidents WHERE analysis_id = ? ORDER BY id""", (int(analysis_id),)
        ).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


def delete_analysis(analysis_id: int, db_path: str | Path | None = None) -> bool:
    """Delete one saved analysis and its incidents/appearances. Returns True if it existed."""
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM incidents WHERE analysis_id = ?", (int(analysis_id),))
        conn.execute("DELETE FROM account_appearances WHERE analysis_id = ?", (int(analysis_id),))
        return conn.execute("DELETE FROM analyses WHERE id = ?", (int(analysis_id),)).rowcount > 0


def delete_all_history(db_path: str | Path | None = None) -> int:
    """Delete every saved analysis. Returns how many were removed."""
    with _connect(db_path) as conn:
        count = int(conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0])
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM account_appearances")
        conn.execute("DELETE FROM analyses")
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('analyses', 'incidents')")  # restart IDs at 1
        return count


def persistent_accounts(min_logs: int = 2, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Accounts flagged in at least one uploaded log AND present in at least `min_logs` logs.

    A log counts as "flagged" when it holds a real (non-history) incident for the account.
    Logs analysed before appearance tracking existed count only where the account was flagged.
    Results are review prompts, not proof of anything.
    """
    with _connect(db_path) as conn:
        analyses = {r["id"]: dict(r) for r in conn.execute("SELECT id, filename, analyzed_at FROM analyses")}
        appearances = conn.execute("SELECT analysis_id, account_key, account, event_count FROM account_appearances").fetchall()
        incidents = conn.execute(
            """SELECT analysis_id, account_key, account, rule, severity FROM incidents
               WHERE is_history_signal = 0 AND account_key IS NOT NULL AND account_key != ''"""
        ).fetchall()

    people: dict[str, dict[str, Any]] = {}

    def person(key: str, name: str) -> dict[str, Any]:
        return people.setdefault(key, {"key": key, "account": name, "logs": {}, "rules": set(), "max_rank": 0, "max_severity": ""})

    def log_slot(p: dict[str, Any], analysis_id: int) -> dict[str, Any]:
        return p["logs"].setdefault(analysis_id, {"flagged": False, "incidents": 0, "events": None})

    for r in appearances:
        p = person(r["account_key"], r["account"])
        log_slot(p, r["analysis_id"])["events"] = int(r["event_count"])
    for r in incidents:
        p = person(r["account_key"], r["account"] or r["account_key"])
        slot = log_slot(p, r["analysis_id"])
        slot["flagged"] = True
        slot["incidents"] += 1
        if r["rule"]:
            p["rules"].add(r["rule"])
        rank = SEVERITY_RANK.get(str(r["severity"] or "").strip().casefold(), 0)
        if rank > p["max_rank"]:
            p["max_rank"], p["max_severity"] = rank, str(r["severity"]).strip()

    results = []
    for p in people.values():
        known = {aid: slot for aid, slot in p["logs"].items() if aid in analyses}
        flagged_logs = sum(1 for s in known.values() if s["flagged"])
        if flagged_logs < 1 or len(known) < min_logs:
            continue
        timeline = [
            {"analysis_id": aid, "filename": analyses[aid]["filename"], "analyzed_at": analyses[aid]["analyzed_at"],
             "flagged": slot["flagged"], "incidents": slot["incidents"], "events": slot["events"]}
            for aid, slot in sorted(known.items())
        ]
        results.append({
            "key": p["key"], "account": p["account"], "logs_seen": len(known), "flagged_logs": flagged_logs,
            "incidents": sum(s["incidents"] for s in known.values()), "max_severity": p["max_severity"],
            "max_rank": p["max_rank"], "rules": sorted(p["rules"]),
            "first_seen": timeline[0]["analyzed_at"], "last_seen": timeline[-1]["analyzed_at"], "timeline": timeline,
        })
    results.sort(key=lambda x: (-x["flagged_logs"], -x["max_rank"], -x["logs_seen"], x["account"].casefold()))
    return results