"""Input validation for Cyber Sentinels synthetic authentication CSVs."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import pandas as pd

REQUIRED_COLUMNS = ["event_id", "timestamp", "account", "computer", "event"]
ALLOWED_EVENTS = {"success", "failure"}

@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data: pd.DataFrame | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    def as_dict(self):
        return {"valid": self.valid, "errors": list(self.errors), "warnings": list(self.warnings), "summary": dict(self.summary)}

def validate_csv(source: pd.DataFrame | str, *, normalize_identifiers: bool = True,
                 reject_duplicate_event_ids: bool = True) -> ValidationResult:
    """Validate a DataFrame or CSV path. Errors block analysis; warnings require review."""
    errors, warnings = [], []
    try:
        df = source.copy() if isinstance(source, pd.DataFrame) else pd.read_csv(source)
    except Exception as exc:
        return ValidationResult(False, [f"Could not read CSV: {exc}"])
    if df.empty:
        return ValidationResult(False, ["The CSV contains no event rows."], data=df,
                                summary={"rows": 0, "columns": list(df.columns)})
    df.columns = [str(c).strip() for c in df.columns]
    if len(set(df.columns)) != len(df.columns):
        errors.append("Column names become duplicated after trimming whitespace.")
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        errors.append("Missing required columns: " + ", ".join(missing))
        return ValidationResult(False, errors, warnings, df, {"rows": len(df), "columns": list(df.columns)})
    if "department_case" not in df.columns:
        warnings.append("Optional 'department_case' column is absent; detection will proceed without department context.")

    for col in ("event_id", "account", "computer"):
        if df[col].isna().any():
            errors.append(f"Column '{col}' contains {int(df[col].isna().sum())} missing value(s).")
            continue
        df[col] = df[col].astype(str)
        if normalize_identifiers:
            df[col] = df[col].str.strip()
        if (df[col] == "").any():
            errors.append(f"Column '{col}' contains blank value(s).")

    if not df["event_id"].isna().any():
        dup = df["event_id"].duplicated(keep=False)
        if dup.any():
            msg = f"{int(dup.sum())} row(s) have duplicate event_id values; evidence references may be ambiguous."
            (errors if reject_duplicate_event_ids else warnings).append(msg)

    parsed = pd.to_datetime(df["timestamp"], errors="coerce")
    if parsed.isna().any():
        errors.append(f"Column 'timestamp' contains {int(parsed.isna().sum())} invalid or missing timestamp(s).")
    else:
        if not parsed.is_monotonic_increasing:
            warnings.append("Rows are not in chronological order. Analysis will sort events by timestamp.")
        df["timestamp"] = parsed

    if df["event"].isna().any():
        errors.append(f"Column 'event' contains {int(df['event'].isna().sum())} missing value(s).")
    else:
        df["event"] = df["event"].astype(str).str.strip().str.lower()
        invalid = sorted(set(df.loc[~df["event"].isin(ALLOWED_EVENTS), "event"]))
        if invalid:
            errors.append("Unsupported event value(s): " + ", ".join(repr(x) for x in invalid) + ". Allowed: success, failure.")

    if "department_case" in df:
        df["department_case"] = df["department_case"].apply(lambda x: None if pd.isna(x) else str(x).strip())

    dup_rows = int(df.duplicated().sum())
    if dup_rows:
        warnings.append(f"{dup_rows} fully duplicated row(s) detected; confirm whether they represent duplicate ingestion.")

    summary = {
        "rows": int(len(df)), "columns": list(df.columns),
        "success_events": int((df["event"] == "success").sum()) if "event" in df else 0,
        "failure_events": int((df["event"] == "failure").sum()) if "event" in df else 0,
        "unique_accounts": int(df["account"].nunique(dropna=True)) if "account" in df else 0,
        "unique_computers": int(df["computer"].nunique(dropna=True)) if "computer" in df else 0,
        "department_context_available": "department_case" in df.columns,
        "authenticity_verified": False, "completeness_verified": False,
    }
    return ValidationResult(not errors, errors, warnings, df, summary)
