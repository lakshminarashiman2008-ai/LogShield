
from validator import validate_csv
from detector import analyze_events

CSV_FILE = "test_logs.csv"

print("\n=== LOGSHIELD CSV VALIDATION ===")

result = validate_csv(CSV_FILE)

print("Valid:", result.valid)

for error in result.errors:
    print("ERROR:", error)

for warning in result.warnings:
    print("WARNING:", warning)

if not result.valid:
    print("\nCSV validation failed. Analysis stopped.")
    raise SystemExit(1)

print("\nRows:", result.summary.get("rows"))
print("CSV validation passed.")

print("\n=== LOGSHIELD DETECTION ===")

alerts = analyze_events(result.data)

print("Alerts detected:", len(alerts))

if alerts.empty:
    print("No suspicious activity detected.")
else:
    columns = [
        "rule_id",
        "rule_name",
        "severity",
        "account",
        "computer",
        "start_time",
        "end_time",
        "event_ids",
        "evidence",
        "recommendation",
    ]

    available = [c for c in columns if c in alerts.columns]
    print(alerts[available].to_string(index=False))

    alerts.to_csv("test_alerts.csv", index=False)
    print("\nSaved alerts to test_alerts.csv")
