# LogShield — Detection Core

Synthetic authentication-log validation and explainable review alerts.

Required columns: `event_id`, `timestamp`, `account`, `computer`, `event`. Optional context: `department_case` (never used as a rule input). Event values are `success` or `failure`.

## Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Usage
```python
from validator import validate_csv
from detector import analyze_events, DEFAULT_SETTINGS
result = validate_csv("sample_data.csv")
if result.valid:
    alerts = analyze_events(result.data, DEFAULT_SETTINGS)
else:
    print(result.errors)
```

Edit thresholds/hours in `DEFAULT_SETTINGS`, or pass an override dictionary to `analyze_events(df, settings)`. The future Settings UI can pass the same dictionary. Alerts prioritize human review; they do not prove compromise or block accounts. Validation cannot prove that logs are authentic or complete.
