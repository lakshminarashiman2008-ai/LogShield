import unittest
import pandas as pd
from detector import analyze_events
from validator import validate_csv

COLS = ["event_id", "timestamp", "account", "computer", "event", "department_case"]
def frame(rows):
    return pd.DataFrame(rows, columns=COLS)

class ValidatorTests(unittest.TestCase):
    def test_valid_and_normalized(self):
        r = validate_csv(frame([["1","2026-10-14 09:00"," alice "," lab1 "," FAILURE ","IT"]]))
        self.assertTrue(r.valid, r.errors)
        self.assertEqual(r.data.loc[0, "account"], "alice")
        self.assertEqual(r.data.loc[0, "event"], "failure")
    def test_missing_columns(self):
        self.assertFalse(validate_csv(pd.DataFrame({"event_id":["1"]})).valid)
    def test_duplicate_ids_block(self):
        d = frame([["1","2026-10-14 09:00","a","pc","failure","IT"],["1","2026-10-14 09:01","a","pc","failure","IT"]])
        self.assertFalse(validate_csv(d).valid)
    def test_out_of_order_warning(self):
        d = frame([["2","2026-10-14 09:02","a","pc","success","IT"],["1","2026-10-14 09:01","a","pc","failure","IT"]])
        r = validate_csv(d)
        self.assertTrue(r.valid, r.errors)
        self.assertTrue(r.warnings)

class DetectorTests(unittest.TestCase):
    def test_failure_then_success(self):
        d = frame([[str(i),f"2026-10-14 09:0{i}","a","pc","failure","IT"] for i in range(3)] +
                  [["4","2026-10-14 09:04","a","pc","success","IT"]])
        r = analyze_events(d, {"deduplicate_overlapping_alerts":False})
        self.assertIn("R1", set(r.rule_id))
    def test_after_hours(self):
        d = frame([["1","2026-10-14 19:00","a","pc","success","IT"]])
        self.assertIn("R2", set(analyze_events(d, {"deduplicate_overlapping_alerts":False}).rule_id))
    def test_consecutive_failures(self):
        d = frame([[str(i),f"2026-10-14 09:{i:02}","a","pc","failure","IT"] for i in range(1,6)])
        self.assertIn("R3", set(analyze_events(d, {"deduplicate_overlapping_alerts":False}).rule_id))
    def test_cross_account(self):
        d = frame([[str(i),f"2026-10-14 09:0{i}","acct"+str(i),"pc","failure","IT"] for i in range(1,7)])
        self.assertIn("R5", set(analyze_events(d, {"deduplicate_overlapping_alerts":False}).rule_id))
    def test_department_not_detection_input(self):
        rows = [["1","2026-10-14 09:00","a","pc","failure","Dept A"],["2","2026-10-14 09:01","a","pc","failure","Dept A"],["3","2026-10-14 09:02","a","pc","failure","Dept A"],["4","2026-10-14 09:03","a","pc","success","Dept A"]]
        a = analyze_events(frame(rows), {"deduplicate_overlapping_alerts":False})
        for row in rows: row[-1] = "Dept B"
        b = analyze_events(frame(rows), {"deduplicate_overlapping_alerts":False})
        self.assertEqual(list(a.rule_id), list(b.rule_id))
        self.assertEqual(list(a.event_ids), list(b.event_ids))
    def test_bad_threshold_order(self):
        d = frame([["1","2026-10-14 09:00","a","pc","failure","IT"]])
        with self.assertRaises(ValueError):
            analyze_events(d, {"consecutive_medium_threshold":10,"consecutive_high_threshold":8})

if __name__ == "__main__":
    unittest.main()
