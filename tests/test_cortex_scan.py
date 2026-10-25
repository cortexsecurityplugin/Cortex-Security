import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cortex_scan import scan

class CortexScannerTests(unittest.TestCase):
    def test_detects_eval_as_unverified_triage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.py").write_text("value = eval(user_input)\n", encoding="utf-8")
            report = scan(root)
            self.assertEqual(report["files_scanned"], 1)
            self.assertTrue(any(f["rule_id"] == "CX001" for f in report["findings"]))
            self.assertTrue(all(f["status"] == "unverified_triage" for f in report["findings"]))

    def test_skips_virtual_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".venv").mkdir()
            (root / ".venv" / "bad.py").write_text("eval(x)\n", encoding="utf-8")
            report = scan(root)
            self.assertEqual(report["finding_count"], 0)


    def test_excludes_reports_scripts_and_test_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "tests").mkdir()
            (root / "reports").mkdir()
            (root / "scripts" / "helper.py").write_text("eval(x)\\n", encoding="utf-8")
            (root / "tests" / "fixture.py").write_text("eval(x)\\n", encoding="utf-8")
            (root / "reports" / "scan-report.json").write_text('{"value": "eval(x)"}', encoding="utf-8")
            (root / "app.py").write_text("print('safe')\\n", encoding="utf-8")
            report = scan(root)
            self.assertEqual(report["files_scanned"], 1)
            self.assertEqual(report["finding_count"], 0)

    def test_redacts_credential_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text('api_key = "this-is-a-long-example-secret"\n', encoding="utf-8")
            report = scan(root)
            matches = [f for f in report["findings"] if f["rule_id"] == "CX005"]
            self.assertTrue(matches)
            self.assertNotIn("this-is-a-long-example-secret", matches[0]["evidence"])

if __name__ == "__main__":
    unittest.main()
