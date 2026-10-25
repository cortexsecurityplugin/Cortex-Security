import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cortex_scan import scan, to_sarif

class CortexScannerTests(unittest.TestCase):
    def test_detects_dynamic_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")
            report = scan(root)
            self.assertEqual(report["version"], "0.2.0")
            self.assertTrue(any(f["rule_id"] == "CX001" for f in report["findings"]))

    def test_secret_evidence_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = "this-is-a-fake-secret-value"
            (root / "settings.py").write_text(f'api_key = "{secret}"\n', encoding="utf-8")
            findings = [f for f in scan(root)["findings"] if f["rule_id"] == "CX005"]
            self.assertTrue(findings)
            self.assertNotIn(secret, json.dumps(findings))
            self.assertIn("redacted", findings[0]["evidence"])

    def test_dependency_hygiene(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests\nflask==3.0.0\n# comment\n", encoding="utf-8")
            findings = [f for f in scan(root)["findings"] if f["rule_id"] == "CX101"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["evidence"], "requests")

    def test_exclude_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests" / "fixture.py").write_text("eval(test_input)\n", encoding="utf-8")
            report = scan(root, ["tests"])
            self.assertEqual(report["files_scanned"], 1)
            self.assertEqual(len(report["findings"]), 1)

    def test_sarif_shape(self):
        report = {"files_scanned": 1, "notice": "triage", "findings": [{
            "rule_id": "CX001", "title": "Dynamic execution", "description": "desc",
            "remediation": "fix", "severity": "high", "confidence": "low",
            "path": "app.py", "line": 3, "evidence": "eval(x)", "status": "unverified_triage"}]}
        sarif = to_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "CX001")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 3)

if __name__ == "__main__":
    unittest.main()
