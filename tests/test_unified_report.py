import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUILDER = Path(__file__).resolve().parents[1] / "scripts" / "build_unified_report.py"


class UnifiedReportTests(unittest.TestCase):
    def test_normalizes_reports_and_marks_empty_dependency_audit_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            (reports / "audit-run-status.json").write_text(json.dumps({
                "cortex": {"available": True, "success": True},
                "bandit": {"available": True, "success": True},
                "pip_audit": {"available": True, "success": True},
            }), encoding="utf-8")
            (reports / "scan-report.json").write_text(json.dumps({
                "files_scanned": 2, "findings": [{
                    "rule_id": "TEST001", "severity": "medium",
                    "message": "example finding", "path": "a.py", "line": 7
                }]
            }), encoding="utf-8")
            (reports / "bandit-report.json").write_text(json.dumps({
                "results": [{
                    "test_id": "B101", "issue_severity": "LOW",
                    "issue_confidence": "HIGH", "issue_text": "assert used",
                    "filename": "b.py", "line_number": 2
                }]
            }), encoding="utf-8")
            (reports / "pip-audit-report.json").write_text(json.dumps({
                "dependencies": [], "fixes": []
            }), encoding="utf-8")

            run = subprocess.run([
                sys.executable, str(BUILDER), "--target", str(root),
                "--report-dir", str(reports), "--requirements-file", "requirements.txt"
            ], capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            unified = json.loads((reports / "unified-audit-report.json").read_text(encoding="utf-8"))
            self.assertEqual(unified["summary"]["total_findings"], 2)
            self.assertEqual(unified["checks"]["pip_audit"]["status"], "inconclusive")
            self.assertEqual(unified["overall_status"], "inconclusive")
            self.assertTrue((reports / "unified-audit-summary.md").is_file())


if __name__ == "__main__":
    unittest.main()
