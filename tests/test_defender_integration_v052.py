import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from defender_integration import build_report


class DefenderCorrelationTests(unittest.TestCase):
    def test_matches_resource_to_inventory_without_claiming_current_threat(self):
        fs = {
            "target": r"C:\sample", "files_scanned": 1,
            "inventory": [{
                "path": "sample.exe", "absolute_path": r"C:\sample\sample.exe",
                "sha256": "abc123", "size_bytes": 100,
            }],
        }
        defender = {"scan": {"target": r"C:\sample"}, "threat_detections": [{
            "ThreatID": 123, "ThreatName": "Example.Detection",
            "InitialDetectionTime": "2026-10-14T10:00:00",
            "ActionSuccess": True, "ThreatStatusID": 4,
            "Resources": [r"file:_C:\sample\sample.exe"],
        }]}
        report = build_report(fs, defender)
        self.assertEqual(report["raw_history_records"], 1)
        self.assertEqual(report["records_matching_inventory"], 1)
        self.assertEqual(report["records"][0]["correlation_status"], "matched_to_inventory")
        self.assertEqual(report["records"][0]["remediation_state"], "unknown")
        self.assertEqual(report["current_threat_status"], "unknown")

    def test_history_snapshot_comparison(self):
       	old_record = {
            "ThreatID": 123,
            "InitialDetectionTime": "2026-10-14T10:00:00",
            "ThreatStatusID": 4,
            "ActionSuccess": True,
            "Resources": [r"file:_C:\sample\old.exe"],
        }
        new_record = {
            "ThreatID": 456,
            "InitialDetectionTime": "2026-10-26T00:31:00",
            "ThreatStatusID": 4,
            "ActionSuccess": True,
            "Resources": [r"file:_C:\sample\new.exe"],
        }

        report = build_report(
            {"inventory": [], "files_scanned": 0},
            {
                "history_snapshot_before": [old_record],
                "history_snapshot_after": [old_record, new_record],
                "threat_detections": [old_record, new_record],
            },
        )

        self.assertEqual(report["history_comparison_status"], "completed")
        self.assertEqual(report["history_records_before"], 1)
        self.assertEqual(report["history_records_after"], 2)
        self.assertEqual(report["new_distinct_history_records"], 1)
        self.assertEqual(report["current_threat_status"], "unknown")

    def test_exact_duplicates_are_deduplicated(self):
        record = {
            "ThreatID": 123, "InitialDetectionTime": "2026-10-14T10:00:00",
            "ThreatStatusID": 4, "ActionSuccess": True,
            "Resources": [r"file:_C:\sample\bad.exe"],
        }
        report = build_report(
            {"inventory": [], "files_scanned": 0},
            {"threat_detections": [record, record.copy()]},
        )
        self.assertEqual(report["raw_history_records"], 2)
        self.assertEqual(report["unique_history_records"], 1)
        self.assertEqual(report["exact_duplicate_records_removed"], 1)
        self.assertEqual(report["historical_or_unattributed_records"], 1)

    def test_unmatched_detection_is_preserved_as_unattributed(self):
        report = build_report(
            {"inventory": [], "files_scanned": 0},
            {"threat_detections": [{
                "ThreatName": "Example",
                "Resources": [r"file:_C:\elsewhere\x.exe"],
            }]},
        )
        self.assertEqual(report["records_matching_inventory"], 0)
        self.assertEqual(report["records"][0]["record_classification"], "historical_or_unattributed")
        self.assertEqual(report["records"][0]["remediation_state"], "unknown")


if __name__ == "__main__":
    unittest.main()


