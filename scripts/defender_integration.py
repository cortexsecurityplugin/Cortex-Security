#!/usr/bin/env python3
"""Correlate Cortex inventory with exported Defender history without overclaiming incidents.

Defender's Get-MpThreatDetection output is historical system-wide data and does not
prove a record came from a particular custom scan. This module preserves records,
deduplicates exact repeats, and reports inventory matches without declaring current
threats or confirmed remediation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def normalize_path(value):
    if not value:
        return None
    return str(value).replace("/", "\\").casefold()


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _record_key(detection: dict) -> str:
    """Stable fingerprint for exact duplicate history records."""
    key_fields = {
        "ThreatID": detection.get("ThreatID", detection.get("threat_id")),
        "ThreatName": detection.get("ThreatName", detection.get("threat_name")),
        "InitialDetectionTime": detection.get("InitialDetectionTime", detection.get("initial_detection_time")),
        "LastThreatStatusChangeTime": detection.get("LastThreatStatusChangeTime", detection.get("last_status_change_time")),
        "ThreatStatusID": detection.get("ThreatStatusID", detection.get("threat_status_id")),
        "ActionSuccess": detection.get("ActionSuccess", detection.get("action_success")),
        "Resources": sorted(str(x) for x in _as_list(detection.get("Resources", detection.get("resources")))),
    }
    raw = json.dumps(key_fields, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_report(filesystem_report: dict, defender_report: dict) -> dict:
    inventory = filesystem_report.get("inventory", [])
    by_path = {}
    for item in inventory:
        path_key = normalize_path(item.get("absolute_path") or item.get("path"))
        if path_key:
            by_path[path_key] = item

    raw_detections = defender_report.get("threat_detections", [])
    unique_detections = []
    seen = set()
    duplicate_count = 0
    for detection in raw_detections:
        fingerprint = _record_key(detection)
        if fingerprint in seen:
            duplicate_count += 1
            continue
        seen.add(fingerprint)
        unique_detections.append(detection)

    records = []
    matched_records = 0
    for detection in unique_detections:
        resources = _as_list(detection.get("Resources") or detection.get("resources"))
        threat_name = (
            detection.get("ThreatName") or detection.get("threat_name")
            or detection.get("ThreatID") or detection.get("threat_id")
            or "Defender detection"
        )
        detection_time = (
            detection.get("InitialDetectionTime") or detection.get("initial_detection_time")
        )
        matched = []
        for resource in resources:
            resource_text = str(resource)
            candidate = resource_text
            # Handle common Defender resource prefixes without assuming all formats.
            lowered = candidate.lower()
            if lowered.startswith("file:_"):
                candidate = candidate[6:]
            elif lowered.startswith("file:"):
                candidate = candidate[5:]
            candidate = candidate.strip('"')
            item = by_path.get(normalize_path(candidate))
            if item:
                matched.append({
                    "inventory_path": item.get("absolute_path") or item.get("path"),
                    "sha256": item.get("sha256"),
                    "size_bytes": item.get("size_bytes"),
                })
        if matched:
            matched_records += 1

        action_success = detection.get("ActionSuccess", detection.get("action_success"))
        status_id = detection.get("ThreatStatusID", detection.get("threat_status_id"))
        records.append({
            "source": "Microsoft Defender",
            "record_classification": "historical_or_unattributed",
            "threat_name": str(threat_name),
            "threat_id": detection.get("ThreatID", detection.get("threat_id")),
            "detection_time": detection_time,
            "last_status_change_time": detection.get("LastThreatStatusChangeTime", detection.get("last_status_change_time")),
            "action_success_reported": action_success,
            "threat_status_id_raw": status_id,
            "remediation_state": "unknown",
            "resources": [str(x) for x in resources],
            "cortex_inventory_matches": matched,
            "correlation_status": "matched_to_inventory" if matched else "not_matched_to_inventory",
            "raw_detection": detection,
            "note": "Defender history does not establish that this record came from the requested custom scan or that the threat is currently active.",
        })

    # Compare Defender history snapshots when available.
    # New records are temporal differences, not confirmed scan findings.
    history_before = defender_report.get("history_snapshot_before")
    history_after = defender_report.get("history_snapshot_after")

    history_comparison_status = "unavailable"
    new_history_records = None
    before_count = None
    after_count = None

    if isinstance(history_before, list) and isinstance(history_after, list):
        before_keys = {_record_key(item) for item in history_before}
        after_keys = {_record_key(item) for item in history_after}

        before_count = len(history_before)
        after_count = len(history_after)
        new_history_records = len(after_keys - before_keys)
        history_comparison_status = "completed"

    scan = defender_report.get("scan", {})
    return {
        "schema_version": "0.5.2",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "filesystem_target": filesystem_report.get("target"),
        "filesystem_files_scanned": filesystem_report.get("files_scanned", 0),
        "defender_scan": scan,
        "scan_attribution": "unavailable_from_threat_history",
	 "history_comparison_status": history_comparison_status,
        "history_records_before": before_count,
        "history_records_after": after_count,
        "new_distinct_history_records": new_history_records,
        "current_threat_status": "unknown",
        "raw_history_records": len(raw_detections),
        "unique_history_records": len(unique_detections),
        "exact_duplicate_records_removed": duplicate_count,
        "historical_or_unattributed_records": len(records),
        "records_matching_inventory": matched_records,
        "current_threat_status": "unknown",
        "current_threat_status_note": "Historical Defender records cannot establish whether threats are currently active.",
        "records": records,
        "limitations": [
            "Get-MpThreatDetection can return historical system-wide records, not just findings from the latest custom scan.",
            "A resource path match is correlation evidence, not proof that the file is currently present or malicious.",
            "ActionSuccess is preserved as reported but is not treated as proof of current remediation.",
            "ThreatStatusID is preserved as a raw value; this tool does not guess its meaning.",
            "This module does not quarantine files, terminate processes, or change antivirus settings."
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--filesystem-report", required=True)
    parser.add_argument("--defender-report", required=True)
    parser.add_argument("--output", default="reports/defender-correlation-report.json")
    args = parser.parse_args()
    fs_report = load_json(Path(args.filesystem_report))
    defender_report = load_json(Path(args.defender_report))
    report = build_report(fs_report, defender_report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Defender history records: {report['raw_history_records']}")
    print(f"Unique history records: {report['unique_history_records']}")
    print(f"Exact duplicate records removed: {report['exact_duplicate_records_removed']}")
    print(f"Records matching inventory: {report['records_matching_inventory']}")
    print("Confirmed current threats: 0 (not established by history correlation)")
    print(f"Correlation report: {output.resolve()}")
    print("No files or Defender settings were changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

