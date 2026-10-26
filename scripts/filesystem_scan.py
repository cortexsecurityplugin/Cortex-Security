#!/usr/bin/env python3
"""Cortex Security v0.5 filesystem inventory and heuristic triage scanner.

Read-only: does not delete, modify, quarantine, or execute scanned files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git", ".venv", ".venv-security", "venv", "__pycache__", "reports",
    "node_modules", "quarantine", ".cortex-quarantine"
}
TEXT_EXTENSIONS = {
    ".py", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".ts", ".jsx", ".tsx",
    ".html", ".htm", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".env", ".txt", ".sh", ".sql", ".xml", ".md"
}
RULES = [
    ("FS001", "high", re.compile(r"(?i)\b(eval|exec)\s*\("),
     "Dynamic code execution pattern", "Review whether untrusted input can reach dynamic execution."),
    ("FS002", "high", re.compile(r"(?i)(api[_-]?key|client[_-]?secret|secret[_-]?key|password|passwd|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
     "Possible hard-coded credential", "Verify whether the value is real; rotate it if exposed."),
    ("FS003", "medium", re.compile(r"(?i)(powershell|pwsh).{0,100}(-enc(odedcommand)?\b|frombase64string)"),
     "Possible encoded PowerShell execution", "Inspect the command and its origin before running or removing anything."),
    ("FS004", "medium", re.compile(r"(?i)\b(certutil|bitsadmin)\b.{0,120}(https?://|decode|download)"),
     "Possible LOLBin download or decode command", "Validate context; administrators and installers may use these tools legitimately."),
    ("FS005", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "Private-key material detected", "Confirm whether this is authorized key material and ensure it is not exposed."),
]
SUSPICIOUS_EXTENSIONS = {".scr", ".pif", ".hta", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".bat", ".cmd", ".com", ".exe", ".dll", ".msi"}

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()

def is_excluded(path: Path, root: Path, excludes: list[str]) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in excludes for part in rel_parts)

def scan(target: Path, excludes: list[str], max_file_mb: int) -> dict:
    target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    if target.is_file():
        candidates = [target]
        root = target.parent
    else:
        root = target
        candidates = []
        for current, dirs, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            dirs[:] = [
                d for d in dirs
                if d not in excludes and not (current_path / d).is_symlink()
            ]
            for name in names:
                path = current_path / name
                if not is_excluded(path, root, excludes) and not path.is_symlink():
                    candidates.append(path)

    max_bytes = max_file_mb * 1024 * 1024
    inventory, findings, errors = [], [], []
    for path in candidates:
        try:
            stat = path.stat()
            if not path.is_file():
                continue
            entry = {
                "path": str(path.relative_to(root)) if path != root else path.name,
                "absolute_path": str(path),
                "size_bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "extension": path.suffix.lower(),
                "sha256": None,
                "content_inspected": False,
            }
            if stat.st_size <= max_bytes:
                entry["sha256"] = sha256_file(path)
                if path.suffix.lower() in TEXT_EXTENSIONS:
                    try:
                        content = path.read_text(encoding="utf-8", errors="replace")
                        # Avoid matching the scanner's own rule definitions.
                        # Continue scanning all other supported files normally.
                        if path.name.lower() != "filesystem_scan.py":
                            entry["content_inspected"] = True
                            for line_no, line in enumerate(content.splitlines(), 1):
                                for rule_id, severity, pattern, title, remediation in RULES:
                                    if pattern.search(line):
                                        findings.append({
                                            "rule_id": rule_id, "severity": severity,
                                            "path": entry["path"], "line": line_no,
                                            "title": title, "evidence": line[:240],
                                            "remediation": remediation,
                                            "status": "unverified_triage",
                                        })
                    except OSError as exc:
                        errors.append({"path": str(path), "error": str(exc)})
            elif path.suffix.lower() in TEXT_EXTENSIONS:
                entry["skip_reason"] = f"file exceeds {max_file_mb} MB inspection limit"
            if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                entry["review_flag"] = "executable_or_script_extension"
            inventory.append(entry)
        except (OSError, PermissionError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
    return {
        "schema_version": "0.5.0",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "files_scanned": len(inventory),
        "findings_count": len(findings),
        "inventory": inventory,
        "findings": findings,
        "errors": errors,
        "limitations": [
            "Heuristic matches are unverified triage, not a malware verdict.",
            "This scanner does not execute files or detect all malware.",
            "Oversized files are inventoried but not hashed or content-inspected.",
            "Use Microsoft Defender or another trusted antivirus for malware detection and remediation."
        ],
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--output", default="reports/filesystem-scan.json")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--max-file-mb", type=int, default=50)
    args = parser.parse_args()
    if args.max_file_mb < 1:
        parser.error("--max-file-mb must be at least 1")
    excludes = sorted(DEFAULT_EXCLUDES | set(args.exclude))
    try:
        report = scan(Path(args.target), excludes, args.max_file_mb)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Scanned {report['files_scanned']} files; {report['findings_count']} heuristic finding(s).")
        print(f"Inventory/report: {output.resolve()}")
        print("Reminder: heuristic findings are not confirmed malware; no files were changed.")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Filesystem scan failed: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
