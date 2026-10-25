#!/usr/bin/env python3
"""Lightweight, read-only heuristic source scanner for Cortex Security.

This tool is for triage only. It does not execute scanned code, resolve control
flow, prove exploitability, or replace dedicated security scanners.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from datetime import datetime, timezone

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
    "target", "vendor", ".tox", ".next"
}
MAX_FILE_BYTES = 1_500_000
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".go",
    ".rb", ".php", ".sh", ".ps1", ".yaml", ".yml", ".json", ".toml",
    ".ini", ".cfg", ".conf", ".xml", ".html", ".sql", ".tf", ".dockerfile",
    ".env.example"
}

RULES = [
    {
        "id": "CX001", "severity": "high", "confidence": "low",
        "title": "Possible dynamic code execution",
        "extensions": {".py"},
        "pattern": re.compile(r"\b(eval|exec)\s*\("),
        "description": "Dynamic execution can become code injection if input is attacker-controlled.",
        "remediation": "Avoid eval/exec for data processing. Use a safe parser or explicit dispatch and validate inputs."
    },
    {
        "id": "CX002", "severity": "high", "confidence": "low",
        "title": "Possible shell command construction",
        "extensions": {".py"},
        "pattern": re.compile(r"\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\([^\\n]*(shell\s*=\s*True)"),
        "description": "Shell execution can enable command injection when untrusted data reaches the command string.",
        "remediation": "Prefer argument lists with shell=False. Validate arguments and avoid concatenating user-controlled strings."
    },
    {
        "id": "CX003", "severity": "medium", "confidence": "low",
        "title": "Possible weak or obsolete hash",
        "extensions": {".py", ".js", ".ts"},
        "pattern": re.compile(r"\b(md5|sha1)\s*\(", re.IGNORECASE),
        "description": "MD5/SHA-1 are unsuitable for new collision-resistant security uses; context may be non-security related.",
        "remediation": "For password storage use a dedicated password hashing function. For integrity/signatures prefer a modern algorithm appropriate to the use case."
    },
    {
        "id": "CX004", "severity": "medium", "confidence": "low",
        "title": "Possible disabled TLS certificate verification",
        "extensions": {".py"},
        "pattern": re.compile(r"\bverify\s*=\s*False\b"),
        "description": "Disabling certificate verification can expose HTTPS connections to interception.",
        "remediation": "Enable certificate verification and configure the correct CA bundle."
    },
    {
        "id": "CX005", "severity": "medium", "confidence": "low",
        "title": "Possible hard-coded credential",
        "extensions": {".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf"},
        "pattern": re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        "description": "A credential-like assignment may contain a hard-coded secret. Placeholder values can trigger this rule.",
        "remediation": "Move secrets to a secret manager or environment variable, rotate any exposed real credential, and avoid committing secrets."
    },
    {
        "id": "CX006", "severity": "medium", "confidence": "low",
        "title": "Possible SQL string interpolation",
        "extensions": {".py"},
        "pattern": re.compile(r"(?i)(execute|executemany)\s*\(\s*(f['\"]|['\"][^'\"]*%s|['\"][^'\"]*\+)", re.IGNORECASE),
        "description": "Constructing SQL strings can introduce injection if untrusted data is embedded.",
        "remediation": "Use parameterized queries and pass values separately from SQL text."
    },
    {
        "id": "CX007", "severity": "low", "confidence": "low",
        "title": "Possible permissive CORS configuration",
        "extensions": {".py", ".js", ".ts", ".yaml", ".yml", ".json"},
        "pattern": re.compile(r"(?i)(allow_origins|Access-Control-Allow-Origin|cors).{0,100}(\*|['\"]\*['\"])", re.IGNORECASE),
        "description": "Wildcard CORS may be intentional for public resources but is risky for authenticated APIs.",
        "remediation": "Restrict allowed origins to trusted sites where credentials or sensitive data are involved."
    },
]

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def scan_file(path: Path, root: Path) -> list[dict]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []
    ext = path.suffix.lower()
    if path.name.lower() == "dockerfile":
        ext = ".dockerfile"
    findings = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if ext not in rule["extensions"] or not rule["pattern"].search(line):
                continue
            # Avoid echoing possible secrets in reports.
            evidence = "[redacted: matching source line]" if rule["id"] == "CX005" else line.strip()[:240]
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "title": rule["title"],
                "path": str(path.relative_to(root)),
                "line": line_no,
                "evidence": evidence,
                "description": rule["description"],
                "remediation": rule["remediation"],
                "status": "unverified_triage"
            })
    return findings

def scan(root: Path) -> dict:
    root = root.resolve()
    findings = []
    files_scanned = 0
    for path in root.rglob("*"):
        if not path.is_file() or should_skip(path.relative_to(root)):
            continue
        # Avoid scanning the scanner itself and test fixtures that deliberately
        # contain vulnerable patterns. These files test detection logic, not app risk.
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0].lower() in {"scripts", "tests"}:
            continue
        if path.name.lower() in {"scan-report.json", "cortex-scan-report.json"}:
            continue
        ext = path.suffix.lower()
        if path.name.lower() == "dockerfile":
            ext = ".dockerfile"
        if ext not in TEXT_EXTENSIONS and ext != ".dockerfile":
            continue
        findings.extend(scan_file(path, root))
        files_scanned += 1
    return {
        "tool": "Cortex Security Heuristic Scanner",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(root),
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "notice": "Heuristic triage only. Findings are unverified and results are not proof of security or insecurity.",
        "findings": findings
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only heuristic scanner for authorized code repositories.")
    parser.add_argument("target", nargs="?", default=".", help="Repository or directory to scan")
    parser.add_argument("--output", default="reports/scan-report.json", help="JSON report path")
    args = parser.parse_args()
    root = Path(args.target)
    if not root.exists() or not root.is_dir():
        parser.error(f"target must be an existing directory: {root}")
    report = scan(root)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Scanned {report['files_scanned']} files; {report['finding_count']} triage finding(s).")
    print(f"Report: {output.resolve()}")
    print("Reminder: findings are unverified; manually validate before treating as vulnerabilities.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
