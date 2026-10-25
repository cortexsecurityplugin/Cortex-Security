#!/usr/bin/env python3
"""Read-only heuristic source scanner for Cortex Security; triage only."""
from __future__ import annotations
import argparse, fnmatch, json, re
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.2.0"
MAX_FILE_BYTES = 1_500_000
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
             "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
             "target", "vendor", ".tox", ".next"}
TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java",
                   ".go", ".rb", ".php", ".sh", ".ps1", ".yaml", ".yml", ".json",
                   ".toml", ".ini", ".cfg", ".conf", ".xml", ".html", ".sql",
                   ".tf", ".txt", ".properties", ".env", ".pem", ".key"}

RULES = [
    ("CX001", "high", "low", "Possible dynamic code execution", {".py"},
     re.compile(r"\b(eval|exec)\s*\("),
     "Dynamic execution can become code injection if input is attacker-controlled.",
     "Avoid eval/exec for data processing. Use a safe parser or explicit dispatch."),
    ("CX002", "high", "low", "Possible shell command construction", {".py"},
     re.compile(r"\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\([^\\n]*(shell\s*=\s*True)"),
     "Shell execution can enable command injection when untrusted data reaches the command string.",
     "Prefer argument lists with shell=False; validate arguments and avoid concatenating untrusted strings."),
    ("CX003", "medium", "low", "Possible weak or obsolete hash", {".py", ".js", ".ts"},
     re.compile(r"\b(md5|sha1)\s*\(", re.I),
     "MD5/SHA-1 are unsuitable for new collision-resistant security uses; context may be non-security related.",
     "Use a modern algorithm appropriate to the security use case."),
    ("CX004", "medium", "low", "Possible disabled TLS certificate verification", {".py"},
     re.compile(r"\bverify\s*=\s*False\b"),
     "Disabling certificate verification can expose HTTPS connections to interception.",
     "Enable certificate verification and configure the correct CA bundle."),
    ("CX005", "high", "medium", "Possible hard-coded credential",
     {".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env"},
     re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|secret[_-]?key|password|passwd|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
     "A credential-like assignment may contain a hard-coded secret. Placeholders can trigger this rule.",
     "Move secrets to a secret manager or environment variable. Rotate real exposed credentials."),
    ("CX006", "medium", "low", "Possible SQL string interpolation", {".py"},
     re.compile(r"""(?i)(execute|executemany)\s*\(\s*(f['"]|['"][^'"]*%s|['"][^'"]*\+)"""),
     "Constructing SQL strings can introduce injection if untrusted data is embedded.",
     "Use parameterized queries and pass values separately from SQL text."),
    ("CX007", "low", "low", "Possible permissive CORS configuration", {".py", ".js", ".ts", ".yaml", ".yml", ".json"},
     re.compile(r"""(?i)(allow_origins|Access-Control-Allow-Origin|cors).{0,100}(\*|['"]\*['"])"""),
     "Wildcard CORS may be intentional for public resources but is risky for authenticated APIs.",
     "Restrict allowed origins to trusted sites when credentials or sensitive data are involved."),
    ("CX008", "high", "medium", "Possible private key material", {".pem", ".key", ".txt", ".env", ".conf", ".cfg"},
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "A private-key header was found in a text file; it may be a test fixture or real key.",
     "Do not commit private keys. Remove them from source control, rotate them, and review repository history."),
    ("CX009", "medium", "low", "Possible cloud access key identifier",
     {".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".txt"},
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "A string resembles an AWS access key ID. Validate whether it is a real credential.",
     "Revoke and rotate exposed credentials, review cloud audit logs, and use short-lived role-based credentials."),
]

def finding(rule_id, severity, confidence, title, path, line, evidence, description, remediation):
    return {"rule_id": rule_id, "severity": severity, "confidence": confidence,
            "title": title, "path": path, "line": line, "evidence": evidence,
            "description": description, "remediation": remediation,
            "status": "unverified_triage"}

def should_skip(relative: Path, excludes: list[str]) -> bool:
    if any(part in SKIP_DIRS for part in relative.parts):
        return True
    path = relative.as_posix()
    return any(
        path == pat.rstrip("/") or path.startswith(pat.rstrip("/") + "/")
        or fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(relative.name, pat)
        for pat in excludes
    )

def scan_file(path: Path, root: Path) -> list[dict]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    ext = path.suffix.lower()
    if path.name.lower() == "dockerfile":
        ext = ".dockerfile"
    rel = path.relative_to(root).as_posix()
    results = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for rid, severity, confidence, title, extensions, pattern, description, remediation in RULES:
            if ext not in extensions or not pattern.search(line):
                continue
            evidence = "[redacted: possible secret material]" if rid in {"CX005", "CX008", "CX009"} else line.strip()[:240]
            results.append(finding(rid, severity, confidence, title, rel, line_no, evidence, description, remediation))
    return results

def scan_dependency_hygiene(path: Path, root: Path) -> list[dict]:
    if path.name.lower() != "requirements.txt":
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        spec = line.split(";", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?", spec):
            out.append(finding("CX101", "low", "medium", "Unpinned Python dependency",
                path.relative_to(root).as_posix(), number, spec[:120],
                "An unpinned dependency may resolve to different versions across installations.",
                "Pin a reviewed version or use a lockfile and run a dedicated dependency vulnerability scanner."))
    return out

def to_sarif(report: dict) -> dict:
    rules, results = {}, []
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    for f in report["findings"]:
        rid = f["rule_id"]
        rules.setdefault(rid, {"id": rid, "name": f["title"],
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f["description"]},
            "help": {"text": f["remediation"]},
            "defaultConfiguration": {"level": levels.get(f["severity"], "warning")}})
        results.append({"ruleId": rid, "level": levels.get(f["severity"], "warning"),
            "message": {"text": f'{f["title"]}: {f["evidence"]}'},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["path"]},
                "region": {"startLine": f["line"]}}}],
            "properties": {"confidence": f["confidence"], "status": f["status"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0", "runs": [{"tool": {"driver": {
            "name": "Cortex Security Heuristic Scanner", "version": VERSION,
            "informationUri": "https://github.com/cortexsecurityplugin/Cortex-Security",
            "rules": list(rules.values())}},
            "results": results, "properties": {"filesScanned": report["files_scanned"],
            "notice": report["notice"]}}]}

def scan(root: Path, excludes: list[str] | None = None) -> dict:
    root = root.resolve()
    excludes = excludes or []
    results, count = [], 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if should_skip(rel, excludes):
            continue
        if path.name.lower() in {"scan-report.json", "cortex-scan-report.json", "scan-report.sarif", "cortex-scan-report.sarif"}:
            continue
        ext = path.suffix.lower()
        if path.name.lower() == "dockerfile":
            ext = ".dockerfile"
        if ext not in TEXT_EXTENSIONS and ext != ".dockerfile":
            continue
        count += 1
        results.extend(scan_file(path, root))
        if path.name.lower() == "requirements.txt":
            results.extend(scan_dependency_hygiene(path, root))
    results.sort(key=lambda x: (x["path"], x["line"], x["rule_id"]))
    return {"tool": "Cortex Security Heuristic Scanner", "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(), "target": str(root),
        "files_scanned": count, "finding_count": len(results),
        "notice": "Heuristic triage only. Findings are unverified; dependency checks do not query CVE databases. Results are not proof of security or insecurity.",
        "findings": results}

def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only heuristic scanner for authorized code repositories.")
    parser.add_argument("target", nargs="?", default=".", help="Repository or directory to scan")
    parser.add_argument("--output", default="reports/scan-report.json", help="JSON report output path")
    parser.add_argument("--sarif-output", help="Optional SARIF 2.1.0 report output path")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                        help="Exclude a path/glob; repeat as needed, e.g. --exclude tests")
    args = parser.parse_args()
    root = Path(args.target)
    if not root.exists() or not root.is_dir():
        parser.error(f"target must be an existing directory: {root}")
    report = scan(root, args.exclude)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.sarif_output:
        sarif_path = Path(args.sarif_output)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
    print(f"Scanned {report['files_scanned']} files; {report['finding_count']} triage finding(s).")
    print(f"JSON report: {output.resolve()}")
    if args.sarif_output:
        print(f"SARIF report: {Path(args.sarif_output).resolve()}")
    print("Reminder: validate findings manually. This tool does not check dependency CVEs.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
