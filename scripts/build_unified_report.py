#!/usr/bin/env python3
"""Combine Cortex, Bandit, and pip-audit JSON outputs into a unified audit report."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def normalize_cortex(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for item in report.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        findings.append({
            "source": "cortex",
            "rule_id": item.get("rule_id") or item.get("rule") or item.get("id") or "unknown",
            "severity": str(item.get("severity") or "unknown").lower(),
            "title": item.get("title") or item.get("message") or item.get("description") or "Cortex heuristic finding",
            "path": item.get("path") or item.get("file") or item.get("filename"),
            "line": item.get("line"),
            "evidence": item.get("evidence"),
            "remediation": item.get("remediation"),
        })
    return findings


def normalize_bandit(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for item in report.get("results", []) or []:
        if not isinstance(item, dict):
            continue
        findings.append({
            "source": "bandit",
            "rule_id": item.get("test_id", "unknown"),
            "severity": str(item.get("issue_severity") or "unknown").lower(),
            "confidence": str(item.get("issue_confidence") or "unknown").lower(),
            "title": item.get("issue_text") or "Bandit finding",
            "path": item.get("filename"),
            "line": item.get("line_number"),
            "evidence": item.get("code"),
            "remediation": "Review the finding and apply a context-appropriate fix.",
        })
    return findings


def normalize_pip_audit(report: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    dependency_count = 0
    for dep in report.get("dependencies", []) or []:
        if not isinstance(dep, dict):
            continue
        dependency_count += 1
        for vuln in dep.get("vulns", []) or []:
            if not isinstance(vuln, dict):
                continue
            fix_versions = vuln.get("fix_versions") or []
            findings.append({
                "source": "pip-audit",
                "rule_id": vuln.get("id") or "unknown",
                "severity": str(vuln.get("severity") or "unknown").lower(),
                "title": f"{dep.get('name', 'unknown-package')} {dep.get('version', 'unknown-version')}: "
                         f"{vuln.get('id', 'vulnerability')}",
                "package": dep.get("name"),
                "installed_version": dep.get("version"),
                "fix_versions": fix_versions,
                "description": vuln.get("description"),
                "remediation": ("Upgrade to one of: " + ", ".join(map(str, fix_versions))
                                if fix_versions else "Review the advisory and select a patched version."),
            })
    return findings, dependency_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--requirements-file", default="requirements.txt")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    report_dir = Path(args.report_dir).resolve()
    status = read_json(report_dir / "audit-run-status.json") or {}
    cortex = read_json(report_dir / "scan-report.json")
    bandit = read_json(report_dir / "bandit-report.json")
    pip_audit = read_json(report_dir / "pip-audit-report.json")

    all_findings: list[dict[str, Any]] = []
    checks: dict[str, dict[str, Any]] = {}

    def tool_status(key: str, report: dict[str, Any] | None, count: int | None = None) -> str:
        run = status.get(key, {})
        if not run.get("available", False):
            return "not_run"
        if not run.get("success", False):
            return "error"
        if report is None:
            return "error"
        if key == "pip_audit" and count == 0:
            return "inconclusive"
        return "findings" if (count or 0) > 0 else "passed"

    cortex_findings = normalize_cortex(cortex or {})
    bandit_findings = normalize_bandit(bandit or {})
    pip_findings, dependency_count = normalize_pip_audit(pip_audit or {})
    all_findings.extend(cortex_findings)
    all_findings.extend(bandit_findings)
    all_findings.extend(pip_findings)

    checks["cortex"] = {
        "status": tool_status("cortex", cortex, len(cortex_findings)),
        "report": "scan-report.json",
        "finding_count": len(cortex_findings),
        "files_scanned": (cortex or {}).get("files_scanned"),
    }
    checks["bandit"] = {
        "status": tool_status("bandit", bandit, len(bandit_findings)),
        "report": "bandit-report.json",
        "finding_count": len(bandit_findings),
    }
    checks["pip_audit"] = {
        "status": tool_status("pip_audit", pip_audit, dependency_count),
        "report": "pip-audit-report.json",
        "requirements_file": args.requirements_file,
        "dependencies_audited": dependency_count,
        "vulnerability_count": len(pip_findings),
        "note": ("No dependencies were represented in the report; this is inconclusive, not a clean bill of health."
                 if dependency_count == 0 else None),
    }

    severity_counts = Counter(str(f.get("severity", "unknown")).lower() for f in all_findings)
    report = {
        "schema_version": "1.0",
        "product": "Cortex Security",
        "version": "0.4.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "overall_status": (
            "error" if any(v["status"] == "error" for v in checks.values())
            else "inconclusive" if any(v["status"] in ("inconclusive", "not_run") for v in checks.values())
            else "findings" if all_findings else "passed"
        ),
        "checks": checks,
        "summary": {
            "total_findings": len(all_findings),
            "by_source": {
                "cortex": len(cortex_findings),
                "bandit": len(bandit_findings),
                "pip_audit": len(pip_findings),
            },
            "by_severity": dict(sorted(severity_counts.items())),
        },
        "findings": all_findings,
        "limitations": [
            "Heuristic and static-analysis results do not prove a project is secure.",
            "Dependency results apply only to the requirements file recorded for this run.",
            "A pip-audit report with zero dependencies is inconclusive.",
            "Review individual tool reports for complete tool-specific metadata.",
        ],
    }
    json_path = report_dir / "unified-audit-report.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    lines = [
        "# Cortex Security v0.4 — Unified Audit Summary", "",
        f"- **Generated:** {report['generated_at']}",
        f"- **Target:** `{target}`",
        f"- **Overall status:** **{report['overall_status'].upper()}**",
        f"- **Total normalized findings:** {len(all_findings)}", "",
        "| Check | Status | Findings / dependencies | Report |",
        "|---|---|---:|---|",
        f"| Cortex heuristic scanner | {checks['cortex']['status']} | {len(cortex_findings)} findings | `scan-report.json` |",
        f"| Bandit | {checks['bandit']['status']} | {len(bandit_findings)} findings | `bandit-report.json` |",
        f"| pip-audit | {checks['pip_audit']['status']} | {dependency_count} dependencies; {len(pip_findings)} vulnerabilities | `pip-audit-report.json` |",
        "",
    ]
    if dependency_count == 0:
        lines += ["**Dependency audit limitation:** pip-audit reported zero dependencies. This is inconclusive, not proof that dependencies are vulnerability-free.", ""]
    if all_findings:
        lines += ["## Findings", ""]
        for i, finding in enumerate(all_findings, 1):
            location = ""
            if finding.get("path"):
                location = f" — `{finding['path']}`"
                if finding.get("line") is not None:
                    location += f":{finding['line']}"
            lines.append(f"{i}. **[{finding.get('severity', 'unknown').upper()}] {finding.get('source')} / {finding.get('rule_id')}** — {finding.get('title')}{location}")
            if finding.get("remediation"):
                lines.append(f"   - Remediation: {finding['remediation']}")
        lines.append("")
    else:
        lines += ["No findings were normalized from the available reports. This is not a guarantee of security.", ""]
    lines += ["## Limitations", ""] + [f"- {item}" for item in report["limitations"]] + [""]
    (report_dir / "unified-audit-summary.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Unified JSON: {json_path}")
    print(f"Unified summary: {report_dir / 'unified-audit-summary.md'}")
    print(f"Overall status: {report['overall_status']}; normalized findings: {len(all_findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
