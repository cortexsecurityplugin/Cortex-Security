---
name: cortex-security
description: Use Cortex Security's local read-only filesystem scanner and reports for evidence-based defensive triage.
version: 0.1.0
category: security
tags: [cortex, security, audit, windows]
platforms: [windows]
status: published
confidence: 0.95
source: imported
---

## When to Use

Use this skill when asked to scan an authorized project with Cortex Security or interpret its reports. Use the `cortex_security_*` MCP tools when available; this skill alone does not grant filesystem access.

## Procedure

1. Call `cortex_security_status` to check that the integration and scanner are available.
2. Confirm the target is within configured allowed scan roots. If rejected, ask the user to configure an approved root; never bypass the boundary using shell or another tool.
3. For a requested audit, call `cortex_security_scan_filesystem` on the approved target.
4. Use `cortex_security_list_reports` and `cortex_security_get_report` to review the output.
5. Describe heuristic matches as unverified triage leads, not confirmed malware. Separate severity from confidence and mention errors, exclusions, and limitations.
6. Keep historical Defender records separate from current scan results. An unchanged history snapshot does not prove a system is clean.
7. Do not delete files, execute suspicious code, change Defender settings, or claim to quarantine malware.

## Pitfalls

- Successful tool execution does not prove the system is clean.
- A Python virtual environment isolates packages, not the process from Windows.
- The allowed-root setting is an access boundary, not a complete operating-system sandbox.
- Reports may contain internal paths and sensitive evidence; reveal only what is needed.
- This integration does not run Defender scans or perform remediation.

## Verification

- Confirm status reports the scanner as available.
- Confirm scan results show target, file count, findings, errors, and report path.
- Confirm the JSON report can be read with `cortex_security_get_report`.
- State what ran, what did not run, and what remains unknown.
