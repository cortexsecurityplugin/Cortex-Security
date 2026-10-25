# Cortex Security

Cortex Security is a Codex plugin starter for defensive code auditing. It packages a reusable Codex skill, a deterministic Python source scanner, a report directory convention, and an extension plan for future host/network defense.

## Current status

**Starter / alpha.** The included scanner is a lightweight heuristic triage tool, not a substitute for a full SAST, dependency, secrets, or dynamic-analysis suite. It may produce false positives and miss vulnerabilities.

## Structure

```text
CortexSecurity/
├── .codex-plugin/plugin.json
├── .mcp.json
├── AGENTS.md
├── README.md
├── requirements.txt
├── skills/cortex-code-audit/SKILL.md
├── scripts/cortex_scan.py
├── tests/test_cortex_scan.py
├── reports/.gitkeep
└── docs/ARCHITECTURE.md
```

## Requirements

- Python 3.10+
- Codex with plugin/skill support
- Optional scanners can be installed separately after reviewing their official documentation.

No API key is required for the included local scanner.

## Run the scanner

From this directory:

```powershell
python scripts/cortex_scan.py . --output reports/scan-report.json
```

To scan a target repository:

```powershell
python scripts/cortex_scan.py "C:\path\to\repo" --output reports\scan-report.json
```

The scanner does not execute the target code. It skips common virtual-environment, build, dependency, and VCS directories. Review the scope before relying on results.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Use with Codex locally

For a repository-specific skill, copy the `skills/cortex-code-audit` directory into the target repository at:

```text
.agents/skills/cortex-code-audit/
```

Keep `AGENTS.md` at the repository root. Start Codex from that repository and invoke `$cortex-code-audit` (or ask Codex to use the Cortex code-audit workflow).

Codex scans `.agents/skills` locations in the repository hierarchy. If the skill does not appear, restart Codex and check the path.

## Package as a plugin

The `.codex-plugin/plugin.json` manifest declares the skills folder and MCP configuration. The `.mcp.json` file is intentionally empty: the first release needs no MCP server. Add one only when there is a real external tool service to connect, and document authentication and permissions.

Plugin packaging and installation support can vary by Codex surface/version. Use the current official Codex plugin instructions for the specific client you use.

## Security principles

- Read-only by default.
- No network scanning or exploitation in this first release.
- No automatic remediation.
- Do not commit reports containing secrets, internal paths, or sensitive source snippets.
- Treat scanner results as triage leads until manually validated.

## Roadmap

1. Add tested rules and structured findings.
2. Add optional SAST, dependency, and secret-scanning adapters.
3. Add CI integration and SARIF export.
4. Add a local MCP server exposing controlled scan/report tools.
5. Add host telemetry and network-analysis modules behind separate permissions and explicit user approval.
