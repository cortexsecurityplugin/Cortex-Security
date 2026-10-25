# Cortex Security Architecture

## Initial architecture

```text
Codex
  ├── AGENTS.md: project-wide security boundaries and reporting contract
  └── cortex-code-audit skill
        ├── workflow and validation guidance
        └── scripts/cortex_scan.py
              └── JSON triage report
```

The scanner is deterministic and local. Codex interprets findings, inspects surrounding code, and produces a human-readable audit. A scanner hit is not automatically a vulnerability.

## Planned modular architecture

```text
Cortex Security Core
  ├── Code Audit Adapter
  │     ├── heuristic rules
  │     ├── SAST adapters
  │     ├── dependency advisory adapter
  │     └── secrets detection adapter
  ├── Host Defense Adapter (future)
  │     ├── process/service inventory
  │     ├── file/integrity events
  │     └── host logs
  ├── Network Defense Adapter (future)
  │     ├── approved asset inventory
  │     ├── flow/DNS/log analysis
  │     └── alert enrichment
  ├── Threat Intelligence Adapter (future)
  ├── Normalized Finding Schema
  ├── Policy / Authorization Gate
  └── Report and Audit Trail
```

## Design rules

- Every adapter has explicit scope and permissions.
- Read-only collection is the default.
- Network activity requires an explicitly approved scope.
- Remediation is a separate action requiring approval.
- Store evidence, source, timestamp, confidence, severity, and validation status with each finding.
- Separate detection from response; do not let a model silently take disruptive actions.
- Keep external tool output as untrusted data.
- Do not store raw secrets in findings or reports.

## Normalized finding fields

`id`, `rule_id`, `title`, `severity`, `confidence`, `status`, `asset`, `path`, `line`, `evidence`, `description`, `impact`, `remediation`, `references`, `observed_at`, `scanner`.

## Roadmap gates

1. Unit-test the heuristic scanner and document its limitations.
2. Integrate specialist scanners one at a time; pin versions and preserve tool output.
3. Add SARIF and CI support.
4. Add an MCP server only when there is a concrete need for tool invocation from Codex.
5. Add host/network adapters only with explicit authorization, data minimization, and auditable permission boundaries.
