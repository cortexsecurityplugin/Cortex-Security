# Cortex Security v0.2.0

## Added
- Repeatable `--exclude` path/glob options; common generated and dependency directories remain excluded.
- Heuristic checks for private-key headers and AWS access-key-ID-shaped strings.
- Redacted evidence for secret-related findings.
- Basic `requirements.txt` hygiene check for unpinned dependencies (`CX101`).
- Optional SARIF 2.1.0 output via `--sarif-output`.
- Five unit tests for detections, redaction, exclusions, dependency hygiene, and SARIF structure.

## Limitations
- Heuristic triage only; pattern matches can be false positives.
- Dependency hygiene is not a CVE lookup and does not establish whether a package is vulnerable.
- No findings does not prove a repository is secure.
