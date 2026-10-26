# Cortex Security + Odysseus integration (preview)

This optional adapter exposes the existing v0.5 filesystem scanner and selected reports to Odysseus through an MCP stdio server.

## Tools
- `cortex_security_status`: integration/scanner status and allowed roots.
- `cortex_security_scan_filesystem`: read-only heuristic scan of an approved target.
- `cortex_security_list_reports`: list allowlisted reports.
- `cortex_security_get_report`: read a named report with response-size limits.

It does not run Defender scans, execute arbitrary shell commands, quarantine/delete files, or change Windows settings.

## Install on native Windows Odysseus

From `R:\CortexSecurity` in PowerShell:

```powershell
.\.venv-security\Scripts\python.exe -m pip install -r .\integrations\odysseus\requirements-odysseus.txt
```

In Odysseus Settings > MCP, add a local stdio server with:
- Command: `R:\CortexSecurity\.venv-security\Scripts\python.exe`
- Argument: `R:\CortexSecurity\integrations\odysseus\cortex_security_mcp.py`
- `CORTEX_SECURITY_ROOT=R:\CortexSecurity`
- `CORTEX_SECURITY_ALLOWED_ROOTS=R:\CortexSecurity`

Use the actual installed paths if different. Keep the server local and do not put secrets in its environment.

The default scan boundary is the Cortex Security repository only. To authorize another project, add its exact directory to `CORTEX_SECURITY_ALLOWED_ROOTS`, separated by a semicolon on Windows. This is a tool-level access boundary, not an OS sandbox.

## Docker warning
This configuration assumes Odysseus can launch a Windows process and see `R:\CortexSecurity`. If Odysseus runs in Docker, the host path is not automatically visible; configure an explicit volume mount or a host-side bridge first.

## Import the skill
After these files are committed and pushed to your GitHub repo, import this folder in Odysseus Brain > Skills:
`https://github.com/cortexsecurityplugin/Cortex-Security/tree/main/integrations/odysseus/skill`

The skill and MCP server are separate: importing the skill teaches workflow, while the MCP server provides tools. Odysseus may require its own skill review/publish flow.

## Verify
1. In Agent mode, call `cortex_security_status`; do not scan yet.
2. Verify the allowed roots shown are correct.
3. Ask for a scan of `R:\CortexSecurity\scripts`.
4. Read `filesystem-scan.json` through the report tool.

Heuristic matches are not confirmed malware. An unchanged Defender history does not prove a system is clean. Python venvs isolate packages, not host permissions.
