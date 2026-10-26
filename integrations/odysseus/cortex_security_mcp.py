"""MCP stdio server exposing bounded Cortex Security operations."""
import logging, sys
from mcp.server.fastmcp import FastMCP
from cortex_security_adapter import get_report, list_reports, scan_filesystem, security_status

logging.basicConfig(stream=sys.stderr, level=logging.INFO)
mcp = FastMCP("cortex-security")

@mcp.tool()
def cortex_security_status() -> dict:
    """Show integration status and configured scan roots."""
    return security_status()

@mcp.tool()
def cortex_security_scan_filesystem(target: str, max_file_mb: int = 50) -> dict:
    """Run the existing read-only Cortex filesystem scanner on an allowed target."""
    return scan_filesystem(target, max_file_mb)

@mcp.tool()
def cortex_security_list_reports() -> dict:
    """List known Cortex Security reports without reading arbitrary files."""
    return list_reports()

@mcp.tool()
def cortex_security_get_report(report_name: str, max_chars: int = 20000) -> dict:
    """Read an allowlisted Cortex Security report with a bounded response size."""
    return get_report(report_name, max_chars)

if __name__ == "__main__":
    mcp.run(transport="stdio")
