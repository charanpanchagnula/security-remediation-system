"""
MCP stdio server for the Security Remediation System.

Configure in ~/.claude/claude_desktop_config.json:
{
  "mcpServers": {
    "secremediator": {
      "command": "secremediator-mcp",
      "env": { "SECREMEDIATOR_API_URL": "http://localhost:8000" }
    }
  }
}
"""
import os
import json
import asyncio
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from .client import SecRemediatorClient
from .archiver import create_archive
from .config import save_to_history, get_api_url
from pathlib import Path

API_URL = os.environ.get("SECREMEDIATOR_API_URL", get_api_url())
server = Server("secremediator")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="run_security_scan",
            description=(
                "Zip a local directory and submit it for security scanning. "
                "Returns a scan_id immediately — the scan is async and may take minutes to hours. "
                "Call get_scan_results to check status when ready."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to directory"},
                    "scanners": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["semgrep", "checkov", "trivy"],
                    },
                    "project_name": {"type": "string"},
                    "author": {"type": "string"},
                },
                "required": ["path", "project_name"],
            },
        ),
        Tool(
            name="get_scan_results",
            description="Get status and findings for a scan. Returns status: queued|in_progress|completed.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="request_remediation",
            description="Get AI-generated remediation for a specific vulnerability by its vuln id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "vuln_id": {"type": "string"},
                },
                "required": ["scan_id", "vuln_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    client = SecRemediatorClient(api_url=API_URL)

    if name == "run_security_scan":
        path = arguments["path"]
        project_name = arguments["project_name"]
        author = arguments.get("author", os.environ.get("USER", "unknown"))
        scanners = arguments.get("scanners", ["semgrep", "checkov", "trivy"])

        archive_path = await asyncio.to_thread(create_archive, path)
        try:
            result = await asyncio.to_thread(
                client.upload_scan,
                archive_path, project_name, author, scanners
            )
        finally:
            Path(archive_path).unlink(missing_ok=True)

        scan_id = result["scan_id"]
        save_to_history({
            "scan_id": scan_id,
            "project_name": project_name,
            "author": author,
            "scanners": scanners,
            "path": path,
            "submitted_at": datetime.utcnow().isoformat(),
            "api_url": API_URL,
        })

        return [TextContent(type="text", text=json.dumps({
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan queued. Call get_scan_results(scan_id='{scan_id}') when ready to review findings.",
        }, indent=2))]

    elif name == "get_scan_results":
        data = await asyncio.to_thread(client.get_scan, arguments["scan_id"])
        return [TextContent(type="text", text=json.dumps(data, indent=2))]

    elif name == "request_remediation":
        result = await asyncio.to_thread(
            client.request_remediation, arguments["scan_id"], arguments["vuln_id"]
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _main():
    from mcp.server.lowlevel.server import InitializationOptions, NotificationOptions
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="secremediator",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main():
    asyncio.run(_main())


if __name__ == "__main__":
    main()
