"""
MCP stdio server for the Security Remediation System.

Configure in ~/.claude/claude_desktop_config.json:
{
  "mcpServers": {
    "security-pipeline": {
      "command": "security-pipeline-mcp",
      "env": { "SECURITY_PIPELINE_API_URL": "http://localhost:8000" }
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
from .client import SecurityPipelineClient
from .config import load_history, get_api_url
from .cli import (
    _apply_patch_changes,
    _run_remediate_all_loop,
    _ensure_security_scan_dir,
    _submit_scan_job,
)
from pathlib import Path

API_URL = os.environ.get("SECURITY_PIPELINE_API_URL", get_api_url())
server = Server("security-pipeline")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="run_full_pipeline",
            description=(
                "Run the complete security pipeline in one call (exactly two scans): "
                "submit scan → wait for findings → generate patches for all vulnerabilities → "
                "apply all patches at once → single batch revalidation scan → return dry-run preview. "
                "Lock files (uv.lock, poetry.lock, etc.) are skipped automatically. "
                "False positives are detected and excluded from revalidation. "
                "After revalidation, writes REPORT-CRITICAL.md and REPORT-HIGH.md to "
                ".security-scan/patches/<scan_id>/ and saves full vulnerability details to "
                ".security-scan/sessions/<scan_id>.json. "
                "Patch generation uses the backend autonomous agent. "
                "Long-running blocking call. Returns scan_id, revalidation_scan_id, summary, and dry_run_patches."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to directory to scan",
                    },
                    "project_name": {"type": "string"},
                    "author": {"type": "string"},
                    "scanners": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["semgrep", "checkov", "trivy"],
                    },
                    "severity": {
                        "type": "string",
                        "description": "Comma-separated severities to include, e.g. 'CRITICAL,HIGH'. Omit for all.",
                    },
                },
                "required": ["path", "project_name"],
            },
        ),
        Tool(
            name="run_security_scan",
            description=(
                "Archive a local directory and submit it for security scanning. "
                "Returns a scan_id immediately — the scan runs asynchronously (minutes to hours). "
                "Call poll_scan_status to track progress, then get_scan_results when completed."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to directory"},
                    "project_name": {"type": "string"},
                    "author": {"type": "string"},
                    "scanners": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["semgrep", "checkov", "trivy"],
                    },
                },
                "required": ["path", "project_name"],
            },
        ),
        Tool(
            name="poll_scan_status",
            description=(
                "Lightweight status check on a running scan — returns status and summary only, "
                "no full findings payload. Call every 30s while waiting. "
                "Stop when status is 'completed' or 'failed'."
            ),
            inputSchema={
                "type": "object",
                "properties": {"scan_id": {"type": "string"}},
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="get_scan_results",
            description="Get status, all findings, and any completed remediations for a scan.",
            inputSchema={
                "type": "object",
                "properties": {"scan_id": {"type": "string"}},
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="get_vulnerability_detail",
            description=(
                "Get full details for a specific vulnerability: message, vulnerable code snippet, "
                "surrounding context, taint trace, and metadata."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "vuln_id": {"type": "string"},
                },
                "required": ["scan_id", "vuln_id"],
            },
        ),
        Tool(
            name="apply_remediation",
            description=(
                "Apply a single generated patch to the local file on disk. "
                "Only applies if revalidation passed, unless force=true. "
                "Reads .security-scan/patches/<scan_id>/<vuln_id>/patch.json."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "vuln_id": {"type": "string"},
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute path to the scanned repository root",
                    },
                    "force": {
                        "type": "boolean",
                        "default": False,
                        "description": "Apply even if revalidation failed",
                    },
                },
                "required": ["scan_id", "vuln_id", "repo_path"],
            },
        ),
        Tool(
            name="apply_all_remediations",
            description=(
                "Apply all patches that passed revalidation for a given scan. "
                "Skips patches that failed revalidation unless force=true."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute path to the scanned repository root",
                    },
                    "force": {
                        "type": "boolean",
                        "default": False,
                        "description": "Apply even patches that failed revalidation",
                    },
                },
                "required": ["scan_id", "repo_path"],
            },
        ),
        Tool(
            name="sync_sessions",
            description=(
                "Refresh scan status for all sessions in .security-scan/ of a local repo. "
                "Updates each session file with current status, summary, and full vulnerability details "
                "(severity, rule_id, file_path, scanner, etc.) from the backend. "
                "Returns list of sessions with their current status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute path to the scanned repository root",
                    }
                },
                "required": ["repo_path"],
            },
        ),
        Tool(
            name="list_scans",
            description="List all previously submitted scans with their current status from local history.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="revalidate_scan",
            description=(
                "Trigger server-side batch revalidation for all remediations in a completed scan. "
                "Applies all patches together to the workspace and runs one final scan to determine "
                "PASS/FAIL per vulnerability. Returns immediately — poll get_scan_results to check "
                "when remediations have revalidation_status populated."
            ),
            inputSchema={
                "type": "object",
                "properties": {"scan_id": {"type": "string"}},
                "required": ["scan_id"],
            },
        ),
    ]


def _safe_path_component(value: str) -> str:
    """
    Reject values that would cause path traversal when used as a single path component.
    Raises ValueError if the value contains a path separator or dotdot segment.
    """
    if not value:
        raise ValueError("Empty path component")
    # Disallow any directory separator or parent-directory traversal
    if "/" in value or "\\" in value or ".." in value:
        raise ValueError(f"Invalid path component (potential traversal): {value!r}")
    return value


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        return await _call_tool_inner(name, arguments)
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e), "tool": name}))]


async def _call_tool_inner(name: str, arguments: dict) -> list[TextContent]:
    client = SecurityPipelineClient(api_url=API_URL)

    if name == "run_full_pipeline":
        target = Path(arguments["path"])
        author = arguments.get("author", os.environ.get("USER", "unknown"))
        scanners = arguments.get("scanners", ["semgrep", "checkov", "trivy"])

        scan_id, _scan_dir = await asyncio.to_thread(
            _submit_scan_job,
            target,
            arguments["project_name"],
            author,
            scanners,
            API_URL,
        )

        result = await asyncio.to_thread(
            _run_remediate_all_loop,
            client,
            scan_id,
            target,
            arguments.get("severity"),
            True,  # quiet — no console output on stdio wire
            scanners,
        )

        return [TextContent(type="text", text=json.dumps({
            "scan_id": scan_id,
            "passed": result["passed"],
            "failed": result["failed"],
            "skipped": result["skipped"],
            "total_vulns": result["total_vulns"],
            "patches_dir": result["patches_dir"],
            "revalidation_scan_id": result.get("revalidation_scan_id"),
            "dry_run_patches": result.get("dry_run_patches", []),
        }, indent=2))]

    elif name == "run_security_scan":
        target = Path(arguments["path"])
        author = arguments.get("author", os.environ.get("USER", "unknown"))
        scanners = arguments.get("scanners", ["semgrep", "checkov", "trivy"])

        scan_id, _scan_dir = await asyncio.to_thread(
            _submit_scan_job,
            target,
            arguments["project_name"],
            author,
            scanners,
            API_URL,
        )

        return [TextContent(type="text", text=json.dumps({
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan queued. Call poll_scan_status(scan_id='{scan_id}') to track progress.",
        }, indent=2))]

    elif name == "poll_scan_status":
        data = await asyncio.to_thread(client.get_scan, arguments["scan_id"])
        return [TextContent(type="text", text=json.dumps({
            "scan_id": arguments["scan_id"],
            "status": data.get("status"),
            "summary": data.get("summary", {}),
        }, indent=2))]

    elif name == "get_scan_results":
        data = await asyncio.to_thread(client.get_scan, arguments["scan_id"])
        return [TextContent(type="text", text=json.dumps(data, indent=2))]

    elif name == "get_vulnerability_detail":
        result = await asyncio.to_thread(
            client.get_vulnerability, arguments["scan_id"], arguments["vuln_id"]
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "apply_remediation":
        scan_id = arguments["scan_id"]
        vuln_id = arguments["vuln_id"]
        repo_path = Path(arguments["repo_path"])
        force = arguments.get("force", False)

        patch_file = repo_path / ".security-scan" / "patches" / scan_id / vuln_id / "patch.json"
        reval_file = repo_path / ".security-scan" / "patches" / scan_id / vuln_id / "revalidation.json"

        if not patch_file.exists():
            return [TextContent(type="text", text=json.dumps({"error": f"patch.json not found at {patch_file}"}))]

        patch = json.loads(patch_file.read_text())
        reval_status = json.loads(reval_file.read_text()).get("status", "UNKNOWN") if reval_file.exists() else "NOT_RUN"

        if reval_status != "PASS" and not force:
            return [TextContent(type="text", text=json.dumps({
                "error": f"Revalidation status is {reval_status}. Pass force=true to apply anyway.",
                "revalidation_status": reval_status,
            }))]

        applied_files = _apply_patch_changes(repo_path, patch.get("code_changes", []))

        if applied_files:
            session_file = repo_path / ".security-scan" / "sessions" / f"{scan_id}.json"
            if session_file.exists():
                session = json.loads(session_file.read_text())
                session.setdefault("remediation_status", {})[vuln_id] = "applied"
                session_file.write_text(json.dumps(session, indent=2))

        return [TextContent(type="text", text=json.dumps({
            "status": "applied",
            "vuln_id": vuln_id,
            "revalidation_status": reval_status,
            "applied_files": applied_files,
            "summary": patch.get("summary", ""),
        }, indent=2))]

    elif name == "apply_all_remediations":
        scan_id = arguments["scan_id"]
        repo_path = Path(arguments["repo_path"])
        force = arguments.get("force", False)
        patches_base = repo_path / ".security-scan" / "patches" / scan_id

        if not patches_base.exists():
            return [TextContent(type="text", text=json.dumps({"error": f"No patches found at {patches_base}"}))]

        applied = []
        skipped = []

        for patch_dir in patches_base.iterdir():
            if not patch_dir.is_dir():
                continue
            patch_file = patch_dir / "patch.json"
            reval_file = patch_dir / "revalidation.json"
            if not patch_file.exists():
                continue

            patch = json.loads(patch_file.read_text())
            vid = patch.get("vuln_id", patch_dir.name)
            reval_status = json.loads(reval_file.read_text()).get("status", "UNKNOWN") if reval_file.exists() else "NOT_RUN"

            if reval_status != "PASS" and not force:
                skipped.append({"vuln_id": vid, "reason": f"revalidation {reval_status}"})
                continue

            applied_files = _apply_patch_changes(repo_path, patch.get("code_changes", []))
            if applied_files:
                session_file = repo_path / ".security-scan" / "sessions" / f"{scan_id}.json"
                if session_file.exists():
                    session = json.loads(session_file.read_text())
                    session.setdefault("remediation_status", {})[vid] = "applied"
                    session_file.write_text(json.dumps(session, indent=2))
            applied.append({"vuln_id": vid, "applied_files": applied_files, "revalidation_status": reval_status})

        return [TextContent(type="text", text=json.dumps({
            "applied": applied,
            "skipped": skipped,
            "total_applied": len(applied),
            "total_skipped": len(skipped),
        }, indent=2))]

    elif name == "sync_sessions":
        repo_path = Path(arguments["repo_path"])
        sessions_dir = repo_path / ".security-scan" / "sessions"
        if not sessions_dir.exists():
            return [TextContent(type="text", text=json.dumps({"sessions": [], "message": "No .security-scan/ found."}))]

        results = []
        for session_file in sessions_dir.glob("*.json"):
            session = json.loads(session_file.read_text())
            scan_id = session["scan_id"]
            try:
                data = await asyncio.to_thread(client.get_scan, scan_id)
                session["status"] = data.get("status", "unknown")
                session["summary"] = data.get("summary", {})
                all_vulns = data.get("vulnerabilities", [])
                session["vulnerability_ids"] = [v["id"] for v in all_vulns]
                session["vulnerabilities"] = [
                    {
                        "id": v["id"],
                        "rule_id": v.get("rule_id"),
                        "severity": v.get("severity"),
                        "file_path": v.get("file_path"),
                        "start_line": v.get("start_line"),
                        "end_line": v.get("end_line"),
                        "message": v.get("message"),
                        "scanner": v.get("scanner"),
                    }
                    for v in all_vulns
                ]
                session["last_synced_at"] = datetime.utcnow().isoformat()
                session_file.write_text(json.dumps(session, indent=2))
                results.append({"scan_id": scan_id, "status": session["status"], "summary": session["summary"]})
            except Exception as e:
                results.append({"scan_id": scan_id, "status": "error", "error": str(e)})

        return [TextContent(type="text", text=json.dumps({"sessions": results}, indent=2))]

    elif name == "list_scans":
        history = load_history()
        items = []
        for entry in history:
            try:
                data = await asyncio.to_thread(client.get_scan, entry["scan_id"])
                status = data.get("status", "unknown")
            except Exception:
                status = "unreachable"
            items.append({
                "scan_id": entry["scan_id"],
                "project_name": entry.get("project_name"),
                "submitted_at": entry.get("submitted_at"),
                "status": status,
            })
        return [TextContent(type="text", text=json.dumps(items, indent=2))]

    elif name == "revalidate_scan":
        result = await asyncio.to_thread(client.revalidate_scan, arguments["scan_id"])
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _main():
    from mcp.server.lowlevel.server import InitializationOptions, NotificationOptions
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="security-pipeline",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main():
    import sys

    # Detect direct terminal invocation (--help, -h, or interactive stdin).
    # The MCP server communicates over stdio JSON-RPC and cannot be used as a
    # regular CLI tool — it must be launched by Claude Code via the MCP config.
    if "--help" in sys.argv or "-h" in sys.argv or sys.stdin.isatty():
        print(
            "security-pipeline-mcp — MCP stdio server for the Security Pipeline\n"
            "\n"
            "This process is not meant to be run directly from a terminal.\n"
            "It speaks JSON-RPC over stdin/stdout and must be launched by Claude Code.\n"
            "\n"
            "To register with Claude Code, add to ~/.claude/claude_desktop_config.json:\n"
            "\n"
            '  {\n'
            '    "mcpServers": {\n'
            '      "security-pipeline": {\n'
            '        "command": "security-pipeline-mcp",\n'
            '        "env": { "SECURITY_PIPELINE_API_URL": "http://localhost:8000" }\n'
            '      }\n'
            '    }\n'
            '  }\n'
            "\n"
            "Then restart Claude Code. The MCP tools will appear under /mcp.\n"
            "\n"
            "For the regular CLI, use: security-pipeline --help\n",
            file=sys.stderr,
        )
        sys.exit(0)

    asyncio.run(_main())


if __name__ == "__main__":
    main()
