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
from .config import save_to_history, load_history, get_api_url, save_archive, get_archive_path
from .cli import _apply_patch_changes, _run_remediate_all_loop, _ensure_security_scan_dir, _security_scan_dir, _submit_scan_job
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
            name="get_vulnerability_detail",
            description=(
                "Get full details for a specific vulnerability: complete message, vulnerable code snippet, "
                "surrounding context, taint trace, and metadata. Use this after get_scan_results to "
                "deeply inspect a finding before requesting remediation."
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
            name="request_remediation",
            description=(
                    "Trigger AI-generated remediation for a specific vulnerability. "
                    "Returns immediately with status 'pending' or 'completed'. "
                    "If pending, call get_scan_results to check when the remediation appears "
                    "in the scan's remediations list."
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
            name="poll_scan_status",
            description=(
                "Lightweight status check on a running scan. Returns status and summary only — "
                "no full findings payload. Call this in a loop (e.g. every 30s) while waiting for "
                "long-running scans. Stop polling when status is 'completed' or 'failed'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_scans",
            description="List all previously submitted scans with their status from local history.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="sync_sessions",
            description=(
                "Refresh scan status for all sessions in .security-scan/ of a local repo. "
                "Returns list of sessions with their current status from backend."
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
            name="apply_all_remediations",
            description=(
                "Apply all patches that passed revalidation for a given scan. "
                "Reads .security-scan/patches/<scan_id>/*/patch.json and writes new_code to disk. "
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
            name="apply_remediation",
            description=(
                "Apply a generated patch to the local file on disk. "
                "Reads .security-scan/patches/<scan_id>/<vuln_id>/patch.json and writes new_code "
                "to the affected lines in the file. Only applies if revalidation passed unless force=true. "
                "Returns a summary of what changed."
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
            name="remediate_all",
            description=(
                "Run full remediation loop for a completed scan. "
                "Polls scan to completion, generates AI patches for all vulnerabilities, revalidates each patch. "
                "Long-running blocking call. Returns summary with passed/failed/skipped counts."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "repo_path": {
                        "type": "string",
                        "description": "Absolute path to the scanned repository root",
                    },
                    "severity": {
                        "type": "string",
                        "description": "Comma-separated severities to include, e.g. CRITICAL,HIGH. Omit for all.",
                    },
                    "use_local_claude": {
                        "type": "boolean",
                        "default": False,
                        "description": "Use local Claude Agent SDK instead of backend engine",
                    },
                },
                "required": ["scan_id", "repo_path"],
            },
        ),
        Tool(
            name="run_full_pipeline",
            description=(
                "Run complete security pipeline in one call: archive → submit → wait for results → patch all → revalidate. "
                "Long-running blocking call. Returns scan_id and remediation summary."
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
                        "description": "Comma-separated severities to include. Omit for all.",
                    },
                    "use_local_claude": {
                        "type": "boolean",
                        "default": False,
                    },
                },
                "required": ["path", "project_name"],
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

    elif name == "get_vulnerability_detail":
        result = await asyncio.to_thread(
            client.get_vulnerability, arguments["scan_id"], arguments["vuln_id"]
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "request_remediation":
        result = await asyncio.to_thread(
            client.request_remediation, arguments["scan_id"], arguments["vuln_id"]
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "poll_scan_status":
        data = await asyncio.to_thread(client.get_scan, arguments["scan_id"])
        return [TextContent(type="text", text=json.dumps({
            "scan_id": arguments["scan_id"],
            "status": data.get("status"),
            "summary": data.get("summary", {}),
        }, indent=2))]

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
                session["vulnerability_ids"] = [v["id"] for v in data.get("vulnerabilities", [])]
                session["last_synced_at"] = datetime.utcnow().isoformat()
                session_file.write_text(json.dumps(session, indent=2))
                results.append({"scan_id": scan_id, "status": session["status"], "summary": session["summary"]})
            except Exception as e:
                results.append({"scan_id": scan_id, "status": "error", "error": str(e)})

        return [TextContent(type="text", text=json.dumps({"sessions": results}, indent=2))]

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

        if reval_file.exists():
            reval_status = json.loads(reval_file.read_text()).get("status", "UNKNOWN")
        else:
            reval_status = "NOT_RUN"

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

    elif name == "remediate_all":
        scan_id = arguments["scan_id"]
        repo_path = Path(arguments["repo_path"])
        severity = arguments.get("severity")
        use_local_claude = arguments.get("use_local_claude", False)

        result = await asyncio.to_thread(
            _run_remediate_all_loop,
            client,
            scan_id,
            repo_path,
            severity,
            use_local_claude,
            True,  # quiet=True — suppress console output on stdio wire
        )

        return [TextContent(type="text", text=json.dumps({
            "scan_id": scan_id,
            "passed": result["passed"],
            "failed": result["failed"],
            "skipped": result["skipped"],
            "total_vulns": result["total_vulns"],
            "patches_dir": result["patches_dir"],
        }, indent=2))]

    elif name == "run_full_pipeline":
        path = arguments["path"]
        project_name = arguments["project_name"]
        author = arguments.get("author", os.environ.get("USER", "unknown"))
        scanners = arguments.get("scanners", ["semgrep", "checkov", "trivy"])
        severity = arguments.get("severity")
        use_local_claude = arguments.get("use_local_claude", False)
        target = Path(path)

        scan_id, scan_dir = await asyncio.to_thread(
            _submit_scan_job,
            target,
            project_name,
            author,
            scanners,
            API_URL,
        )

        result = await asyncio.to_thread(
            _run_remediate_all_loop,
            client,
            scan_id,
            target,
            severity,
            use_local_claude,
            True,  # quiet=True
        )

        return [TextContent(type="text", text=json.dumps({
            "scan_id": scan_id,
            "passed": result["passed"],
            "failed": result["failed"],
            "skipped": result["skipped"],
            "total_vulns": result["total_vulns"],
            "patches_dir": result["patches_dir"],
        }, indent=2))]

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
