---
name: security-scan
description: Run security scanning and AI-powered remediation on a codebase. Supports quick mode (one call) and manual step-by-step mode.
triggers:
  - "run security scan"
  - "scan for vulnerabilities"
  - "security remediation"
  - "fix security issues"
  - "secremediator"
---

# Security Scan Skill

Scan a codebase for security vulnerabilities and auto-generate AI-powered patches using the `secremediator` MCP tools.

## Prerequisites

- Backend running at `SECREMEDIATOR_API_URL` (default: http://localhost:8000)
- `secremediator-mcp` binary in PATH (`pip install secremediator` or `uv tool install secremediator`)
- MCP server registered in your Claude Code config

## Quick Mode (Recommended)

Use `run_full_pipeline` to scan and remediate in a single call:

> ⚠️ **Long-running operation** — this may take several minutes. The tool will block until scanning and remediation complete.

1. Call `run_full_pipeline` with:
   - `path`: absolute path to the repository (ask user if unclear)
   - `project_name`: project name (default: directory name)
   - `author`: optional — user's name for the audit trail
   - `severity`: optional — e.g. `"CRITICAL,HIGH"` to remediate only critical/high severity findings
   - `use_local_claude`: `false` (use backend engine) or `true` (use local Claude Agent SDK)

2. Show results to the user:
   - Total vulnerabilities found
   - Patches passed / failed / skipped revalidation
   - Patches directory path
   - Apply command: `secremediator apply <scan_id> --all`

## Manual Mode (Step-by-Step)

Use individual tools for more control:

**Step 1 — Submit scan**
Call `run_security_scan` with `path` and `project_name`. Save the returned `scan_id`.

**Step 2 — Wait for results**
Call `poll_scan_status` every 30 seconds until `status` is `"completed"` or `"failed"`.

**Step 3 — Review findings**
Call `get_scan_results` with the `scan_id`. Show the user findings grouped by severity.
Ask: "These N findings were detected. Shall I generate patches for all of them?"

**Step 4 — Generate patches**
Call `remediate_all` with the `scan_id` and `repo_path`. This is a long-running blocking call.

**Step 5 — Show revalidation results**
Display the returned summary (passed/failed/skipped).

**Step 6 — Apply patches**
For patches that passed revalidation, call `apply_all_remediations` with `scan_id` and `repo_path`.
Or have the user run: `secremediator apply <scan_id> --all`

## Notes

- Patches are stored in `.security-scan/patches/<scan_id>/<vuln_id>/patch.json`
- Revalidation results are in `.security-scan/patches/<scan_id>/<vuln_id>/revalidation.json`
- Session state is in `.security-scan/sessions/<scan_id>.json`
- The `.security-scan/` directory is gitignored by default
- To refresh session state: call `sync_sessions` with `repo_path`
- To apply individual patches: call `apply_remediation` with `scan_id`, `vuln_id`, and `repo_path`
