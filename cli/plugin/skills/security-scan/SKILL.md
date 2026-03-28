---
name: security-scan
description: Scan a codebase for security vulnerabilities, generate AI patches via the backend autonomous agent, revalidate, and show a dry-run diff before applying. Supports quick mode (one call) and step-by-step mode.
triggers:
  - "run security scan"
  - "scan for vulnerabilities"
  - "security remediation"
  - "fix security issues"
  - "security-pipeline"
---

# Security Scan Skill

Scan a codebase for security vulnerabilities and generate AI-powered patches using the `security-pipeline` MCP tools.
**Patch generation uses the backend autonomous agent by default.**
Use the `--local` CLI flag to use the local Claude Agent SDK (multi-turn) instead.

## Prerequisites

- Backend running at `SECURITY_PIPELINE_API_URL` (default: `http://localhost:8000`)
- `security-pipeline-mcp` in PATH (install: `uv tool install security-pipeline`)
- MCP server registered in Claude Code config (see README.md for setup)

---

## Quick Mode (Recommended)

Call `run_full_pipeline` — scans, patches, and revalidates in one blocking call.

> ⚠️ **Long-running** — performs exactly **two scans**: initial scan + one batch revalidation.

**Parameters:**
| Parameter | Default | Description |
|-----------|---------|-------------|
| `path` | required | Absolute path to the repo |
| `project_name` | required | Display name for the scan |
| `author` | `$USER` | Name for the audit trail |
| `scanners` | `["semgrep","checkov","trivy"]` | Which scanners to run |
| `severity` | all | Filter, e.g. `"CRITICAL,HIGH"` |
| `max_iterations` | `6` | Max iterations per vuln (only used with CLI `--local` flag) |

**What to show the user from the response:**
- Total vulnerabilities found (`total_vulns`)
- Revalidation: passed / failed / skipped
- `revalidation_scan_id` — the batch revalidation scan
- `dry_run_patches` — list of passing patches with full diffs (what `apply --all` would write)
- Report files generated: `.security-scan/patches/<scan_id>/REPORT-CRITICAL.md` and `REPORT-HIGH.md`
- Apply command: `security-pipeline apply <scan_id> --all`

---

## Manual Mode (Step-by-Step)

**Step 1 — Submit scan**
Call `run_security_scan` with `path` and `project_name`. Save the returned `scan_id`.

**Step 2 — Wait for results**
Call `poll_scan_status` every 30s until `status` is `"completed"` or `"failed"`.

**Step 3 — Review findings**
Call `get_scan_results`. Show findings grouped by severity.
Ask: "N findings detected — shall I generate patches for all?"

**Step 4 — Generate patches + batch revalidation**
Use `run_full_pipeline` or the CLI command `security-pipeline remediate-all <scan_id>`.
Generates all patches via the backend autonomous agent, then runs **one** revalidation scan with every patch applied at once.
Use `--local` CLI flag to use local Claude Agent SDK (multi-turn) instead.

**Step 5 — Show dry-run preview and apply**
Display the `dry_run_patches` from the response — these are exactly what `apply --all` will write.
Then call `apply_all_remediations` or tell the user to run `security-pipeline apply <scan_id> --all`.

---

## Key Details

### Two-scan pipeline
- **Scan 1**: finds all vulnerabilities
- **Scan 2**: one batch revalidation — all patches applied at once, single scan to verify
- Per-patch result determined by whether original vuln still appears and whether new issues were introduced

### Revalidation statuses
| Status | Meaning |
|--------|---------|
| `PASS` | Original vulnerability fixed, no new issues introduced |
| `FAIL_STILL_VULNERABLE` | Original vulnerability still present |
| `FAIL_NEW_ISSUES` | Patch introduced new findings in the same file |
| `FAIL_BOTH` | Original still present AND new issues introduced |

### Special handling
- **Lock files** (`uv.lock`, `poetry.lock`, `package-lock.json`, etc.) — skipped automatically; user must fix via their package manager
- **False positives** — when the autonomous agent determines a finding is not a real vulnerability, it marks it as such; these are skipped from revalidation and noted in reports
- **Evaluation concerns** — when the agent has partial confidence, concerns are recorded in the patch and appear in reports

### Generated files after `run_full_pipeline`

```
.security-scan/                        # gitignored by default
├── sessions/
│   └── <scan_id>.json                 # full scan metadata + vulnerability details
└── patches/
    └── <scan_id>/
        ├── REPORT-CRITICAL.md         # markdown report for all CRITICAL findings
        ├── REPORT-HIGH.md             # markdown report for all HIGH findings
        └── <vuln_id>/
            ├── patch.json             # generated patch with code changes
            └── revalidation.json      # per-vuln revalidation result
```

**REPORT-*.md** files include: scanner, rule, file location, message, patch summary, confidence score, code diff, revalidation status, security implications, evaluation concerns, and false positive flag. Only created when findings of that severity exist.

**sessions/<scan_id>.json** includes full vulnerability metadata (severity, rule_id, file_path, start/end lines, message, scanner) plus remediation_status tracking per vuln_id.

---

## All MCP Tools

| Tool | Description |
|------|-------------|
| `run_full_pipeline` | Full pipeline in one call: scan → patch all via backend autonomous agent → batch revalidate → reports |
| `run_security_scan` | Submit directory for scanning, returns `scan_id` immediately |
| `poll_scan_status` | Lightweight status check, call every 30s while waiting |
| `get_scan_results` | Full findings + remediations for a completed scan |
| `get_vulnerability_detail` | Deep detail for a specific vulnerability |
| `apply_remediation` | Apply a single generated patch to disk (checks revalidation status) |
| `apply_all_remediations` | Apply all PASS patches for a scan |
| `sync_sessions` | Refresh all `.security-scan/sessions/` from backend (updates vulnerability details) |
| `list_scans` | List all scans from local history |
