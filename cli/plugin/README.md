# security-pipeline Claude Code Plugin

A Claude Code plugin that bundles the `security-pipeline` MCP server, security scan skill, and pre-push warning hook into one installable unit.

## What it includes

- **MCP Server** — 11 tools for security scanning, remediation, and patch management
- **Skill** — `/security-pipeline:security-scan` — guided security scan workflow (quick mode or manual)
- **Hook** — Pre-push warning when unpatched security findings exist in `.security-scan/`

## Prerequisites

1. **Backend running** — the security-pipeline API backend must be accessible:
   ```bash
   export SECURITY_PIPELINE_API_URL=http://localhost:8000
   ```

2. **CLI installed** — `security-pipeline-mcp` must be in PATH:
   ```bash
   uv tool install security-pipeline
   # or from source (editable):
   cd cli && uv tool install --editable . --force
   ```

## Installation

```bash
claude --plugin-dir path/to/cli/plugin
```

Or add to your Claude Code settings:
```json
{
  "plugins": ["path/to/cli/plugin"]
}
```

## Usage

### Quick security scan

Use the skill: `/security-pipeline:security-scan`

Or call the MCP tool directly: `run_full_pipeline`

### Apply generated patches

```bash
security-pipeline apply <scan_id> --all
```

### View findings

```bash
security-pipeline results <scan_id>
```

### View generated reports

After `remediate_all` or `run_full_pipeline` completes, severity reports are written automatically:

```bash
cat .security-scan/patches/<scan_id>/REPORT-CRITICAL.md
cat .security-scan/patches/<scan_id>/REPORT-HIGH.md
```

Reports include: rule, file location, patch summary, confidence score, code diff, revalidation status, security implications, and evaluation concerns.

---

## MCP Tools Reference

| Tool | Description |
|------|-------------|
| `run_full_pipeline` | Full pipeline in one call: scan → patch all → batch revalidate → generate reports |
| `run_security_scan` | Submit directory for scanning, returns `scan_id` immediately |
| `poll_scan_status` | Lightweight status check (call every 30s while scan is running) |
| `get_scan_results` | Full findings + remediations for a completed scan |
| `get_vulnerability_detail` | Deep detail for a specific vulnerability |
| `request_remediation` | Queue server-side AI remediation for a single vulnerability |
| `remediate_all` | Patch all vulns + batch revalidate for an existing completed scan |
| `apply_remediation` | Apply a single generated patch to files on disk |
| `apply_all_remediations` | Apply all patches that passed revalidation for a scan |
| `sync_sessions` | Refresh session state + full vulnerability details from backend |
| `list_scans` | List all scans from local history with current status |

---

## Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `SECURITY_PIPELINE_API_URL` | `http://localhost:8000` | Backend API URL |
| `ANTHROPIC_API_KEY` | (from env) | Required for local Claude patch generation; picked up automatically if set |

---

## Output File Structure

All output is written to `.security-scan/` at the scanned repo root. The entire directory is gitignored automatically.

```
.security-scan/
├── .gitignore                         # Contains "*" — entire dir is gitignored
├── sessions/
│   └── <scan_id>.json                 # Scan metadata + full vulnerability details
└── patches/
    └── <scan_id>/
        ├── REPORT-CRITICAL.md         # Generated after remediate_all; CRITICAL findings only
        ├── REPORT-HIGH.md             # Generated after remediate_all; HIGH findings only
        └── <vuln_id>/
            ├── patch.json             # Generated patch (code changes, confidence, false positive flag)
            └── revalidation.json      # Revalidation result (PASS / FAIL_* status)
```

### Session file schema

```json
{
  "scan_id": "uuid",
  "project_name": "my-project",
  "author": "alice",
  "scanners": ["semgrep", "checkov", "trivy"],
  "path": "/abs/path/to/repo",
  "submitted_at": "ISO8601",
  "api_url": "http://localhost:8000",
  "status": "completed",
  "summary": { "total_vulnerabilities": 5 },
  "vulnerability_ids": ["uuid1", "uuid2"],
  "vulnerabilities": [
    {
      "id": "uuid1",
      "rule_id": "CKV_AWS_21",
      "severity": "HIGH",
      "file_path": "modules/storage/main.tf",
      "start_line": 24,
      "end_line": 27,
      "message": "Ensure S3 bucket versioning is enabled",
      "scanner": "checkov"
    }
  ],
  "remediation_status": {
    "uuid1": "applied"
  },
  "last_synced_at": "ISO8601"
}
```

### Patch file schema (`patch.json`)

```json
{
  "vuln_id": "uuid",
  "scan_id": "uuid",
  "summary": "Enable S3 bucket versioning",
  "confidence_score": 0.97,
  "is_false_positive": false,
  "generated_by": "local_claude",
  "created_at": "ISO8601",
  "code_changes": [
    {
      "file_path": "modules/storage/main.tf",
      "start_line": 24,
      "end_line": 27,
      "original_code": "...",
      "new_code": "...",
      "description": "..."
    }
  ],
  "security_implications": ["..."],
  "evaluation_concerns": ["..."]
}
```

### Revalidation file schema (`revalidation.json`)

```json
{
  "vuln_id": "uuid",
  "original_scan_id": "uuid",
  "revalidation_scan_id": "uuid",
  "patched_files": ["modules/storage/main.tf"],
  "status": "PASS",
  "original_vuln_still_present": false,
  "new_findings_in_patched_files": [],
  "validated_at": "ISO8601",
  "note": "Batch revalidation: all patches applied together in a single scan"
}
```

Revalidation statuses: `PASS`, `FAIL_STILL_VULNERABLE`, `FAIL_NEW_ISSUES`, `FAIL_BOTH`

---

## Pre-push Hook

The hook warns (never blocks) when unpatched findings exist before a `git push`. It reads the most recent session in `.security-scan/sessions/` and shows:

- Count of unpatched findings by severity (CRITICAL/HIGH prioritised)
- Commands to review, apply patches, or re-run the pipeline

The hook is attached to `PreToolUse` on `Bash` commands containing `git push`.

---

## Special Handling

- **Lock files** (`uv.lock`, `poetry.lock`, `package-lock.json`, `yarn.lock`, etc.) — skipped automatically during patch generation. Fix dependency CVEs via your package manager instead.
- **False positives** — when local Claude determines a finding is not exploitable, it marks it as such. False positives are excluded from revalidation and noted in reports.
- **Evaluation concerns** — when Claude has partial confidence, concerns are recorded in `patch.json` and appear in `REPORT-*.md`.
