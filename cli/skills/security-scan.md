---
name: security-scan
description: Scan a codebase for vulnerabilities, generate AI patches via the backend autonomous agent, run a single batch revalidation, then show a dry-run diff of all passing patches.
---

## /security-scan

Runs the complete two-scan security remediation pipeline using the security-pipeline MCP server.
**Patch generation uses the backend autonomous agent by default.**
Pass `--local` in CLI commands to use the local Claude Agent SDK (multi-turn) instead.

### Pipeline

1. **Submit scan** — call `run_security_scan` with:
   - `path`: absolute path to the workspace root
   - `project_name`: the directory name is a good default
   - `scanners`: `["semgrep", "checkov", "trivy"]`

2. **Poll until complete** — call `poll_scan_status` every 30s.
   Print a progress update each poll. Stop when `status` is `"completed"` or `"failed"`.

3. **Show findings** — call `get_scan_results`. Display totals by severity.

4. **Generate all patches** — call `run_full_pipeline` (or use the CLI `security-pipeline remediate-all <scan_id>`).
   This uses the backend autonomous agent to generate patches for every vulnerability.
   Use `--local` CLI flag only if you want the local Claude Agent SDK (multi-turn) instead.

   Internally this:
   - Skips lock files automatically (`uv.lock`, `poetry.lock`, etc.) — tell user to fix those via package manager
   - Marks false positives as skipped (not patched, not revalidated)
   - Generates patches for all remaining findings
   - Applies all patches at once to a temp copy of the source
   - Submits patched tar as **one** revalidation scan
   - Analyses per-vulnerability results from that single scan
   - Writes `REPORT-CRITICAL.md` and `REPORT-HIGH.md` to `.security-scan/patches/<scan_id>/`

5. **Show dry-run diff** — display every passing patch from `dry_run_patches` as a before/after diff.
   This is the final preview before anything is written to disk.
   Revalidation status per patch: `PASS | FAIL_STILL_VULNERABLE | FAIL_NEW_ISSUES | FAIL_BOTH`

6. **Report and offer to apply** — summarise:
   - N vulnerabilities found, M patches passed revalidation
   - `revalidation_scan_id` — the single batch revalidation scan
   - Any FAIL patches that need manual review
   - Report files at `.security-scan/patches/<scan_id>/REPORT-CRITICAL.md` and `REPORT-HIGH.md`
   - Apply command: `security-pipeline apply <scan_id> --all`

### Output files

```
.security-scan/                        # gitignored — created at repo root
├── sessions/
│   └── <scan_id>.json                 # scan metadata + full vulnerability details
└── patches/
    └── <scan_id>/
        ├── REPORT-CRITICAL.md         # auto-generated; only if CRITICAL findings exist
        ├── REPORT-HIGH.md             # auto-generated; only if HIGH findings exist
        └── <vuln_id>/
            ├── patch.json             # generated code changes + confidence score
            └── revalidation.json      # PASS/FAIL status from batch revalidation
```

### Notes

- The backend must be running (`docker compose up -d` or `APP_ENV=local uvicorn ...`)
- Remediation uses the backend autonomous agent by default
- Use `--local` CLI flag to use local Claude Agent SDK (multi-turn) instead
- All files in `.security-scan/` are gitignored automatically
- To apply patches manually: `security-pipeline apply <scan_id> --all`
- To preview without applying: `security-pipeline apply <scan_id> --all --dry-run`
- `sync_sessions` updates session files with latest backend status and full vulnerability details
