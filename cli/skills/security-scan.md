---
name: security-scan
description: Run a full security scan on the current repo, generate AI patches for all findings, revalidate each fix, and apply passing patches.
---

## /security-scan

Runs the complete security remediation loop using the secremediator MCP server.

### Steps

1. **Start scan**
   Call `run_security_scan` with:
   - `path`: absolute path to the current workspace root
   - `project_name`: name of the project (use the directory name)
   - `scanners`: ["semgrep", "checkov", "trivy"]

   Note the `scan_id` from the response.

2. **Poll until complete**
   Call `poll_scan_status` every 30 seconds until `status` is `"completed"` or `"failed"`.
   Print a status update each poll so the developer sees progress.

3. **Review findings**
   Call `get_scan_results` with the `scan_id`.
   Show the developer a summary: total findings by severity.

4. **Generate patches**
   For each CRITICAL and HIGH finding:
   a. Call `get_vulnerability_detail` to get full context and code snippet
   b. Call `request_remediation` to trigger patch generation
   c. Poll `poll_scan_status` until the remediation appears in results

5. **Revalidation**
   Revalidation runs automatically as part of `remediate-all` CLI command.
   Each patch is tested by re-scanning with only the patched files replaced.
   Status per patch: PASS | FAIL_STILL_VULNERABLE | FAIL_NEW_ISSUES | FAIL_BOTH

6. **Apply passing patches**
   For each patch with revalidation status PASS:
   Call `apply_remediation` with `scan_id`, `vuln_id`, and `repo_path`.

7. **Report to developer**
   Summarise: N vulnerabilities found, M patches generated, K passed revalidation and applied.
   List any FAIL patches that need manual review.

### Notes
- Scanning runs inside the Docker backend container — `docker compose up -d` must be running
- For local Claude remediation instead of backend engine: use CLI `secremediator remediate-all <scan_id> --use-local-claude`
- Patches and revalidation results are stored in `.security-scan/` inside the scanned repo (gitignored)
- To apply patches manually: `secremediator apply <scan_id> --all`
