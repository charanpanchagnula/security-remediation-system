---
name: security-scan
description: >
  Run a security scan on the current repository, or retrieve results for a previous scan.
  Trigger when the developer says /security-scan, "scan my code", "run security scan",
  or "show results for <scan_id>".
---

# Security Scan

## Trigger Mode (no scan_id provided)

1. Detect the project root — use the nearest `.git` directory from the current working directory.
2. Call the `run_security_scan` MCP tool:
   - `path`: absolute path to project root
   - `project_name`: name of the root directory
   - `author`: `$USER` env var, or ask the developer
   - `scanners`: `["semgrep", "checkov", "trivy"]` unless specified otherwise
3. Respond with:

   ```
   Scan submitted.

   Session ID: <scan_id>
   Scanners: semgrep, checkov, trivy

   Fast scanners (semgrep, checkov) typically finish in 2-5 minutes.
   Vendor scanners may take longer.

   When ready: say "show results for <scan_id>"
   Or run:     secremediator results <scan_id>
   ```

4. Do NOT poll or wait. Fire and forget.

## Results Mode (scan_id provided)

1. Call `get_scan_results` with the scan_id.
2. If status is `queued` or `in_progress`: tell the developer to check back later.
3. If status is `completed`:
   - Group findings: CRITICAL → HIGH → MEDIUM → LOW → INFO
   - For each: scanner, file, line, rule_id, message (first 120 chars), vuln_id
   - Show totals by severity
   - Ask: "Would you like remediation for any of these?"
4. If yes to remediation:
   - Ask which finding, or offer to start with CRITICAL/HIGH
   - Call `request_remediation(scan_id, vuln_id)`
   - Show: explanation, suggested fix, confidence score
   - Offer to continue with next finding

## Rules
- Never auto-poll after submitting. Always fire-and-forget.
- Always show the scan_id prominently.
- Only call `request_remediation` when the developer explicitly asks.
