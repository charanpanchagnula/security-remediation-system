# Design: `remediate` CLI command + `results` as hub

**Date:** 2026-03-06
**Branch:** feature/local-cli-mcp
**Status:** Approved

---

## Problem

The existing CLI workflow requires too many commands for a developer to remember: scan, status, results, vuln details, remediate, poll for remediation. Each step requires passing IDs around manually, creating too much cognitive overhead.

Additionally, the remediation endpoint was synchronous (10–60s wait with no feedback), making the CLI feel broken.

---

## Goals

1. Add a `remediate <scan_id> <vuln_id>` CLI command — fire-and-forget, returns immediately
2. Make `results` the single hub where all state is visible (findings + remediation status inline)
3. Reduce mental model to: `scan` → `results` → `remediate` → `results again`
4. Allow opening a fix in `$EDITOR` directly from `results`, with local file search (no path arg needed)

---

## Command Surface

| Command | Status | Change |
|---|---|---|
| `scan <path>` | Existing | Unchanged |
| `status` | Existing | Unchanged (all-scans overview) |
| `results <scan_id>` | Existing | **Enhanced** — hub for findings + remediation inline |
| `vuln <scan_id> <vuln_id>` | Existing | Unchanged (deep inspection) |
| `remediate <scan_id> <vuln_id>` | **New** | Fire-and-forget async trigger |

---

## `remediate` Command

```
secremediator remediate <scan_id> <vuln_id> [--api-url]
```

- Hits `POST /api/v1/scan/{scan_id}/remediate/{vuln_id}` (now async)
- Returns immediately (< 1s)
- Output:
  ```
  Remediation queued for vuln-abc123
  Check back with: secremediator results <scan_id>
  ```

---

## `results` as Hub

Each vulnerability block shows its remediation state inline:

```
HIGH (3)

  semgrep  app/db.py:42
  sql-injection-taint
  User input interpolated directly into SQL query
  id: vuln-abc123

  [no remediation]   run: secremediator remediate <scan_id> vuln-abc123

  semgrep  app/auth.py:17
  hardcoded-secret
  API key hardcoded in source
  id: vuln-def456

  Remediation generating...

  semgrep  app/api.py:88
  ssrf
  Unvalidated URL passed to requests.get
  id: vuln-ghi789

  Confidence: 0.91  Use an allowlist of permitted hosts
    - url = request.args.get("url")
    - resp = requests.get(url)
    + ALLOWED = {"api.example.com"}
    + parsed = urlparse(request.args.get("url"))
    + if parsed.hostname not in ALLOWED: abort(400)
    + resp = requests.get(parsed.geturl())
  Security notes:
    - Verify allowlist covers all intended upstream hosts
  [FALSE POSITIVE: AI confidence 0.43]
```

After displaying findings, if any remediations are `ready`:
```
Open a fix in editor? [y/N]
  1. vuln-ghi789  app/api.py:88  ssrf
> Select:
```

### File resolution for editor open

The `file_path` in `CodeChange` is relative to the Docker container (e.g. `/workspace/app/api.py`). To find the local file:

1. Strip container-specific prefix, keep meaningful tail (e.g. `app/api.py`)
2. Glob `**/app/api.py` from CWD
3. **1 match** → open `$VISUAL` or `$EDITOR` at `+<start_line>` (fallback: `vi`)
4. **Multiple matches** → numbered picker
5. **0 matches** → warn with original path, skip

For multiple `code_changes` in one remediation, repeat per file.

---

## Backend Changes

### `POST /api/v1/scan/{scan_id}/remediate/{vuln_id}`

Change from synchronous (await) to background task:
- Add a `BackgroundTask` that runs `orchestrator.remediate_vulnerability(scan_id, vuln_id)`
- Orchestrator callback persists result back into scan document per-vuln
- Endpoint returns `{"status": "pending", "vuln_id": vuln_id}` immediately

### Remediation storage per-vuln

Each vulnerability in the scan document gets an optional `remediation` field:
- `null` — not requested
- `{"status": "pending"}` — generating
- Full `RemediationResponse` payload — complete

### `GET /api/v1/scans/{scan_id}`

No new endpoint needed. The scan document already contains all vulns; embedding remediation per-vuln means `results` fetches everything in one call (no N+1).

---

## Files Changed

| File | Change |
|---|---|
| `cli/src/secremediator/cli.py` | Add `remediate` command; enhance `results` with inline remediation display + editor open flow |
| `cli/src/secremediator/client.py` | No changes (existing `request_remediation` is sufficient) |
| `cli/src/secremediator/mcp_server.py` | Update `request_remediation` tool description to reflect async behaviour |
| `backend/src/remediation_api/routers/scan.py` | Make single-vuln endpoint async (background task) |
| `backend/src/remediation_api/services/results.py` | Add `update_vuln_remediation(scan_id, vuln_id, data)` and `set_vuln_remediation_pending(scan_id, vuln_id)` |
| `backend/src/remediation_api/agents/orchestrator.py` | After remediation generation, call result_service to persist; set pending on trigger |

---

## Edge Cases

- `is_false_positive=True` → show bold warning inline but still display diff and allow editor open (user decides)
- No `$EDITOR` / `$VISUAL` set → fall back to `vi`; if `vi` missing, print path and suggest manual edit
- Scan still queued/in_progress → `results` already handles this; remediation field will be null for all vulns
- Multiple `code_changes` per remediation → open files sequentially, one editor session per file
- Remediation for a vuln that is a false positive → still store and display, confidence score and FP flag are visible

---

## Out of Scope

- Batch remediate all (`remediate-all`) — backend endpoint exists but no CLI command planned now
- Auto-applying patches without user review — intentionally excluded (too risky: line drift, encoding, AI errors)
- Syntax validation of `new_code` before display — future improvement
