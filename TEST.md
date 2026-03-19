# Manual Testing Guide

## Automated Tests

Run the automated test suites first — they cover unit and integration logic without needing a live backend.

### CLI tests (26 tests)

```bash
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli
uv sync
uv run pytest tests/ -v
# Expected: 26 passed (test_cli_agent.py x10, test_cli_run.py x5, test_mcp_server.py x11)
```

### Backend tests

```bash
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/backend
uv sync
uv run pytest tests/ -v
```

---

## Prerequisites

```bash
# Python 3.11+
python3 --version

# uv
uv --version

# Node 18+
node --version && npm --version

# Check .env has DEEPSEEK_API_KEY (or ANTHROPIC_API_KEY)
grep -E "DEEPSEEK_API_KEY|ANTHROPIC_API_KEY" /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/.env
```

---

## Part 1: Start the Backend

Open **Terminal 1**:

```bash
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/backend
uv sync
APP_ENV=local uv run uvicorn src.remediation_api.main:app --port 8000 --reload
```

Expected:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

Smoke test:
```bash
curl http://localhost:8000/health
```

---

## Part 2: Start the Frontend

Open **Terminal 2**:

```bash
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

---

## Part 3: CLI Smoke Tests

```bash
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli
uv sync
```

### 3.1 — Scan only

```bash
# Submit a scan (returns immediately with scan_id)
uv run security-pipeline scan . --scanners semgrep --project test-local

# Check status of all your scans
uv run security-pipeline status

# Once completed, view findings
uv run security-pipeline results <scan-id>

# Deep detail for one vulnerability
uv run security-pipeline vuln <scan-id> <vuln-id>
```

### 3.2 — Remediate all vulnerabilities for a scan

```bash
# After scan is completed — generate + revalidate patches for all findings
uv run security-pipeline remediate-all <scan-id>

# Filter to only CRITICAL and HIGH severity
uv run security-pipeline remediate-all <scan-id> --severity CRITICAL,HIGH

# Use local Claude Agent SDK instead of the backend engine (no API key needed)
uv run security-pipeline remediate-all <scan-id> --use-local-claude
```

Patches land in `.security-scan/patches/<scan-id>/<vuln-id>/patch.json`.

### 3.3 — Run the full pipeline in one shot (NEW)

```bash
# Scan + remediate-all in a single command
uv run security-pipeline run . --project my-project

# With filters
uv run security-pipeline run . --severity HIGH,CRITICAL --scanners semgrep

# Using local Claude
uv run security-pipeline run . --use-local-claude
```

Expected output:
```
Running full pipeline: /path/to/repo
✓ Scan queued. <scan-id>
Polling...  completed
N findings to remediate
  ✓ HIGH python.sqli  app/db.py:10   Patch generated  confidence: 0.92
    Revalidating...
    ✓ Revalidation PASS

Done.  ✓ 3 PASS  ⚠ 0 FAIL  — 1 skipped
Patches in: .security-scan/patches/<scan-id>
Apply with: security-pipeline apply <scan-id> --all
```

### 3.4 — Apply patches

```bash
# Preview what would change (dry run)
uv run security-pipeline apply <scan-id> --all --dry-run

# Apply all patches that passed revalidation
uv run security-pipeline apply <scan-id> --all

# Apply a single vulnerability's patch
uv run security-pipeline apply <scan-id> --vuln <vuln-id>

# Force-apply even patches that failed revalidation
uv run security-pipeline apply <scan-id> --all --force
```

### 3.5 — Sync sessions

```bash
# Refresh status for all sessions in .security-scan/ from the backend
uv run security-pipeline sync .
```

---

## Part 4: MCP Server Smoke Tests

Start the MCP server in stdio mode (normally Claude Code handles this, but you can test manually):

```bash
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli
uv run security-pipeline-mcp
```

The server listens on stdin/stdout. Use the Claude Code MCP integration or a test harness to call tools.

### Available MCP tools (11 total)

| Tool | What it does |
|------|-------------|
| `run_full_pipeline` | Archive → submit → poll → patch all → revalidate in one call |
| `run_security_scan` | Submit directory, returns `scan_id` immediately |
| `poll_scan_status` | Lightweight status check (poll every 30s while waiting) |
| `get_scan_results` | Full findings + remediations for a completed scan |
| `get_vulnerability_detail` | Deep detail for one vulnerability |
| `request_remediation` | Queue AI remediation for one vulnerability |
| `remediate_all` | Full remediation loop for a completed scan (long-running) |
| `apply_remediation` | Apply a single generated patch to disk |
| `apply_all_remediations` | Apply all passing patches for a scan |
| `sync_sessions` | Refresh all session states from backend |
| `list_scans` | List scans from local history |

### Configure in Claude Code

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-pipeline": {
      "command": "security-pipeline-mcp",
      "env": {
        "SECURITY_PIPELINE_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

Then use the `run_full_pipeline` tool to scan and remediate in one MCP call.

---

## Part 5: Claude Code Plugin

The plugin lives at `cli/plugin/` and bundles the MCP server, skill, and pre-push hook.

### Install

```bash
# Install CLI (makes security-pipeline-mcp available in PATH)
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli
uv tool install .

# Register the plugin with Claude Code
claude --plugin-dir /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli/plugin
```

### Verify plugin structure

```bash
find cli/plugin -type f | sort
```

Expected files:
```
cli/plugin/.claude-plugin/plugin.json
cli/plugin/.mcp.json
cli/plugin/README.md
cli/plugin/hooks/hooks.json
cli/plugin/hooks/pre-push-warn.sh
cli/plugin/skills/security-scan/SKILL.md
```

### Test the skill

In Claude Code, run:
```
/security-pipeline:security-scan
```

It will prompt for the repo path and run either quick mode (`run_full_pipeline`) or manual mode.

### Test the pre-push warning hook

Create a fake session with unpatched findings:

```bash
mkdir -p /tmp/test-repo/.security-scan/sessions
cat > /tmp/test-repo/.security-scan/sessions/test-scan.json <<'EOF'
{
  "scan_id": "test-scan-001",
  "vulnerability_ids": ["vuln-1", "vuln-2"],
  "remediation_status": {"vuln-1": "applied"},
  "status": "completed"
}
EOF

cd /tmp/test-repo
export TOOL_INPUT='{"command": "git push origin main"}'
bash /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli/plugin/hooks/pre-push-warn.sh
```

Expected output:
```
⚠️  security-pipeline: 1 of 2 findings not yet patched (scan: test-sca...)
   Review patches : security-pipeline results test-scan-001
   Apply patches  : security-pipeline apply test-scan-001 --all
   Or run pipeline: security-pipeline run .
```

---

## Part 6: API Smoke Tests

While backend is running:

```bash
# List scans
curl http://localhost:8000/api/v1/scans | python3 -m json.tool

# Submit a scan via API directly
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/juice-shop/juice-shop", "scanner_types": ["semgrep"]}'

# Poll until completed
SCAN_ID=<paste-scan-id>
curl http://localhost:8000/api/v1/scans/$SCAN_ID | python3 -c "
import json, sys; d=json.load(sys.stdin)
print('Status:', d.get('status'))
print('Vulns:', d.get('summary', {}).get('total_vulnerabilities', 0))
"

# Trigger single remediation
VULN_ID=$(curl -s http://localhost:8000/api/v1/scans/$SCAN_ID | python3 -c "
import json,sys; d=json.load(sys.stdin); print(d['vulnerabilities'][0]['id'])")
curl -X POST http://localhost:8000/api/v1/scan/$SCAN_ID/remediate/$VULN_ID
```

### Key API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/scans` | List all scans |
| `POST` | `/api/v1/scan` | Submit a GitHub repo scan |
| `GET` | `/api/v1/scans/{scan_id}` | Scan detail + vulns + remediations |
| `POST` | `/api/v1/scan/{scan_id}/remediate/{vuln_id}` | Queue single remediation |
| `POST` | `/api/v1/scan/{scan_id}/remediate-all` | Queue batch remediation |
| `DELETE` | `/api/v1/scans/{scan_id}` | Delete a scan |

---

## Part 7: Browser UI Test

1. Open [http://localhost:3000](http://localhost:3000) and sign in.
2. Go to **New Scan** → submit a GitHub repo URL.
3. Wait for status `completed`.
4. Click **View** → select a vulnerability.
5. Click **Generate AI Remediation** — spinner, then fix panel appears.

**What to verify:**
- Code fix block shows file changes with diff.
- `description` field appears per change (grey italic line).
- `evaluation_concerns` shows yellow warning box if present.
- Confidence score badge is visible.

---

## If Something Goes Wrong

**Backend won't start:**
```bash
cd backend && uv sync
```

**`security-pipeline-mcp` not found:**
```bash
cd cli && uv tool install .
# or add to PATH: export PATH="$PATH:$(uv tool dir)/bin"
```

**Remediation times out:**
- Check backend terminal for errors (DeepSeek or Anthropic API issue).
- Root `.env` must have `DEEPSEEK_API_KEY` or `ANTHROPIC_API_KEY`.

**Frontend can't reach API:**
- Confirm backend on port 8000: `curl http://localhost:8000/health`
- Frontend proxies to `http://localhost:8000` via `next.config.ts`.

**Patches not found after `remediate-all`:**
- Check `.security-scan/patches/<scan-id>/` in the scanned directory.
- If `.security-scan/` doesn't exist, the scan may not have completed — check `security-pipeline status`.

**`run` command exits with "Scan failed":**
- The backend may have rejected the archive. Check backend logs.
- Ensure the target directory isn't empty and contains code files.

---

## Part 8: Updated Pipeline Flow (Two-Scan Batch Revalidation)

The pipeline now performs exactly **two scans** regardless of the number of vulnerabilities found:
1. **Scan 1** — initial findings scan
2. **Scan 2** — single batch revalidation (all patches applied at once)

Patch generation uses **local Claude by default**. Pass `--use-backend` to use the server engine.

### 8.1 — CLI: full pipeline with local Claude (default)

```bash
# Default: uses local Claude Agent SDK for patch generation
uv run security-pipeline run . --project my-project

# Filter to critical/high only
uv run security-pipeline run . --severity CRITICAL,HIGH

# Opt-in to server-side engine instead
uv run security-pipeline run . --use-backend
```

Expected output:
```
Running full pipeline: /path/to/repo
✓ Scan queued. <scan-id>

Phase 1 of 2 — Generating patches for N findings
Using local Claude (Agent SDK)
  ▸ HIGH python.sqli  app/db.py:10
    ✓ Patch generated  confidence: 0.91
  ▸ MEDIUM ...
    ✓ Patch generated  confidence: 0.85

Phase 2 of 2 — Single batch revalidation (N patches → 1 scan)
  Patched source tar: .security-scan/patches/<scan-id>/patched-source.tar.gz
  Revalidation scan: <reval-scan-id>
  Polling batch-revalidation...  completed
  ✓ <vuln-id>: PASS
  ✓ <vuln-id>: PASS

Done.  ✓ 2 PASS  ⚠ 0 FAIL  — 0 skipped

── Dry Run: security-pipeline apply <scan-id> --all ──
2 patch(es) would be applied:

<vuln-id>  confidence=0.91  Replace raw query with parameterized statement
  app/db.py  lines 10–12
  - cursor.execute("SELECT * FROM users WHERE id=" + user_id)
  + cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))

To apply: security-pipeline apply <scan-id> --all
```

### 8.2 — CLI: remediate-all on existing scan

```bash
# Default: local Claude
uv run security-pipeline remediate-all <scan-id>

# Opt-in: backend engine
uv run security-pipeline remediate-all <scan-id> --use-backend

# Severity filter
uv run security-pipeline remediate-all <scan-id> --severity CRITICAL,HIGH
```

### 8.3 — Verify patched source tar

After a run, verify the batch revalidation artifacts exist:

```bash
SCAN_DIR=".security-scan/patches/<scan-id>"

# Patched source tar (all patches applied)
ls -lh $SCAN_DIR/patched-source.tar.gz

# Per-vulnerability results
for d in $SCAN_DIR/*/; do
  echo "=== $(basename $d) ==="
  cat $d/revalidation.json | python3 -m json.tool | grep '"status"'
done
```

---

## Part 9: MCP Server Testing in Claude Code

### 9.1 — Register the MCP server

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-pipeline": {
      "command": "security-pipeline-mcp",
      "env": {
        "SECURITY_PIPELINE_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

Restart Claude Code after editing. Verify the server appears:
```
/mcp
```
You should see `security-pipeline` listed with 11 tools.

### 9.2 — Tool: `run_full_pipeline` (quick mode, recommended)

In Claude Code, ask:
> "Run the full security pipeline on `/path/to/my-repo`"

Claude will call `run_full_pipeline`. Expected response fields:
```json
{
  "scan_id": "...",
  "revalidation_scan_id": "...",
  "passed": 2,
  "failed": 0,
  "skipped": 1,
  "total_vulns": 3,
  "patches_dir": "/path/to/.security-scan/patches/<scan_id>",
  "dry_run_patches": [
    {
      "vuln_id": "...",
      "summary": "Replace raw SQL with parameterized query",
      "confidence_score": 0.91,
      "code_changes": [...],
      "revalidation_status": "PASS"
    }
  ]
}
```

To use the backend engine instead of local Claude:
> "Run the full security pipeline on `/path/to/my-repo` using the backend engine"

(Claude should set `use_backend_engine: true`)

### 9.3 — Tool: manual step-by-step flow

```
# Step 1: submit
"Scan /path/to/repo for security issues"
→ calls run_security_scan, saves scan_id

# Step 2: poll
"Check if scan <scan_id> is done"
→ calls poll_scan_status every 30s

# Step 3: results
"Show me the findings for scan <scan_id>"
→ calls get_scan_results

# Step 4: patch + batch revalidation
"Remediate all findings for scan <scan_id>, repo is at /path/to/repo"
→ calls remediate_all (uses local Claude by default)

# Step 5: apply
"Apply all passing patches for scan <scan_id>"
→ calls apply_all_remediations
```

### 9.4 — Tool: `remediate_all` parameter reference

| Parameter | Default | Effect |
|-----------|---------|--------|
| `scan_id` | required | The scan to remediate |
| `repo_path` | required | Local path to the repository |
| `severity` | all | `"CRITICAL,HIGH"` to filter |
| `use_backend_engine` | `false` | `true` = server AI, `false` = local Claude |

### 9.5 — Tool: single-patch operations

```
# Inspect one vulnerability in detail
"Show me details for vulnerability <vuln_id> in scan <scan_id>"
→ calls get_vulnerability_detail

# Apply only one patch
"Apply the patch for vulnerability <vuln_id> from scan <scan_id>"
→ calls apply_remediation

# Force-apply a patch that failed revalidation
"Force apply the patch for <vuln_id> even though revalidation failed"
→ calls apply_remediation with force=true
```

### 9.6 — Tool: session management

```
# Refresh all session statuses in a repo
"Sync the security scan sessions for /path/to/repo"
→ calls sync_sessions

# List all your scans
"List all my security scans"
→ calls list_scans
```

---

## Part 10: Claude Code Plugin Testing

The plugin at `cli/plugin/` installs the MCP server, skill, and pre-push hook together.

### 10.1 — Install

```bash
# 1. Install the CLI tool (makes security-pipeline-mcp available in PATH)
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli
uv tool install .

# 2. Verify the binary is available
security-pipeline-mcp --help || echo "add $(uv tool dir)/bin to PATH"

# 3. Register the plugin with Claude Code
claude --plugin-dir /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli/plugin
```

### 10.2 — Verify plugin files

```bash
find /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli/plugin -type f | sort
```

Expected:
```
cli/plugin/hooks/hooks.json
cli/plugin/hooks/pre-push-warn.sh
cli/plugin/skills/security-scan/SKILL.md
```

### 10.3 — Test the `/security-scan` skill

In Claude Code, type:
```
/security-pipeline:security-scan
```

The skill should activate and Claude should:
1. Ask for the repo path (or use current workspace)
2. Offer quick mode (`run_full_pipeline`) or manual mode
3. In quick mode: call `run_full_pipeline` and display the dry-run patches from the response
4. Show the apply command: `security-pipeline apply <scan_id> --all`

**Verify skill triggers:** The skill should also activate when you say any of these:
- "run security scan"
- "scan for vulnerabilities"
- "security remediation"
- "fix security issues"
- "security-pipeline"

### 10.4 — Test the pre-push warning hook

Create a fake session with unpatched findings and simulate a pre-push event:

```bash
mkdir -p /tmp/test-repo/.security-scan/sessions
cat > /tmp/test-repo/.security-scan/sessions/test-scan.json <<'EOF'
{
  "scan_id": "test-scan-001",
  "vulnerability_ids": ["vuln-1", "vuln-2"],
  "remediation_status": {"vuln-1": "applied"},
  "status": "completed"
}
EOF

cd /tmp/test-repo
git init
export TOOL_INPUT='{"command": "git push origin main"}'
bash /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system/cli/plugin/hooks/pre-push-warn.sh
```

Expected output (warning, does not block push):
```
⚠️  security-pipeline: 1 of 2 findings not yet patched (scan: test-sca...)
   Review patches : security-pipeline results test-scan-001
   Apply patches  : security-pipeline apply test-scan-001 --all
   Or run pipeline: security-pipeline run .
```

**Verify no warning when all patched:**
```bash
cat > /tmp/test-repo/.security-scan/sessions/test-scan.json <<'EOF'
{
  "scan_id": "test-scan-001",
  "vulnerability_ids": ["vuln-1", "vuln-2"],
  "remediation_status": {"vuln-1": "applied", "vuln-2": "applied"},
  "status": "completed"
}
EOF
bash /path/to/pre-push-warn.sh
# Expected: no output (all findings patched)
```

---

## Part 11: Antigravity / Remote MCP Testing

When testing the MCP server via Antigravity (or any remote MCP host):

### 11.1 — Configuration

Set `SECURITY_PIPELINE_API_URL` to point at the deployed backend:
```json
{
  "mcpServers": {
    "security-pipeline": {
      "command": "security-pipeline-mcp",
      "env": {
        "SECURITY_PIPELINE_API_URL": "https://your-backend.example.com"
      }
    }
  }
}
```

### 11.2 — Smoke test sequence

Run these tools in order to verify end-to-end connectivity:

1. `list_scans` — should return `[]` or existing history (no backend needed)
2. `run_security_scan` with a small directory — verifies upload and scan submission
3. `poll_scan_status` with the returned `scan_id` — verifies backend reachability
4. Once `"completed"`: `get_scan_results` — verifies findings retrieval
5. `remediate_all` with `repo_path` — verifies local Claude patch generation + batch revalidation

### 11.3 — Key differences vs local testing

| Aspect | Local | Remote (Antigravity) |
|--------|-------|----------------------|
| Backend URL | `http://localhost:8000` | Deployed URL in env |
| MCP transport | stdio | Remote (SSE or HTTP) |
| Archive upload | Local file → POST | Same, but over internet |
| Patch generation | Local Claude (default) | Local Claude on the MCP host |
| Archive saved at | `~/.security-pipeline/archives/` | MCP host filesystem |

### 11.4 — Troubleshooting remote

```bash
# Verify MCP binary on the host
which security-pipeline-mcp
security-pipeline-mcp --help

# Test backend connectivity from the MCP host
curl $SECURITY_PIPELINE_API_URL/health

# Check archive storage path
python3 -c "from security_pipeline.config import get_archive_path; print(get_archive_path('test'))"
```
