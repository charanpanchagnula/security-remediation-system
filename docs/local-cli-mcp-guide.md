# Local CLI + MCP Plugin — Implementation Guide

> **Branch:** `feature/local-cli-mcp` | **PR:** #2

---

## What Was Built

This feature adds a local developer workflow to the Security Remediation System. Instead of only accepting GitHub URLs, the system can now scan any local directory directly from the terminal or from within Claude Code.

### Architecture Overview

```
Developer machine
├── secremediator CLI  ──────────────────────────────┐
│   (scan / status / results)                        │
│                                                    ▼
├── secremediator-mcp (stdio server)      POST /api/v1/scan/upload
│   (Claude Code MCP tools)                          │
│                                                    ▼
└── Local directory ──► tar.gz ──────► Backend API (Docker)
                                                     │
                                            orchestrator.ingest_upload()
                                                     │
                                            local storage + queue
                                                     │
                                            scanner worker (semgrep etc.)
                                                     │
                                            scan results stored locally
```

### New Files

| File | Purpose |
|------|---------|
| `backend/src/remediation_api/models/scan.py` | Added `ScannerJob` model, `project_name` / `author` / `source` audit fields to `ScanResult` |
| `backend/src/remediation_api/agents/orchestrator.py` | Added `ingest_upload()` — accepts a local archive instead of a GitHub URL |
| `backend/src/remediation_api/routers/upload.py` | New `POST /api/v1/scan/upload` endpoint |
| `backend/src/remediation_api/main.py` | Registered the upload router |
| `backend/pyproject.toml` + `uv.lock` | Added `python-multipart>=0.0.9` |
| `Dockerfile` | Added `mkdir -p /data` for the persistent volume |
| `docker-compose.yml` | Local dev stack with persistent `secremediator_data` volume |
| `cli/pyproject.toml` | `secremediator` package definition |
| `cli/src/secremediator/config.py` | Reads/writes `~/.secremediator/config.json` and `history.json` |
| `cli/src/secremediator/client.py` | `httpx`-based API client |
| `cli/src/secremediator/archiver.py` | Creates a `tar.gz` from a local dir (excludes `.git`, `.venv`, `node_modules`, etc.) |
| `cli/src/secremediator/cli.py` | Typer CLI — `scan`, `status`, `results` commands |
| `cli/src/secremediator/mcp_server.py` | MCP stdio server — `run_security_scan`, `get_scan_results`, `request_remediation` |
| `cli/skills/security-scan.md` | Claude Code skill for `/security-scan` |
| `cli/README.md` | Installation and usage docs |

---

## Prerequisites

- **Docker Desktop** (must be running) — the backend runs in Docker
- **Python 3.12+**
- **uv** — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- **gh CLI** (optional, for PR workflows)

---

## Running Locally — Step by Step

### 1. Start the Backend

From the repo root:

```bash
docker-compose up --build
```

This builds the full Docker image (Go + Trivy + Python backend) and starts the API on `http://localhost:8000`. First build takes a few minutes.

To verify the API is up:

```bash
curl http://localhost:8000/health
```

Expected: `{"status": "ok"}` (or similar health response).

To run in the background:

```bash
docker-compose up -d
docker-compose logs -f   # tail logs
```

### 2. Install the CLI

```bash
cd cli
uv venv
uv pip install -e .
```

Verify:

```bash
secremediator --help
```

Expected output:

```
Usage: secremediator [OPTIONS] COMMAND [ARGS]...

 secremediator — local security scanning CLI

Commands:
  scan     Submit a directory for security scanning.
  status   Show all your submitted scans and their current status.
  results  Fetch and display findings for a completed scan.
```

### 3. Submit a Scan

```bash
# Scan any local directory
secremediator scan ./my-project

# With options
secremediator scan ./my-project \
  --project my-project \
  --author yourname \
  --scanners semgrep,checkov
```

The CLI will:
1. Create a `tar.gz` archive of the directory (skipping `.git`, `.venv`, `node_modules`, etc.)
2. Upload it to the backend via `POST /api/v1/scan/upload`
3. Print the `scan_id` and return immediately (scan runs in background)

Example output:
```
Scanning: /Users/you/my-project
Project: my-project  Author: yourname  Scanners: semgrep, checkov

✓ Archive ready (142 KB)
✓ Scan queued.

  Session ID: a3f2c1d4-...

  Check status : secremediator status
  View results : secremediator results a3f2c1d4-...
```

### 4. Check Scan Status

```bash
secremediator status
```

Shows a table of all scans you have submitted from this machine, with live status from the API:

```
                     Your Scans
┌──────────────────────────────────────┬─────────────┬─────────────────────┬─────────────────┬────────────┬──────────┐
│ Scan ID                              │ Project     │ Submitted           │ Scanners        │ Status     │ Findings │
├──────────────────────────────────────┼─────────────┼─────────────────────┼─────────────────┼────────────┼──────────┤
│ a3f2c1d4-...                         │ my-project  │ 2026-03-06 11:00:00 │ semgrep, checkov│ in_progress│        — │
└──────────────────────────────────────┴─────────────┴─────────────────────┴─────────────────┴────────────┴──────────┘
```

Statuses: `queued` → `in_progress` → `completed` / `failed`

Semgrep and Checkov typically finish within 2–5 minutes. Trivy may take longer depending on the project.

### 5. View Results

```bash
secremediator results <scan_id>

# Filter by severity
secremediator results <scan_id> --severity HIGH
```

Example output:
```
Results — my-project
Status: completed  Total: 3

HIGH (1)
  ▸ semgrep  src/auth/login.py:42
    python.lang.security.audit.hardcoded-password
    Detected a hardcoded password...
    id: b1c2d3e4-...

MEDIUM (2)
  ...

Tip: use the vuln id above with 'request_remediation' in Claude Code or the API.
```

---

## Claude Code MCP Integration

### 1. Register the MCP Server

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secremediator": {
      "command": "secremediator-mcp",
      "env": {
        "SECREMEDIATOR_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

> Make sure `secremediator-mcp` is on your `$PATH` (it will be after `uv pip install -e .`).

### 2. Install the Skill

```bash
mkdir -p ~/.claude/skills
cp cli/skills/security-scan.md ~/.claude/skills/
```

Restart Claude Code.

### 3. Usage in Claude Code

**Trigger a scan:**
```
/security-scan
```
or
```
scan my code for security issues
```

Claude will call `run_security_scan` with the current project root and return a `scan_id` immediately. It will **not** poll — scans are async.

**View results:**
```
show results for <scan_id>
```

Claude will call `get_scan_results`, group findings by severity, and offer to generate remediations.

**Request a fix:**

When Claude shows findings, say "yes" or "fix the hardcoded password finding". Claude will call `request_remediation(scan_id, vuln_id)` and show the AI-generated fix with confidence score.

---

## API Reference (New Endpoint)

### `POST /api/v1/scan/upload`

Accepts a `multipart/form-data` request.

**Form fields:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `file` | file | ✅ | — | `tar.gz` archive of the project |
| `project_name` | string | ✅ | — | Name for audit trail |
| `author` | string | | `"unknown"` | Developer identity |
| `scanners` | string | | `"semgrep,checkov,trivy"` | Comma-separated scanner list |

**Response:**
```json
{
  "scan_id": "a3f2c1d4-...",
  "message_id": "msg-abc",
  "status": "queued"
}
```

**Example with curl:**
```bash
# Create a test archive
mkdir -p /tmp/test_proj
echo "password = 'hardcoded_secret'" > /tmp/test_proj/bad.py
tar -czf /tmp/test_proj.tar.gz -C /tmp test_proj/

# Upload
curl -X POST http://localhost:8000/api/v1/scan/upload \
  -F "file=@/tmp/test_proj.tar.gz" \
  -F "project_name=test_proj" \
  -F "author=yourname" \
  -F "scanners=semgrep"
```

---

## Data Model Changes

### New `ScannerJob` model

Tracks the status of each scanner within a scan session:

```python
class ScannerJob(BaseModel):
    scanner: str           # "semgrep", "checkov", "trivy", etc.
    status: str            # "queued" | "in_progress" | "completed" | "failed"
    internal_scan_id: str  # vendor-assigned ID (e.g. Checkmarx scan ID)
    vuln_count: int        # findings from this scanner
```

### New `ScanResult` audit fields

```python
class ScanResult(BaseModel):
    project_name: Optional[str]  # e.g. "payments-api"
    author: Optional[str]        # developer who triggered the scan
    source: str                  # "cli" | "mcp" | "web" | "grc"
    scanner_jobs: List[ScannerJob]
    # ... existing fields
```

---

## Configuration

The CLI stores settings in `~/.secremediator/`:

| File | Contents |
|------|---------|
| `~/.secremediator/config.json` | `{ "api_url": "http://localhost:8000" }` |
| `~/.secremediator/history.json` | Last 100 scans submitted from this machine |

To point the CLI at a remote or staging API:

```bash
# Edit the config file
cat > ~/.secremediator/config.json <<EOF
{ "api_url": "https://your-api.company.com" }
EOF
```

Or pass `--api-url` per command:

```bash
secremediator scan ./my-project --api-url https://staging.company.com
```

---

## Testing Status

| Component | Verified | Method |
|-----------|----------|--------|
| `ScanResult` / `ScannerJob` model imports | ✅ | `python -c "from ...models.scan import ..."` |
| CLI help and command structure | ✅ | `secremediator --help` |
| Archive creation (excludes noise dirs) | ✅ | Python test: 97KB, 19 .py files |
| MCP `tools/list` response | ✅ | JSON-RPC handshake + tools/list |
| `POST /api/v1/scan/upload` endpoint | ⚠️ Not run | Docker daemon was off during dev |
| End-to-end scan job processing | ⚠️ Not run | Requires running backend |
| `secremediator scan` uploading to API | ⚠️ Not run | Requires running backend |
| Docker build + compose | ⚠️ Not run | Docker daemon was off during dev |

The full integration test requires `docker-compose up` to be run with Docker Desktop running. The individual components (models, CLI, MCP protocol) have been verified in isolation.

---

## Adding Future Scanners

The `scanner_jobs` array and `--scanners` flag are open-ended. To add Checkmarx or Prisma:

1. Add the scanner name to the list the backend accepts
2. Implement `_run_checkmarx()` in `backend/src/remediation_api/services/scanner.py`
3. `ScannerJob.internal_scan_id` already holds the vendor-assigned scan ID
4. No CLI or MCP changes needed — names pass straight through

---

## Troubleshooting

**`secremediator: command not found`**
```bash
# Make sure the CLI venv is active or use uv run
cd cli && uv run secremediator --help
```

**`Upload failed: Connection refused`**
- The backend is not running. Start it: `docker-compose up -d`

**`uv sync` fails with lancedb error on macOS x86_64**
- Known issue: `lancedb>=0.26.0` has no macOS x86_64 wheel
- The backend runs in Docker (Linux) where it works fine
- For local Python checks, use the existing `.venv` directly

**MCP server not appearing in Claude Code**
- Verify `secremediator-mcp` is on `$PATH`: `which secremediator-mcp`
- Check `~/.claude/claude_desktop_config.json` syntax
- Restart Claude Code after config changes
