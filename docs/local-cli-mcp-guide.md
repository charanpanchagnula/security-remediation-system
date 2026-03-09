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
                                        data/archives/{scan_id}.tar.gz  (temp)
                                                     │
                                            scanner worker (semgrep/checkov/trivy)
                                                     │
                                        archive deleted ──► data/results/scans/{scan_id}.json
```

### New Files

| File | Purpose |
|------|---------|
| `backend/src/remediation_api/models/scan.py` | Added `ScannerJob` model, `project_name` / `author` / `source` audit fields to `ScanResult` |
| `backend/src/remediation_api/agents/orchestrator.py` | Added `ingest_upload()` — accepts a local archive instead of a GitHub URL; `process_scan_job` now preserves audit fields and deletes archive after scan |
| `backend/src/remediation_api/routers/upload.py` | New `POST /api/v1/scan/upload` endpoint |
| `backend/src/remediation_api/main.py` | Registered the upload router |
| `backend/src/remediation_api/services/storage.py` | `get_storage()` now uses `WORK_DIR` so all files go to the bind-mounted `data/` folder |
| `backend/src/remediation_api/services/results.py` | `get_all_scans()` now includes audit fields in list view |
| `backend/pyproject.toml` + `uv.lock` | Added `python-multipart>=0.0.9` |
| `Dockerfile.backend` | Backend-only image (no Clerk keys needed) for local dev/testing |
| `docker-compose.yml` | Local dev stack; bind-mounts `./data` so results are visible on the host |
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

---

## Running Locally — Step by Step

### 1. Start the Backend

From the repo root:

```bash
docker-compose up --build
```

This builds the backend-only Docker image (Go + Trivy + Semgrep + Checkov + Python) and starts the API on `http://localhost:8000`. First build takes a few minutes.

> **Note:** Uses `Dockerfile.backend` which skips the Next.js frontend build — no Clerk keys required for local dev.

To verify the API is up:

```bash
curl http://localhost:8000/health
# {"status": "ok", "environment": "local"}
```

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
# Scan the current directory
secremediator scan .

# Scan with all options
secremediator scan ./my-project \
  --project my-project \
  --author yourname \
  --scanners semgrep,checkov,trivy
```

The CLI will:
1. Create a `tar.gz` archive of the directory, skipping `.git`, `.venv`, `node_modules`, `__pycache__`, `dist`, `build`, `.next`
2. Upload it to the backend via `POST /api/v1/scan/upload`
3. Print the `scan_id` and return immediately — the scan runs in the background

Example output:
```
Scanning: /Users/you/my-project
Project: my-project  Author: yourname  Scanners: semgrep, checkov, trivy

✓ Archive ready (171 KB)
✓ Scan queued.

  Session ID: a3f2c1d4-...

  Check status : secremediator status
  View results : secremediator results a3f2c1d4-...
```

### 4. Check Scan Status

```bash
secremediator status
```

Shows a live table of all scans you have submitted from this machine, fetching current status from the API.

Statuses: `queued` → `in_progress` → `completed` / `failed`

Semgrep and Checkov typically finish within 1–2 minutes. Trivy scans lock files and container images, also fast.

### 5. View Results

```bash
secremediator results <scan_id>

# Filter by severity
secremediator results <scan_id> --severity HIGH
```

Example output for a real scan of this repo (43 findings):
```
Results — security-remediation-system
Status: completed  Total: 43

HIGH (29)
  ▸ checkov  terraform/modules/queue/main.tf:9
    CKV_AWS_27
    Ensure all data stored in the SQS queue is encrypted
    id: 6fa0b08d-...

  ▸ trivy  backend/uv.lock:1
    CVE-2026-24486
    python-multipart: Arbitrary file write via path traversal vulnerability
    id: 7c63f29e-...
...
Tip: use the vuln id above with 'request_remediation' in Claude Code or the API.
```

---

## Where Data Lives

### On the host machine (via bind mount)

After `docker-compose up`, a `data/` directory appears in the repo root:

```
data/
├── archives/
│   └── upload-{scan_id}.tar.gz   # exists while scan is queued/running, deleted after ✅
├── results/
│   └── scans/
│       └── {scan_id}.json         # permanent scan record — readable directly ✅
└── queue/
    └── ...                        # in-memory queue state
```

You can read any result directly:

```bash
cat data/results/scans/<scan_id>.json | python3 -m json.tool
```

> `data/` is gitignored.

### On the developer machine (CLI audit log)

The CLI keeps a local record of **scans you submitted** in `~/.secremediator/`:

```
~/.secremediator/
├── config.json     # { "api_url": "http://localhost:8000" }
└── history.json    # last 100 scans you submitted (scan_id, project, timestamps)
```

This is a **local audit log** — it's what `secremediator status` reads to know which scan IDs to look up. The actual results are always fetched live from the API.

### Temp file lifecycle

| File | Created | Deleted |
|------|---------|---------|
| `/tmp/tmpXXX.tar.gz` on host (CLI) | `create_archive()` | CLI `finally` block, immediately after upload |
| `/tmp/tmpXXX.tar.gz` inside container | `upload.py tempfile` | `ingest_upload` `os.remove()`, before queuing |
| `data/archives/upload-{scan_id}.tar.gz` | `ingest_upload` | `process_scan_job` after scanning completes |
| Temp workspace inside container | `scanner_service.prepare_workspace()` | `tmp_dir.cleanup()` after scanning |

Nothing persists longer than needed.

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

> `secremediator-mcp` is on your `$PATH` after `uv pip install -e .` in the `cli/` directory.

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
or say: `scan my code for security issues`

Claude will call `run_security_scan` with the current project root and return a `scan_id` immediately. It will **not** poll — scans are async.

**View results:**
```
show results for <scan_id>
```

Claude calls `get_scan_results`, groups findings by severity, and offers to generate remediations.

**Request a fix:**

Say "fix the path traversal finding" or "yes". Claude calls `request_remediation(scan_id, vuln_id)` and shows the AI-generated fix with confidence score.

---

## API Reference (New Endpoint)

### `POST /api/v1/scan/upload`

Accepts `multipart/form-data`.

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

**curl example:**
```bash
mkdir -p /tmp/test_proj && echo "password = 'secret'" > /tmp/test_proj/bad.py
tar -czf /tmp/test_proj.tar.gz -C /tmp test_proj/

curl -X POST http://localhost:8000/api/v1/scan/upload \
  -F "file=@/tmp/test_proj.tar.gz" \
  -F "project_name=test_proj" \
  -F "author=yourname" \
  -F "scanners=semgrep,checkov,trivy"
```

---

## Data Model Changes

### New `ScannerJob` model

Tracks the status of each scanner within a scan session:

```python
class ScannerJob(BaseModel):
    scanner: str                    # "semgrep", "checkov", "trivy", etc.
    status: str                     # "queued" | "in_progress" | "completed" | "failed"
    internal_scan_id: Optional[str] # vendor-assigned ID (e.g. Checkmarx scan ID)
    vuln_count: int                 # findings from this scanner
```

### New `ScanResult` audit fields

```python
class ScanResult(BaseModel):
    project_name: Optional[str]     # e.g. "payments-api"
    author: Optional[str]           # developer who triggered the scan
    source: str                     # "cli" | "mcp" | "web" | "grc"
    scanner_jobs: List[ScannerJob]
    # ... existing fields unchanged
```

---

## Configuration

### CLI config (`~/.secremediator/config.json`)

Created automatically on first run. To point the CLI at a different API:

```bash
cat > ~/.secremediator/config.json <<EOF
{ "api_url": "https://your-api.company.com" }
EOF
```

Or per-command:

```bash
secremediator scan ./my-project --api-url https://staging.company.com
```

### Docker environment variables

Set in `docker-compose.yml` or via `.env` file in the repo root:

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `local` | `local` uses file storage; `production` uses S3/SQS |
| `WORK_DIR` | `/data` | Root for all scan data (results, archives, queue) |
| `OPENAI_API_KEY` | — | Required for AI remediation generation |
| `DEEPSEEK_API_KEY` | — | Alternative LLM for remediation |

---

## Testing Status

All components have been end-to-end verified with a running backend:

| Component | Result |
|-----------|--------|
| Docker build (`Dockerfile.backend`) | ✅ Builds cleanly |
| `GET /health` | ✅ `{"status":"ok","environment":"local"}` |
| `POST /api/v1/scan/upload` (curl) | ✅ Returns `scan_id + status: queued` |
| `secremediator scan` → live API | ✅ Archives, uploads, prints scan_id |
| `secremediator status` | ✅ Shows live status table |
| `secremediator results <scan_id>` | ✅ Shows grouped findings |
| Full project scan (semgrep+checkov+trivy) | ✅ 43 findings on this repo |
| Audit fields (`project_name`, `author`, `source`) | ✅ Preserved through worker, visible in API |
| Archive deleted after scan | ✅ Confirmed: `data/archives/` empty after completion |
| Results visible on host at `data/results/scans/` | ✅ Confirmed |
| `~/.secremediator/history.json` updated | ✅ Confirmed |
| MCP `tools/list` (JSON-RPC handshake) | ✅ All 3 tools returned |

---

## Adding Future Scanners

The `scanner_jobs` array and `--scanners` flag are open-ended. To add Checkmarx or Prisma Cloud:

1. Implement `_run_checkmarx()` in `backend/src/remediation_api/services/scanner.py`
2. `ScannerJob.internal_scan_id` already holds the vendor-assigned scan ID
3. No CLI or MCP changes needed — scanner names pass straight through

---

## Troubleshooting

**`secremediator: command not found`**
```bash
cd cli && uv run secremediator --help
# or add the venv bin to PATH: export PATH="$PWD/cli/.venv/bin:$PATH"
```

**`Upload failed: Connection refused`**
- Backend is not running: `docker-compose up -d`

**`uv sync` fails with lancedb error on macOS x86_64**
- Pre-existing issue: `lancedb>=0.26.0` has no macOS x86_64 wheel
- Backend runs in Docker (Linux) where it works fine — not a blocker

**Archive is very large**
- The archiver excludes `.git`, `.venv`, `venv`, `node_modules`, `__pycache__`, `.next`, `dist`, `build`
- It does **not** exclude `data/` — if scanning the repo root with a populated `data/` folder, exclude it: `secremediator scan . --project myproj` will include `data/`; consider scanning a subdirectory or clearing `data/` first

**MCP server not appearing in Claude Code**
- Verify `secremediator-mcp` is on `$PATH`: `which secremediator-mcp`
- Check `~/.claude/claude_desktop_config.json` is valid JSON
- Restart Claude Code after any config changes
