# Local CLI + MCP Plugin Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a `secremediator` Python package that lets developers scan their local working directory against the security remediation backend via CLI and Claude Code MCP, with full audit trail.

**Architecture:** A unified Python package (`cli/`) exposes three interfaces from the same codebase — a Typer CLI, an MCP stdio server, and a shared API client. The backend gains one new endpoint (`POST /api/v1/scan/upload`) that accepts a tar.gz file upload instead of a GitHub URL, bypassing the github_service entirely. Per-scanner tracking is added via a `scanner_jobs` array inside each scan record so that multi-scanner sessions (e.g. semgrep + checkmarx) each retain their own internal ID. Everything runs locally via Docker Compose with a persistent volume; the AWS path remains intact and is selected by `APP_ENV`.

**Tech Stack:** FastAPI (backend), Python-multipart (file upload), Typer + Rich (CLI), httpx (HTTP client), mcp (MCP server SDK), Docker Compose (local orchestration), uv (dependency management)

---

## Task 1: Add `python-multipart` to backend dependencies

FastAPI requires this package to handle `UploadFile` / multipart form data.

**Files:**
- Modify: `backend/pyproject.toml`

**Step 1: Add the dependency**

In `backend/pyproject.toml`, add to the `dependencies` list:
```toml
"python-multipart>=0.0.9",
```

**Step 2: Sync the lockfile**

```bash
cd backend
uv sync
```
Expected: lockfile updated, no errors.

**Step 3: Commit**

```bash
git add backend/pyproject.toml backend/uv.lock
git commit -m "feat: add python-multipart for file upload support"
```

---

## Task 2: Extend scan models with scanner_jobs and audit fields

Adds per-scanner job tracking and developer audit fields to the scan data model.

**Files:**
- Modify: `backend/src/remediation_api/models/scan.py`

**Step 1: Add `ScannerJob` model and audit fields to `ScanResult`**

Replace the contents of `backend/src/remediation_api/models/scan.py` with:

```python
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class TraceNode(BaseModel):
    """Represents a step in a data flow trace (for source-to-sink analysis)."""
    file_path: str = Field(..., description="File where this step occurs")
    line_number: int = Field(..., description="Line number")
    code_snippet: str = Field(..., description="Code at this step")
    step_description: str = Field(default="", description="Description of the data flow event")


class Vulnerability(BaseModel):
    """Normalized vulnerability finding from a scanner."""
    id: str = Field(..., description="Unique ID for this specific finding instance")
    rule_id: str = Field(..., description="Scanner rule identifier")
    message: str = Field(..., description="Scanner description of the issue")
    severity: str = Field(..., description="Severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")

    scanner: str = Field(..., description="Scanner that found this issue")
    file_path: str
    start_line: int
    end_line: int

    code_snippet: str = Field(..., description="The vulnerable code itself")
    surrounding_context: str = Field(..., description="Lines of code around the vulnerability")

    taint_trace: List[TraceNode] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScannerJob(BaseModel):
    """Tracks the status of one scanner within a session."""
    scanner: str = Field(..., description="Scanner name (semgrep, checkov, trivy, checkmarx...)")
    status: str = Field(default="queued", description="queued | in_progress | completed | failed")
    internal_scan_id: Optional[str] = Field(default=None, description="External/vendor scan ID if applicable")
    vuln_count: int = Field(default=0)


class ScanResult(BaseModel):
    scan_id: str                          # Session-level identifier (overarching)
    project_name: Optional[str] = None   # e.g. "payments-api"
    author: Optional[str] = None         # Developer who triggered the scan
    source: str = Field(default="web", description="Trigger source: cli | mcp | web | grc")
    repo_url: str
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = None
    timestamp: str
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    scanner_jobs: List[ScannerJob] = Field(default_factory=list)
```

**Step 2: Verify nothing breaks in the backend**

```bash
cd backend
uv run python -c "from src.remediation_api.models.scan import ScanResult, ScannerJob; print('OK')"
```
Expected: `OK`

**Step 3: Commit**

```bash
git add backend/src/remediation_api/models/scan.py
git commit -m "feat: add ScannerJob model and audit fields (project_name, author, source)"
```

---

## Task 3: Add `ingest_upload` method to orchestrator

A new orchestrator entry point that accepts a local file path (already saved to disk by the endpoint) instead of a GitHub URL.

**Files:**
- Modify: `backend/src/remediation_api/agents/orchestrator.py`

**Step 1: Add `ingest_upload` method**

In `orchestrator.py`, add this method to the `Orchestrator` class, directly after `ingest_scan`:

```python
async def ingest_upload(
    self,
    archive_path: str,
    project_name: str,
    author: str,
    source: str,
    scanner_types: List[str]
) -> Dict[str, Any]:
    """
    Entry point for CLI/MCP uploads.
    Accepts a pre-saved local tar.gz, stores it, and queues a scan job.
    Bypasses github_service entirely.
    """
    import os
    from ..services.storage import get_storage

    scan_id = str(uuid.uuid4())
    storage = get_storage()

    # Store the uploaded archive under a consistent key
    archive_key = f"archives/upload-{scan_id}.tar.gz"
    storage.upload_file(archive_path, archive_key)

    try:
        os.remove(archive_path)
    except Exception:
        pass

    scanner_jobs = [
        {"scanner": s, "status": "queued", "internal_scan_id": None, "vuln_count": 0}
        for s in scanner_types
    ]

    message = {
        "scan_id": scan_id,
        "repo_url": f"local://{project_name}",
        "commit_sha": None,
        "branch": "local",
        "archive_key": archive_key,
        "scanner_types": scanner_types,
        "timestamp": datetime.utcnow().isoformat(),
    }

    msg_id = queue_service.send_message(message)

    initial_result = {
        "scan_id": scan_id,
        "project_name": project_name,
        "author": author,
        "source": source,
        "repo_url": f"local://{project_name}",
        "branch": "local",
        "commit_sha": None,
        "archive_key": archive_key,
        "timestamp": message["timestamp"],
        "status": "queued",
        "scanner_types": scanner_types,
        "scanner_jobs": scanner_jobs,
        "vulnerabilities": [],
        "remediations": [],
        "summary": {"total_vulnerabilities": 0, "remediations_generated": 0},
    }
    result_service.save_scan_result(scan_id, initial_result)

    return {"scan_id": scan_id, "message_id": msg_id, "status": "queued"}
```

**Step 2: Verify import**

```bash
cd backend
uv run python -c "from src.remediation_api.agents.orchestrator import orchestrator; print('OK')"
```
Expected: `OK`

**Step 3: Commit**

```bash
git add backend/src/remediation_api/agents/orchestrator.py
git commit -m "feat: add ingest_upload orchestrator method for CLI/MCP file uploads"
```

---

## Task 4: Add the upload endpoint

New router file with `POST /api/v1/scan/upload` that saves the incoming tar.gz to a temp file, then calls `orchestrator.ingest_upload`.

**Files:**
- Create: `backend/src/remediation_api/routers/upload.py`
- Modify: `backend/src/remediation_api/main.py`

**Step 1: Create `upload.py`**

```python
import os
import tempfile
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import List
from ..agents.orchestrator import orchestrator
from ..logger import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.post("/scan/upload")
async def upload_scan(
    file: UploadFile = File(..., description="tar.gz archive of the project directory"),
    project_name: str = Form(..., description="Project name for audit trail"),
    author: str = Form(default="unknown", description="Developer identity"),
    scanners: str = Form(default="semgrep,checkov,trivy", description="Comma-separated scanner list"),
):
    """
    Accept a local directory archive and queue a scan.
    Used by the CLI and MCP server instead of the GitHub-URL-based endpoint.
    """
    scanner_types = [s.strip() for s in scanners.split(",") if s.strip()]
    if not scanner_types:
        raise HTTPException(status_code=400, detail="At least one scanner must be specified")

    content = await file.read()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    logger.info(
        f"Upload received: project='{project_name}' author='{author}' "
        f"size={len(content)}B scanners={scanner_types}"
    )

    try:
        result = await orchestrator.ingest_upload(
            archive_path=tmp_path,
            project_name=project_name,
            author=author,
            source="cli",
            scanner_types=scanner_types,
        )
        return result
    except Exception as e:
        logger.error(f"Upload scan ingestion failed: {e}", exc_info=True)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(status_code=500, detail=str(e))
```

**Step 2: Register the router in `main.py`**

In `backend/src/remediation_api/main.py`, change the router import line from:
```python
from .routers import scan, health
```
to:
```python
from .routers import scan, health, upload
```

Add this line after the existing `app.include_router` calls:
```python
app.include_router(upload.router, prefix="/api/v1", tags=["Upload"])
```

**Step 3: Test the endpoint manually**

Start the backend:
```bash
cd backend
APP_ENV=local uv run uvicorn src.remediation_api.main:app --reload --port 8000
```

In another terminal, create a test archive and POST it:
```bash
cd /tmp
mkdir -p test_proj
echo "password = 'hardcoded_secret'" > test_proj/bad.py
tar -czf test_proj.tar.gz test_proj/
curl -X POST http://localhost:8000/api/v1/scan/upload \
  -F "file=@test_proj.tar.gz" \
  -F "project_name=test_proj" \
  -F "author=charan" \
  -F "scanners=semgrep"
```
Expected: `{"scan_id": "...", "message_id": "...", "status": "queued"}`

**Step 4: Commit**

```bash
git add backend/src/remediation_api/routers/upload.py backend/src/remediation_api/main.py
git commit -m "feat: add POST /api/v1/scan/upload endpoint for CLI/MCP file uploads"
```

---

## Task 5: Add Docker Compose for local development

Replaces manual `docker build && docker run` with a compose setup that persists data between restarts.

**Files:**
- Create: `docker-compose.yml`
- Modify: `Dockerfile`

**Step 1: Create `docker-compose.yml` in the repo root**

```yaml
version: "3.9"

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      APP_ENV: local
      WORK_DIR: /data
      DEEPSEEK_API_KEY: ${DEEPSEEK_API_KEY:-}
      OPENAI_API_KEY: ${OPENAI_API_KEY:-}
    volumes:
      - secremediator_data:/data
    restart: unless-stopped

volumes:
  secremediator_data:
    driver: local
```

**Step 2: Update the Dockerfile to create `/data`**

Find this line in the Dockerfile:
```dockerfile
RUN mkdir -p local_storage work_dir
```
Replace it with:
```dockerfile
RUN mkdir -p local_storage work_dir /data
```

**Step 3: Build and start**

```bash
docker-compose up --build
```
Expected: API starts on port 8000. Logs show `Starting background worker task...`

**Step 4: Verify upload endpoint works inside Docker**

```bash
curl -X POST http://localhost:8000/api/v1/scan/upload \
  -F "file=@/tmp/test_proj.tar.gz" \
  -F "project_name=test_proj" \
  -F "author=charan" \
  -F "scanners=semgrep"
```
Expected: `{"scan_id": "...", "status": "queued"}`

**Step 5: Commit**

```bash
git add docker-compose.yml Dockerfile
git commit -m "feat: add docker-compose for local dev with persistent data volume"
```

---

## Task 6: Scaffold the CLI package

Creates the `cli/` package with uv dependency management.

**Files:**
- Create: `cli/pyproject.toml`
- Create: `cli/src/secremediator/__init__.py`
- Create: `cli/src/secremediator/config.py`
- Create: `cli/src/secremediator/client.py`

**Step 1: Create `cli/pyproject.toml`**

```toml
[project]
name = "secremediator"
version = "0.1.0"
description = "Local security scan CLI and MCP server for the Security Remediation System"
requires-python = ">=3.12"
dependencies = [
    "typer>=0.12.0",
    "rich>=13.0.0",
    "httpx>=0.27.0",
    "mcp>=1.0.0",
]

[project.scripts]
secremediator = "secremediator.cli:app"
secremediator-mcp = "secremediator.mcp_server:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/secremediator"]
```

**Step 2: Create `cli/src/secremediator/__init__.py`**

Empty file:
```python
```

**Step 3: Create `cli/src/secremediator/config.py`**

```python
import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".secremediator"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history.json"

DEFAULT_CONFIG = {
    "api_url": "http://localhost:8000",
}


def load_config() -> dict:
    CONFIG_DIR.mkdir(exist_ok=True)
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    return json.loads(CONFIG_FILE.read_text())


def get_api_url() -> str:
    return load_config().get("api_url", DEFAULT_CONFIG["api_url"])


def load_history() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except Exception:
        return []


def save_to_history(entry: dict):
    CONFIG_DIR.mkdir(exist_ok=True)
    history = load_history()
    history.insert(0, entry)
    HISTORY_FILE.write_text(json.dumps(history[:100], indent=2))
```

**Step 4: Create `cli/src/secremediator/client.py`**

```python
import httpx
from pathlib import Path
from typing import Optional
from .config import get_api_url


class SecRemediatorClient:
    def __init__(self, api_url: Optional[str] = None):
        self.api_url = api_url or get_api_url()

    def upload_scan(
        self,
        archive_path: str,
        project_name: str,
        author: str,
        scanners: list[str],
        timeout: int = 60,
    ) -> dict:
        """POST /api/v1/scan/upload"""
        with open(archive_path, "rb") as f:
            response = httpx.post(
                f"{self.api_url}/api/v1/scan/upload",
                files={"file": (Path(archive_path).name, f, "application/gzip")},
                data={
                    "project_name": project_name,
                    "author": author,
                    "scanners": ",".join(scanners),
                },
                timeout=timeout,
            )
        response.raise_for_status()
        return response.json()

    def get_scan(self, scan_id: str) -> dict:
        """GET /api/v1/scans/{scan_id}"""
        response = httpx.get(f"{self.api_url}/api/v1/scans/{scan_id}", timeout=30)
        response.raise_for_status()
        return response.json()

    def list_scans(self) -> list:
        """GET /api/v1/scans"""
        response = httpx.get(f"{self.api_url}/api/v1/scans", timeout=30)
        response.raise_for_status()
        return response.json()

    def request_remediation(self, scan_id: str, vuln_id: str) -> dict:
        """POST /api/v1/scan/{scan_id}/remediate/{vuln_id}"""
        response = httpx.post(
            f"{self.api_url}/api/v1/scan/{scan_id}/remediate/{vuln_id}",
            timeout=120,
        )
        response.raise_for_status()
        return response.json()
```

**Step 5: Install the package locally**

```bash
cd cli
uv venv
uv pip install -e .
uv run secremediator --help
```
Expected: help text with no commands yet.

**Step 6: Commit**

```bash
git add cli/
git commit -m "feat: scaffold secremediator CLI package with config and API client"
```

---

## Task 7: CLI `scan`, `status`, and `results` commands

**Files:**
- Create: `cli/src/secremediator/archiver.py`
- Create: `cli/src/secremediator/cli.py`

**Step 1: Create `cli/src/secremediator/archiver.py`**

```python
import tarfile
import tempfile
from pathlib import Path

EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".next", "dist", "build",
}


def create_archive(source_dir: str) -> str:
    """
    Creates a tar.gz of source_dir, skipping common noise directories.
    Returns the path to the temp archive file (caller must delete it).
    """
    source_path = Path(source_dir).resolve()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
    tmp.close()

    with tarfile.open(tmp.name, "w:gz") as tar:
        for item in source_path.rglob("*"):
            # Skip excluded dirs
            if any(part in EXCLUDE_DIRS for part in item.parts):
                continue
            if item.is_file():
                tar.add(item, arcname=str(item.relative_to(source_path)))

    return tmp.name
```

**Step 2: Create `cli/src/secremediator/cli.py`**

```python
import os
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from datetime import datetime

from .archiver import create_archive
from .client import SecRemediatorClient
from .config import save_to_history, load_history, get_api_url

app = typer.Typer(help="secremediator — local security scanning CLI")
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(".", help="Directory to scan"),
    scanners: str = typer.Option("semgrep,checkov,trivy", "--scanners", "-s"),
    author: str = typer.Option("", "--author", "-a", help="Your name for audit trail"),
    project: str = typer.Option("", "--project", "-p", help="Project name (defaults to dir name)"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Submit a directory for security scanning."""
    target = Path(path).resolve()
    if not target.is_dir():
        rprint(f"[red]Error:[/red] '{path}' is not a directory.")
        raise typer.Exit(1)

    project_name = project or target.name
    author_name = author or os.environ.get("USER", "unknown")
    scanner_list = [s.strip() for s in scanners.split(",") if s.strip()]

    console.print(f"\n[bold]Scanning:[/bold] {target}")
    console.print(f"[dim]Project:[/dim] {project_name}  [dim]Author:[/dim] {author_name}  [dim]Scanners:[/dim] {', '.join(scanner_list)}\n")

    with console.status("[bold green]Creating archive..."):
        archive_path = create_archive(str(target))

    size_kb = Path(archive_path).stat().st_size // 1024
    console.print(f"[green]✓[/green] Archive ready ({size_kb} KB)")

    client = SecRemediatorClient(api_url=api_url)
    with console.status("[bold green]Uploading..."):
        try:
            result = client.upload_scan(
                archive_path=archive_path,
                project_name=project_name,
                author=author_name,
                scanners=scanner_list,
            )
        except Exception as e:
            rprint(f"[red]Upload failed:[/red] {e}")
            raise typer.Exit(1)
        finally:
            try:
                Path(archive_path).unlink(missing_ok=True)
            except Exception:
                pass

    scan_id = result["scan_id"]
    save_to_history({
        "scan_id": scan_id,
        "project_name": project_name,
        "author": author_name,
        "scanners": scanner_list,
        "path": str(target),
        "submitted_at": datetime.utcnow().isoformat(),
        "api_url": api_url or get_api_url(),
    })

    console.print(f"\n[green]✓[/green] Scan queued.")
    console.print(f"\n  [bold]Session ID:[/bold] {scan_id}")
    console.print(f"\n  Check status : [cyan]secremediator status[/cyan]")
    console.print(f"  View results : [cyan]secremediator results {scan_id}[/cyan]\n")


@app.command()
def status():
    """Show all your submitted scans and their current status."""
    history = load_history()
    if not history:
        rprint("[yellow]No scans found.[/yellow] Run [cyan]secremediator scan[/cyan] first.")
        return

    table = Table(title="Your Scans", show_header=True, header_style="bold cyan")
    table.add_column("Scan ID", style="dim", width=38)
    table.add_column("Project")
    table.add_column("Submitted", width=20)
    table.add_column("Scanners")
    table.add_column("Status")
    table.add_column("Findings", justify="right")

    for entry in history:
        scan_id = entry["scan_id"]
        client = SecRemediatorClient(api_url=entry.get("api_url"))
        try:
            data = client.get_scan(scan_id)
            scan_status = data.get("status", "unknown")
            vuln_count = str(data.get("summary", {}).get("total_vulnerabilities", "—"))
        except Exception:
            scan_status = "unreachable"
            vuln_count = "—"

        color = {"queued": "yellow", "in_progress": "blue", "completed": "green",
                 "failed": "red", "unreachable": "dim"}.get(scan_status, "white")

        table.add_row(
            scan_id,
            entry.get("project_name", "—"),
            entry.get("submitted_at", "—")[:19].replace("T", " "),
            ", ".join(entry.get("scanners", [])),
            f"[{color}]{scan_status}[/{color}]",
            vuln_count,
        )

    console.print(table)


@app.command()
def results(
    scan_id: str = typer.Argument(..., help="Scan ID to fetch results for"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
):
    """Fetch and display findings for a completed scan."""
    client = SecRemediatorClient(api_url=api_url)
    with console.status(f"Fetching {scan_id}..."):
        try:
            data = client.get_scan(scan_id)
        except Exception as e:
            rprint(f"[red]Failed:[/red] {e}")
            raise typer.Exit(1)

    scan_status = data.get("status", "unknown")
    if scan_status in ("queued", "in_progress"):
        rprint(f"[yellow]Scan is still {scan_status}.[/yellow] Check back later.")
        return

    vulns = data.get("vulnerabilities", [])
    if severity:
        vulns = [v for v in vulns if v.get("severity", "").upper() == severity.upper()]

    if not vulns:
        rprint("[green]No findings.[/green]")
        return

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    severity_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
                       "LOW": "blue", "INFO": "dim", "UNKNOWN": "white"}
    by_sev: dict = {}
    for v in vulns:
        by_sev.setdefault(v.get("severity", "UNKNOWN").upper(), []).append(v)

    summary = data.get("summary", {})
    console.print(f"\n[bold]Results — {data.get('project_name', scan_id)}[/bold]")
    console.print(f"[dim]Status:[/dim] {scan_status}  [dim]Total:[/dim] {summary.get('total_vulnerabilities', len(vulns))}\n")

    for sev in severity_order:
        group = by_sev.get(sev, [])
        if not group:
            continue
        color = severity_colors.get(sev, "white")
        console.print(f"[bold {color}]{sev}[/bold {color}] ({len(group)})")
        for v in group:
            console.print(f"  [{color}]▸[/{color}] [cyan]{v.get('scanner')}[/cyan]  {v.get('file_path')}:{v.get('start_line')}")
            console.print(f"    [dim]{v.get('rule_id')}[/dim]")
            console.print(f"    {v.get('message', '')[:120]}")
            console.print(f"    [dim]id: {v.get('id')}[/dim]\n")

    console.print("[dim]Tip: use the vuln id above with 'request_remediation' in Claude Code or the API.[/dim]\n")
```

**Step 3: Test all three commands**

```bash
cd cli
uv run secremediator scan ../backend --project backend-test --author charan
uv run secremediator status
# wait a minute, then:
uv run secremediator results <scan_id_from_above>
```

**Step 4: Commit**

```bash
git add cli/src/secremediator/archiver.py cli/src/secremediator/cli.py
git commit -m "feat: add scan, status, results CLI commands with Rich output"
```

---

## Task 8: Build the MCP server

**Files:**
- Create: `cli/src/secremediator/mcp_server.py`

**Step 1: Create `cli/src/secremediator/mcp_server.py`**

```python
"""
MCP stdio server for the Security Remediation System.

Configure in ~/.claude/claude_desktop_config.json:
{
  "mcpServers": {
    "secremediator": {
      "command": "secremediator-mcp",
      "env": { "SECREMEDIATOR_API_URL": "http://localhost:8000" }
    }
  }
}
"""
import os
import json
import asyncio
from datetime import datetime
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from .client import SecRemediatorClient
from .archiver import create_archive
from .config import save_to_history, get_api_url
from pathlib import Path

API_URL = os.environ.get("SECREMEDIATOR_API_URL", get_api_url())
server = Server("secremediator")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="run_security_scan",
            description=(
                "Zip a local directory and submit it for security scanning. "
                "Returns a scan_id immediately — the scan is async and may take minutes to hours. "
                "Call get_scan_results to check status when ready."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute path to directory"},
                    "scanners": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["semgrep", "checkov", "trivy"],
                    },
                    "project_name": {"type": "string"},
                    "author": {"type": "string"},
                },
                "required": ["path", "project_name"],
            },
        ),
        Tool(
            name="get_scan_results",
            description="Get status and findings for a scan. Returns status: queued|in_progress|completed.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="request_remediation",
            description="Get AI-generated remediation for a specific vulnerability by its vuln id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "vuln_id": {"type": "string"},
                },
                "required": ["scan_id", "vuln_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    client = SecRemediatorClient(api_url=API_URL)

    if name == "run_security_scan":
        path = arguments["path"]
        project_name = arguments["project_name"]
        author = arguments.get("author", os.environ.get("USER", "unknown"))
        scanners = arguments.get("scanners", ["semgrep", "checkov", "trivy"])

        archive_path = await asyncio.to_thread(create_archive, path)
        try:
            result = await asyncio.to_thread(
                client.upload_scan,
                archive_path, project_name, author, scanners
            )
        finally:
            Path(archive_path).unlink(missing_ok=True)

        scan_id = result["scan_id"]
        save_to_history({
            "scan_id": scan_id,
            "project_name": project_name,
            "author": author,
            "scanners": scanners,
            "path": path,
            "submitted_at": datetime.utcnow().isoformat(),
            "api_url": API_URL,
        })

        return [TextContent(type="text", text=json.dumps({
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Scan queued. Call get_scan_results(scan_id='{scan_id}') when ready to review findings.",
        }, indent=2))]

    elif name == "get_scan_results":
        data = await asyncio.to_thread(client.get_scan, arguments["scan_id"])
        return [TextContent(type="text", text=json.dumps(data, indent=2))]

    elif name == "request_remediation":
        result = await asyncio.to_thread(
            client.request_remediation, arguments["scan_id"], arguments["vuln_id"]
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


def main():
    asyncio.run(stdio_server(server))


if __name__ == "__main__":
    main()
```

**Step 2: Reinstall and test**

```bash
cd cli
uv pip install -e .
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | uv run secremediator-mcp
```
Expected: JSON listing the three tools.

**Step 3: Commit**

```bash
git add cli/src/secremediator/mcp_server.py
git commit -m "feat: add MCP server with run_security_scan, get_scan_results, request_remediation"
```

---

## Task 9: Claude Code Skill

**Files:**
- Create: `cli/skills/security-scan.md`
- Create: `cli/README.md`

**Step 1: Create `cli/skills/security-scan.md`**

````markdown
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
````

**Step 2: Create `cli/README.md`**

```markdown
# secremediator CLI

Local security scanning CLI and Claude Code MCP plugin for the Security Remediation System.

## Prerequisites

- Python 3.12+
- uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Security Remediation System API running (see docker-compose.yml in repo root)

## Install

```bash
cd cli
uv venv
uv pip install -e .
```

## Usage

```bash
# Scan a directory
secremediator scan ./my-project --scanners semgrep,checkov

# Check all your scans
secremediator status

# View results
secremediator results <scan_id>
```

## Claude Code Integration

### 1. Install the MCP server

The MCP server is installed automatically when you run `uv pip install -e .`.

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

### 2. Install the skill

```bash
mkdir -p ~/.claude/skills
cp cli/skills/security-scan.md ~/.claude/skills/
```

Restart Claude Code. Then use `/security-scan` in any conversation.

## Configuration

The CLI stores config and scan history in `~/.secremediator/`.

To point the CLI at a different API instance:

```bash
# Edit ~/.secremediator/config.json
{ "api_url": "https://your-internal-api.company.com" }
```
```

**Step 3: Commit**

```bash
git add cli/skills/ cli/README.md
git commit -m "feat: add Claude Code skill and installation docs"
```

---

## Task 10: End-to-end smoke test

**Step 1: Start the backend**

```bash
docker-compose up -d
```

**Step 2: Scan the backend directory itself**

```bash
cd cli
uv run secremediator scan ../backend --project backend-self-scan --author charan --scanners semgrep
```
Expected: scan_id printed, entry in `~/.secremediator/history.json`.

**Step 3: Check status**

```bash
uv run secremediator status
```
Expected: row with status `queued` or `in_progress`.

**Step 4: Wait ~60s then fetch results**

```bash
uv run secremediator results <scan_id>
```
Expected: findings grouped by severity, or "No findings".

**Step 5: Verify audit fields in the API**

```bash
curl -s http://localhost:8000/api/v1/scans | python3 -m json.tool | grep -A5 "project_name"
```
Expected: `project_name`, `author`, `source: "cli"`, `scanner_jobs` visible in the response.

**Step 6: Commit**

```bash
git add .
git commit -m "chore: smoke test passed — local CLI + MCP + Docker stack complete"
```

---

## Quick Reference

| What | Command |
|---|---|
| Start backend | `docker-compose up` |
| Submit scan | `secremediator scan ./my-project` |
| Check scans | `secremediator status` |
| View results | `secremediator results <scan_id>` |
| MCP server | `secremediator-mcp` (Claude Code launches this) |
| Install skill | `cp cli/skills/security-scan.md ~/.claude/skills/` |

## Adding Future Scanners (Checkmarx, Prisma, etc.)

1. Add the scanner name to `scanner_types` the backend accepts
2. Implement `_run_checkmarx()` in `backend/src/remediation_api/services/scanner.py`
3. `ScannerJob.internal_scan_id` already exists to store vendor-assigned IDs
4. No CLI changes needed — `--scanners` passes names straight through to the API
