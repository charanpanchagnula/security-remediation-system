# Remediate Command Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `secremediator remediate` CLI command that fire-and-forgets remediation generation, and enhance `results` to be the single hub showing findings + remediation state inline, with an option to open fixes in `$EDITOR`.

**Architecture:** The backend's single-vuln remediation endpoint becomes truly async — it marks the vuln as `pending` in the scan document and queues a background task; the CLI's `results` command joins vulns with remediations and pending markers from the same scan payload (one API call, no N+1). A helper function searches the local filesystem for the file referenced in a `CodeChange` so the developer never has to provide a path.

**Tech Stack:** Python 3.12, FastAPI BackgroundTasks, Typer, Rich, httpx, pytest, typer.testing.CliRunner

---

## Task 1: Backend — pending remediation tracking in ResultService

**Files:**
- Modify: `backend/src/remediation_api/services/results.py`
- Create: `backend/tests/test_results_pending.py`

### Step 1: Create the test file

```python
# backend/tests/test_results_pending.py
import json
import tempfile
import os
import pytest
from unittest.mock import patch, MagicMock

# Minimal scan document for tests
SCAN = {
    "scan_id": "scan-1",
    "vulnerabilities": [{"id": "vuln-1"}, {"id": "vuln-2"}],
    "remediations": [],
    "summary": {},
}


def _make_service(tmp_path):
    """Create a ResultService backed by a temp local directory."""
    from remediation_api.services.results import ResultService
    from remediation_api.services.storage import LocalStorageService
    svc = ResultService.__new__(ResultService)
    svc.storage = LocalStorageService(base_dir=str(tmp_path))
    return svc


def _save(svc, data):
    import tempfile, json
    key = f"scans/{data['scan_id']}.json"
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(data, f)
        tmp = f.name
    svc.storage.upload_file(tmp, key)
    os.unlink(tmp)


def test_set_pending_adds_vuln_id(tmp_path):
    svc = _make_service(tmp_path)
    _save(svc, SCAN)
    svc.set_vuln_remediation_pending("scan-1", "vuln-1")
    result = svc.get_scan("scan-1")
    assert "vuln-1" in result["pending_remediations"]


def test_set_pending_is_idempotent(tmp_path):
    svc = _make_service(tmp_path)
    _save(svc, SCAN)
    svc.set_vuln_remediation_pending("scan-1", "vuln-1")
    svc.set_vuln_remediation_pending("scan-1", "vuln-1")
    result = svc.get_scan("scan-1")
    assert result["pending_remediations"].count("vuln-1") == 1


def test_clear_pending_removes_vuln_id(tmp_path):
    svc = _make_service(tmp_path)
    scan = {**SCAN, "pending_remediations": ["vuln-1", "vuln-2"]}
    _save(svc, scan)
    svc.clear_vuln_remediation_pending("scan-1", "vuln-1")
    result = svc.get_scan("scan-1")
    assert "vuln-1" not in result["pending_remediations"]
    assert "vuln-2" in result["pending_remediations"]


def test_clear_pending_safe_when_not_present(tmp_path):
    svc = _make_service(tmp_path)
    _save(svc, SCAN)
    # Should not raise
    svc.clear_vuln_remediation_pending("scan-1", "vuln-99")
```

### Step 2: Run tests to confirm they fail

```bash
cd backend && uv run pytest tests/test_results_pending.py -v
```

Expected: `FAILED` — `set_vuln_remediation_pending` does not exist yet.

### Step 3: Add the two methods to ResultService

In `backend/src/remediation_api/services/results.py`, add after `get_scan` (before `delete_scan`):

```python
def set_vuln_remediation_pending(self, scan_id: str, vuln_id: str) -> None:
    """Mark a vulnerability as having remediation in-flight."""
    scan_data = self.get_scan(scan_id)
    if not scan_data:
        return
    pending = scan_data.setdefault("pending_remediations", [])
    if vuln_id not in pending:
        pending.append(vuln_id)
    self.save_scan_result(scan_id, scan_data)

def clear_vuln_remediation_pending(self, scan_id: str, vuln_id: str) -> None:
    """Remove a vulnerability from the pending remediation list."""
    scan_data = self.get_scan(scan_id)
    if not scan_data:
        return
    pending = scan_data.get("pending_remediations", [])
    scan_data["pending_remediations"] = [v for v in pending if v != vuln_id]
    self.save_scan_result(scan_id, scan_data)
```

### Step 4: Run tests to confirm they pass

```bash
cd backend && uv run pytest tests/test_results_pending.py -v
```

Expected: 4 PASSED.

### Step 5: Commit

```bash
git add backend/src/remediation_api/services/results.py backend/tests/test_results_pending.py
git commit -m "feat(backend): add pending remediation tracking to ResultService"
```

---

## Task 2: Backend — make remediation endpoint async (fire-and-forget)

**Files:**
- Modify: `backend/src/remediation_api/routers/scan.py`
- Create: `backend/tests/test_remediation_endpoint.py`

### Step 1: Create the test file

```python
# backend/tests/test_remediation_endpoint.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock

@pytest.fixture
def client():
    from remediation_api.main import app
    return TestClient(app)


def test_remediate_returns_pending_immediately(client):
    scan = {
        "scan_id": "scan-1",
        "vulnerabilities": [{"id": "vuln-1", "rule_id": "r1", "message": "m",
                              "file_path": "f.py", "start_line": 1, "end_line": 1,
                              "severity": "HIGH", "scanner": "semgrep",
                              "code_snippet": "", "surrounding_context": "",
                              "taint_trace": [], "metadata": {}}],
        "remediations": [],
        "pending_remediations": [],
        "summary": {},
        "repo_url": "https://github.com/x/y",
    }
    with patch("remediation_api.routers.scan.result_service") as mock_rs, \
         patch("remediation_api.routers.scan.orchestrator") as mock_orch:
        mock_rs.get_scan.return_value = scan
        mock_rs.set_vuln_remediation_pending.return_value = None
        mock_orch.remediate_vulnerability = AsyncMock(return_value=None)

        resp = client.post("/api/v1/scan/scan-1/remediate/vuln-1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "pending"
        assert body["vuln_id"] == "vuln-1"
        mock_rs.set_vuln_remediation_pending.assert_called_once_with("scan-1", "vuln-1")


def test_remediate_returns_completed_if_already_done(client):
    existing_rem = {"vulnerability_id": "vuln-1", "summary": "Fixed", "code_changes": []}
    scan = {
        "scan_id": "scan-1",
        "vulnerabilities": [{"id": "vuln-1"}],
        "remediations": [existing_rem],
        "pending_remediations": [],
        "summary": {},
        "repo_url": "https://github.com/x/y",
    }
    with patch("remediation_api.routers.scan.result_service") as mock_rs:
        mock_rs.get_scan.return_value = scan
        resp = client.post("/api/v1/scan/scan-1/remediate/vuln-1")
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"
        mock_rs.set_vuln_remediation_pending.assert_not_called()


def test_remediate_returns_pending_if_already_queued(client):
    scan = {
        "scan_id": "scan-1",
        "vulnerabilities": [{"id": "vuln-1"}],
        "remediations": [],
        "pending_remediations": ["vuln-1"],
        "summary": {},
        "repo_url": "https://github.com/x/y",
    }
    with patch("remediation_api.routers.scan.result_service") as mock_rs:
        mock_rs.get_scan.return_value = scan
        resp = client.post("/api/v1/scan/scan-1/remediate/vuln-1")
        assert resp.status_code == 200
        assert resp.json()["status"] == "pending"
        mock_rs.set_vuln_remediation_pending.assert_not_called()
```

### Step 2: Run tests to confirm they fail

```bash
cd backend && uv run pytest tests/test_remediation_endpoint.py -v
```

Expected: FAILED — endpoint still synchronous, returns full remediation body not `{status: pending}`.

### Step 3: Rewrite the single-vuln remediation endpoint

Replace the `remediate_vuln_endpoint` function in `backend/src/remediation_api/routers/scan.py` (lines 34–49):

```python
@router.post("/scan/{scan_id}/remediate/{vuln_id}")
async def remediate_vuln_endpoint(scan_id: str, vuln_id: str, background_tasks: BackgroundTasks):
    """Triggers remediation for a single vulnerability. Returns immediately."""
    scan_data = result_service.get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Idempotent: already done
    existing = next(
        (r for r in scan_data.get("remediations", []) if r.get("vulnerability_id") == vuln_id),
        None,
    )
    if existing:
        return {"status": "completed", "vuln_id": vuln_id}

    # Idempotent: already queued
    if vuln_id in scan_data.get("pending_remediations", []):
        return {"status": "pending", "vuln_id": vuln_id}

    # Mark as pending immediately
    result_service.set_vuln_remediation_pending(scan_id, vuln_id)

    async def _run():
        try:
            await orchestrator.remediate_vulnerability(scan_id, vuln_id)
        finally:
            result_service.clear_vuln_remediation_pending(scan_id, vuln_id)

    background_tasks.add_task(_run)
    return {"status": "pending", "vuln_id": vuln_id}
```

### Step 4: Run tests to confirm they pass

```bash
cd backend && uv run pytest tests/test_remediation_endpoint.py -v
```

Expected: 3 PASSED.

### Step 5: Commit

```bash
git add backend/src/remediation_api/routers/scan.py backend/tests/test_remediation_endpoint.py
git commit -m "feat(backend): make single-vuln remediation endpoint async (fire-and-forget)"
```

---

## Task 3: CLI — add `remediate` command

**Files:**
- Modify: `cli/src/secremediator/cli.py`
- Create: `cli/tests/__init__.py`
- Create: `cli/tests/test_remediate_cmd.py`

### Step 1: Add pytest to CLI dev deps

```bash
cd cli && uv add --dev pytest pytest-mock
```

### Step 2: Create test file

```python
# cli/tests/test_remediate_cmd.py
import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from secremediator.cli import app

runner = CliRunner()


def test_remediate_queued_output():
    mock_client = MagicMock()
    mock_client.request_remediation.return_value = {"status": "pending", "vuln_id": "vuln-1"}
    with patch("secremediator.cli.SecRemediatorClient", return_value=mock_client):
        result = runner.invoke(app, ["remediate", "scan-abc", "vuln-1"])
    assert result.exit_code == 0
    assert "queued" in result.output.lower()
    assert "scan-abc" in result.output


def test_remediate_already_completed_output():
    mock_client = MagicMock()
    mock_client.request_remediation.return_value = {"status": "completed", "vuln_id": "vuln-1"}
    with patch("secremediator.cli.SecRemediatorClient", return_value=mock_client):
        result = runner.invoke(app, ["remediate", "scan-abc", "vuln-1"])
    assert result.exit_code == 0
    assert "already" in result.output.lower() or "completed" in result.output.lower()


def test_remediate_api_failure():
    mock_client = MagicMock()
    mock_client.request_remediation.side_effect = Exception("connection refused")
    with patch("secremediator.cli.SecRemediatorClient", return_value=mock_client):
        result = runner.invoke(app, ["remediate", "scan-abc", "vuln-1"])
    assert result.exit_code == 1
```

### Step 3: Run tests to confirm they fail

```bash
cd cli && uv run pytest tests/test_remediate_cmd.py -v
```

Expected: ERROR — `remediate` command does not exist.

### Step 4: Add `remediate` command to cli.py

Add this after the `vuln` command in `cli/src/secremediator/cli.py`:

```python
@app.command()
def remediate(
    scan_id: str = typer.Argument(..., help="Scan ID the vulnerability belongs to"),
    vuln_id: str = typer.Argument(..., help="Vulnerability ID to remediate"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Queue AI remediation for a specific vulnerability (fire-and-forget)."""
    client = SecRemediatorClient(api_url=api_url)
    try:
        result = client.request_remediation(scan_id, vuln_id)
    except Exception as e:
        rprint(f"[red]Failed:[/red] {e}")
        raise typer.Exit(1)

    status = result.get("status")
    if status == "completed":
        console.print(f"\n[green]✓[/green] Remediation already completed for [dim]{vuln_id}[/dim]")
        console.print(f"  Run [cyan]secremediator results {scan_id}[/cyan] to view it.\n")
    else:
        console.print(f"\n[green]✓[/green] Remediation queued for [dim]{vuln_id}[/dim]")
        console.print(f"\n  Check back with: [cyan]secremediator results {scan_id}[/cyan]\n")
```

### Step 5: Run tests to confirm they pass

```bash
cd cli && uv run pytest tests/test_remediate_cmd.py -v
```

Expected: 3 PASSED.

### Step 6: Also update the tip at the bottom of `vuln` command

In `cli/src/secremediator/cli.py` line 226, the existing tip already says `secremediator remediate {scan_id} {vuln_id}` — confirm this matches the new command signature (it does, no change needed).

### Step 7: Commit

```bash
git add cli/src/secremediator/cli.py cli/tests/__init__.py cli/tests/test_remediate_cmd.py cli/pyproject.toml cli/uv.lock
git commit -m "feat(cli): add remediate command (fire-and-forget)"
```

---

## Task 4: CLI — enhance `results` with inline remediation display

**Files:**
- Modify: `cli/src/secremediator/cli.py`
- Create: `cli/tests/test_results_remediation.py`

### Step 1: Create the test file

```python
# cli/tests/test_results_remediation.py
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock
from secremediator.cli import app

runner = CliRunner()

SCAN_WITH_REMEDIATION = {
    "status": "completed",
    "project_name": "myproject",
    "summary": {"total_vulnerabilities": 2},
    "vulnerabilities": [
        {
            "id": "vuln-1", "severity": "HIGH", "scanner": "semgrep",
            "file_path": "app/db.py", "start_line": 42, "end_line": 44,
            "rule_id": "sql-inject", "message": "SQL injection via f-string",
        },
        {
            "id": "vuln-2", "severity": "MEDIUM", "scanner": "semgrep",
            "file_path": "app/auth.py", "start_line": 17, "end_line": 17,
            "rule_id": "hardcoded-secret", "message": "Hardcoded API key",
        },
    ],
    "remediations": [
        {
            "vulnerability_id": "vuln-1",
            "summary": "Use parameterized queries",
            "explanation": "The user input is interpolated directly...",
            "confidence_score": 0.92,
            "is_false_positive": False,
            "security_implications": ["Ensure all call sites are updated"],
            "code_changes": [
                {
                    "file_path": "/workspace/app/db.py",
                    "start_line": 42,
                    "end_line": 44,
                    "original_code": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                    "new_code": 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
                }
            ],
        }
    ],
    "pending_remediations": ["vuln-2"],
}


def test_results_shows_remediation_inline():
    mock_client = MagicMock()
    mock_client.get_scan.return_value = SCAN_WITH_REMEDIATION
    with patch("secremediator.cli.SecRemediatorClient", return_value=mock_client):
        result = runner.invoke(app, ["results", "scan-abc"])
    assert result.exit_code == 0
    assert "Use parameterized queries" in result.output
    assert "0.92" in result.output


def test_results_shows_pending_state():
    mock_client = MagicMock()
    mock_client.get_scan.return_value = SCAN_WITH_REMEDIATION
    with patch("secremediator.cli.SecRemediatorClient", return_value=mock_client):
        result = runner.invoke(app, ["results", "scan-abc"])
    assert "generating" in result.output.lower() or "pending" in result.output.lower()


def test_results_shows_no_remediation_hint():
    scan = {**SCAN_WITH_REMEDIATION, "remediations": [], "pending_remediations": []}
    mock_client = MagicMock()
    mock_client.get_scan.return_value = scan
    with patch("secremediator.cli.SecRemediatorClient", return_value=mock_client):
        result = runner.invoke(app, ["results", "scan-abc"])
    assert "remediate" in result.output.lower()


def test_results_shows_diff_style_code():
    mock_client = MagicMock()
    mock_client.get_scan.return_value = SCAN_WITH_REMEDIATION
    with patch("secremediator.cli.SecRemediatorClient", return_value=mock_client):
        result = runner.invoke(app, ["results", "scan-abc"])
    assert "-" in result.output or "+" in result.output
```

### Step 2: Run tests to confirm they fail

```bash
cd cli && uv run pytest tests/test_results_remediation.py -v
```

Expected: FAILED — `results` does not show remediation yet.

### Step 3: Enhance the `results` command

Replace the `results` function body in `cli/src/secremediator/cli.py`. Keep the signature identical. Change the vuln rendering loop section (after the `by_sev` grouping) to:

```python
    # Build remediation lookups from scan data
    remediations_by_vuln = {
        r["vulnerability_id"]: r
        for r in data.get("remediations", [])
    }
    pending_vulns = set(data.get("pending_remediations", []))

    for sev in severity_order:
        group = by_sev.get(sev, [])
        if not group:
            continue
        color = severity_colors.get(sev, "white")
        console.print(f"[bold {color}]{sev}[/bold {color}] ({len(group)})")
        for v in group:
            vuln_id = v.get("id", "")
            console.print(f"  [{color}]▸[/{color}] [cyan]{v.get('scanner')}[/cyan]  {v.get('file_path')}:{v.get('start_line')}")
            console.print(f"    [dim]{v.get('rule_id')}[/dim]")
            console.print(f"    {v.get('message', '')[:120]}")
            console.print(f"    [dim]id: {vuln_id}[/dim]")

            rem = remediations_by_vuln.get(vuln_id)
            if rem:
                fp_note = "  [yellow][FALSE POSITIVE][/yellow]" if rem.get("is_false_positive") else ""
                conf = rem.get("confidence_score", 0)
                console.print(f"    [green]✓ Remediation ready[/green]  confidence: {conf:.2f}{fp_note}")
                console.print(f"    [bold]{rem.get('summary', '')}[/bold]")
                for change in rem.get("code_changes", []):
                    console.print(f"    [dim]{change.get('file_path')}  lines {change.get('start_line')}–{change.get('end_line')}[/dim]")
                    for line in change.get("original_code", "").splitlines():
                        console.print(f"    [red]- {line}[/red]")
                    for line in change.get("new_code", "").splitlines():
                        console.print(f"    [green]+ {line}[/green]")
                for note in rem.get("security_implications", []):
                    console.print(f"    [dim]• {note}[/dim]")
            elif vuln_id in pending_vulns:
                console.print(f"    [yellow]⏳ Remediation generating...[/yellow]")
            else:
                console.print(f"    [dim]run: secremediator remediate {scan_id} {vuln_id}[/dim]")
            console.print()

    # Prompt to open editor if any remediations are ready with code changes
    ready_rems = [
        (vid, r) for vid, r in remediations_by_vuln.items()
        if r.get("code_changes")
    ]
    if ready_rems and sys.stdout.isatty():
        _offer_editor_open(scan_id, ready_rems)
```

Also add `import sys` at the top of `cli.py` if not already present.

Remove the old tip line at the bottom of the loop (`console.print("[dim]Tip: run...")`).

### Step 4: Run tests to confirm they pass

```bash
cd cli && uv run pytest tests/test_results_remediation.py -v
```

Expected: 4 PASSED.

### Step 5: Commit

```bash
git add cli/src/secremediator/cli.py cli/tests/test_results_remediation.py
git commit -m "feat(cli): show remediation state inline in results command"
```

---

## Task 5: CLI — editor open flow (file search helper)

**Files:**
- Modify: `cli/src/secremediator/cli.py`
- Create: `cli/tests/test_editor_open.py`

### Step 1: Create the test file

```python
# cli/tests/test_editor_open.py
import pytest
from pathlib import Path
from unittest.mock import patch


def test_find_local_file_exact_suffix(tmp_path):
    """Finds a file by progressively shorter path suffix."""
    target = tmp_path / "app" / "db.py"
    target.parent.mkdir(parents=True)
    target.write_text("x")

    from secremediator.cli import _find_local_file
    with patch("secremediator.cli.Path") as MockPath:
        # Patch cwd to return tmp_path
        MockPath.cwd.return_value = tmp_path
        MockPath.side_effect = lambda *a, **kw: Path(*a, **kw)
        results = _find_local_file("/workspace/project/app/db.py")

    assert any(str(r).endswith("app/db.py") for r in results)


def test_find_local_file_multiple_matches(tmp_path):
    for sub in ["a", "b"]:
        f = tmp_path / sub / "util.py"
        f.parent.mkdir(parents=True)
        f.write_text("x")

    from secremediator.cli import _find_local_file
    with patch("secremediator.cli.Path") as MockPath:
        MockPath.cwd.return_value = tmp_path
        MockPath.side_effect = lambda *a, **kw: Path(*a, **kw)
        results = _find_local_file("/app/util.py")

    assert len(results) >= 2


def test_find_local_file_not_found(tmp_path):
    from secremediator.cli import _find_local_file
    with patch("secremediator.cli.Path") as MockPath:
        MockPath.cwd.return_value = tmp_path
        MockPath.side_effect = lambda *a, **kw: Path(*a, **kw)
        results = _find_local_file("/workspace/nonexistent.py")

    assert results == []
```

### Step 2: Run tests to confirm they fail

```bash
cd cli && uv run pytest tests/test_editor_open.py -v
```

Expected: FAILED — `_find_local_file` does not exist.

### Step 3: Add helper functions to cli.py

Add these two functions **before** the `@app.command()` decorators in `cli/src/secremediator/cli.py`:

```python
def _find_local_file(container_path: str) -> list:
    """Search CWD for a file matching the container path tail, trying progressively shorter suffixes."""
    import os
    parts = Path(container_path.lstrip("/")).parts
    cwd = Path.cwd()
    for i in range(len(parts)):
        suffix = str(Path(*parts[i:]))
        matches = list(cwd.glob(f"**/{suffix}"))
        if matches:
            return matches
    return []


def _offer_editor_open(scan_id: str, ready_rems: list) -> None:
    """Prompt user to open a remediation fix in $EDITOR."""
    import subprocess
    answer = typer.confirm("\nOpen a fix in editor?", default=False)
    if not answer:
        return

    if len(ready_rems) == 1:
        chosen_rem = ready_rems[0][1]
    else:
        console.print("\nAvailable remediations:")
        for i, (vid, rem) in enumerate(ready_rems, 1):
            first_file = rem["code_changes"][0]["file_path"] if rem.get("code_changes") else "?"
            console.print(f"  {i}. [dim]{vid}[/dim]  {first_file}")
        raw = typer.prompt("Select number", default="1")
        try:
            chosen_rem = ready_rems[int(raw) - 1][1]
        except (ValueError, IndexError):
            rprint("[red]Invalid selection.[/red]")
            return

    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    for change in chosen_rem.get("code_changes", []):
        matches = _find_local_file(change["file_path"])
        if not matches:
            rprint(f"[yellow]Could not find {change['file_path']} locally. Edit manually.[/yellow]")
            continue
        if len(matches) == 1:
            local_file = matches[0]
        else:
            console.print(f"\nMultiple files found for [cyan]{change['file_path']}[/cyan]:")
            for i, m in enumerate(matches, 1):
                console.print(f"  {i}. {m}")
            raw = typer.prompt("Select number", default="1")
            try:
                local_file = matches[int(raw) - 1]
            except (ValueError, IndexError):
                rprint("[red]Invalid selection.[/red]")
                continue
        line = change.get("start_line", 1)
        console.print(f"\n[dim]Opening {local_file} at line {line} with {editor}...[/dim]")
        subprocess.run([editor, f"+{line}", str(local_file)])
```

### Step 4: Run tests to confirm they pass

```bash
cd cli && uv run pytest tests/test_editor_open.py -v
```

Expected: 3 PASSED.

### Step 5: Run full CLI test suite

```bash
cd cli && uv run pytest tests/ -v
```

Expected: All tests pass.

### Step 6: Commit

```bash
git add cli/src/secremediator/cli.py cli/tests/test_editor_open.py
git commit -m "feat(cli): add file search helper and editor open flow for remediation"
```

---

## Task 6: MCP — update tool description to reflect async behavior

**Files:**
- Modify: `cli/src/secremediator/mcp_server.py`

### Step 1: Update the `request_remediation` tool description

In `cli/src/secremediator/mcp_server.py`, find the `request_remediation` Tool definition (around line 82) and update its description from:

```python
description="Get AI-generated remediation for a specific vulnerability by its vuln id.",
```

to:

```python
description=(
    "Trigger AI-generated remediation for a specific vulnerability. "
    "Returns immediately with status 'pending' or 'completed'. "
    "If pending, call get_scan_results to check when the remediation appears "
    "in the scan's remediations list."
),
```

### Step 2: Manual smoke test

```bash
cd cli && uv run secremediator --help
```

Confirm all five commands appear: `scan`, `status`, `results`, `vuln`, `remediate`.

### Step 3: Commit

```bash
git add cli/src/secremediator/mcp_server.py
git commit -m "docs(mcp): update request_remediation tool description for async behavior"
```

---

## Smoke Test (manual, with stack running)

```bash
# 1. Scan a project
secremediator scan ./myproject

# 2. Check results (shows findings, all with "run: secremediator remediate ..." hints)
secremediator results <scan_id>

# 3. Queue remediation for one finding
secremediator remediate <scan_id> <vuln_id>
# Expected: "Remediation queued. Check back with: secremediator results <scan_id>"

# 4. Re-run results — should show ⏳ pending, then after a minute show the fix inline
secremediator results <scan_id>

# 5. When remediation is ready, results prompts "Open a fix in editor? [y/N]"
#    Answering y searches CWD and opens $EDITOR at the right line
```
