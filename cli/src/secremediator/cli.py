import json
import os
import sys
import subprocess
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from datetime import datetime

from .archiver import create_archive
from .client import SecRemediatorClient
from .config import save_to_history, load_history, get_api_url, save_archive, get_archive_path

app = typer.Typer(help="secremediator — local security scanning CLI")
console = Console()


def _security_scan_dir(target: Path) -> Path:
    return target / ".security-scan"


def _ensure_security_scan_dir(target: Path) -> Path:
    d = _security_scan_dir(target)
    (d / "sessions").mkdir(parents=True, exist_ok=True)
    (d / "patches").mkdir(parents=True, exist_ok=True)
    gitignore = d / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*\n")
    return d


def _save_session(scan_dir: Path, data: dict):
    path = scan_dir / "sessions" / f"{data['scan_id']}.json"
    path.write_text(json.dumps(data, indent=2))


def _load_session(scan_dir: Path, scan_id: str) -> Optional[dict]:
    path = scan_dir / "sessions" / f"{scan_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _find_local_file(container_path: str) -> list:
    """Search CWD for a file matching the container path tail, trying progressively shorter suffixes."""
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
            try:
                Path(archive_path).unlink(missing_ok=True)
            except Exception:
                pass
            raise typer.Exit(1)

    scan_id = result["scan_id"]
    try:
        if Path(archive_path).exists():
            save_archive(scan_id, archive_path)
            Path(archive_path).unlink()
    except Exception:
        try:
            Path(archive_path).unlink(missing_ok=True)
        except Exception:
            pass
    save_to_history({
        "scan_id": scan_id,
        "project_name": project_name,
        "author": author_name,
        "scanners": scanner_list,
        "path": str(target),
        "submitted_at": datetime.utcnow().isoformat(),
        "api_url": api_url or get_api_url(),
    })

    scan_dir = _ensure_security_scan_dir(target)
    _save_session(scan_dir, {
        "scan_id": scan_id,
        "project_name": project_name,
        "author": author_name,
        "scanners": scanner_list,
        "path": str(target),
        "submitted_at": datetime.utcnow().isoformat(),
        "api_url": api_url or get_api_url(),
        "status": "queued",
        "summary": {},
        "vulnerability_ids": [],
        "remediation_status": {},
        "last_synced_at": None,
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
    """Fetch and display findings, remediation state, and offer to open fixes in editor."""
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

    ready_rems = [
        (vid, r) for vid, r in remediations_by_vuln.items()
        if r.get("code_changes")
    ]
    if ready_rems and sys.stdout.isatty():
        _offer_editor_open(scan_id, ready_rems)


@app.command()
def vuln(
    scan_id: str = typer.Argument(..., help="Scan ID the vulnerability belongs to"),
    vuln_id: str = typer.Argument(..., help="Vulnerability ID to inspect"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Show full details for a specific vulnerability."""
    client = SecRemediatorClient(api_url=api_url)
    with console.status(f"Fetching vulnerability {vuln_id}..."):
        try:
            v = client.get_vulnerability(scan_id, vuln_id)
        except Exception as e:
            rprint(f"[red]Failed:[/red] {e}")
            raise typer.Exit(1)

    sev = v.get("severity", "UNKNOWN").upper()
    severity_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
                       "LOW": "blue", "INFO": "dim", "UNKNOWN": "white"}
    color = severity_colors.get(sev, "white")

    console.print(f"\n[bold]Vulnerability Detail[/bold]  [dim]{v.get('id')}[/dim]")
    console.print(f"  [{color}]{sev}[/{color}]  [cyan]{v.get('scanner')}[/cyan]  {v.get('rule_id')}")
    console.print(f"  [bold]Location:[/bold] {v.get('file_path')}:{v.get('start_line')}–{v.get('end_line')}")
    console.print(f"\n  [bold]Message:[/bold]\n  {v.get('message', '')}\n")

    if v.get("code_snippet"):
        console.print(f"  [bold]Vulnerable Code:[/bold]")
        for line in v["code_snippet"].splitlines():
            console.print(f"  [red]│[/red] {line}")
        console.print()

    if v.get("surrounding_context"):
        console.print(f"  [bold]Context:[/bold]")
        for line in v["surrounding_context"].splitlines():
            console.print(f"  [dim]│[/dim] {line}")
        console.print()

    if v.get("taint_trace"):
        console.print(f"  [bold]Taint Trace:[/bold]")
        for i, node in enumerate(v["taint_trace"], 1):
            console.print(f"  [dim]{i}.[/dim] {node.get('file_path')}:{node.get('line_number')}  {node.get('step_description', '')}")
            console.print(f"     [dim]{node.get('code_snippet', '')}[/dim]")
        console.print()

    if v.get("metadata"):
        console.print(f"  [bold]Metadata:[/bold]")
        for k, val in v["metadata"].items():
            console.print(f"  [dim]{k}:[/dim] {val}")
        console.print()

    console.print(f"  [dim]To remediate: secremediator remediate {scan_id} {vuln_id}[/dim]\n")


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

    if result.get("status") == "completed":
        console.print(f"\n[green]✓[/green] Remediation already completed for [dim]{vuln_id}[/dim]")
        console.print(f"  Run [cyan]secremediator results {scan_id}[/cyan] to view it.\n")
    else:
        console.print(f"\n[green]✓[/green] Remediation queued for [dim]{vuln_id}[/dim]")
        console.print(f"\n  Check back with: [cyan]secremediator results {scan_id}[/cyan]\n")


@app.command()
def sync(
    path: str = typer.Argument(".", help="Repo directory containing .security-scan/"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Refresh scan status for all sessions in .security-scan/."""
    target = Path(path).resolve()
    scan_dir = _security_scan_dir(target)
    sessions_dir = scan_dir / "sessions"
    if not sessions_dir.exists():
        rprint("[yellow]No .security-scan/ found.[/yellow]")
        return

    sessions = list(sessions_dir.glob("*.json"))
    if not sessions:
        rprint("[yellow]No sessions found.[/yellow]")
        return

    for session_file in sessions:
        session = json.loads(session_file.read_text())
        scan_id = session["scan_id"]
        client = SecRemediatorClient(api_url=api_url or session.get("api_url"))
        try:
            data = client.get_scan(scan_id)
            session["status"] = data.get("status", "unknown")
            session["summary"] = data.get("summary", {})
            session["vulnerability_ids"] = [v["id"] for v in data.get("vulnerabilities", [])]
            session["last_synced_at"] = datetime.utcnow().isoformat()
            session_file.write_text(json.dumps(session, indent=2))
            console.print(f"[green]✓[/green] {scan_id[:8]}...  {session['status']}")
        except Exception as e:
            rprint(f"[red]✗[/red] {scan_id[:8]}...  {e}")


def _poll_until_complete(client: SecRemediatorClient, scan_id: str, label: str = "") -> dict:
    """Poll a scan every 10s, printing a dot per poll, until status is terminal."""
    import time
    terminal = {"completed", "failed"}
    console.print(f"[dim]Polling {label or scan_id[:8]}...[/dim] ", end="")
    while True:
        data = client.get_scan(scan_id)
        status = data.get("status", "unknown")
        if status in terminal:
            console.print(f" {status}")
            return data
        console.print(".", end="", highlight=False)
        time.sleep(10)


def _run_revalidation(
    client: SecRemediatorClient,
    original_scan_id: str,
    vuln: dict,
    patch: dict,
    api_url: str,
) -> dict:
    """
    Revalidate a patch by:
    1. Extracting original archive to temp dir
    2. Overwriting patched files with new_code
    3. Re-archiving and submitting a new scan
    4. Checking: original vuln gone AND no new issues in patched files
    """
    import tarfile, tempfile
    from .archiver import create_archive

    archive_path = get_archive_path(original_scan_id)
    if not archive_path:
        return {
            "vuln_id": vuln["id"],
            "original_scan_id": original_scan_id,
            "revalidation_scan_id": None,
            "patched_files": [],
            "status": "SKIPPED_NO_ARCHIVE",
            "original_vuln_still_present": None,
            "new_findings_in_patched_files": [],
            "validated_at": datetime.utcnow().isoformat(),
            "note": "Original archive not found; cannot revalidate",
        }

    patched_files = [c["file_path"] for c in patch.get("code_changes", [])]

    with tempfile.TemporaryDirectory() as tmp:
        extract_dir = Path(tmp) / "source"
        extract_dir.mkdir()

        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(extract_dir, filter="data")

        for change in patch.get("code_changes", []):
            target_file = extract_dir / change["file_path"].lstrip("/")
            if not target_file.exists():
                continue
            lines = target_file.read_text().splitlines(keepends=True)
            s = change["start_line"] - 1
            e = change["end_line"]
            new_lines = [change["new_code"] + "\n"] if change["new_code"] else []
            lines[s:e] = new_lines
            target_file.write_text("".join(lines))

        reval_archive = create_archive(str(extract_dir))
        try:
            result = client.upload_scan(
                archive_path=reval_archive,
                project_name=f"revalidation_{vuln['id'][:8]}",
                author="secremediator-revalidation",
                scanners=["semgrep", "checkov", "trivy"],
            )
        finally:
            Path(reval_archive).unlink(missing_ok=True)

    reval_scan_id = result["scan_id"]
    reval_data = _poll_until_complete(client, reval_scan_id, f"revalidation {vuln['id'][:8]}")
    reval_vulns = reval_data.get("vulnerabilities", [])

    original_still_present = any(
        v.get("rule_id") == vuln.get("rule_id")
        and v.get("file_path") == vuln.get("file_path")
        and v.get("start_line") == vuln.get("start_line")
        for v in reval_vulns
    )

    new_issues = [
        v for v in reval_vulns
        if v.get("file_path") in patched_files
        and not (
            v.get("rule_id") == vuln.get("rule_id")
            and v.get("file_path") == vuln.get("file_path")
            and v.get("start_line") == vuln.get("start_line")
        )
    ]

    if not original_still_present and not new_issues:
        status = "PASS"
    elif original_still_present and new_issues:
        status = "FAIL_BOTH"
    elif original_still_present:
        status = "FAIL_STILL_VULNERABLE"
    else:
        status = "FAIL_NEW_ISSUES"

    return {
        "vuln_id": vuln["id"],
        "original_scan_id": original_scan_id,
        "revalidation_scan_id": reval_scan_id,
        "patched_files": patched_files,
        "status": status,
        "original_vuln_still_present": original_still_present,
        "new_findings_in_patched_files": new_issues,
        "validated_at": datetime.utcnow().isoformat(),
        "note": "Only files touched by the patch are checked for new issues",
    }


@app.command("remediate-all")
def remediate_all(
    scan_id: str = typer.Argument(..., help="Scan ID to remediate"),
    use_local_claude: bool = typer.Option(False, "--use-local-claude", help="Use local Claude via Anthropic SDK instead of backend engine"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Comma-separated severities to include, e.g. CRITICAL,HIGH"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Run full remediation loop: poll -> patch -> revalidate. Patches land in .security-scan/."""
    import time
    client = SecRemediatorClient(api_url=api_url)

    history = load_history()
    entry = next((e for e in history if e["scan_id"] == scan_id), None)
    if not entry:
        rprint(f"[red]Scan {scan_id} not found in history.[/red]")
        raise typer.Exit(1)

    target = Path(entry["path"])
    scan_dir = _ensure_security_scan_dir(target)
    patches_base = scan_dir / "patches" / scan_id

    console.print(f"\n[bold]Waiting for scan to complete...[/bold]")
    data = _poll_until_complete(client, scan_id)
    if data.get("status") == "failed":
        rprint("[red]Scan failed.[/red]")
        raise typer.Exit(1)

    vulns = data.get("vulnerabilities", [])
    if severity:
        allowed = {s.strip().upper() for s in severity.split(",")}
        vulns = [v for v in vulns if v.get("severity", "").upper() in allowed]

    if not vulns:
        rprint("[green]No findings to remediate.[/green]")
        return

    console.print(f"\n[bold]{len(vulns)} findings to remediate[/bold]")
    if use_local_claude:
        console.print("[dim]Using local Claude (Agent SDK)[/dim]")
        from .agent import LocalClaudeRemediator
        remediator = LocalClaudeRemediator()
    else:
        console.print("[dim]Using backend remediation engine[/dim]")

    passed = failed = skipped = 0

    for vuln in vulns:
        vuln_id = vuln["id"]
        patch_dir = patches_base / vuln_id
        patch_dir.mkdir(parents=True, exist_ok=True)
        patch_file = patch_dir / "patch.json"
        reval_file = patch_dir / "revalidation.json"

        console.print(f"\n[cyan]▸[/cyan] {vuln.get('severity')} {vuln.get('rule_id')}  {vuln.get('file_path')}:{vuln.get('start_line')}")

        try:
            if use_local_claude:
                vuln_detail = client.get_vulnerability(scan_id, vuln_id)
                source = vuln_detail.get("code_snippet", "") or vuln_detail.get("surrounding_context", "")
                patch = remediator.generate_patch(vuln_detail, source)
            else:
                client.request_remediation(scan_id, vuln_id)
                for _ in range(60):
                    scan_data = client.get_scan(scan_id)
                    rems = {r["vulnerability_id"]: r for r in scan_data.get("remediations", [])}
                    if vuln_id in rems:
                        rem = rems[vuln_id]
                        patch = {
                            "summary": rem.get("summary", ""),
                            "confidence_score": rem.get("confidence_score", 0),
                            "is_false_positive": rem.get("is_false_positive", False),
                            "code_changes": rem.get("code_changes", []),
                            "security_implications": rem.get("security_implications", []),
                        }
                        break
                    time.sleep(10)
                else:
                    rprint(f"  [yellow]Timed out waiting for remediation.[/yellow]")
                    skipped += 1
                    continue

            patch["vuln_id"] = vuln_id
            patch["scan_id"] = scan_id
            patch["generated_by"] = "local_claude" if use_local_claude else "backend_engine"
            patch["created_at"] = datetime.utcnow().isoformat()
            patch_file.write_text(json.dumps(patch, indent=2))
            console.print(f"  [green]✓[/green] Patch generated  confidence: {patch.get('confidence_score', 0):.2f}")

        except Exception as e:
            rprint(f"  [red]✗[/red] Patch generation failed: {e}")
            skipped += 1
            continue

        console.print(f"  [dim]Revalidating...[/dim]")
        try:
            reval = _run_revalidation(client, scan_id, vuln, patch, api_url or get_api_url())
            reval_file.write_text(json.dumps(reval, indent=2))
            if reval["status"] == "PASS":
                console.print(f"  [green]✓[/green] Revalidation PASS")
                passed += 1
            else:
                console.print(f"  [yellow]⚠[/yellow] Revalidation {reval['status']}")
                failed += 1
        except Exception as e:
            rprint(f"  [red]✗[/red] Revalidation error: {e}")
            skipped += 1

    console.print(f"\n[bold]Done.[/bold]  ✓ {passed} PASS  ⚠ {failed} FAIL  — {skipped} skipped")
    console.print(f"Patches in: [cyan]{scan_dir / 'patches' / scan_id}[/cyan]")
    console.print(f"Apply with: [cyan]secremediator apply {scan_id} --all[/cyan]\n")


@app.command()
def apply(
    scan_id: str = typer.Argument(..., help="Scan ID whose patches to apply"),
    vuln_id: Optional[str] = typer.Option(None, "--vuln", help="Apply a single vulnerability's patch"),
    all_patches: bool = typer.Option(False, "--all", help="Apply all patches that passed revalidation"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would change without modifying files"),
    force: bool = typer.Option(False, "--force", help="Apply even patches that failed revalidation"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Apply generated patches to files on disk."""
    if not vuln_id and not all_patches:
        rprint("[red]Specify --vuln <id> or --all.[/red]")
        raise typer.Exit(1)

    history = load_history()
    entry = next((e for e in history if e["scan_id"] == scan_id), None)
    if not entry:
        rprint(f"[red]Scan {scan_id} not in history.[/red]")
        raise typer.Exit(1)

    target = Path(entry["path"])
    patches_base = _security_scan_dir(target) / "patches" / scan_id

    if not patches_base.exists():
        rprint(f"[red]No patches found at {patches_base}[/red]")
        raise typer.Exit(1)

    if vuln_id:
        patch_dirs = [patches_base / vuln_id]
    else:
        patch_dirs = [d for d in patches_base.iterdir() if d.is_dir()]

    applied = skipped = 0

    for patch_dir in patch_dirs:
        patch_file = patch_dir / "patch.json"
        reval_file = patch_dir / "revalidation.json"

        if not patch_file.exists():
            rprint(f"[yellow]No patch.json in {patch_dir.name}[/yellow]")
            skipped += 1
            continue

        patch = json.loads(patch_file.read_text())
        vid = patch.get("vuln_id", patch_dir.name)

        if reval_file.exists():
            reval = json.loads(reval_file.read_text())
            reval_status = reval.get("status", "UNKNOWN")
        else:
            reval_status = "NOT_RUN"

        if reval_status != "PASS" and not force:
            if reval_status == "NOT_RUN":
                if not typer.confirm(f"  {vid[:8]}: revalidation not run — apply anyway?", default=False):
                    skipped += 1
                    continue
            else:
                rprint(f"  [yellow]Skipping {vid[:8]}: revalidation {reval_status}. Use --force to override.[/yellow]")
                skipped += 1
                continue

        changes = patch.get("code_changes", [])
        if not changes:
            rprint(f"  [yellow]{vid[:8]}: no code_changes in patch.[/yellow]")
            skipped += 1
            continue

        console.print(f"\n[cyan]{vid[:8]}[/cyan]  revalidation={reval_status}  confidence={patch.get('confidence_score', 0):.2f}")

        files_written = 0
        for change in changes:
            file_path = target / change["file_path"].lstrip("/")
            if not file_path.exists():
                rprint(f"  [red]File not found: {file_path}[/red]")
                skipped += 1
                continue

            lines = file_path.read_text().splitlines(keepends=True)
            s = change["start_line"] - 1
            e = change["end_line"]
            new_lines = [change["new_code"] + "\n"] if change["new_code"] else []

            console.print(f"  [dim]{change['file_path']}  lines {change['start_line']}–{change['end_line']}[/dim]")
            for l in change.get("original_code", "").splitlines():
                console.print(f"  [red]- {l}[/red]")
            for l in change.get("new_code", "").splitlines():
                console.print(f"  [green]+ {l}[/green]")

            if not dry_run:
                lines[s:e] = new_lines
                file_path.write_text("".join(lines))
                files_written += 1

        if not dry_run:
            if files_written > 0:
                session_file = _security_scan_dir(target) / "sessions" / f"{scan_id}.json"
                if session_file.exists():
                    session = json.loads(session_file.read_text())
                    session.setdefault("remediation_status", {})[vid] = "applied"
                    session_file.write_text(json.dumps(session, indent=2))
                applied += 1
        else:
            console.print(f"  [dim](dry-run — not written)[/dim]")

    if dry_run:
        console.print(f"\n[dim]Dry run complete. {len(patch_dirs)} patches previewed.[/dim]")
    else:
        console.print(f"\n[bold]Done.[/bold]  {applied} applied  {skipped} skipped\n")
