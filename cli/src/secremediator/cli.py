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
from .config import save_to_history, load_history, get_api_url

app = typer.Typer(help="secremediator — local security scanning CLI")
console = Console()


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
