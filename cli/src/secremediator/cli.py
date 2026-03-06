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
