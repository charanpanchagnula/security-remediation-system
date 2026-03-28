import json
import os
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from datetime import datetime

from .archiver import create_archive
from .client import SecurityPipelineClient
from .config import save_to_history, load_history, get_api_url, save_archive, get_archive_path

app = typer.Typer(help="security-pipeline — local security scanning CLI")
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


def _apply_patch_changes(base_path: Path, changes: list) -> list:
    """Apply code_changes from a patch to files under base_path. Returns list of written file paths."""
    written = []
    for change in changes:
        file_path = base_path / change["file_path"].lstrip("/")
        if not file_path.exists():
            continue
        lines = file_path.read_text().splitlines(keepends=True)
        s = change["start_line"] - 1
        e = change["end_line"]
        new_lines = [change["new_code"] + "\n"] if change["new_code"] else []
        lines[s:e] = new_lines
        file_path.write_text("".join(lines))
        written.append(change["file_path"])
    return written


def _submit_scan_job(
    target: Path,
    project_name: str,
    author_name: str,
    scanner_list: list,
    api_url: Optional[str],
) -> tuple:
    """Archive, upload, persist to history and .security-scan/. Returns (scan_id, scan_dir)."""
    archive_path = create_archive(str(target))
    client = SecurityPipelineClient(api_url=api_url)
    result = client.upload_scan(
        archive_path=archive_path,
        project_name=project_name,
        author=author_name,
        scanners=scanner_list,
    )
    scan_id = result["scan_id"]
    try:
        if Path(archive_path).exists():
            save_archive(scan_id, archive_path)
    finally:
        Path(archive_path).unlink(missing_ok=True)
    submitted_at = datetime.utcnow().isoformat()
    save_to_history({
        "scan_id": scan_id,
        "project_name": project_name,
        "author": author_name,
        "scanners": scanner_list,
        "path": str(target),
        "submitted_at": submitted_at,
        "api_url": api_url or get_api_url(),
    })
    scan_dir = _ensure_security_scan_dir(target)
    _save_session(scan_dir, {
        "scan_id": scan_id,
        "project_name": project_name,
        "author": author_name,
        "scanners": scanner_list,
        "path": str(target),
        "submitted_at": submitted_at,
        "api_url": api_url or get_api_url(),
        "status": "queued",
        "summary": {},
        "vulnerability_ids": [],
        "remediation_status": {},
        "last_synced_at": None,
    })
    return (scan_id, scan_dir)


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

    with console.status("[bold green]Archiving and uploading..."):
        try:
            scan_id, scan_dir = _submit_scan_job(
                target=target,
                project_name=project_name,
                author_name=author_name,
                scanner_list=scanner_list,
                api_url=api_url,
            )
        except Exception as e:
            rprint(f"[red]Upload failed:[/red] {e}")
            raise typer.Exit(1)

    console.print(f"[green]✓[/green] Archive ready and uploaded")

    console.print(f"\n[green]✓[/green] Scan queued.")
    console.print(f"\n  [bold]Session ID:[/bold] {scan_id}")
    console.print(f"\n  Check status : [cyan]security-pipeline status[/cyan]")
    console.print(f"  View results : [cyan]security-pipeline results {scan_id}[/cyan]\n")


@app.command()
def status():
    """Show all your submitted scans and their current status."""
    history = load_history()
    if not history:
        rprint("[yellow]No scans found.[/yellow] Run [cyan]security-pipeline scan[/cyan] first.")
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
        client = SecurityPipelineClient(api_url=entry.get("api_url"))
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
    """Fetch and display findings and remediation state."""
    client = SecurityPipelineClient(api_url=api_url)
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
                console.print(f"    [dim]run: security-pipeline remediate {scan_id} {vuln_id}[/dim]")
            console.print()



@app.command()
def vuln(
    scan_id: str = typer.Argument(..., help="Scan ID the vulnerability belongs to"),
    vuln_id: str = typer.Argument(..., help="Vulnerability ID to inspect"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Show full details for a specific vulnerability."""
    client = SecurityPipelineClient(api_url=api_url)
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

    console.print(f"  [dim]To remediate: security-pipeline remediate {scan_id} {vuln_id}[/dim]\n")


@app.command()
def remediate(
    scan_id: str = typer.Argument(..., help="Scan ID the vulnerability belongs to"),
    vuln_id: str = typer.Argument(..., help="Vulnerability ID to remediate"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Queue AI remediation for a specific vulnerability (fire-and-forget)."""
    client = SecurityPipelineClient(api_url=api_url)
    try:
        result = client.request_remediation(scan_id, vuln_id)
    except Exception as e:
        rprint(f"[red]Failed:[/red] {e}")
        raise typer.Exit(1)

    if result.get("status") == "completed":
        console.print(f"\n[green]✓[/green] Remediation already completed for [dim]{vuln_id}[/dim]")
        console.print(f"  Run [cyan]security-pipeline results {scan_id}[/cyan] to view it.\n")
    else:
        console.print(f"\n[green]✓[/green] Remediation queued for [dim]{vuln_id}[/dim]")
        console.print(f"\n  Check back with: [cyan]security-pipeline results {scan_id}[/cyan]\n")


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
        client = SecurityPipelineClient(api_url=api_url or session.get("api_url"))
        try:
            data = client.get_scan(scan_id)
            session["status"] = data.get("status", "unknown")
            session["summary"] = data.get("summary", {})
            all_vulns = data.get("vulnerabilities", [])
            session["vulnerability_ids"] = [v["id"] for v in all_vulns]
            session["vulnerabilities"] = [
                {
                    "id": v["id"],
                    "rule_id": v.get("rule_id"),
                    "severity": v.get("severity"),
                    "file_path": v.get("file_path"),
                    "start_line": v.get("start_line"),
                    "end_line": v.get("end_line"),
                    "message": v.get("message"),
                    "scanner": v.get("scanner"),
                }
                for v in all_vulns
            ]
            session["last_synced_at"] = datetime.utcnow().isoformat()
            session_file.write_text(json.dumps(session, indent=2))
            console.print(f"[green]✓[/green] {scan_id[:8]}...  {session['status']}")
        except Exception as e:
            rprint(f"[red]✗[/red] {scan_id[:8]}...  {e}")


def _poll_until_complete(client: SecurityPipelineClient, scan_id: str, label: str = "", quiet: bool = False) -> dict:
    """Poll a scan every 10s, printing a dot per poll, until status is terminal."""
    import time
    terminal = {"completed", "failed"}
    if not quiet:
        console.print(f"[dim]Polling {label or scan_id[:8]}...[/dim] ", end="")
    while True:
        data = client.get_scan(scan_id)
        status = data.get("status", "unknown")
        if status in terminal:
            if not quiet:
                console.print(f" {status}")
            return data
        if not quiet:
            console.print(".", end="", highlight=False)
        time.sleep(10)


def _run_batch_revalidation(
    client: "SecurityPipelineClient",
    original_scan_id: str,
    vulns_patches: list,
    patches_base: Path,
    scanners: list | None = None,
    quiet: bool = False,
) -> tuple:
    """
    Apply all patches at once to the original archive, submit a single revalidation scan.
    Deletes the original archive after extraction — it is not needed after revalidation.
    Returns (reval_data, reval_scan_id) or (None, None) if original archive is missing.
    """
    import tarfile, tempfile
    from .archiver import create_archive

    archive_path = get_archive_path(original_scan_id)
    if not archive_path:
        if not quiet:
            rprint("[yellow]Original archive not found — skipping batch revalidation.[/yellow]")
        return None, None

    with tempfile.TemporaryDirectory() as tmp:
        extract_dir = Path(tmp) / "source"
        extract_dir.mkdir()

        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(extract_dir, filter="data")
        Path(archive_path).unlink(missing_ok=True)

        for _vuln, patch in vulns_patches:
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

    patches_base.mkdir(parents=True, exist_ok=True)

    try:
        result = client.upload_scan(
            archive_path=reval_archive,
            project_name=f"revalidation_{original_scan_id[:8]}",
            author="security-pipeline-revalidation",
            scanners=scanners or ["semgrep", "checkov", "trivy"],
        )
    finally:
        Path(reval_archive).unlink(missing_ok=True)

    reval_scan_id = result["scan_id"]
    if not quiet:
        console.print(f"[dim]Revalidation scan: {reval_scan_id}[/dim]")

    reval_data = _poll_until_complete(client, reval_scan_id, "batch-revalidation", quiet=quiet)
    return reval_data, reval_scan_id


def _write_severity_reports(patches_base: Path, vulns: list) -> None:
    """Write REPORT-CRITICAL.md and REPORT-HIGH.md to patches_base."""
    vuln_by_id = {v["id"]: v for v in vulns}
    scan_id = patches_base.name

    for severity in ("CRITICAL", "HIGH"):
        entries = []
        for patch_dir in sorted(d for d in patches_base.iterdir() if d.is_dir()):
            patch_file = patch_dir / "patch.json"
            reval_file = patch_dir / "revalidation.json"
            if not patch_file.exists():
                continue
            patch = json.loads(patch_file.read_text())
            vuln_id = patch.get("vuln_id", patch_dir.name)
            vuln = vuln_by_id.get(vuln_id, {})
            if vuln.get("severity", "").upper() != severity:
                continue
            reval_status = "NOT_RUN"
            if reval_file.exists():
                reval_status = json.loads(reval_file.read_text()).get("status", "UNKNOWN")
            entries.append((vuln, patch, reval_status))

        if not entries:
            continue

        lines = [
            f"# Security Report — {severity}",
            "",
            f"Scan: `{scan_id}`  |  {len(entries)} finding(s)",
            "",
        ]

        for vuln, patch, reval_status in entries:
            vuln_id = vuln.get("id", patch.get("vuln_id", ""))
            rule = vuln.get("rule_id", "unknown")
            scanner = vuln.get("scanner", "unknown")
            fp = vuln.get("file_path", "unknown")
            sl = vuln.get("start_line", "?")
            el = vuln.get("end_line", "?")
            message = vuln.get("message", "")
            conf = patch.get("confidence_score", 0)
            summary = patch.get("summary", "")
            reval_icon = "PASS ✅" if reval_status == "PASS" else (f"{reval_status} ⚠️" if reval_status.startswith("FAIL") else reval_status)
            fp_note = "  **[FALSE POSITIVE]**" if patch.get("is_false_positive") else ""

            lines += [
                "---",
                "",
                f"## {rule}",
                "",
                f"**Scanner:** {scanner}  |  **File:** `{fp}:{sl}-{el}`",
                f"**ID:** `{vuln_id}`",
                "",
                f"**Message:** {message}",
                "",
                f"**Patch:** {summary}{fp_note}  |  **Confidence:** {conf:.2f}  |  **Revalidation:** {reval_icon}",
                "",
            ]

            for change in patch.get("code_changes", []):
                desc = change.get("description", "")
                if desc:
                    lines += [f"**Change:** {desc}", ""]
                orig = change.get("original_code", "")
                new = change.get("new_code", "")
                if orig or new:
                    lines.append("```diff")
                    for ln in orig.splitlines():
                        lines.append(f"- {ln}")
                    for ln in new.splitlines():
                        lines.append(f"+ {ln}")
                    lines += ["```", ""]

            implications = patch.get("security_implications", [])
            if implications:
                lines.append("**Security implications:**")
                for imp in implications:
                    lines.append(f"- {imp}")
                lines.append("")

            concerns = [c for c in patch.get("evaluation_concerns", []) if c]
            if concerns:
                lines.append("**Evaluation concerns:**")
                for c in concerns:
                    lines.append(f"- {c}")
                lines.append("")

        report_file = patches_base / f"REPORT-{severity}.md"
        report_file.write_text("\n".join(lines) + "\n")


def _collect_dry_run_patches(patches_base: Path) -> list:
    """Return structured data for all PASS patches (used for display and MCP responses)."""
    if not patches_base.exists():
        return []
    result = []
    for patch_dir in sorted(d for d in patches_base.iterdir() if d.is_dir()):
        patch_file = patch_dir / "patch.json"
        reval_file = patch_dir / "revalidation.json"
        if not patch_file.exists():
            continue
        patch = json.loads(patch_file.read_text())
        reval_status = "NOT_RUN"
        if reval_file.exists():
            reval_status = json.loads(reval_file.read_text()).get("status", "UNKNOWN")
        if reval_status == "PASS" and patch.get("code_changes"):
            result.append({
                "vuln_id": patch.get("vuln_id"),
                "summary": patch.get("summary", ""),
                "confidence_score": patch.get("confidence_score", 0),
                "code_changes": patch.get("code_changes", []),
                "revalidation_status": reval_status,
            })
    return result


def _show_apply_dry_run(scan_id: str, dry_run_patches: list) -> None:
    """Print all PASS patches as a dry-run diff preview."""
    console.print(f"\n[bold cyan]── Dry Run: security-pipeline apply {scan_id} --all ──[/bold cyan]")
    if not dry_run_patches:
        console.print("[dim]No passing patches to apply.[/dim]\n")
        return
    console.print(f"[dim]{len(dry_run_patches)} patch(es) would be applied:[/dim]\n")
    for item in dry_run_patches:
        vid = (item.get("vuln_id") or "unknown")
        console.print(f"[cyan]{vid[:8]}[/cyan]  confidence={item.get('confidence_score', 0):.2f}  {item.get('summary', '')}")
        for change in item.get("code_changes", []):
            console.print(f"  [dim]{change['file_path']}  lines {change['start_line']}–{change['end_line']}[/dim]")
            for line in change.get("original_code", "").splitlines():
                console.print(f"  [red]- {line}[/red]")
            for line in change.get("new_code", "").splitlines():
                console.print(f"  [green]+ {line}[/green]")
        console.print()
    console.print(f"[bold]To apply: security-pipeline apply {scan_id} --all[/bold]\n")


def _run_remediate_all_loop(
    client: "SecurityPipelineClient",
    scan_id: str,
    target: Path,
    severity: Optional[str] = None,
    use_local_claude: bool = True,
    use_multi_turn: bool = False,
    max_iterations: int = 6,
    quiet: bool = False,
    scanners: list | None = None,
) -> dict:
    """
    Efficient two-scan pipeline:
      1. Poll scan → get all findings
      2. Generate patches for every vulnerability (no per-patch revalidation)
      3. Apply all patches at once → create patched tar → submit single revalidation scan
      4. Analyse per-vulnerability results from the batch revalidation scan
      5. Show dry-run apply preview (all passing patches)

    Saves patch.json and revalidation.json to .security-scan/patches/<scan_id>/<vuln_id>/.
    Returns summary dict including revalidation_scan_id and dry_run_patches.
    """
    import time

    if not quiet:
        console.print(f"\n[bold]Waiting for scan to complete...[/bold]")
    data = _poll_until_complete(client, scan_id, quiet=quiet)
    if data.get("status") == "failed":
        raise RuntimeError("Scan failed.")

    scan_dir = _ensure_security_scan_dir(target)
    patches_base = scan_dir / "patches" / scan_id

    # Persist scan results into the session file now that we have real data
    session_file = scan_dir / "sessions" / f"{scan_id}.json"
    if session_file.exists():
        session = json.loads(session_file.read_text())
        session["status"] = data.get("status", "completed")
        session["summary"] = data.get("summary", {})
        all_vulns = data.get("vulnerabilities", [])
        session["vulnerability_ids"] = [v["id"] for v in all_vulns]
        session["vulnerabilities"] = [
            {
                "id": v["id"],
                "rule_id": v.get("rule_id"),
                "severity": v.get("severity"),
                "file_path": v.get("file_path"),
                "start_line": v.get("start_line"),
                "end_line": v.get("end_line"),
                "message": v.get("message"),
                "scanner": v.get("scanner"),
            }
            for v in all_vulns
        ]
        session["last_synced_at"] = datetime.utcnow().isoformat()
        session_file.write_text(json.dumps(session, indent=2))

    vulns = data.get("vulnerabilities", [])
    if severity:
        allowed = {s.strip().upper() for s in severity.split(",")}
        vulns = [v for v in vulns if v.get("severity", "").upper() in allowed]

    if not vulns:
        if not quiet:
            rprint("[green]No findings to remediate.[/green]")
        return {
            "passed": 0, "failed": 0, "skipped": 0,
            "patches_dir": str(patches_base), "total_vulns": 0,
            "revalidation_scan_id": None, "dry_run_patches": [],
        }

    if not quiet:
        console.print(f"\n[bold]Phase 1 of 2 — Generating patches for {len(vulns)} findings[/bold]")

    remediator = None
    if use_local_claude:
        from .agent import LocalClaudeRemediator, CLAUDE_SDK_AVAILABLE
        if CLAUDE_SDK_AVAILABLE:
            if not quiet:
                console.print("[dim]Using local Claude (Agent SDK)[/dim]")
            remediator = LocalClaudeRemediator()
        else:
            if not quiet:
                rprint("[yellow]claude_agent_sdk unavailable (not running inside Claude Code) — falling back to backend engine[/yellow]")
            use_local_claude = False
    if not use_local_claude and not quiet:
        console.print("[dim]Using backend remediation engine[/dim]")

    if use_multi_turn:
        from .multi_turn_agent import MultiTurnRemediator, CLAUDE_SDK_AVAILABLE as MT_AVAILABLE
        if not MT_AVAILABLE:
            if not quiet:
                rprint("[yellow]claude_agent_sdk unavailable — falling back to single-shot[/yellow]")
            use_multi_turn = False

    skipped = 0
    patchable: list = []   # (vuln, patch) pairs with real code_changes

    _LOCK_FILES = {"uv.lock", "poetry.lock", "package-lock.json", "yarn.lock",
                   "Pipfile.lock", "Gemfile.lock", "go.sum", "cargo.lock"}

    for vuln in vulns:
        vuln_id = vuln["id"]
        patch_dir = patches_base / vuln_id
        patch_dir.mkdir(parents=True, exist_ok=True)
        patch_file = patch_dir / "patch.json"

        if not quiet:
            console.print(f"\n[cyan]▸[/cyan] {vuln.get('severity')} {vuln.get('rule_id')}  {vuln.get('file_path')}:{vuln.get('start_line')}")

        if use_local_claude and Path(vuln.get("file_path", "")).name in _LOCK_FILES:
            if not quiet:
                console.print(f"  [dim]↩ Lock file — cannot patch directly. Fix manually with your package manager.[/dim]")
            skipped += 1
            continue

        try:
            if use_multi_turn:
                if not quiet:
                    console.print("[dim]Using multi-turn Claude (iterative loop)[/dim]")
                vuln_detail = client.get_vulnerability(scan_id, vuln_id)
                mt = MultiTurnRemediator(max_iterations=max_iterations)
                patch, iteration_log = mt.remediate(vuln_detail, work_dir=str(target))
                patch["iteration_log"] = iteration_log

            if not use_multi_turn and use_local_claude:
                vuln_detail = client.get_vulnerability(scan_id, vuln_id)
                full_file_path = target / vuln_detail.get("file_path", "")
                if full_file_path.is_file():
                    source = full_file_path.read_text()
                else:
                    source = vuln_detail.get("surrounding_context", "") or vuln_detail.get("code_snippet", "")
                patch = remediator.generate_patch(vuln_detail, source)
            elif not use_multi_turn:
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
                    if not quiet:
                        rprint(f"  [yellow]Timed out waiting for remediation.[/yellow]")
                    skipped += 1
                    continue

            patch["vuln_id"] = vuln_id
            patch["scan_id"] = scan_id
            patch["generated_by"] = "multi_turn" if use_multi_turn else ("local_claude" if use_local_claude else "backend_engine")
            patch["created_at"] = datetime.utcnow().isoformat()
            # Pop iteration_log BEFORE writing patch.json so it doesn't appear in both files
            iter_log = patch.pop("iteration_log", None)
            patch_file.write_text(json.dumps(patch, indent=2))
            if iter_log:
                iter_log_file = patch_dir / "iteration_log.json"
                iter_log_file.write_text(json.dumps(iter_log, indent=2))
            if not quiet:
                console.print(f"  [green]✓[/green] Patch generated  confidence: {patch.get('confidence_score', 0):.2f}")

            if patch.get("is_false_positive"):
                if not quiet:
                    console.print(f"  [yellow]↩[/yellow] False positive — excluded from revalidation")
                skipped += 1
            elif patch.get("code_changes"):
                patchable.append((vuln, patch))
            else:
                skipped += 1

        except Exception as e:
            if not quiet:
                rprint(f"  [red]✗[/red] Patch generation failed: {e}")
            skipped += 1

    # Phase 2: Single batch revalidation scan
    passed = failed = 0
    reval_scan_id = None

    if patchable:
        if not quiet:
            console.print(f"\n[bold]Phase 2 of 2 — Single batch revalidation ({len(patchable)} patches → 1 scan)[/bold]")

        reval_data, reval_scan_id = _run_batch_revalidation(
            client=client,
            original_scan_id=scan_id,
            vulns_patches=patchable,
            patches_base=patches_base,
            scanners=scanners,
            quiet=quiet,
        )

        if reval_data:
            reval_vulns = reval_data.get("vulnerabilities", [])

            for vuln, patch in patchable:
                vuln_id = vuln["id"]
                reval_file = patches_base / vuln_id / "revalidation.json"
                patched_files = [c["file_path"] for c in patch.get("code_changes", [])]

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

                if original_still_present and new_issues:
                    status = "FAIL_BOTH"
                elif original_still_present:
                    status = "FAIL_STILL_VULNERABLE"
                elif new_issues:
                    status = "FAIL_NEW_ISSUES"
                else:
                    status = "PASS"

                reval_file.write_text(json.dumps({
                    "vuln_id": vuln_id,
                    "original_scan_id": scan_id,
                    "revalidation_scan_id": reval_scan_id,
                    "patched_files": patched_files,
                    "status": status,
                    "original_vuln_still_present": original_still_present,
                    "new_findings_in_patched_files": new_issues,
                    "validated_at": datetime.utcnow().isoformat(),
                    "note": "Batch revalidation: all patches applied together in a single scan",
                }, indent=2))

                if not quiet:
                    icon = "[green]✓[/green]" if status == "PASS" else "[yellow]⚠[/yellow]"
                    console.print(f"  {icon} {vuln_id[:8]}: {status}")

                if status == "PASS":
                    passed += 1
                else:
                    failed += 1
        else:
            skipped += len(patchable)

    if not quiet:
        console.print(f"\n[bold]Done.[/bold]  ✓ {passed} PASS  ⚠ {failed} FAIL  — {skipped} skipped")
        console.print(f"Patches in: [cyan]{patches_base}[/cyan]\n")

    # Phase 3: Severity reports + dry-run apply preview
    _write_severity_reports(patches_base, vulns)
    dry_run_patches = _collect_dry_run_patches(patches_base)
    if not quiet:
        _show_apply_dry_run(scan_id, dry_run_patches)

    return {
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "patches_dir": str(patches_base),
        "total_vulns": len(vulns),
        "revalidation_scan_id": reval_scan_id,
        "dry_run_patches": dry_run_patches,
    }


@app.command("remediate-all")
def remediate_all(
    scan_id: str = typer.Argument(..., help="Scan ID to remediate"),
    use_backend: bool = typer.Option(False, "--use-backend", help="Use backend AI engine instead of local Claude Agent SDK"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Comma-separated severities to include, e.g. CRITICAL,HIGH"),
    multi_turn: bool = typer.Option(False, "--multi-turn", help="Use iterative multi-turn agent loop"),
    max_iterations: int = typer.Option(6, "--max-iterations", help="Max iterations per vulnerability (multi-turn only)"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Generate patches and run batch revalidation for a completed scan. Default: local Claude."""
    client = SecurityPipelineClient(api_url=api_url)

    history = load_history()
    entry = next((e for e in history if e["scan_id"] == scan_id), None)
    if not entry:
        rprint(f"[red]Scan {scan_id} not found in history.[/red]")
        raise typer.Exit(1)

    try:
        _run_remediate_all_loop(
            client=client,
            scan_id=scan_id,
            target=Path(entry["path"]),
            severity=severity,
            use_local_claude=not use_backend,
            use_multi_turn=multi_turn,
            max_iterations=max_iterations,
            quiet=False,
            scanners=entry.get("scanners"),
        )
    except RuntimeError as e:
        rprint(f"[red]{e}[/red]")
        raise typer.Exit(1)


@app.command()
def run(
    path: str = typer.Argument(".", help="Directory to scan and remediate in one shot"),
    scanners: str = typer.Option("semgrep,checkov,trivy", "--scanners", "-s"),
    author: str = typer.Option("", "--author", "-a", help="Your name for audit trail"),
    project: str = typer.Option("", "--project", "-p", help="Project name (defaults to dir name)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Comma-separated severities: CRITICAL,HIGH"),
    use_backend: bool = typer.Option(False, "--use-backend", help="Use backend AI engine instead of local Claude Agent SDK"),
    api_url: Optional[str] = typer.Option(None, "--api-url"),
):
    """Scan + remediate in one shot (2 total scans). Default: local Claude for patch generation."""
    target = Path(path).resolve()
    if not target.is_dir():
        rprint(f"[red]Error:[/red] '{path}' is not a directory.")
        raise typer.Exit(1)

    project_name = project or target.name
    author_name = author or os.environ.get("USER", "unknown")
    scanner_list = [s.strip() for s in scanners.split(",") if s.strip()]

    console.print(f"\n[bold]Running full pipeline:[/bold] {target}")

    try:
        scan_id, scan_dir = _submit_scan_job(
            target=target,
            project_name=project_name,
            author_name=author_name,
            scanner_list=scanner_list,
            api_url=api_url,
        )
    except Exception as e:
        rprint(f"[red]Upload failed:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"\n[green]✓[/green] Scan queued. [dim]{scan_id}[/dim]")

    client = SecurityPipelineClient(api_url=api_url)

    try:
        _run_remediate_all_loop(
            client=client,
            scan_id=scan_id,
            target=target,
            severity=severity,
            use_local_claude=not use_backend,
            quiet=False,
            scanners=scanner_list,
        )
    except RuntimeError as e:
        rprint(f"[red]{e}[/red]")
        raise typer.Exit(1)


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
            if patch.get("is_false_positive"):
                console.print(f"  [yellow]↩[/yellow] {vid[:8]}: false positive — no changes to apply")
            else:
                rprint(f"  [yellow]{vid[:8]}: no code_changes in patch.[/yellow]")
            skipped += 1
            continue

        console.print(f"\n[cyan]{vid[:8]}[/cyan]  revalidation={reval_status}  confidence={patch.get('confidence_score', 0):.2f}")

        for change in changes:
            console.print(f"  [dim]{change['file_path']}  lines {change['start_line']}–{change['end_line']}[/dim]")
            for l in change.get("original_code", "").splitlines():
                console.print(f"  [red]- {l}[/red]")
            for l in change.get("new_code", "").splitlines():
                console.print(f"  [green]+ {l}[/green]")

        if not dry_run:
            written = _apply_patch_changes(target, changes)
            if written:
                session_file = _security_scan_dir(target) / "sessions" / f"{scan_id}.json"
                if session_file.exists():
                    session = json.loads(session_file.read_text())
                    session.setdefault("remediation_status", {})[vid] = "applied"
                    session_file.write_text(json.dumps(session, indent=2))
                applied += 1
            else:
                rprint(f"  [red]No files found on disk for {vid[:8]} — skipped.[/red]")
                skipped += 1
        else:
            console.print(f"  [dim](dry-run — not written)[/dim]")

    if dry_run:
        console.print(f"\n[dim]Dry run complete. {len(patch_dirs)} patches previewed.[/dim]")
    else:
        console.print(f"\n[bold]Done.[/bold]  {applied} applied  {skipped} skipped\n")
