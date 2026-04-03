#!/usr/bin/env python3
"""
End-to-end local test harness for the autonomous remediation agent.

Usage:
    python scripts/test_autonomous_local.py \\
        --repo-path /path/to/Vulnerable-Flask-App \\
        --project-name vuln-flask \\
        --backend http://localhost:8000 \\
        --scanners semgrep \\
        --output conversation_log.txt

No backend package imports — stdlib + requests only.
"""

import argparse
import io
import json
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# Archive helpers
# ---------------------------------------------------------------------------

def create_archive(repo_path: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(repo_path, arcname=repo_path.name)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def upload_scan(backend: str, archive: bytes, project_name: str, author: str, scanners: str) -> dict:
    resp = requests.post(
        f"{backend}/api/v1/scan/upload",
        files={"file": ("archive.tar.gz", archive, "application/gzip")},
        data={"project_name": project_name, "author": author, "scanners": scanners},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def poll_scan(backend: str, scan_id: str, timeout_s: int = 300, interval_s: int = 5) -> dict:
    url = f"{backend}/api/v1/scans/{scan_id}"
    deadline = time.monotonic() + timeout_s
    print(f"  Polling scan {scan_id} (timeout {timeout_s}s) ...", flush=True)
    while time.monotonic() < deadline:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("status", "unknown")
        n_vulns = len(data.get("vulnerabilities", []))
        print(f"  [{_now()}] status={status} vulns={n_vulns}", flush=True)
        if status == "completed":
            return data
        if status == "failed":
            raise RuntimeError(f"Scan failed: {data.get('error', 'unknown error')}")
        time.sleep(interval_s)
    raise TimeoutError(f"Scan did not complete within {timeout_s}s")


def trigger_remediate_vuln(backend: str, scan_id: str, vuln_id: str) -> dict:
    resp = requests.post(f"{backend}/api/v1/scan/{scan_id}/remediate/{vuln_id}", timeout=30)
    resp.raise_for_status()
    return resp.json()


def trigger_remediate_all(backend: str, scan_id: str) -> dict:
    resp = requests.post(f"{backend}/api/v1/scan/{scan_id}/remediate-all", timeout=30)
    resp.raise_for_status()
    return resp.json()


def poll_remediations(backend: str, scan_id: str, n_vulns: int, timeout_s: int = 600, interval_s: int = 10) -> dict:
    url = f"{backend}/api/v1/scans/{scan_id}"
    deadline = time.monotonic() + timeout_s
    print(f"  Polling remediations for {n_vulns} vulns (timeout {timeout_s}s) ...", flush=True)
    while time.monotonic() < deadline:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        n_done = len(data.get("remediations", []))
        print(f"  [{_now()}] remediations={n_done}/{n_vulns}", flush=True)
        if n_done >= n_vulns:
            return data
        time.sleep(interval_s)
    # Timeout — return partial results (still useful for the log)
    return requests.get(url, timeout=15).json()


# ---------------------------------------------------------------------------
# Log formatting
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _trunc(s: str, n: int = 600) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + f" ...[+{len(s)-n} chars]"


def _fmt_llm_messages(messages: list) -> list[str]:
    """Format the full LLM conversation (system/user/assistant turns)."""
    lines = ["  ── LLM Conversation ──────────────────────────────────────────────"]
    for i, msg in enumerate(messages, 1):
        role = msg.get("role", "?").upper()
        content = msg.get("content") or ""
        reasoning = msg.get("reasoning") or ""
        tool_calls = msg.get("tool_calls", [])

        lines.append(f"  [{i}] {role}")

        if reasoning:
            lines.append(f"      <thinking>")
            for line in _trunc(reasoning, 1500).splitlines():
                lines.append(f"        {line}")
            lines.append(f"      </thinking>")

        if content:
            for line in content.splitlines():
                lines.append(f"      {line}")

        if tool_calls:
            for tc in tool_calls:
                # tc is either a ToolExecution dict or an OpenAI-style tool call dict
                if isinstance(tc, dict):
                    name = tc.get("tool", tc.get("tool_name", tc.get("name", "?")))
                    inp = tc.get("input", tc.get("tool_args", tc.get("arguments", {})))
                    out = tc.get("output", tc.get("result", ""))
                    lines.append(f"      [call] {name}(")
                    lines.append(f"               in:  {_trunc(json.dumps(inp, ensure_ascii=False), 300)}")
                    if out:
                        lines.append(f"               out: {_trunc(str(out), 300)}")
                    lines.append(f"             )")

    lines.append("  ── End Conversation ───────────────────────────────────────────")
    return lines


def _fmt_iteration(it: dict, idx: int) -> list[str]:
    lines = [f"  --- Iteration {idx} ---"]
    for tc in it.get("tool_calls", []):
        tool = tc.get("tool", "?")
        inp = json.dumps(tc.get("input", {}), ensure_ascii=False)
        out = _trunc(tc.get("output", ""))
        lines.append(f"    [tool] {tool}")
        lines.append(f"      in:  {_trunc(inp, 300)}")
        lines.append(f"      out: {out}")
    val = it.get("validation_results")
    if val:
        lines.append(f"    validation: {json.dumps(val, ensure_ascii=False)}")
    return lines


def write_conversation_log(output_path: Path, scan_data: dict, final_data: dict, target_vuln_ids: set = None) -> None:
    vulns = scan_data.get("vulnerabilities", [])
    if target_vuln_ids:
        vulns = [v for v in vulns if v.get("id") in target_vuln_ids]
    remediations = {r["vulnerability_id"]: r for r in final_data.get("remediations", [])}

    lines = [
        "=" * 72,
        "AUTONOMOUS REMEDIATION CONVERSATION LOG",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Scan ID:   {scan_data.get('scan_id', 'unknown')}",
        f"Project:   {scan_data.get('project_name', 'unknown')}",
        f"Vulns (scanned): {scan_data.get('summary', {}).get('total_vulnerabilities', len(vulns))}  "
        f"Vulns (logged): {len(vulns)}  Remediated: {len(remediations)}",
        "=" * 72,
        "",
    ]

    for i, vuln in enumerate(vulns, 1):
        vid = vuln.get("id", f"vuln-{i}")
        rule = vuln.get("rule_id", vuln.get("check_id", "unknown"))
        severity = vuln.get("severity", "unknown")
        file_path = vuln.get("file_path", vuln.get("path", "unknown"))
        start_line = vuln.get("start_line", vuln.get("line", "?"))
        message = vuln.get("message", vuln.get("description", ""))

        lines += [
            "─" * 72,
            f"[{i}/{len(vulns)}] {rule}  severity={severity}",
            f"  File:    {file_path}:{start_line}",
            f"  Message: {message}",
            f"  ID:      {vid}",
        ]

        rem = remediations.get(vid)
        if rem is None:
            lines.append("  Status: NOT REMEDIATED")
            lines.append("")
            continue

        lines.append(f"  Status:     {rem.get('status', '?')}")
        lines.append(f"  Confidence: {rem.get('confidence_score', '?')}")
        lines.append(f"  False pos:  {rem.get('is_false_positive', '?')}")
        lines.append(f"  Summary:    {rem.get('summary', '')}")

        # Full LLM conversation
        llm_messages = rem.get("llm_messages", [])
        if llm_messages:
            lines.extend(_fmt_llm_messages(llm_messages))
        else:
            lines.append("  [no llm_messages — agent may have failed before producing output]")

        # Per-iteration tool call log
        iteration_log = rem.get("iteration_log", [])
        if iteration_log:
            lines.append(f"  Tool call iterations: {len(iteration_log)}")
            for idx, it in enumerate(iteration_log, 1):
                lines.extend(_fmt_iteration(it, idx))

        # Code changes
        for change in rem.get("code_changes", []):
            lines += [
                f"  Code change: {change.get('file_path')} "
                f"L{change.get('start_line')}–{change.get('end_line')}",
                f"    - {_trunc(change.get('original_code',''), 200)}",
                f"    + {_trunc(change.get('new_code',''), 200)}",
            ]

        if rem.get("error"):
            lines.append(f"  Error: {rem['error']}")

        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nConversation log written to: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="E2E test harness for the autonomous remediation agent")
    p.add_argument("--repo-path", required=True, help="Local path to the repo to scan")
    p.add_argument("--project-name", required=True, help="Project name for the scan")
    p.add_argument("--backend", default="http://localhost:8000", help="Backend base URL")
    p.add_argument("--scanners", default="semgrep", help="Comma-separated scanner list")
    p.add_argument("--output", default="conversation_log.txt", help="Output file for the conversation log")
    p.add_argument("--max-vulns", type=int, default=0, help="Only remediate the first N vulnerabilities (0 = all)")
    p.add_argument("--scan-timeout", type=int, default=300, help="Seconds to wait for scan completion")
    p.add_argument("--remediation-timeout", type=int, default=600, help="Seconds to wait for all remediations")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    repo_path = Path(args.repo_path).resolve()
    output_path = Path(args.output)

    if not repo_path.exists():
        print(f"ERROR: --repo-path does not exist: {repo_path}", file=sys.stderr)
        return 1

    # 1. Archive
    print(f"[1/5] Creating tar.gz of {repo_path} ...", flush=True)
    archive = create_archive(repo_path)
    print(f"      Archive size: {len(archive):,} bytes", flush=True)

    # 2. Upload
    print(f"[2/5] Uploading to {args.backend} ...", flush=True)
    upload_result = upload_scan(
        backend=args.backend,
        archive=archive,
        project_name=args.project_name,
        author="test-harness",
        scanners=args.scanners,
    )
    scan_id = upload_result.get("scan_id")
    if not scan_id:
        print(f"ERROR: No scan_id in upload response: {upload_result}", file=sys.stderr)
        return 1
    print(f"      scan_id: {scan_id}", flush=True)

    # 3. Poll scan
    print(f"[3/5] Waiting for scan to complete ...", flush=True)
    scan_data = poll_scan(args.backend, scan_id, timeout_s=args.scan_timeout)
    n_vulns = len(scan_data.get("vulnerabilities", []))
    print(f"      Scan complete: {n_vulns} vulnerabilities found", flush=True)

    if n_vulns == 0:
        print("      No vulnerabilities found — writing empty log and exiting.")
        write_conversation_log(output_path, scan_data, scan_data)
        return 0

    # Fail fast: autonomous agent requires work_dir to be persisted
    work_dir = scan_data.get("work_dir")
    if not work_dir:
        print(
            "\nERROR: work_dir is not set in scan result.\n"
            "The backend is running old code without workspace persistence.\n"
            "Rebuild the Docker image:  docker compose build api && docker compose up -d api",
            file=sys.stderr,
        )
        return 1
    print(f"      work_dir: {work_dir}", flush=True)

    # Apply --max-vulns limit
    vulns = scan_data.get("vulnerabilities", [])
    target_vulns = vulns[:args.max_vulns] if args.max_vulns > 0 else vulns
    n_target = len(target_vulns)
    if n_target < n_vulns:
        print(f"      Limiting to first {n_target}/{n_vulns} vulnerabilities (--max-vulns {args.max_vulns})", flush=True)

    # 4. Trigger remediations
    if args.max_vulns > 0:
        print(f"[4/5] Triggering remediation for {n_target} vulns individually ...", flush=True)
        for vuln in target_vulns:
            r = trigger_remediate_vuln(args.backend, scan_id, vuln["id"])
            print(f"      queued {vuln['id'][:8]}... → {r.get('status')}", flush=True)
    else:
        print(f"[4/5] Triggering remediate-all ...", flush=True)
        rem_resp = trigger_remediate_all(args.backend, scan_id)
        print(f"      Response: {rem_resp}", flush=True)

    # 5. Poll remediations
    print(f"[5/5] Waiting for {n_target} remediations ...", flush=True)
    final_data = poll_remediations(args.backend, scan_id, n_target, timeout_s=args.remediation_timeout)
    n_done = len(final_data.get("remediations", []))
    print(f"      Remediations done: {n_done}/{n_target}", flush=True)

    write_conversation_log(output_path, scan_data, final_data, target_vuln_ids={v["id"] for v in target_vulns})
    return 0 if n_done >= n_target else 1


if __name__ == "__main__":
    sys.exit(main())
