"""Scanner parsers for semgrep, checkov, and trivy output.

Each parse_* function is a pure function that takes a parsed JSON dict
and a file_path, returning a list of vulnerability dicts in the canonical
format:

    {
        "scanner": str,
        "rule_id": str,
        "severity": str,
        "message": str,
        "file_path": str,
        "start_line": int,
        "end_line": int,
        "metadata": {"resource": str},
    }

The run_* functions write code to a temp file/dir, invoke the CLI tool,
and return the parsed results.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

# Autoresearch venv directory (contains the semgrep 1.x binary).
_AUTORESEARCH_VENV_BIN = Path(__file__).parent.parent / ".venv" / "bin"
# Directory containing rules.yaml for local semgrep rules (avoids --config auto network fetch).
_SEMGREP_RULES_DIR = Path(__file__).parent.parent / "benchmark" / "semgrep"

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
    "INFO": "LOW",
}


# ---------------------------------------------------------------------------
# Pure parser functions
# ---------------------------------------------------------------------------


def parse_semgrep_output(data: dict[str, Any], file_path: str) -> list[dict[str, Any]]:
    """Parse semgrep --json output into canonical vulnerability dicts.

    Args:
        data: Parsed JSON dict from semgrep ``--json`` output.
        file_path: Only return results whose ``path`` matches this value.

    Returns:
        List of vulnerability dicts.
    """
    vulns: list[dict[str, Any]] = []
    for result in data.get("results", []):
        if result.get("path") != file_path:
            continue
        extra = result.get("extra", {})
        raw_severity = extra.get("severity", "")
        severity = _SEMGREP_SEVERITY_MAP.get(raw_severity, raw_severity)
        vuln: dict[str, Any] = {
            "scanner": "semgrep",
            "rule_id": result.get("check_id", ""),
            "severity": severity,
            "message": extra.get("message", ""),
            "file_path": file_path,
            "start_line": result.get("start", {}).get("line", 0),
            "end_line": result.get("end", {}).get("line", 0),
            "metadata": {"resource": ""},
        }
        vulns.append(vuln)
    return vulns


def parse_checkov_output(data: dict[str, Any], file_path: str) -> list[dict[str, Any]]:
    """Parse checkov --output json output into canonical vulnerability dicts.

    Args:
        data: Parsed JSON dict from checkov ``--output json`` output.
        file_path: Only return results whose ``file_path`` matches this value.

    Returns:
        List of vulnerability dicts. Severity is always ``"MEDIUM"`` because
        checkov's basic JSON output does not include severity levels.
    """
    vulns: list[dict[str, Any]] = []
    results = data.get("results", {})
    failed_checks = results.get("failed_checks", [])
    for check in failed_checks:
        if check.get("file_path") != file_path:
            continue
        check_info = check.get("check", {})
        message = check_info.get("name", "") if check_info else ""
        if not message:
            message = check.get("check_id", "")
        line_range = check.get("file_line_range", [0, 0])
        start_line = line_range[0] if len(line_range) > 0 else 0
        end_line = line_range[1] if len(line_range) > 1 else 0
        vuln: dict[str, Any] = {
            "scanner": "checkov",
            "rule_id": check.get("check_id", ""),
            "severity": "MEDIUM",
            "message": message,
            "file_path": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "metadata": {"resource": check.get("resource", "")},
        }
        vulns.append(vuln)
    return vulns


def parse_trivy_output(data: dict[str, Any], file_path: str) -> list[dict[str, Any]]:
    """Parse trivy fs --format json output into canonical vulnerability dicts.

    Args:
        data: Parsed JSON dict from trivy ``fs --format json`` output.
        file_path: Only return results whose ``Target`` matches this value.

    Returns:
        List of vulnerability dicts. ``start_line`` and ``end_line`` are
        always 1 because trivy does not report line numbers for package files.
    """
    vulns: list[dict[str, Any]] = []
    for result in data.get("Results", []):
        if result.get("Target") != file_path:
            continue
        vulnerabilities = result.get("Vulnerabilities") or []
        for v in vulnerabilities:
            message = v.get("Title") or v.get("Description") or ""
            vuln: dict[str, Any] = {
                "scanner": "trivy",
                "rule_id": v.get("VulnerabilityID", ""),
                "severity": v.get("Severity", ""),
                "message": message,
                "file_path": file_path,
                "start_line": 1,
                "end_line": 1,
                "metadata": {"resource": v.get("PkgName", "")},
            }
            vulns.append(vuln)
    return vulns


# ---------------------------------------------------------------------------
# Runner functions
# ---------------------------------------------------------------------------


def run_semgrep(code: str, file_path: str = "code.py") -> list[dict[str, Any]]:
    """Write *code* to a temp file, run semgrep, return parsed results.

    Args:
        code: Source code to scan.
        file_path: Filename hint (used as the temp file name suffix).

    Returns:
        List of vulnerability dicts, or ``[]`` on timeout / JSON errors /
        tool not found.
    """
    suffix = Path(file_path).suffix or ".py"
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False) as tmp:
            tmp.write(code)
            tmp_path = tmp.name
    except OSError:
        return []
    try:
        semgrep_bin = str(_AUTORESEARCH_VENV_BIN / "semgrep")
        proc = subprocess.run(
            [semgrep_bin, "--config", "rules.yaml", tmp_path, "--json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(_SEMGREP_RULES_DIR),
        )
        data = json.loads(proc.stdout)
        # Remap the temp path back to the original file_path for callers.
        for result in data.get("results", []):
            result["path"] = file_path if result.get("path") == tmp_path else result.get("path")
        return parse_semgrep_output(data, file_path)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def run_checkov(code: str, file_path: str = "main.tf") -> list[dict[str, Any]]:
    """Write *code* to a temp file, run checkov, return parsed results.

    Args:
        code: Source code / IaC config to scan.
        file_path: Filename hint (used as the temp file name suffix).

    Returns:
        List of vulnerability dicts, or ``[]`` on timeout / JSON errors /
        tool not found.
    """
    suffix = Path(file_path).suffix or ".tf"
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False) as tmp:
            tmp.write(code)
            tmp_path = tmp.name
    except OSError:
        return []
    try:
        proc = subprocess.run(
            ["checkov", "-f", tmp_path, "--output", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        data = json.loads(proc.stdout)
        # Checkov strips the directory and emits "/<basename>" in file_path.
        checkov_path = "/" + Path(tmp_path).name
        results = data.get("results", {})
        for check in results.get("failed_checks", []):
            if check.get("file_path") == checkov_path:
                check["file_path"] = file_path
        return parse_checkov_output(data, file_path)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def parse_codeql_sarif(data: dict[str, Any], file_path: str) -> list[dict[str, Any]]:
    """Parse CodeQL SARIF output into canonical vulnerability dicts.

    Args:
        data: Parsed SARIF JSON dict from ``codeql database analyze --format=sarif-latest``.
        file_path: Only return results whose URI ends with this value.

    Returns:
        List of vulnerability dicts.
    """
    _CODEQL_SEVERITY_MAP: dict[str, str] = {
        "error": "HIGH",
        "warning": "MEDIUM",
        "note": "LOW",
        "recommendation": "LOW",
    }
    vulns: list[dict[str, Any]] = []
    for run in data.get("runs", []):
        # Build rule metadata index for severity lookup.
        rule_meta: dict[str, dict] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rule_meta[rule.get("id", "")] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            locations = result.get("locations", [])
            if not locations:
                continue
            phys = locations[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            if not (uri == file_path or uri.endswith("/" + file_path) or uri.endswith(file_path)):
                continue
            region = phys.get("region", {})
            start_line = region.get("startLine", 1)
            end_line = region.get("endLine", start_line)

            # Determine severity from rule properties or result level.
            meta = rule_meta.get(rule_id, {})
            props = meta.get("properties", {})
            raw_sev = (
                props.get("severity")
                or props.get("problem.severity")
                or result.get("level", "warning")
            ).lower()
            severity = _CODEQL_SEVERITY_MAP.get(raw_sev, "MEDIUM")

            message = result.get("message", {}).get("text", "")
            vuln: dict[str, Any] = {
                "scanner": "codeql",
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "metadata": {"resource": ""},
            }
            vulns.append(vuln)
    return vulns


def run_codeql(code: str, file_path: str = "code.py") -> list[dict[str, Any]]:
    """Write *code* to a temp dir, create a CodeQL database, analyze, return results.

    Requires the ``codeql`` CLI to be installed and on PATH, and the
    ``codeql/python-queries`` pack to be available (downloaded via
    ``codeql pack download codeql/python-queries``).

    Args:
        code: Python source code to analyze.
        file_path: Filename hint used as the source file name inside the temp dir.

    Returns:
        List of vulnerability dicts, or ``[]`` if CodeQL is not installed,
        database creation fails, or the analysis times out.
    """
    import shutil

    if shutil.which("codeql") is None:
        return []

    suffix = Path(file_path).suffix or ".py"
    language = "python" if suffix == ".py" else "javascript"

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            src_dir = Path(tmp_dir) / "src"
            src_dir.mkdir()
            src_file = src_dir / Path(file_path).name
            src_file.write_text(code)
            db_dir = Path(tmp_dir) / "db"
            sarif_out = Path(tmp_dir) / "results.sarif"

            # Create database.
            create_proc = subprocess.run(
                [
                    "codeql", "database", "create",
                    str(db_dir),
                    f"--language={language}",
                    f"--source-root={src_dir}",
                    "--overwrite",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if create_proc.returncode != 0:
                return []

            # Analyze with standard security queries.
            analyze_proc = subprocess.run(
                [
                    "codeql", "database", "analyze",
                    str(db_dir),
                    f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls",
                    "--format=sarif-latest",
                    f"--output={sarif_out}",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if analyze_proc.returncode != 0 or not sarif_out.exists():
                return []

            data = json.loads(sarif_out.read_text())
            return parse_codeql_sarif(data, file_path)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []


def run_trivy(code: str, file_path: str = "requirements.txt") -> list[dict[str, Any]]:
    """Write *code* to a temp dir, run trivy fs, return parsed results.

    Args:
        code: Contents of the dependency/manifest file to scan.
        file_path: Filename used inside the temp dir (e.g. ``requirements.txt``).

    Returns:
        List of vulnerability dicts, or ``[]`` on timeout / JSON errors /
        tool not found.
    """
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_file = Path(tmp_dir) / Path(file_path).name
            target_file.write_text(code)
            try:
                proc = subprocess.run(
                    ["trivy", "fs", "--format", "json", "--quiet", tmp_dir],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                data = json.loads(proc.stdout)
                # Trivy reports Target as the basename; remap to original file_path.
                results = parse_trivy_output(data, target_file.name)
                for r in results:
                    r["file_path"] = file_path
                return results
            except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
                return []
    except OSError:
        return []
