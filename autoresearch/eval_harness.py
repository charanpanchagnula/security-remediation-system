"""
Evaluation harness for the security remediation benchmark.

Public interface:
    run_full_harness(benchmark_dir, remediator) -> float

Prints per-case progress lines and a final `COMPOSITE_SCORE: <float>` line.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make LocalClaudeRemediator importable from the sibling CLI package.
_CLI_SRC = Path(__file__).parent.parent / "cli" / "src"
if str(_CLI_SRC) not in sys.path:
    sys.path.insert(0, str(_CLI_SRC))

import json

from autoresearch.patch_applier import apply_patch, count_changed_lines
from autoresearch.scanner_parsers import run_checkov, run_semgrep, run_trivy


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def load_benchmark_cases(benchmark_dir: Path) -> list[dict]:
    """Load all JSON case files from benchmark_dir/{semgrep,checkov,trivy}/*.json."""
    cases: list[dict] = []
    for scanner_name in ("semgrep", "checkov", "trivy"):
        scanner_dir = benchmark_dir / scanner_name
        if not scanner_dir.is_dir():
            continue
        for json_file in sorted(scanner_dir.glob("*.json")):
            try:
                cases.append(json.loads(json_file.read_text()))
            except (json.JSONDecodeError, OSError) as exc:
                print(f"[warn] Could not load {json_file}: {exc}")
    return cases


def find_matching_vuln(vulns: list[dict], expected_rule_id: str) -> dict | None:
    """Return the first vuln whose rule_id matches expected_rule_id, or None."""
    for v in vulns:
        if v.get("rule_id") == expected_rule_id:
            return v
    return None


def compute_score(
    fix_success: float,
    no_regression: float,
    patch_minimality: float,
) -> float:
    """Weighted composite: 0.6*fix + 0.2*no_regression + 0.2*minimality."""
    return 0.6 * fix_success + 0.2 * no_regression + 0.2 * patch_minimality


# ---------------------------------------------------------------------------
# run_case
# ---------------------------------------------------------------------------


def run_case(
    case: dict,
    remediator,
    scanner_funcs: dict,
) -> dict:
    """
    Run a single benchmark case.

    Parameters
    ----------
    case:
        Benchmark case dict (loaded from JSON).
    remediator:
        Object with a ``remediate(vuln_dict) -> patch_dict`` method.
    scanner_funcs:
        Mapping from scanner name to callable, e.g.
        ``{"semgrep": run_semgrep, "checkov": run_checkov, "trivy": run_trivy}``.

    Returns
    -------
    dict with keys ``id``, ``status``, ``score``.
    Statuses: ok | skip | error | patch_error | false_positive
    """
    case_id = case.get("id", "unknown")
    scanner_name = case.get("scanner", "semgrep")
    expected_rule_id = case.get("expected_rule_id", "")
    vulnerable_code = case.get("vulnerable_code", "")
    file_path = case.get("file_path", "code.py")

    run_scanner = scanner_funcs.get(scanner_name)
    if run_scanner is None:
        return {"id": case_id, "status": "skip", "score": None}

    # ------------------------------------------------------------------
    # Pre-scan
    # ------------------------------------------------------------------
    pre_vulns = run_scanner(vulnerable_code, file_path)
    matched_vuln = find_matching_vuln(pre_vulns, expected_rule_id)

    if matched_vuln is None:
        # Broken case — expected rule not detected; skip without scoring.
        return {"id": case_id, "status": "skip", "score": None}

    # ------------------------------------------------------------------
    # Remediate
    # ------------------------------------------------------------------
    try:
        patch = remediator.remediate(matched_vuln)
    except Exception:
        return {"id": case_id, "status": "error", "score": 0.0}

    # Handle false positives reported by the remediator.
    if patch.get("is_false_positive"):
        return {"id": case_id, "status": "false_positive", "score": 0.0}

    # ------------------------------------------------------------------
    # Apply patch
    # ------------------------------------------------------------------
    code_changes = patch.get("code_changes", [])
    patched_code = vulnerable_code
    try:
        for change in code_changes:
            patched_code = apply_patch(patched_code, change)
    except (ValueError, KeyError) as exc:
        return {"id": case_id, "status": "patch_error", "score": 0.0}

    # ------------------------------------------------------------------
    # Post-scan
    # ------------------------------------------------------------------
    post_vulns = run_scanner(patched_code, file_path)

    pre_rule_ids = {v["rule_id"] for v in pre_vulns}
    post_rule_ids = {v["rule_id"] for v in post_vulns}

    fix_success = 0.0 if expected_rule_id in post_rule_ids else 1.0
    new_rule_ids = post_rule_ids - pre_rule_ids
    no_regression = 0.0 if new_rule_ids else 1.0

    original_lines = len(vulnerable_code.splitlines())
    lines_changed = count_changed_lines(vulnerable_code, patched_code)
    if original_lines > 0:
        patch_minimality = 1.0 - min(lines_changed, original_lines) / original_lines
    else:
        patch_minimality = 1.0

    score = compute_score(fix_success, no_regression, patch_minimality)
    return {"id": case_id, "status": "ok", "score": score}


# ---------------------------------------------------------------------------
# run_full_harness
# ---------------------------------------------------------------------------


def run_full_harness(
    benchmark_dir: Path | None = None,
    remediator=None,
) -> float:
    """
    Load all benchmark cases, run each, aggregate scores, and print results.

    Final stdout line is always: ``COMPOSITE_SCORE: <float>``

    Returns the composite score (0.0 if no scoreable cases).
    """
    if benchmark_dir is None:
        benchmark_dir = Path(__file__).parent / "benchmark"

    if remediator is None:
        from security_pipeline.agent import LocalClaudeRemediator  # noqa: PLC0415

        remediator = LocalClaudeRemediator()

    scanner_funcs = {
        "semgrep": run_semgrep,
        "checkov": run_checkov,
        "trivy": run_trivy,
    }

    cases = load_benchmark_cases(benchmark_dir)
    scores: list[float] = []

    for case in cases:
        result = run_case(case, remediator, scanner_funcs)
        score_display = f"{result['score']:.4f}" if result["score"] is not None else "None"
        print(f"[{result['id']}] status={result['status']} score={score_display}")
        if result["status"] not in ("skip",) and result["score"] is not None:
            scores.append(result["score"])

    composite = sum(scores) / len(scores) if scores else 0.0
    print(f"COMPOSITE_SCORE: {composite:.4f}")
    return composite


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_full_harness()
