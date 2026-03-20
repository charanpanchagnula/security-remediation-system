"""Unit tests for eval_harness.py — all scanner/remediator calls are mocked."""

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the autoresearch package root is importable.
sys.path.insert(0, str(Path(__file__).parent.parent))

from eval_harness import (
    compute_score,
    find_matching_vuln,
    load_benchmark_cases,
    run_case,
    run_full_harness,
)


# ---------------------------------------------------------------------------
# compute_score
# ---------------------------------------------------------------------------


def test_compute_score_weights():
    """0.6*fix + 0.2*no_regression + 0.2*minimality."""
    result = compute_score(fix_success=1.0, no_regression=1.0, patch_minimality=1.0)
    assert result == pytest.approx(1.0)

    result = compute_score(fix_success=1.0, no_regression=0.0, patch_minimality=0.0)
    assert result == pytest.approx(0.6)

    result = compute_score(fix_success=0.0, no_regression=1.0, patch_minimality=0.0)
    assert result == pytest.approx(0.2)

    result = compute_score(fix_success=0.0, no_regression=0.0, patch_minimality=1.0)
    assert result == pytest.approx(0.2)

    result = compute_score(fix_success=0.0, no_regression=0.0, patch_minimality=0.0)
    assert result == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# load_benchmark_cases
# ---------------------------------------------------------------------------


def test_load_benchmark_cases(tmp_path):
    """Loads all JSON files from {benchmark_dir}/{semgrep,checkov,trivy}/*.json."""
    semgrep_dir = tmp_path / "semgrep"
    semgrep_dir.mkdir()
    checkov_dir = tmp_path / "checkov"
    checkov_dir.mkdir()
    trivy_dir = tmp_path / "trivy"
    trivy_dir.mkdir()

    case1 = {"id": "case_001", "scanner": "semgrep", "expected_rule_id": "rule.a"}
    case2 = {"id": "case_002", "scanner": "checkov", "expected_rule_id": "CKV_001"}

    (semgrep_dir / "case_001.json").write_text(json.dumps(case1))
    (checkov_dir / "case_002.json").write_text(json.dumps(case2))

    cases = load_benchmark_cases(tmp_path)
    assert len(cases) == 2
    ids = {c["id"] for c in cases}
    assert ids == {"case_001", "case_002"}


# ---------------------------------------------------------------------------
# find_matching_vuln
# ---------------------------------------------------------------------------


def test_find_matching_vuln_found():
    vulns = [
        {"rule_id": "rule.a", "severity": "HIGH"},
        {"rule_id": "rule.b", "severity": "LOW"},
    ]
    result = find_matching_vuln(vulns, "rule.a")
    assert result is not None
    assert result["rule_id"] == "rule.a"


def test_find_matching_vuln_not_found():
    vulns = [
        {"rule_id": "rule.x", "severity": "HIGH"},
    ]
    result = find_matching_vuln(vulns, "rule.does.not.exist")
    assert result is None


def test_find_matching_vuln_empty_list():
    assert find_matching_vuln([], "rule.a") is None


# ---------------------------------------------------------------------------
# run_case — skip when pre-scan returns empty
# ---------------------------------------------------------------------------


def test_run_case_skip_when_prescan_empty():
    """When the scanner finds nothing, the case is marked skip (broken case)."""
    case = {
        "id": "sql_001",
        "scanner": "semgrep",
        "expected_rule_id": "python.lang.sql_injection",
        "vulnerable_code": "query = f'SELECT * FROM users WHERE id={user_id}'",
        "file_path": "app.py",
        "start_line": 1,
        "end_line": 1,
    }
    mock_scanner = MagicMock(return_value=[])
    scanner_funcs = {"semgrep": mock_scanner}
    remediator = MagicMock()

    result = run_case(case, remediator, scanner_funcs)

    assert result["id"] == "sql_001"
    assert result["status"] == "skip"
    assert result["score"] is None
    remediator.generate_patch.assert_not_called()


# ---------------------------------------------------------------------------
# run_case — ok path
# ---------------------------------------------------------------------------


def test_run_case_ok():
    """Full happy path: pre-scan finds vuln, remediator returns patch, post-scan clean."""
    vulnerable_code = "query = f'SELECT * FROM users WHERE id={user_id}'\n"
    patched_code = "query = 'SELECT * FROM users WHERE id=?'\n"

    case = {
        "id": "sql_001",
        "scanner": "semgrep",
        "expected_rule_id": "python.lang.sql_injection",
        "vulnerable_code": vulnerable_code,
        "file_path": "app.py",
        "start_line": 1,
        "end_line": 1,
    }

    pre_vuln = {
        "rule_id": "python.lang.sql_injection",
        "severity": "HIGH",
        "start_line": 1,
        "end_line": 1,
        "file_path": "app.py",
    }

    # Pre-scan returns the vuln; post-scan returns nothing (fix successful).
    mock_scanner = MagicMock(side_effect=[
        [pre_vuln],  # pre-scan
        [],           # post-scan
    ])
    scanner_funcs = {"semgrep": mock_scanner}

    mock_remediator = MagicMock()
    mock_remediator.generate_patch.return_value = {
        "is_false_positive": False,
        "code_changes": [
            {
                "start_line": 1,
                "end_line": 1,
                "new_code": "query = 'SELECT * FROM users WHERE id=?'",
            }
        ],
    }

    result = run_case(case, mock_remediator, scanner_funcs)

    assert result["id"] == "sql_001"
    assert result["status"] == "ok"
    assert result["score"] is not None
    assert 0.0 <= result["score"] <= 1.0
    # fix_success=1.0, no_regression=1.0 → at minimum 0.6+0.2 = 0.8
    assert result["score"] >= 0.8


def test_run_case_false_positive():
    """When remediator marks is_false_positive=True, status is false_positive."""
    case = {
        "id": "fp_001",
        "scanner": "semgrep",
        "expected_rule_id": "python.lang.some_rule",
        "vulnerable_code": "x = 1\n",
        "file_path": "app.py",
        "start_line": 1,
        "end_line": 1,
    }

    pre_vuln = {
        "rule_id": "python.lang.some_rule",
        "severity": "LOW",
        "start_line": 1,
        "end_line": 1,
        "file_path": "app.py",
    }

    mock_scanner = MagicMock(return_value=[pre_vuln])
    scanner_funcs = {"semgrep": mock_scanner}

    mock_remediator = MagicMock()
    mock_remediator.generate_patch.return_value = {
        "is_false_positive": True,
        "code_changes": [],
    }

    result = run_case(case, mock_remediator, scanner_funcs)

    assert result["id"] == "fp_001"
    assert result["status"] == "false_positive"
    assert result["score"] == 0.0


def test_run_case_error_on_remediator_exception():
    """When remediator.remediate raises, status=error, score=0.0."""
    case = {
        "id": "err_001",
        "scanner": "semgrep",
        "expected_rule_id": "python.lang.some_rule",
        "vulnerable_code": "x = 1\n",
        "file_path": "app.py",
        "start_line": 1,
        "end_line": 1,
    }

    pre_vuln = {
        "rule_id": "python.lang.some_rule",
        "severity": "LOW",
        "start_line": 1,
        "end_line": 1,
        "file_path": "app.py",
    }

    mock_scanner = MagicMock(return_value=[pre_vuln])
    scanner_funcs = {"semgrep": mock_scanner}

    mock_remediator = MagicMock()
    mock_remediator.generate_patch.side_effect = RuntimeError("AI unavailable")

    result = run_case(case, mock_remediator, scanner_funcs)

    assert result["id"] == "err_001"
    assert result["status"] == "error"
    assert result["score"] == 0.0


def test_run_case_patch_error():
    """When apply_patch raises ValueError, status=patch_error, score=0.0."""
    case = {
        "id": "pe_001",
        "scanner": "semgrep",
        "expected_rule_id": "python.lang.some_rule",
        "vulnerable_code": "x = 1\n",
        "file_path": "app.py",
        "start_line": 1,
        "end_line": 1,
    }

    pre_vuln = {
        "rule_id": "python.lang.some_rule",
        "severity": "LOW",
        "start_line": 1,
        "end_line": 1,
        "file_path": "app.py",
    }

    mock_scanner = MagicMock(return_value=[pre_vuln])
    scanner_funcs = {"semgrep": mock_scanner}

    mock_remediator = MagicMock()
    # Return a change that points to out-of-range lines so apply_patch raises.
    mock_remediator.generate_patch.return_value = {
        "is_false_positive": False,
        "code_changes": [
            {
                "start_line": 999,
                "end_line": 1000,
                "new_code": "x = 2",
            }
        ],
    }

    result = run_case(case, mock_remediator, scanner_funcs)

    assert result["id"] == "pe_001"
    assert result["status"] == "patch_error"
    assert result["score"] == 0.0


# ---------------------------------------------------------------------------
# run_full_harness — composite score printed and returned
# ---------------------------------------------------------------------------


def test_run_full_harness_prints_composite_score(tmp_path, capsys):
    """run_full_harness prints 'COMPOSITE_SCORE: <float>' and returns a float."""
    # Create one mock benchmark case under semgrep/
    semgrep_dir = tmp_path / "semgrep"
    semgrep_dir.mkdir()
    case = {
        "id": "full_001",
        "scanner": "semgrep",
        "expected_rule_id": "python.lang.test_rule",
        "vulnerable_code": "x = 1\n",
        "file_path": "app.py",
        "start_line": 1,
        "end_line": 1,
    }
    (semgrep_dir / "full_001.json").write_text(json.dumps(case))

    # Mock scanner that finds the vuln on pre-scan and nothing on post-scan.
    pre_vuln = {
        "rule_id": "python.lang.test_rule",
        "severity": "HIGH",
        "start_line": 1,
        "end_line": 1,
        "file_path": "app.py",
    }
    mock_scanner = MagicMock(side_effect=[
        [pre_vuln],  # pre-scan
        [],           # post-scan
    ])
    scanner_funcs = {"semgrep": mock_scanner}

    # Mock remediator that returns a clean patch.
    mock_remediator = MagicMock()
    mock_remediator.generate_patch.return_value = {
        "is_false_positive": False,
        "code_changes": [
            {
                "start_line": 1,
                "end_line": 1,
                "new_code": "x = 2",
            }
        ],
    }

    with patch("eval_harness.run_semgrep", mock_scanner), \
         patch("eval_harness.run_checkov", MagicMock(return_value=[])), \
         patch("eval_harness.run_trivy", MagicMock(return_value=[])):
        score = run_full_harness(
            benchmark_dir=tmp_path,
            remediator=mock_remediator,
        )

    # Verify return type.
    assert isinstance(score, float)

    # Verify final stdout line starts with COMPOSITE_SCORE:
    captured = capsys.readouterr()
    lines = [l for l in captured.out.splitlines() if l.strip()]
    assert lines[-1].startswith("COMPOSITE_SCORE:")
