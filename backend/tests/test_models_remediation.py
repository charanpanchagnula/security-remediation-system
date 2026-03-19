"""
Tests for remediation data models.

Covers:
- New `description` field on CodeChange (defaults to "")
- New `evaluation_concerns` field on RemediationResponse (defaults to [])
- Backward compatibility: old stored JSON without these fields still parses
- Schema validation rejects invalid values
"""
import pytest
from pydantic import ValidationError
from remediation_api.models.remediation import CodeChange, RemediationResponse, EvaluationResult


# ---- CodeChange ----

def test_code_change_description_defaults_to_empty_string():
    change = CodeChange(
        file_path="app.py",
        start_line=10,
        end_line=12,
        original_code="old",
        new_code="new",
    )
    assert change.description == ""


def test_code_change_description_set_explicitly():
    change = CodeChange(
        file_path="app.py",
        start_line=10,
        end_line=12,
        original_code="old",
        new_code="new",
        description="Replaces format string with parameterized query",
    )
    assert change.description == "Replaces format string with parameterized query"


def test_code_change_requires_file_path():
    with pytest.raises(ValidationError):
        CodeChange(start_line=1, end_line=1, original_code="x", new_code="y")


def test_code_change_requires_start_and_end_lines():
    with pytest.raises(ValidationError):
        CodeChange(file_path="f.py", original_code="x", new_code="y")


# ---- RemediationResponse ----

def _base_remediation(**overrides):
    defaults = dict(
        vulnerability_id="vuln-1",
        severity="HIGH",
        summary="Fix SQL injection",
        explanation="Use parameterized queries",
        code_changes=[],
        security_implications=[],
    )
    defaults.update(overrides)
    return RemediationResponse(**defaults)


def test_remediation_evaluation_concerns_defaults_to_empty_list():
    rem = _base_remediation()
    assert rem.evaluation_concerns == []


def test_remediation_evaluation_concerns_set():
    rem = _base_remediation(evaluation_concerns=["May break callers expecting string IDs"])
    assert rem.evaluation_concerns == ["May break callers expecting string IDs"]


def test_remediation_is_false_positive_defaults_false():
    rem = _base_remediation()
    assert rem.is_false_positive is False


def test_remediation_confidence_score_defaults_to_zero():
    rem = _base_remediation()
    assert rem.confidence_score == 0.0


def test_remediation_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        _base_remediation(severity="EXTREME")


def test_remediation_valid_severities():
    for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        rem = _base_remediation(severity=sev)
        assert rem.severity == sev


def test_remediation_backward_compat_missing_description_in_code_change():
    """
    Old JSON stored before the description field was added must still parse.
    Pydantic fills in the default empty string.
    """
    data = {
        "vulnerability_id": "vuln-old",
        "severity": "MEDIUM",
        "summary": "Old fix",
        "explanation": "Old explanation",
        "code_changes": [
            {
                "file_path": "main.py",
                "start_line": 5,
                "end_line": 7,
                "original_code": "bad_code",
                "new_code": "good_code",
                # No 'description' key — simulates pre-migration stored data
            }
        ],
        "security_implications": [],
        # No 'evaluation_concerns' key
    }
    rem = RemediationResponse(**data)
    assert rem.code_changes[0].description == ""
    assert rem.evaluation_concerns == []


def test_remediation_with_full_code_change():
    change = CodeChange(
        file_path="db.py",
        start_line=20,
        end_line=22,
        original_code="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        new_code="cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
        description="Replace f-string interpolation with parameterized query",
    )
    rem = _base_remediation(code_changes=[change])
    assert rem.code_changes[0].description != ""


# ---- EvaluationResult ----

def test_evaluation_result_valid():
    result = EvaluationResult(
        completeness_score=0.9,
        correctness_score=0.85,
        security_score=1.0,
        confidence_score=0.9,
        is_false_positive=False,
        is_approved=True,
        feedback=[],
    )
    assert result.is_approved is True
    assert result.confidence_score == 0.9


def test_evaluation_result_score_above_1_rejected():
    with pytest.raises(ValidationError):
        EvaluationResult(
            completeness_score=1.5,
            correctness_score=0.8,
            security_score=0.8,
            confidence_score=0.8,
            is_false_positive=False,
            is_approved=True,
            feedback=[],
        )


def test_evaluation_result_score_below_0_rejected():
    with pytest.raises(ValidationError):
        EvaluationResult(
            completeness_score=-0.1,
            correctness_score=0.8,
            security_score=0.8,
            confidence_score=0.8,
            is_false_positive=False,
            is_approved=False,
            feedback=[],
        )


def test_evaluation_result_feedback_list():
    result = EvaluationResult(
        completeness_score=0.5,
        correctness_score=0.5,
        security_score=0.5,
        confidence_score=0.5,
        is_false_positive=False,
        is_approved=False,
        feedback=["Fix does not address root cause", "Missing null check"],
    )
    assert len(result.feedback) == 2
