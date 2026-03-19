"""
Tests for EvaluatorAgent.evaluate_fix.

Verifies prompt construction and correct return type.
No real LLM calls are made — Agent.run is mocked.
"""
import pytest
from unittest.mock import MagicMock, patch

from remediation_api.models.scan import Vulnerability
from remediation_api.models.remediation import RemediationResponse, EvaluationResult


def _vuln(**overrides):
    defaults = dict(
        id="v1",
        rule_id="python.sql-injection",
        message="SQL injection via user-controlled input",
        severity="HIGH",
        scanner="semgrep",
        file_path="app.py",
        start_line=5,
        end_line=7,
        code_snippet="execute(q % inp)",
        surrounding_context="def run(inp):\n    execute(q % inp)",
    )
    defaults.update(overrides)
    return Vulnerability(**defaults)


def _remediation(**overrides):
    defaults = dict(
        vulnerability_id="v1",
        severity="HIGH",
        summary="Use parameterized queries",
        explanation="Detailed explanation of the fix",
        code_changes=[],
        security_implications=["Minimal risk"],
    )
    defaults.update(overrides)
    return RemediationResponse(**defaults)


def _evaluation(**overrides):
    defaults = dict(
        completeness_score=0.9,
        correctness_score=0.9,
        security_score=0.9,
        confidence_score=0.9,
        is_false_positive=False,
        is_approved=True,
        feedback=[],
    )
    defaults.update(overrides)
    return EvaluationResult(**defaults)


@pytest.fixture
def evaluator_with_mock():
    with patch("remediation_api.agents.evaluator.get_provider"), \
         patch("remediation_api.agents.evaluator.Agent") as MockAgent:
        mock_run = MagicMock()
        mock_run.return_value.content = _evaluation()
        MockAgent.return_value.run = mock_run

        from remediation_api.agents.evaluator import EvaluatorAgent
        ev = EvaluatorAgent()
        yield ev, mock_run


def test_evaluate_fix_returns_evaluation_result(evaluator_with_mock):
    ev, _ = evaluator_with_mock
    result = ev.evaluate_fix(_vuln(), _remediation())
    assert isinstance(result, EvaluationResult)


def test_prompt_contains_vulnerability_message(evaluator_with_mock):
    ev, mock_run = evaluator_with_mock
    ev.evaluate_fix(_vuln(message="Path traversal via unchecked user input"), _remediation())
    prompt = mock_run.call_args[0][0]
    assert "Path traversal via unchecked user input" in prompt


def test_prompt_contains_rule_id(evaluator_with_mock):
    ev, mock_run = evaluator_with_mock
    ev.evaluate_fix(_vuln(rule_id="python.path-traversal"), _remediation())
    prompt = mock_run.call_args[0][0]
    assert "python.path-traversal" in prompt


def test_prompt_contains_proposed_summary(evaluator_with_mock):
    ev, mock_run = evaluator_with_mock
    ev.evaluate_fix(_vuln(), _remediation(summary="Sanitize file path before use"))
    prompt = mock_run.call_args[0][0]
    assert "Sanitize file path before use" in prompt


def test_prompt_contains_scanner_name(evaluator_with_mock):
    ev, mock_run = evaluator_with_mock
    ev.evaluate_fix(_vuln(scanner="checkov"), _remediation())
    prompt = mock_run.call_args[0][0]
    assert "checkov" in prompt


def test_evaluate_fix_passes_remediation_explanation(evaluator_with_mock):
    ev, mock_run = evaluator_with_mock
    ev.evaluate_fix(_vuln(), _remediation(explanation="Replace string formatting with cursor.execute params"))
    prompt = mock_run.call_args[0][0]
    assert "Replace string formatting" in prompt
