"""
Tests for GeneratorAgent.generate_fix.

Verifies prompt construction for all input combinations:
- basic vulnerability context
- github_link inclusion
- reference_remediation (RAG reference)
- previous_feedback (retry loop)

No real LLM calls are made — Agent.run is mocked.
"""
import pytest
from unittest.mock import MagicMock, patch

from remediation_api.models.scan import Vulnerability
from remediation_api.models.remediation import RemediationResponse, CodeChange


def _vuln(**overrides):
    defaults = dict(
        id="v1",
        rule_id="python.sql-injection",
        message="User input flows into SQL query without sanitization",
        severity="HIGH",
        scanner="semgrep",
        file_path="app/db.py",
        start_line=10,
        end_line=12,
        code_snippet="cursor.execute(query % user_input)",
        surrounding_context="def fetch(user_input):\n    cursor.execute(query % user_input)",
    )
    defaults.update(overrides)
    return Vulnerability(**defaults)


def _remediation(**overrides):
    defaults = dict(
        vulnerability_id="v1",
        severity="HIGH",
        summary="Use parameterized queries",
        explanation="Prevents SQL injection by separating code from data",
        code_changes=[],
        security_implications=[],
    )
    defaults.update(overrides)
    return RemediationResponse(**defaults)


@pytest.fixture
def generator_with_mock_agent():
    """
    Creates a GeneratorAgent with the internal Agno Agent mocked.
    Yields (agent_instance, mock_run_callable) so tests can inspect calls.
    """
    with patch("remediation_api.agents.generator.get_provider"), \
         patch("remediation_api.agents.generator.Agent") as MockAgent:
        mock_run = MagicMock()
        mock_run.return_value.content = _remediation()
        MockAgent.return_value.run = mock_run

        from remediation_api.agents.generator import GeneratorAgent
        gen = GeneratorAgent()
        yield gen, mock_run


def test_generate_fix_returns_remediation_response(generator_with_mock_agent):
    gen, _ = generator_with_mock_agent
    result = gen.generate_fix(_vuln())
    assert isinstance(result, RemediationResponse)


def test_prompt_contains_rule_id(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(rule_id="python.hardcoded-secret"))
    prompt = mock_run.call_args[0][0]
    assert "python.hardcoded-secret" in prompt


def test_prompt_contains_file_path(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(file_path="services/auth.py"))
    prompt = mock_run.call_args[0][0]
    assert "services/auth.py" in prompt


def test_prompt_contains_code_snippet(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(code_snippet="SECRET = 'abc123'"))
    prompt = mock_run.call_args[0][0]
    assert "SECRET = 'abc123'" in prompt


def test_prompt_contains_vulnerability_message(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(message="Hardcoded credential detected"))
    prompt = mock_run.call_args[0][0]
    assert "Hardcoded credential detected" in prompt


def test_prompt_contains_severity(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(severity="CRITICAL"))
    prompt = mock_run.call_args[0][0]
    assert "CRITICAL" in prompt


def test_prompt_contains_github_link_when_provided(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    link = "https://github.com/org/repo/blob/abc123/app/db.py#L10-L12"
    gen.generate_fix(_vuln(), github_link=link)
    prompt = mock_run.call_args[0][0]
    assert link in prompt


def test_prompt_shows_na_for_missing_github_link(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(), github_link=None)
    prompt = mock_run.call_args[0][0]
    assert "N/A" in prompt


def test_prompt_includes_similar_past_fix_section_with_reference(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    ref = _remediation(explanation="Use prepared statements as per OWASP A3")
    gen.generate_fix(_vuln(), reference_remediation=ref)
    prompt = mock_run.call_args[0][0]
    assert "SIMILAR PAST FIX" in prompt
    assert "Use prepared statements as per OWASP A3" in prompt


def test_prompt_excludes_similar_past_fix_when_no_reference(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(), reference_remediation=None)
    prompt = mock_run.call_args[0][0]
    assert "SIMILAR PAST FIX" not in prompt


def test_prompt_includes_previous_feedback_section(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(), previous_feedback=["Fix was incomplete", "Still vulnerable to bypass"])
    prompt = mock_run.call_args[0][0]
    assert "PREVIOUS ATTEMPT FEEDBACK" in prompt
    assert "Fix was incomplete" in prompt
    assert "Still vulnerable to bypass" in prompt


def test_prompt_excludes_previous_feedback_when_none(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    gen.generate_fix(_vuln(), previous_feedback=None)
    prompt = mock_run.call_args[0][0]
    assert "PREVIOUS ATTEMPT FEEDBACK" not in prompt


def test_reference_code_pattern_included_in_prompt(generator_with_mock_agent):
    gen, mock_run = generator_with_mock_agent
    change = CodeChange(
        file_path="db.py", start_line=1, end_line=3,
        original_code="old", new_code="cursor.execute(q, (val,))",
        description="Parameterize",
    )
    ref = _remediation(code_changes=[change])
    gen.generate_fix(_vuln(), reference_remediation=ref)
    prompt = mock_run.call_args[0][0]
    assert "cursor.execute(q, (val,))" in prompt
