"""Tests for MultiTurnRemediator. claude_agent_sdk.query is mocked — no API calls made."""
import json
import pytest
from unittest.mock import patch, MagicMock
from security_pipeline.multi_turn_agent import MultiTurnRemediator, IterationEntry


def test_iteration_entry_to_dict():
    entry = IterationEntry(
        iteration=1,
        actions=["read file app/db.py", "proposed patch"],
        patch_proposed={"summary": "fix sql injection"},
        validation_results={"compile": "ok", "tests": "PASS"},
        reasoning="Parameterize the query",
    )
    d = entry.to_dict()
    assert d["iteration"] == 1
    assert d["actions"] == ["read file app/db.py", "proposed patch"]
    assert d["patch_proposed"]["summary"] == "fix sql injection"
    assert d["validation_results"]["tests"] == "PASS"
    assert d["reasoning"] == "Parameterize the query"


def test_default_model_is_sonnet():
    r = MultiTurnRemediator()
    assert r.model == "claude-sonnet-4-6"


def test_custom_model_accepted():
    r = MultiTurnRemediator(model="claude-opus-4-6")
    assert r.model == "claude-opus-4-6"


def test_max_iterations_default():
    r = MultiTurnRemediator()
    assert r.max_iterations == 6


def test_max_iterations_configurable():
    r = MultiTurnRemediator(max_iterations=3)
    assert r.max_iterations == 3


# ---------------------------------------------------------------------------
# Fixtures shared across new tests
# ---------------------------------------------------------------------------

VALID_PATCH = {
    "summary": "Parameterize query",
    "confidence_score": 0.92,
    "is_false_positive": False,
    "code_changes": [{"file_path": "app/db.py", "start_line": 10, "end_line": 12,
                      "original_code": "old", "new_code": "new", "description": "fix"}],
    "security_implications": ["Input isolated"],
    "evaluation_concerns": [],
    "iteration_log": [{"iteration": 1, "actions": ["read app/db.py"],
                       "patch_proposed": {"summary": "Parameterize query"},
                       "validation_results": {"semgrep": "PASS"},
                       "reasoning": "Fixed via parameterization"}],
}

VULN = {"scanner": "semgrep", "rule_id": "python.sql-injection", "severity": "HIGH",
        "message": "SQL injection", "file_path": "app/db.py", "start_line": 10, "end_line": 12}


def _patch_sdk(result_text: str):
    """Patch claude_agent_sdk so remediate() returns result_text as agent output."""
    fake_rm = type("ResultMessage", (), {})
    fake_msg = fake_rm()
    fake_msg.result = result_text

    async def fake_query(*args, **kwargs):
        yield fake_msg

    return (
        patch("security_pipeline.multi_turn_agent.query", new=fake_query),
        patch("security_pipeline.multi_turn_agent.ResultMessage", fake_rm),
    )


# ---------------------------------------------------------------------------
# New tests
# ---------------------------------------------------------------------------

def test_remediate_returns_patch_and_log():
    q_p, rm_p = _patch_sdk(json.dumps(VALID_PATCH))
    with q_p, rm_p:
        r = MultiTurnRemediator()
        patch_dict, log = r.remediate(VULN, work_dir="/tmp/test")
    assert patch_dict["summary"] == "Parameterize query"
    assert patch_dict["confidence_score"] == 0.92
    assert isinstance(log, list)
    assert log[0]["iteration"] == 1


def test_remediate_iteration_log_not_in_patch_dict():
    """iteration_log must be popped from patch dict — callers must not see it there."""
    q_p, rm_p = _patch_sdk(json.dumps(VALID_PATCH))
    with q_p, rm_p:
        r = MultiTurnRemediator()
        patch_dict, _ = r.remediate(VULN, work_dir="/tmp/test")
    assert "iteration_log" not in patch_dict


def test_remediate_raises_when_no_result():
    async def empty(*args, **kwargs):
        return
        yield  # make it an async generator

    with patch("security_pipeline.multi_turn_agent.query", new=empty), \
         patch("security_pipeline.multi_turn_agent.ResultMessage", MagicMock()):
        r = MultiTurnRemediator()
        with pytest.raises(ValueError, match="no result"):
            r.remediate(VULN, work_dir="/tmp/test")


def test_remediate_raises_when_sdk_unavailable():
    with patch("security_pipeline.multi_turn_agent.CLAUDE_SDK_AVAILABLE", False):
        r = MultiTurnRemediator()
        with pytest.raises(RuntimeError, match="claude_agent_sdk"):
            r.remediate(VULN, work_dir="/tmp/test")


def test_remediate_strips_markdown_fences():
    fenced = "```json\n" + json.dumps(VALID_PATCH) + "\n```"
    q_p, rm_p = _patch_sdk(fenced)
    with q_p, rm_p:
        r = MultiTurnRemediator()
        patch_dict, _ = r.remediate(VULN, work_dir="/tmp/test")
    assert patch_dict["is_false_positive"] is False


def test_remediate_strips_generic_code_fence():
    fenced = "```\n" + json.dumps(VALID_PATCH) + "\n```"
    q_p, rm_p = _patch_sdk(fenced)
    with q_p, rm_p:
        r = MultiTurnRemediator()
        patch_dict, _ = r.remediate(VULN, work_dir="/tmp/test")
    assert "code_changes" in patch_dict


def test_remediate_raises_on_non_json():
    q_p, rm_p = _patch_sdk("This is not JSON at all.")
    with q_p, rm_p:
        r = MultiTurnRemediator()
        with pytest.raises(ValueError, match="non-JSON"):
            r.remediate(VULN, work_dir="/tmp/test")


def test_remediate_empty_iteration_log_when_agent_omits_it():
    """If agent returns JSON without iteration_log, log defaults to []."""
    patch_no_log = {k: v for k, v in VALID_PATCH.items() if k != "iteration_log"}
    q_p, rm_p = _patch_sdk(json.dumps(patch_no_log))
    with q_p, rm_p:
        r = MultiTurnRemediator()
        patch_dict, log = r.remediate(VULN, work_dir="/tmp/test")
    assert log == []
    assert "iteration_log" not in patch_dict


def test_user_prompt_contains_vuln_fields():
    r = MultiTurnRemediator()
    prompt = r._build_prompt(VULN, work_dir="/tmp/myproject")
    assert "semgrep" in prompt
    assert "python.sql-injection" in prompt
    assert "app/db.py" in prompt
    assert "/tmp/myproject" in prompt


def test_user_prompt_contains_max_iterations():
    r = MultiTurnRemediator(max_iterations=4)
    vuln = {"scanner": "checkov", "rule_id": "CKV_AWS_1", "severity": "HIGH",
            "message": "test", "file_path": "main.tf", "start_line": 1, "end_line": 5}
    prompt = r._build_prompt(vuln, work_dir="/tmp/proj")
    assert "4" in prompt


def test_system_prompt_contains_workflow_keywords():
    r = MultiTurnRemediator()
    r._build_prompt(VULN, work_dir="/tmp/proj")  # SYSTEM_PROMPT is embedded via _run
    # Check the constant directly
    from security_pipeline.multi_turn_agent import SYSTEM_PROMPT
    assert "compile" in SYSTEM_PROMPT.lower()
    assert "sandbox" in SYSTEM_PROMPT.lower()
    assert "iteration_log" in SYSTEM_PROMPT
