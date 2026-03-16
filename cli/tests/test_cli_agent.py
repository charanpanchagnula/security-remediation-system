"""
Tests for LocalClaudeRemediator in cli/src/secremediator/agent.py.

claude_agent_sdk.query is mocked — no Claude API calls are made.
"""
import json
import pytest
from unittest.mock import patch, MagicMock


VALID_PATCH = {
    "summary": "Replace format string with parameterized query",
    "confidence_score": 0.92,
    "is_false_positive": False,
    "code_changes": [
        {
            "file_path": "app/db.py",
            "start_line": 10,
            "end_line": 12,
            "original_code": "cursor.execute(query % user_input)",
            "new_code": "cursor.execute(query, (user_input,))",
            "description": "Parameterize query to prevent SQL injection",
        }
    ],
    "security_implications": ["Input is now fully isolated from the query string"],
    "evaluation_concerns": [],
}

VULN = {
    "scanner": "semgrep",
    "rule_id": "python.sql-injection",
    "severity": "HIGH",
    "message": "SQL injection via user-controlled format string",
    "file_path": "app/db.py",
    "start_line": 10,
    "end_line": 12,
}

SOURCE = "cursor.execute(query % user_input)"


def _make_fake_query(result_text: str):
    """Returns an async generator function that yields a ResultMessage-like object."""
    async def fake_query(*args, **kwargs):
        msg = MagicMock()
        # Match the isinstance(message, ResultMessage) check by patching ResultMessage
        msg.result = result_text
        yield msg
    return fake_query


def _patch_query_and_result_message(result_text: str):
    """Patches both query and ResultMessage so the isinstance check passes."""
    fake_msg_class = type("ResultMessage", (), {})
    fake_msg = fake_msg_class()
    fake_msg.result = result_text

    async def fake_query(*args, **kwargs):
        yield fake_msg

    return (
        patch("secremediator.agent.query", new=fake_query),
        patch("secremediator.agent.ResultMessage", fake_msg_class),
    )


def test_generate_patch_returns_dict_on_valid_json():
    q_patch, rm_patch = _patch_query_and_result_message(json.dumps(VALID_PATCH))
    with q_patch, rm_patch:
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        result = r.generate_patch(VULN, SOURCE)
    assert isinstance(result, dict)
    assert result["summary"] == VALID_PATCH["summary"]
    assert result["confidence_score"] == 0.92


def test_generate_patch_strips_markdown_fences():
    fenced = "```json\n" + json.dumps(VALID_PATCH) + "\n```"
    q_patch, rm_patch = _patch_query_and_result_message(fenced)
    with q_patch, rm_patch:
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        result = r.generate_patch(VULN, SOURCE)
    assert result["is_false_positive"] is False


def test_generate_patch_strips_generic_code_fence():
    fenced = "```\n" + json.dumps(VALID_PATCH) + "\n```"
    q_patch, rm_patch = _patch_query_and_result_message(fenced)
    with q_patch, rm_patch:
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        result = r.generate_patch(VULN, SOURCE)
    assert "code_changes" in result


def test_generate_patch_raises_on_non_json():
    q_patch, rm_patch = _patch_query_and_result_message("This is not JSON at all.")
    with q_patch, rm_patch:
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        with pytest.raises(ValueError, match="non-JSON output"):
            r.generate_patch(VULN, SOURCE)


def test_generate_patch_records_evaluation_concerns_and_lowers_confidence():
    """Evaluation concerns are preserved in patch and confidence is reduced; patch is not rejected."""
    bad_patch = {**VALID_PATCH, "evaluation_concerns": ["Fix may break legacy callers"], "confidence_score": 0.9}
    q_patch, rm_patch = _patch_query_and_result_message(json.dumps(bad_patch))
    with q_patch, rm_patch:
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        result = r.generate_patch(VULN, SOURCE)
    assert result["evaluation_concerns"] == ["Fix may break legacy callers"]
    assert result["confidence_score"] < 0.9  # reduced


def test_generate_patch_raises_when_no_result_returned():
    async def empty_query(*args, **kwargs):
        return
        yield  # makes it an async generator

    with patch("secremediator.agent.query", new=empty_query), \
         patch("secremediator.agent.ResultMessage", MagicMock()):
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        with pytest.raises(ValueError, match="no result"):
            r.generate_patch(VULN, SOURCE)


def test_generate_patch_false_positive_has_empty_code_changes():
    fp_patch = {
        **VALID_PATCH,
        "is_false_positive": True,
        "code_changes": [],
        "evaluation_concerns": [],
    }
    q_patch, rm_patch = _patch_query_and_result_message(json.dumps(fp_patch))
    with q_patch, rm_patch:
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        result = r.generate_patch(VULN, SOURCE)
    assert result["is_false_positive"] is True
    assert result["code_changes"] == []


def test_prompt_contains_vulnerability_fields():
    """The prompt sent to the agent must include the scanner, rule_id, and source code."""
    captured_prompts = []
    fake_rm = type("ResultMessage", (), {})

    async def capturing_query(*args, **kwargs):
        captured_prompts.append(kwargs.get("prompt", args[0] if args else ""))
        fake_msg = fake_rm()
        fake_msg.result = json.dumps(VALID_PATCH)
        yield fake_msg


    with patch("secremediator.agent.query", new=capturing_query), \
         patch("secremediator.agent.ResultMessage", fake_rm):
        from secremediator.agent import LocalClaudeRemediator
        r = LocalClaudeRemediator()
        r.generate_patch(VULN, SOURCE)

    assert len(captured_prompts) == 1
    prompt = captured_prompts[0]
    assert "semgrep" in prompt
    assert "python.sql-injection" in prompt
    assert SOURCE in prompt


def test_default_model_is_sonnet():
    from secremediator.agent import LocalClaudeRemediator
    r = LocalClaudeRemediator()
    assert r.model == "claude-sonnet-4-6"


def test_custom_model_accepted():
    from secremediator.agent import LocalClaudeRemediator
    r = LocalClaudeRemediator(model="claude-opus-4-6")
    assert r.model == "claude-opus-4-6"
