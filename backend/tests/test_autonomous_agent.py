"""Unit tests — Agno Agent.run() is mocked; no API calls made."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.remediation_api.agents.autonomous_agent import (
    AutonomousRemediatorAgent,
    RemediationToolkit,
    _IterationState,
)

VULN = {
    "scanner": "semgrep", "rule_id": "python.sql-injection",
    "severity": "HIGH", "message": "SQL injection",
    "file_path": "app/db.py", "start_line": 10, "end_line": 12,
}

VALID_PATCH = {
    "summary": "Parameterize query",
    "confidence_score": 0.95,
    "is_false_positive": False,
    "code_changes": [{"file_path": "app/db.py", "start_line": 10, "end_line": 12,
                      "original_code": "old", "new_code": "new", "description": "fix"}],
    "security_implications": ["Input isolated"],
    "evaluation_concerns": [],
}


@pytest.fixture
def work_dir(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("old = 1\nmore\n")
    return str(tmp_path)


# --- _IterationState ---

def test_iteration_state_records_action():
    s = _IterationState()
    s.record_action("read_file(foo.py)")
    s.commit()
    assert s.entries[0]["actions"] == ["read_file(foo.py)"]

def test_iteration_state_increments():
    s = _IterationState()
    s.commit()
    s.commit()
    assert len(s.entries) == 2
    assert s.entries[1]["iteration"] == 2

def test_iteration_state_clears_between_commits():
    s = _IterationState()
    s.record_action("a")
    s.commit()
    s.record_action("b")
    s.commit()
    assert s.entries[0]["actions"] == ["a"]
    assert s.entries[1]["actions"] == ["b"]


# --- RemediationToolkit ---

def test_toolkit_read_file(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    try:
        content = tk.read_file("app/db.py")
        assert "old = 1" in content
    finally:
        tk.cleanup()

def test_toolkit_read_file_missing(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    try:
        result = tk.read_file("nonexistent.py")
        assert "ERROR" in result
    finally:
        tk.cleanup()

def test_toolkit_apply_patch_success(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    try:
        result = tk.apply_patch("app/db.py", "old = 1", "new = 1")
        assert "OK" in result
        sandbox_content = (tk.sandbox_dir / "app" / "db.py").read_text()
        assert "new = 1" in sandbox_content
        assert "old = 1" not in sandbox_content
    finally:
        tk.cleanup()

def test_toolkit_apply_patch_original_not_found(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    try:
        result = tk.apply_patch("app/db.py", "THIS DOES NOT EXIST", "new")
        assert "ERROR" in result
    finally:
        tk.cleanup()

def test_toolkit_apply_patch_does_not_modify_work_dir(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    try:
        tk.apply_patch("app/db.py", "old = 1", "new = 1")
        original = (Path(work_dir) / "app" / "db.py").read_text()
        assert "old = 1" in original  # work_dir untouched
    finally:
        tk.cleanup()

def test_toolkit_rollback_resets_sandbox(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    try:
        tk.apply_patch("app/db.py", "old = 1", "new = 1")
        tk.rollback()
        sandbox_content = (tk.sandbox_dir / "app" / "db.py").read_text()
        assert "old = 1" in sandbox_content
    finally:
        tk.cleanup()

def test_toolkit_list_files(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    try:
        result = tk.list_files("**/*.py")
        assert "db.py" in result
    finally:
        tk.cleanup()

def test_toolkit_cleanup_removes_sandbox(work_dir):
    s = _IterationState()
    tk = RemediationToolkit(work_dir=work_dir, scanner="semgrep", state=s)
    sandbox_path = tk.sandbox_dir
    tk.cleanup()
    assert not sandbox_path.exists()


# --- AutonomousRemediatorAgent ---

def _mock_response(text: str):
    r = MagicMock()
    r.content = text
    return r


def test_remediate_returns_patch_and_log(work_dir):
    with patch("src.remediation_api.agents.autonomous_agent.Agent") as MockAgent:
        MockAgent.return_value.run.return_value = _mock_response(json.dumps(VALID_PATCH))
        agent = AutonomousRemediatorAgent()
        patch_dict, log = agent.remediate(VULN, work_dir)
    assert patch_dict["summary"] == "Parameterize query"
    assert isinstance(log, list)

def test_remediate_strips_markdown_fences(work_dir):
    fenced = "```json\n" + json.dumps(VALID_PATCH) + "\n```"
    with patch("src.remediation_api.agents.autonomous_agent.Agent") as MockAgent:
        MockAgent.return_value.run.return_value = _mock_response(fenced)
        agent = AutonomousRemediatorAgent()
        patch_dict, _ = agent.remediate(VULN, work_dir)
    assert patch_dict["is_false_positive"] is False

def test_remediate_raises_on_non_json(work_dir):
    with patch("src.remediation_api.agents.autonomous_agent.Agent") as MockAgent:
        MockAgent.return_value.run.return_value = _mock_response("Not JSON at all.")
        agent = AutonomousRemediatorAgent()
        with pytest.raises(ValueError, match="non-JSON"):
            agent.remediate(VULN, work_dir)

def test_remediate_cleans_up_sandbox_on_success(work_dir):
    with patch("src.remediation_api.agents.autonomous_agent.Agent") as MockAgent:
        MockAgent.return_value.run.return_value = _mock_response(json.dumps(VALID_PATCH))
        agent = AutonomousRemediatorAgent()
        with patch.object(RemediationToolkit, "cleanup") as mock_cleanup:
            agent.remediate(VULN, work_dir)
        mock_cleanup.assert_called_once()

def test_remediate_cleans_up_sandbox_on_exception(work_dir):
    with patch("src.remediation_api.agents.autonomous_agent.Agent") as MockAgent:
        MockAgent.return_value.run.side_effect = RuntimeError("API failure")
        agent = AutonomousRemediatorAgent()
        with patch.object(RemediationToolkit, "cleanup") as mock_cleanup:
            with pytest.raises(RuntimeError):
                agent.remediate(VULN, work_dir)
        mock_cleanup.assert_called_once()

def test_default_model_is_deepseek():
    agent = AutonomousRemediatorAgent()
    assert "deepseek" in agent.model_id

def test_max_iterations_configurable():
    agent = AutonomousRemediatorAgent(max_iterations=3)
    assert agent.max_iterations == 3

def test_prompt_contains_vuln_fields(work_dir):
    agent = AutonomousRemediatorAgent()
    prompt = agent._build_prompt(VULN, work_dir)
    assert "semgrep" in prompt
    assert "python.sql-injection" in prompt
    assert "app/db.py" in prompt
    assert work_dir in prompt
