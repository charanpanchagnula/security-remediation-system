"""Tests for MultiTurnRemediator. claude_agent_sdk.query is mocked — no API calls made."""
import pytest
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
