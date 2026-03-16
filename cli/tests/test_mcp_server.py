"""Tests for new MCP tools: sync_sessions, apply_all_remediations."""
import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock


def run_tool(name, arguments):
    """Helper to call the MCP call_tool handler synchronously."""
    from secremediator.mcp_server import call_tool
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(call_tool(name, arguments))
    finally:
        loop.close()


def test_sync_sessions_lists_sessions(tmp_path):
    """sync_sessions returns status for all sessions in .security-scan/."""
    sessions_dir = tmp_path / ".security-scan" / "sessions"
    sessions_dir.mkdir(parents=True)

    session_data = {
        "scan_id": "scan-aaa",
        "status": "queued",
        "summary": {},
        "vulnerability_ids": [],
        "last_synced_at": None,
    }
    (sessions_dir / "scan-aaa.json").write_text(json.dumps(session_data))

    with patch("secremediator.mcp_server.SecRemediatorClient") as MockClient:
        mock_client = MockClient.return_value
        mock_client.get_scan.return_value = {
            "status": "completed",
            "summary": {"total_vulnerabilities": 3},
            "vulnerabilities": [{"id": "v1"}, {"id": "v2"}, {"id": "v3"}],
        }

        result = run_tool("sync_sessions", {"repo_path": str(tmp_path)})

    data = json.loads(result[0].text)
    assert len(data["sessions"]) == 1
    assert data["sessions"][0]["scan_id"] == "scan-aaa"
    assert data["sessions"][0]["status"] == "completed"

    # Verify session file was updated on disk
    updated = json.loads((sessions_dir / "scan-aaa.json").read_text())
    assert updated["status"] == "completed"
    assert len(updated["vulnerability_ids"]) == 3


def test_sync_sessions_no_directory(tmp_path):
    """sync_sessions returns empty list when .security-scan/ does not exist."""
    result = run_tool("sync_sessions", {"repo_path": str(tmp_path)})
    data = json.loads(result[0].text)
    assert data["sessions"] == []
    assert "No .security-scan/" in data["message"]


def test_sync_sessions_handles_client_error(tmp_path):
    """sync_sessions returns error entry when backend call fails."""
    sessions_dir = tmp_path / ".security-scan" / "sessions"
    sessions_dir.mkdir(parents=True)

    session_data = {"scan_id": "scan-err", "status": "queued"}
    (sessions_dir / "scan-err.json").write_text(json.dumps(session_data))

    with patch("secremediator.mcp_server.SecRemediatorClient") as MockClient:
        mock_client = MockClient.return_value
        mock_client.get_scan.side_effect = Exception("connection refused")

        result = run_tool("sync_sessions", {"repo_path": str(tmp_path)})

    data = json.loads(result[0].text)
    assert len(data["sessions"]) == 1
    assert data["sessions"][0]["status"] == "error"
    assert "connection refused" in data["sessions"][0]["error"]


def test_apply_all_remediations_applies_passing_patches(tmp_path):
    """apply_all_remediations applies patches with PASS revalidation."""
    scan_id = "scan-bbb"
    patches_dir = tmp_path / ".security-scan" / "patches" / scan_id / "vuln-001"
    patches_dir.mkdir(parents=True)

    patch_data = {
        "vuln_id": "vuln-001",
        "scan_id": scan_id,
        "code_changes": [],  # empty — _apply_patch_changes returns []
        "summary": "Fixed it",
    }
    reval_data = {"status": "PASS"}
    (patches_dir / "patch.json").write_text(json.dumps(patch_data))
    (patches_dir / "revalidation.json").write_text(json.dumps(reval_data))

    result = run_tool("apply_all_remediations", {"scan_id": scan_id, "repo_path": str(tmp_path)})
    data = json.loads(result[0].text)

    assert data["total_applied"] == 1
    assert data["total_skipped"] == 0
    assert data["applied"][0]["vuln_id"] == "vuln-001"


def test_apply_all_remediations_skips_failing_patches(tmp_path):
    """apply_all_remediations skips patches that failed revalidation without force."""
    scan_id = "scan-ccc"
    patches_dir = tmp_path / ".security-scan" / "patches" / scan_id / "vuln-002"
    patches_dir.mkdir(parents=True)

    patch_data = {"vuln_id": "vuln-002", "scan_id": scan_id, "code_changes": []}
    reval_data = {"status": "FAIL"}
    (patches_dir / "patch.json").write_text(json.dumps(patch_data))
    (patches_dir / "revalidation.json").write_text(json.dumps(reval_data))

    result = run_tool("apply_all_remediations", {"scan_id": scan_id, "repo_path": str(tmp_path)})
    data = json.loads(result[0].text)

    assert data["total_applied"] == 0
    assert data["total_skipped"] == 1
    assert data["skipped"][0]["vuln_id"] == "vuln-002"
    assert "FAIL" in data["skipped"][0]["reason"]


def test_apply_all_remediations_force_applies_failing_patches(tmp_path):
    """apply_all_remediations with force=True applies even FAIL revalidation patches."""
    scan_id = "scan-ddd"
    patches_dir = tmp_path / ".security-scan" / "patches" / scan_id / "vuln-003"
    patches_dir.mkdir(parents=True)

    patch_data = {"vuln_id": "vuln-003", "scan_id": scan_id, "code_changes": []}
    reval_data = {"status": "FAIL"}
    (patches_dir / "patch.json").write_text(json.dumps(patch_data))
    (patches_dir / "revalidation.json").write_text(json.dumps(reval_data))

    result = run_tool("apply_all_remediations", {"scan_id": scan_id, "repo_path": str(tmp_path), "force": True})
    data = json.loads(result[0].text)

    assert data["total_applied"] == 1
    assert data["total_skipped"] == 0
    assert data["applied"][0]["vuln_id"] == "vuln-003"
    assert data["applied"][0]["revalidation_status"] == "FAIL"


def test_apply_all_remediations_no_patches_dir(tmp_path):
    """apply_all_remediations returns error when patches dir does not exist."""
    result = run_tool("apply_all_remediations", {"scan_id": "nonexistent", "repo_path": str(tmp_path)})
    data = json.loads(result[0].text)
    assert "error" in data
    assert "No patches found" in data["error"]


def test_apply_all_remediations_no_revalidation_file_skips(tmp_path):
    """apply_all_remediations skips patch with no revalidation.json (status NOT_RUN)."""
    scan_id = "scan-eee"
    patches_dir = tmp_path / ".security-scan" / "patches" / scan_id / "vuln-004"
    patches_dir.mkdir(parents=True)

    patch_data = {"vuln_id": "vuln-004", "scan_id": scan_id, "code_changes": []}
    (patches_dir / "patch.json").write_text(json.dumps(patch_data))
    # No revalidation.json

    result = run_tool("apply_all_remediations", {"scan_id": scan_id, "repo_path": str(tmp_path)})
    data = json.loads(result[0].text)

    assert data["total_skipped"] == 1
    assert "NOT_RUN" in data["skipped"][0]["reason"]


def test_apply_all_remediations_updates_session_on_apply(tmp_path):
    """apply_all_remediations updates session remediation_status when session file exists."""
    scan_id = "scan-fff"
    patches_dir = tmp_path / ".security-scan" / "patches" / scan_id / "vuln-005"
    patches_dir.mkdir(parents=True)

    patch_data = {"vuln_id": "vuln-005", "scan_id": scan_id, "code_changes": []}
    reval_data = {"status": "PASS"}
    (patches_dir / "patch.json").write_text(json.dumps(patch_data))
    (patches_dir / "revalidation.json").write_text(json.dumps(reval_data))

    # Create a session file
    sessions_dir = tmp_path / ".security-scan" / "sessions"
    sessions_dir.mkdir(parents=True)
    session_data = {"scan_id": scan_id, "status": "completed", "vulnerability_ids": ["vuln-005"]}
    session_file = sessions_dir / f"{scan_id}.json"
    session_file.write_text(json.dumps(session_data))

    # Patch _apply_patch_changes to return a file name (simulate a file was changed)
    with patch("secremediator.mcp_server._apply_patch_changes", return_value=["app/db.py"]):
        result = run_tool("apply_all_remediations", {"scan_id": scan_id, "repo_path": str(tmp_path)})

    data = json.loads(result[0].text)
    assert data["total_applied"] == 1

    # Session should be updated
    updated_session = json.loads(session_file.read_text())
    assert updated_session["remediation_status"]["vuln-005"] == "applied"
