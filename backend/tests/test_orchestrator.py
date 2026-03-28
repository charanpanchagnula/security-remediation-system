"""
Tests for Orchestrator agentic loop.
All external I/O (LLM, storage, vector store) is mocked.
"""
import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

import remediation_api.agents.orchestrator  # noqa: F401

from remediation_api.models.scan import Vulnerability
from remediation_api.models.remediation import RemediationResponse


def _vuln(**kw):
    base = dict(id="vuln-abc", rule_id="semgrep.sql-injection", message="SQL injection",
                severity="HIGH", scanner="semgrep", file_path="app.py",
                start_line=10, end_line=12, code_snippet="exec(q)", surrounding_context="ctx")
    base.update(kw)
    return Vulnerability(**base)


def _rem(**kw):
    base = dict(vulnerability_id="vuln-abc", severity="HIGH", summary="Fix",
                explanation="Use params", code_changes=[], security_implications=[],
                evaluation_concerns=[])
    base.update(kw)
    return RemediationResponse(**base)


def _scan(remediations=None, work_dir=None):
    return {
        "scan_id": "scan-1", "repo_url": "https://github.com/org/repo",
        "commit_sha": "abc123", "branch": "main",
        "vulnerabilities": [{"id": "vuln-abc", "rule_id": "semgrep.sql-injection",
                              "message": "SQL injection", "severity": "HIGH", "scanner": "semgrep",
                              "file_path": "app.py", "start_line": 10, "end_line": 12,
                              "code_snippet": "exec(q)", "surrounding_context": "ctx"}],
        "remediations": remediations or [],
        "summary": {"total_vulnerabilities": 1, "remediations_generated": 0},
        **({"work_dir": work_dir} if work_dir is not None else {}),
    }


# ---- remediate_vulnerability: basic error cases ----

@pytest.mark.asyncio
async def test_raises_when_scan_not_found():
    with patch("remediation_api.agents.orchestrator.result_service") as svc:
        svc.get_scan.return_value = None
        from remediation_api.agents.orchestrator import Orchestrator
        with pytest.raises(ValueError, match="Scan not found"):
            await Orchestrator().remediate_vulnerability("no-scan", "v1")


@pytest.mark.asyncio
async def test_raises_when_vuln_not_found():
    with patch("remediation_api.agents.orchestrator.result_service") as svc:
        svc.get_scan.return_value = _scan()
        from remediation_api.agents.orchestrator import Orchestrator
        with pytest.raises(ValueError, match="Vulnerability not found"):
            await Orchestrator().remediate_vulnerability("scan-1", "no-vuln")


# ---- autonomous path tests ----

@pytest.mark.asyncio
async def test_remediate_raises_when_no_workspace():
    """Without a workspace, autonomous remediation raises ValueError."""
    mock_scan = {
        "vulnerabilities": [{"id": "vuln-1", "rule_id": "rule-x", "scanner": "semgrep",
                              "severity": "HIGH", "message": "test", "file_path": "app.py",
                              "start_line": 1, "end_line": 1, "code_snippet": "",
                              "surrounding_context": ""}],
        "remediations": [],
        "work_dir": "/nonexistent/path",
    }
    with patch("remediation_api.agents.orchestrator.result_service.get_scan", return_value=mock_scan):
        with pytest.raises(ValueError, match="Workspace not available"):
            await remediation_api.agents.orchestrator.orchestrator.remediate_vulnerability("scan-1", "vuln-1")


@pytest.mark.asyncio
async def test_idempotent_returns_existing_remediation():
    """If a remediation already exists for a vuln, return it without calling the agent."""
    vuln_id = "vuln-1"
    existing_rem = {
        "vulnerability_id": vuln_id, "severity": "HIGH",
        "summary": "already fixed", "explanation": "pre-existing",
        "code_changes": [], "security_implications": [],
        "evaluation_concerns": [], "is_false_positive": False,
        "confidence_score": 0.9, "iteration_log": [], "llm_messages": []
    }
    mock_scan = {
        "vulnerabilities": [{"id": vuln_id, "rule_id": "rule-x", "scanner": "semgrep",
                              "severity": "HIGH", "message": "test", "file_path": "app.py",
                              "start_line": 1, "end_line": 1, "code_snippet": ""}],
        "remediations": [existing_rem],
        "work_dir": "/nonexistent",
    }
    with patch("remediation_api.agents.orchestrator.result_service.get_scan", return_value=mock_scan):
        with patch.object(remediation_api.agents.orchestrator.orchestrator,
                          "_process_vulnerability_autonomous", new_callable=AsyncMock) as mock_auto:
            result = await remediation_api.agents.orchestrator.orchestrator.remediate_vulnerability("scan-1", vuln_id)
            mock_auto.assert_not_called()
            assert result.summary == "already fixed"


# ---- batch_remediate_scan ----

@pytest.mark.asyncio
async def test_batch_skips_already_remediated():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp_work_dir:
        with patch("remediation_api.agents.orchestrator.result_service") as svc, \
             patch.object(remediation_api.agents.orchestrator.orchestrator,
                          "_process_vulnerability_autonomous", new_callable=AsyncMock) as mock_auto:
            svc.get_scan.return_value = _scan(
                remediations=[_rem(vulnerability_id='vuln-abc').model_dump()],
                work_dir=tmp_work_dir,
            )
            from remediation_api.agents.orchestrator import Orchestrator
            await Orchestrator().batch_remediate_scan("scan-1")
        mock_auto.assert_not_called()


@pytest.mark.asyncio
async def test_batch_returns_early_when_scan_missing():
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch.object(remediation_api.agents.orchestrator.orchestrator,
                      "_process_vulnerability_autonomous", new_callable=AsyncMock) as mock_auto:
        svc.get_scan.return_value = None
        from remediation_api.agents.orchestrator import Orchestrator
        await Orchestrator().batch_remediate_scan("nonexistent")
    mock_auto.assert_not_called()


@pytest.mark.asyncio
async def test_process_scan_job_persists_workspace():
    """workspace is copied to {WORK_DIR}/workspaces/{scan_id} and saved in final_result"""
    import tempfile
    from pathlib import Path
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch("remediation_api.agents.orchestrator.scanner_service") as sc:
        # fake workspace
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "source"
            src.mkdir()
            (src / "app.py").write_text("print('hello')")
            fake_tmp = MagicMock()
            fake_tmp.name = tmp
            fake_tmp.cleanup = MagicMock()
            sc.prepare_workspace = AsyncMock(return_value=fake_tmp)
            sc.scan_directory = AsyncMock(return_value=[])
            svc.get_scan.return_value = {}
            with patch("remediation_api.agents.orchestrator.settings") as cfg:
                cfg.WORK_DIR = tmp
                cfg.USE_LEGACY_SINGLE_SHOT = False
                from remediation_api.agents.orchestrator import Orchestrator
                await Orchestrator().process_scan_job({
                    "scan_id": "test-ws-123",
                    "repo_url": "local://test",
                    "commit_sha": None,
                    "branch": "main",
                    "archive_key": "archives/test.tar.gz",
                    "scanner_types": ["semgrep"],
                    "timestamp": "2026-01-01T00:00:00"
                })
            # workspace should be persisted
            persistent = Path(tmp) / "workspaces" / "test-ws-123"
            assert persistent.exists(), "workspace not persisted"
            assert (persistent / "app.py").exists(), "files not copied"
            # work_dir in saved result should be persistent path
            saved = svc.save_scan_result.call_args_list[-1][0][1]
            assert saved["work_dir"] == str(persistent)
