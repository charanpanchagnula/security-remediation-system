"""
Tests for Orchestrator agentic loop.
All external I/O (LLM, storage, vector store) is mocked.
"""
import asyncio
import pytest
from unittest.mock import MagicMock, patch

from unittest.mock import patch as _patch, MagicMock as _MagicMock
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


def _ev(confidence=0.9, feedback=None):
    return EvaluationResult(completeness_score=confidence, correctness_score=confidence,
                            security_score=confidence, confidence_score=confidence,
                            is_false_positive=False, is_approved=confidence >= 0.7,
                            feedback=feedback or [])


def _scan(remediations=None):
    return {
        "scan_id": "scan-1", "repo_url": "https://github.com/org/repo",
        "commit_sha": "abc123", "branch": "main",
        "vulnerabilities": [{"id": "vuln-abc", "rule_id": "semgrep.sql-injection",
                              "message": "SQL injection", "severity": "HIGH", "scanner": "semgrep",
                              "file_path": "app.py", "start_line": 10, "end_line": 12,
                              "code_snippet": "exec(q)", "surrounding_context": "ctx"}],
        "remediations": remediations or [],
        "summary": {"total_vulnerabilities": 1, "remediations_generated": 0},
    }


async def _sync_thread(func, *args, **kwargs):
    return func(*args, **kwargs)


def _make_vs(hits=None):
    vs = MagicMock()
    vs.search.return_value = hits or []
    vs.store.return_value = None
    return vs


# ---- remediate_vulnerability ----

@pytest.mark.asyncio
async def test_raises_when_scan_not_found():
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()):
        svc.get_scan.return_value = None
        from remediation_api.agents.orchestrator import Orchestrator
        with pytest.raises(ValueError, match="Scan not found"):
            await Orchestrator().remediate_vulnerability("no-scan", "v1")


@pytest.mark.asyncio
async def test_raises_when_vuln_not_found():
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()):
        svc.get_scan.return_value = _scan()
        from remediation_api.agents.orchestrator import Orchestrator
        with pytest.raises(ValueError, match="Vulnerability not found"):
            await Orchestrator().remediate_vulnerability("scan-1", "no-vuln")


@pytest.mark.asyncio
async def test_idempotent_returns_existing_without_generating():
    existing = _rem().model_dump()
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen:
        svc.get_scan.return_value = _scan(remediations=[existing])
        from remediation_api.agents.orchestrator import Orchestrator
        result = await Orchestrator().remediate_vulnerability("scan-1", "vuln-abc")
    assert result is not None
    gen.generate_fix.assert_not_called()


# ---- _process_vulnerability: no RAG ----

@pytest.mark.asyncio
async def test_no_rag_generates_and_returns():
    rem, ev = _rem(), _ev(0.9)
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()):
        gen.generate_fix.return_value = rem
        evl.evaluate_fix.return_value = ev
        from remediation_api.agents.orchestrator import Orchestrator
        result = await Orchestrator()._process_vulnerability(_vuln(), "https://github.com/org/repo", "scan-1")
    assert result is not None
    gen.generate_fix.assert_called_once()
    evl.evaluate_fix.assert_called_once()


# ---- _process_vulnerability: RAG high confidence ----

@pytest.mark.asyncio
async def test_rag_high_confidence_skips_generator():
    cached = _rem()
    vs = _make_vs(hits=[{"score": 0.95, "rule_id": "r1", "remediation": cached.model_dump_json()}])
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=vs):
        evl.evaluate_fix.return_value = _ev(0.9)
        from remediation_api.agents.orchestrator import Orchestrator
        result = await Orchestrator()._process_vulnerability(_vuln(), "https://github.com/org/repo", "scan-1")
    assert result is not None
    gen.generate_fix.assert_not_called()


# ---- _process_vulnerability: RAG low confidence ----

@pytest.mark.asyncio
async def test_rag_low_confidence_falls_through_to_generator():
    cached = _rem()
    vs = _make_vs(hits=[{"score": 0.3, "rule_id": "r1", "remediation": cached.model_dump_json()}])
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=vs):
        evl.evaluate_fix.side_effect = [_ev(0.3), _ev(0.9)]
        gen.generate_fix.return_value = _rem(summary="Improved")
        from remediation_api.agents.orchestrator import Orchestrator
        result = await Orchestrator()._process_vulnerability(_vuln(), "https://github.com/org/repo", "scan-1")
    assert result is not None
    gen.generate_fix.assert_called_once()
    # reference_remediation is the 4th positional arg
    assert gen.generate_fix.call_args[0][3] is not None


# ---- retry loop ----

@pytest.mark.asyncio
async def test_retry_until_pass():
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()), \
         patch("remediation_api.agents.orchestrator.settings") as s:
        s.CONFIDENCE_THRESHOLD = 0.7
        s.MAX_RETRIES = 2
        evl.evaluate_fix.side_effect = [_ev(0.4), _ev(0.9)]
        gen.generate_fix.return_value = _rem()
        from remediation_api.agents.orchestrator import Orchestrator
        result = await Orchestrator()._process_vulnerability(_vuln(), "https://github.com/org/repo", "scan-1")
    assert result is not None
    assert gen.generate_fix.call_count == 2


@pytest.mark.asyncio
async def test_returns_none_after_max_retries():
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()), \
         patch("remediation_api.agents.orchestrator.settings") as s:
        s.CONFIDENCE_THRESHOLD = 0.7
        s.MAX_RETRIES = 1
        evl.evaluate_fix.return_value = _ev(0.3)
        gen.generate_fix.return_value = _rem()
        from remediation_api.agents.orchestrator import Orchestrator
        result = await Orchestrator()._process_vulnerability(_vuln(), "https://github.com/org/repo", "scan-1")
    assert result is None
    assert gen.generate_fix.call_count == 2


@pytest.mark.asyncio
async def test_vector_store_called_on_success():
    vs = _make_vs()
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=vs):
        gen.generate_fix.return_value = _rem()
        evl.evaluate_fix.return_value = _ev(0.9)
        from remediation_api.agents.orchestrator import Orchestrator
        await Orchestrator()._process_vulnerability(_vuln(), "https://github.com/org/repo", "scan-1")
    vs.store.assert_called_once()


@pytest.mark.asyncio
async def test_github_link_built_for_github_repo():
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()):
        gen.generate_fix.return_value = _rem()
        evl.evaluate_fix.return_value = _ev(0.9)
        from remediation_api.agents.orchestrator import Orchestrator
        await Orchestrator()._process_vulnerability(
            _vuln(file_path="app.py", start_line=10, end_line=12),
            "https://github.com/org/repo", "scan-1", git_ref="abc123")
    link = gen.generate_fix.call_args[0][2]
    assert link and "github.com" in link and "abc123" in link


@pytest.mark.asyncio
async def test_no_github_link_for_local_repo():
    with patch("asyncio.to_thread", side_effect=_sync_thread), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent") as evl, \
         patch("remediation_api.agents.orchestrator.result_service"), \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()):
        gen.generate_fix.return_value = _rem()
        evl.evaluate_fix.return_value = _ev(0.9)
        from remediation_api.agents.orchestrator import Orchestrator
        await Orchestrator()._process_vulnerability(_vuln(), "local://my-project", "scan-1")
    assert gen.generate_fix.call_args[0][2] is None


# ---- batch_remediate_scan ----

@pytest.mark.asyncio
async def test_batch_skips_already_remediated():
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen, \
         patch("remediation_api.agents.orchestrator.evaluator_agent"):
        svc.get_scan.return_value = _scan(remediations=[_rem(vulnerability_id='vuln-abc').model_dump()])
        from remediation_api.agents.orchestrator import Orchestrator
        await Orchestrator().batch_remediate_scan("scan-1")
    gen.generate_fix.assert_not_called()


@pytest.mark.asyncio
async def test_batch_returns_early_when_scan_missing():
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()), \
         patch("remediation_api.agents.orchestrator.generator_agent") as gen:
        svc.get_scan.return_value = None
        from remediation_api.agents.orchestrator import Orchestrator
        await Orchestrator().batch_remediate_scan("nonexistent")
    gen.generate_fix.assert_not_called()


@pytest.mark.asyncio
async def test_process_scan_job_persists_workspace():
    """workspace is copied to {WORK_DIR}/workspaces/{scan_id} and saved in final_result"""
    import tempfile, os
    from pathlib import Path
    from unittest.mock import AsyncMock, patch, MagicMock
    with patch("remediation_api.agents.orchestrator.result_service") as svc, \
         patch("remediation_api.agents.orchestrator.get_vector_store", return_value=_make_vs()), \
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
