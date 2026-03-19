# backend/tests/test_results_pending.py
import json
import tempfile
import os
import pytest
from unittest.mock import patch, MagicMock

# Minimal scan document for tests
SCAN = {
    "scan_id": "scan-1",
    "vulnerabilities": [{"id": "vuln-1"}, {"id": "vuln-2"}],
    "remediations": [],
    "summary": {},
}


def _make_service(tmp_path):
    """Create a ResultService backed by a temp local directory."""
    from remediation_api.services.results import ResultService
    from remediation_api.services.storage import LocalStorageService
    svc = ResultService.__new__(ResultService)
    svc.storage = LocalStorageService(base_dir=str(tmp_path))
    return svc


def _save(svc, data):
    import tempfile, json
    key = f"scans/{data['scan_id']}.json"
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(data, f)
        tmp = f.name
    svc.storage.upload_file(tmp, key)
    os.unlink(tmp)


def test_set_pending_adds_vuln_id(tmp_path):
    svc = _make_service(tmp_path)
    _save(svc, SCAN)
    svc.set_vuln_remediation_pending("scan-1", "vuln-1")
    result = svc.get_scan("scan-1")
    assert "vuln-1" in result["pending_remediations"]


def test_set_pending_is_idempotent(tmp_path):
    svc = _make_service(tmp_path)
    _save(svc, SCAN)
    svc.set_vuln_remediation_pending("scan-1", "vuln-1")
    svc.set_vuln_remediation_pending("scan-1", "vuln-1")
    result = svc.get_scan("scan-1")
    assert result["pending_remediations"].count("vuln-1") == 1


def test_clear_pending_removes_vuln_id(tmp_path):
    svc = _make_service(tmp_path)
    scan = {**SCAN, "pending_remediations": ["vuln-1", "vuln-2"]}
    _save(svc, scan)
    svc.clear_vuln_remediation_pending("scan-1", "vuln-1")
    result = svc.get_scan("scan-1")
    assert "vuln-1" not in result["pending_remediations"]
    assert "vuln-2" in result["pending_remediations"]


def test_clear_pending_safe_when_not_present(tmp_path):
    svc = _make_service(tmp_path)
    _save(svc, SCAN)
    # Should not raise
    svc.clear_vuln_remediation_pending("scan-1", "vuln-99")
    result = svc.get_scan("scan-1")
    assert result is not None
    assert result.get("pending_remediations", []) == []
