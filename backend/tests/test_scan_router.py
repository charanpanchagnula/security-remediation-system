"""
Tests for the scan API router.

Uses FastAPI TestClient with orchestrator and result_service mocked out.
Covers all endpoints: health, list, get, delete, remediate, batch-remediate.
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """
    Build the app once with worker mocked so no background threads or LLM
    connections are made during tests.
    """
    with patch("remediation_api.main.run_worker", new_callable=AsyncMock):
        from remediation_api.main import app
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


def test_health_check_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_list_scans_empty(client):
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_all_scans.return_value = []
        resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_returns_list(client):
    summary = {"scan_id": "s1", "status": "completed", "vuln_count": 2, "rem_count": 1}
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_all_scans.return_value = [summary]
        resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["scan_id"] == "s1"


def test_get_scan_not_found(client):
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_scan.return_value = None
        resp = client.get("/api/v1/scans/nonexistent")
    assert resp.status_code == 404


def test_get_scan_returns_detail(client):
    scan = {"scan_id": "scan-1", "status": "completed", "vulnerabilities": [], "remediations": []}
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_scan.return_value = scan
        resp = client.get("/api/v1/scans/scan-1")
    assert resp.status_code == 200
    assert resp.json()["scan_id"] == "scan-1"


def test_delete_scan_success(client):
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.delete_scan.return_value = None
        resp = client.delete("/api/v1/scans/scan-1")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"
    assert resp.json()["scan_id"] == "scan-1"


def test_get_vulnerability_not_found_in_scan(client):
    scan = {"scan_id": "s1", "vulnerabilities": [], "remediations": []}
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_scan.return_value = scan
        resp = client.get("/api/v1/scans/s1/vulnerabilities/v-missing")
    assert resp.status_code == 404


def test_get_vulnerability_returns_detail(client):
    vuln = {
        "id": "v1", "rule_id": "test-rule", "message": "msg",
        "severity": "HIGH", "scanner": "semgrep",
        "file_path": "app.py", "start_line": 1, "end_line": 3,
        "code_snippet": "bad code", "surrounding_context": "ctx",
    }
    scan = {"scan_id": "s1", "vulnerabilities": [vuln], "remediations": []}
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_scan.return_value = scan
        resp = client.get("/api/v1/scans/s1/vulnerabilities/v1")
    assert resp.status_code == 200
    assert resp.json()["id"] == "v1"


def test_remediate_single_vuln_returns_pending(client):
    scan = {
        "scan_id": "s1",
        "vulnerabilities": [{"id": "v1"}],
        "remediations": [],
        "pending_remediations": [],
    }
    from unittest.mock import AsyncMock as _AM
    with patch("remediation_api.routers.scan.result_service") as mock_svc, \
         patch("remediation_api.routers.scan.orchestrator") as mock_orch:
        mock_svc.get_scan.return_value = scan
        mock_svc.set_vuln_remediation_pending.return_value = None
        mock_svc.clear_vuln_remediation_pending.return_value = None
        mock_orch.remediate_vulnerability = _AM(return_value=None)
        resp = client.post("/api/v1/scan/s1/remediate/v1")
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"
    assert resp.json()["vuln_id"] == "v1"


def test_remediate_single_vuln_idempotent_when_already_done(client):
    scan = {
        "scan_id": "s1",
        "vulnerabilities": [{"id": "v1"}],
        "remediations": [{"vulnerability_id": "v1"}],
        "pending_remediations": [],
    }
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_scan.return_value = scan
        resp = client.post("/api/v1/scan/s1/remediate/v1")
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


def test_remediate_single_vuln_already_pending(client):
    scan = {
        "scan_id": "s1",
        "vulnerabilities": [{"id": "v1"}],
        "remediations": [],
        "pending_remediations": ["v1"],
    }
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_scan.return_value = scan
        resp = client.post("/api/v1/scan/s1/remediate/v1")
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"


def test_remediate_single_vuln_scan_not_found(client):
    with patch("remediation_api.routers.scan.result_service") as mock_svc:
        mock_svc.get_scan.return_value = None
        resp = client.post("/api/v1/scan/missing/remediate/v1")
    assert resp.status_code == 404


def test_batch_remediate_returns_started(client):
    with patch("remediation_api.routers.scan.orchestrator"):
        resp = client.post("/api/v1/scan/scan-1/remediate-all")
    assert resp.status_code == 200
    assert resp.json()["status"] == "started"
