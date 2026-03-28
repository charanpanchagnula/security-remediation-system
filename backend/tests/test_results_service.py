"""
Extended ResultService tests: save/get roundtrip, list, delete, malformed file handling.
"""
import json, os, tempfile, pytest
from unittest.mock import patch, MagicMock
from remediation_api.services.storage import LocalStorageService


def _make_service(tmp_path):
    from remediation_api.services.results import ResultService
    svc = ResultService.__new__(ResultService)
    svc.storage = LocalStorageService(base_dir=str(tmp_path))
    return svc


def _write_scan(svc, data):
    key = f"scans/{data['scan_id']}.json"
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(data, f)
        tmp = f.name
    svc.storage.upload_file(tmp, key)
    os.unlink(tmp)


def test_save_and_get_roundtrip(tmp_path):
    svc = _make_service(tmp_path)
    data = {"scan_id": "scan-rnd", "status": "completed", "vulnerabilities": []}
    svc.save_scan_result("scan-rnd", data)
    loaded = svc.get_scan("scan-rnd")
    assert loaded["scan_id"] == "scan-rnd"
    assert loaded["status"] == "completed"


def test_get_nonexistent_scan_returns_none(tmp_path):
    svc = _make_service(tmp_path)
    assert svc.get_scan("does-not-exist") is None


def test_get_all_scans_returns_summaries_sorted_newest_first(tmp_path):
    svc = _make_service(tmp_path)
    for i in range(3):
        _write_scan(svc, {
            "scan_id": f"scan-{i}",
            "timestamp": f"2025-01-0{i+1}T00:00:00",
            "status": "completed",
            "summary": {"total_vulnerabilities": i, "remediations_generated": 0},
        })
    scans = svc.get_all_scans()
    assert len(scans) == 3
    assert scans[0]["scan_id"] == "scan-2"


def test_get_all_scans_empty(tmp_path):
    svc = _make_service(tmp_path)
    assert svc.get_all_scans() == []


def test_get_all_scans_skips_malformed_json(tmp_path):
    svc = _make_service(tmp_path)
    _write_scan(svc, {"scan_id": "good-scan", "timestamp": "2025-01-01T00:00:00",
                      "status": "completed", "summary": {}})
    bad_path = tmp_path / "scans" / "bad.json"
    bad_path.parent.mkdir(exist_ok=True)
    bad_path.write_text("{not valid json")
    scans = svc.get_all_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == "good-scan"


def test_delete_scan_removes_result_json(tmp_path):
    svc = _make_service(tmp_path)
    _write_scan(svc, {"scan_id": "scan-del", "status": "completed", "summary": {}})
    assert svc.get_scan("scan-del") is not None
    svc.delete_scan("scan-del")
    assert svc.get_scan("scan-del") is None


def test_save_conversation_log_creates_file(tmp_path, monkeypatch):
    from remediation_api import config as cfg
    monkeypatch.setattr(cfg.settings, "WORK_DIR", str(tmp_path))
    from remediation_api.services import results as results_module
    # Re-instantiate so it picks up patched settings
    from remediation_api.services.results import ResultService
    svc = ResultService()
    messages = [
        {"role": "system", "content": "You are an agent."},
        {"role": "user", "content": "Fix this vuln."},
        {"role": "assistant", "content": '{"summary": "fixed"}'},
        {"role": "assistant", "tool_calls": [{"tool": "read_file", "input": {"path": "app.py"}, "output": "print('hi')"}]},
    ]
    path = svc.save_conversation_log("scan-1", "vuln-1", messages)
    assert path.exists()
    text = path.read_text()
    assert "[1] SYSTEM" in text
    assert "[2] USER" in text
    assert "[3] ASSISTANT" in text
    assert "[call] read_file" in text


def test_save_preserves_all_fields(tmp_path):
    svc = _make_service(tmp_path)
    data = {
        "scan_id": "s1",
        "status": "completed",
        "vulnerabilities": [{"id": "v1"}],
        "remediations": [{"vulnerability_id": "v1", "evaluation_concerns": ["note"]}],
        "summary": {"total_vulnerabilities": 1, "remediations_generated": 1},
    }
    svc.save_scan_result("s1", data)
    loaded = svc.get_scan("s1")
    assert loaded["remediations"][0]["evaluation_concerns"] == ["note"]
