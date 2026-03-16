"""Tests for _submit_scan_job helper and run command."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from secremediator.cli import app, _submit_scan_job


def test_submit_scan_job_archives_uploads_saves(tmp_path):
    """_submit_scan_job archives, uploads, saves history/session and returns (scan_id, scan_dir)."""
    fake_scan_id = "test-scan-001"

    with patch("secremediator.cli.create_archive", return_value="/tmp/fake.tar.gz") as mock_archive, \
         patch("secremediator.cli.SecRemediatorClient") as MockClient, \
         patch("secremediator.cli.save_archive") as mock_save_archive, \
         patch("secremediator.cli.save_to_history") as mock_save_history, \
         patch("secremediator.cli.Path.unlink"):

        mock_client = MockClient.return_value
        mock_client.upload_scan.return_value = {"scan_id": fake_scan_id}

        scan_id, scan_dir = _submit_scan_job(
            target=tmp_path,
            project_name="myproject",
            author_name="alice",
            scanner_list=["semgrep"],
            api_url=None,
        )

    assert scan_id == fake_scan_id
    assert scan_dir == tmp_path / ".security-scan"
    mock_archive.assert_called_once_with(str(tmp_path))
    mock_client.upload_scan.assert_called_once_with(
        archive_path="/tmp/fake.tar.gz",
        project_name="myproject",
        author="alice",
        scanners=["semgrep"],
    )
    mock_save_history.assert_called_once()
    history_entry = mock_save_history.call_args[0][0]
    assert history_entry["scan_id"] == fake_scan_id
    assert history_entry["project_name"] == "myproject"

    # Check session file written
    session_file = tmp_path / ".security-scan" / "sessions" / f"{fake_scan_id}.json"
    assert session_file.exists()
    session = json.loads(session_file.read_text())
    assert session["scan_id"] == fake_scan_id
    assert session["status"] == "queued"
    assert session["vulnerability_ids"] == []
