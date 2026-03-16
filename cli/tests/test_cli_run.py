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


def test_run_remediate_all_loop_returns_summary(tmp_path):
    """_run_remediate_all_loop polls, generates patches, revalidates, returns summary dict."""
    from secremediator.cli import _run_remediate_all_loop

    scan_data = {
        "status": "completed",
        "summary": {"total_vulnerabilities": 1},
        "vulnerabilities": [
            {
                "id": "vuln-001",
                "severity": "HIGH",
                "rule_id": "python.sqli",
                "file_path": "app/db.py",
                "start_line": 10,
                "end_line": 12,
            }
        ],
    }
    patch_data = {
        "summary": "Fixed SQLi",
        "confidence_score": 0.9,
        "is_false_positive": False,
        "code_changes": [],
        "security_implications": [],
    }
    reval_data = {"status": "SKIPPED_NO_ARCHIVE", "vuln_id": "vuln-001"}

    mock_client = MagicMock()
    mock_client.get_scan.return_value = scan_data
    mock_client.request_remediation.return_value = {"status": "completed"}

    with patch("secremediator.cli._poll_until_complete", return_value=scan_data), \
         patch("secremediator.cli._run_revalidation", return_value=reval_data), \
         patch("secremediator.cli.get_archive_path", return_value=None):

        # Patch the remediation polling loop to return patch immediately
        mock_scan_with_rems = {
            **scan_data,
            "remediations": [
                {
                    "vulnerability_id": "vuln-001",
                    **patch_data,
                }
            ],
        }
        mock_client.get_scan.side_effect = [scan_data, mock_scan_with_rems]

        result = _run_remediate_all_loop(
            client=mock_client,
            scan_id="scan-001",
            target=tmp_path,
            quiet=True,
        )

    assert "passed" in result
    assert "failed" in result
    assert "skipped" in result
    assert "total_vulns" in result
    assert result["total_vulns"] == 1


def test_run_remediate_all_loop_raises_on_failed_scan(tmp_path):
    """_run_remediate_all_loop raises RuntimeError if scan failed."""
    from secremediator.cli import _run_remediate_all_loop

    mock_client = MagicMock()

    with patch("secremediator.cli._poll_until_complete", return_value={"status": "failed"}):
        with pytest.raises(RuntimeError, match="Scan failed"):
            _run_remediate_all_loop(
                client=mock_client,
                scan_id="scan-bad",
                target=tmp_path,
                quiet=True,
            )


def test_run_command_chains_scan_and_remediate(tmp_path):
    """run command calls _submit_scan_job then _run_remediate_all_loop."""
    from typer.testing import CliRunner
    from secremediator.cli import app
    runner = CliRunner()

    fake_scan_id = "run-scan-001"
    fake_scan_dir = tmp_path / ".security-scan"
    fake_result = {"passed": 2, "failed": 0, "skipped": 1, "patches_dir": str(tmp_path), "total_vulns": 3}

    with patch("secremediator.cli._submit_scan_job", return_value=(fake_scan_id, fake_scan_dir)) as mock_submit, \
         patch("secremediator.cli._run_remediate_all_loop", return_value=fake_result) as mock_loop, \
         patch("secremediator.cli.SecRemediatorClient"):
        result = runner.invoke(app, ["run", str(tmp_path)])

    assert result.exit_code == 0, result.output
    mock_submit.assert_called_once()
    mock_loop.assert_called_once()
    assert "run-scan-001" in result.output
    assert "2 PASS" in result.output


def test_run_command_passes_severity_filter(tmp_path):
    """run command passes --severity through to _run_remediate_all_loop."""
    from typer.testing import CliRunner
    from secremediator.cli import app
    runner = CliRunner()

    fake_result = {"passed": 1, "failed": 0, "skipped": 0, "patches_dir": str(tmp_path), "total_vulns": 1}

    with patch("secremediator.cli._submit_scan_job", return_value=("scan-sev", tmp_path / ".security-scan")), \
         patch("secremediator.cli._run_remediate_all_loop", return_value=fake_result) as mock_loop, \
         patch("secremediator.cli.SecRemediatorClient"):
        result = runner.invoke(app, ["run", str(tmp_path), "--severity", "CRITICAL,HIGH"])

    assert result.exit_code == 0, result.output
    call_kwargs = mock_loop.call_args
    assert call_kwargs.kwargs.get("severity") == "CRITICAL,HIGH" or (call_kwargs.args and "CRITICAL,HIGH" in str(call_kwargs.args))
