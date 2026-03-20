"""Tests for scanner_parsers.py — TDD: write tests first, then implement."""

import pytest
from autoresearch.scanner_parsers import (
    parse_semgrep_output,
    parse_checkov_output,
    parse_trivy_output,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.flask.security.injection.tainted-sql-string",
            "path": "/tmp/app.py",
            "extra": {
                "message": "Detected SQL injection via string formatting.",
                "severity": "ERROR",
            },
            "start": {"line": 10},
            "end": {"line": 12},
        },
        {
            "check_id": "python.lang.security.use-defused-xml",
            "path": "/tmp/app.py",
            "extra": {
                "message": "Use defusedxml instead of xml.etree.",
                "severity": "WARNING",
            },
            "start": {"line": 20},
            "end": {"line": 20},
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "/tmp/other.py",  # different file — should be filtered out
            "extra": {
                "message": "Hardcoded password detected.",
                "severity": "INFO",
            },
            "start": {"line": 5},
            "end": {"line": 5},
        },
    ],
    "errors": [],
}

CHECKOV_OUTPUT = {
    "results": {
        "failed_checks": [
            {
                "check_id": "CKV_AWS_20",
                "check_result": {"result": "FAILED"},
                "file_path": "/tmp/main.tf",
                "resource": "aws_s3_bucket.example",
                "file_line_range": [1, 10],
                "check": {"name": "S3 Bucket has an ACL defined which allows public READ access"},
            },
            {
                "check_id": "CKV_AWS_18",
                "check_result": {"result": "FAILED"},
                "file_path": "/tmp/main.tf",
                "resource": "aws_s3_bucket.example",
                "file_line_range": [1, 10],
                "check": {"name": "Ensure the S3 bucket has access logging enabled"},
            },
            {
                "check_id": "CKV_AZURE_1",
                "check_result": {"result": "FAILED"},
                "file_path": "/tmp/other.tf",  # different file — should be filtered
                "resource": "azurerm_storage_account.example",
                "file_line_range": [5, 15],
                "check": {"name": "Ensure that 'Secure transfer required' is set to 'Enabled'"},
            },
        ],
        "passed_checks": [],
    }
}

TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2021-33503",
                    "Severity": "HIGH",
                    "Title": "urllib3: ReDoS in the parsing of authority part of URL",
                    "PkgName": "urllib3",
                },
                {
                    "VulnerabilityID": "CVE-2022-40897",
                    "Severity": "MEDIUM",
                    "Title": "setuptools: denial of service via HTML in a crafted package or custom PackageIndex page",
                    "PkgName": "setuptools",
                },
            ],
        },
        {
            "Target": "Pipfile.lock",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "Severity": "LOW",
                    "Title": "Requests: Proxy-Authorization header leak on redirect",
                    "PkgName": "requests",
                },
            ],
        },
        {
            "Target": "no-vulns.txt",
            "Vulnerabilities": None,  # some results may have None
        },
    ]
}


# ---------------------------------------------------------------------------
# parse_semgrep_output
# ---------------------------------------------------------------------------

class TestParseSemgrepOutput:
    def test_returns_list(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert isinstance(results, list)

    def test_filters_by_file_path(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        # Only 2 results match /tmp/app.py; the third is /tmp/other.py
        assert len(results) == 2

    def test_vuln_dict_keys(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        vuln = results[0]
        assert set(vuln.keys()) == {"scanner", "rule_id", "severity", "message", "file_path", "start_line", "end_line", "metadata"}

    def test_scanner_name(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert all(v["scanner"] == "semgrep" for v in results)

    def test_rule_id(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert results[0]["rule_id"] == "python.flask.security.injection.tainted-sql-string"

    def test_severity_mapping_error_to_high(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert results[0]["severity"] == "HIGH"

    def test_severity_mapping_warning_to_medium(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert results[1]["severity"] == "MEDIUM"

    def test_severity_mapping_info_to_low(self):
        # Use the entry from other.py by scanning that file
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/other.py")
        assert results[0]["severity"] == "LOW"

    def test_message(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert results[0]["message"] == "Detected SQL injection via string formatting."

    def test_file_path(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert all(v["file_path"] == "/tmp/app.py" for v in results)

    def test_start_end_line(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert results[0]["start_line"] == 10
        assert results[0]["end_line"] == 12

    def test_metadata_resource_empty(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/app.py")
        assert results[0]["metadata"] == {"resource": ""}

    def test_empty_results(self):
        results = parse_semgrep_output({"results": [], "errors": []}, "/tmp/app.py")
        assert results == []

    def test_no_matching_file(self):
        results = parse_semgrep_output(SEMGREP_OUTPUT, "/tmp/nonexistent.py")
        assert results == []


# ---------------------------------------------------------------------------
# parse_checkov_output
# ---------------------------------------------------------------------------

class TestParseCheckovOutput:
    def test_returns_list(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert isinstance(results, list)

    def test_filters_by_file_path(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert len(results) == 2

    def test_vuln_dict_keys(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        vuln = results[0]
        assert set(vuln.keys()) == {"scanner", "rule_id", "severity", "message", "file_path", "start_line", "end_line", "metadata"}

    def test_scanner_name(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert all(v["scanner"] == "checkov" for v in results)

    def test_rule_id(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert results[0]["rule_id"] == "CKV_AWS_20"

    def test_severity_is_medium(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert all(v["severity"] == "MEDIUM" for v in results)

    def test_message_uses_check_name(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert results[0]["message"] == "S3 Bucket has an ACL defined which allows public READ access"

    def test_message_falls_back_to_check_id(self):
        data = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_99",
                        "check_result": {"result": "FAILED"},
                        "file_path": "/tmp/main.tf",
                        "resource": "aws_s3_bucket.test",
                        "file_line_range": [1, 5],
                        # no "check" key
                    }
                ],
                "passed_checks": [],
            }
        }
        results = parse_checkov_output(data, "/tmp/main.tf")
        assert results[0]["message"] == "CKV_AWS_99"

    def test_file_path(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert all(v["file_path"] == "/tmp/main.tf" for v in results)

    def test_line_range(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert results[0]["start_line"] == 1
        assert results[0]["end_line"] == 10

    def test_metadata_resource(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/main.tf")
        assert results[0]["metadata"] == {"resource": "aws_s3_bucket.example"}

    def test_empty_failed_checks(self):
        data = {"results": {"failed_checks": [], "passed_checks": []}}
        results = parse_checkov_output(data, "/tmp/main.tf")
        assert results == []

    def test_no_matching_file(self):
        results = parse_checkov_output(CHECKOV_OUTPUT, "/tmp/nonexistent.tf")
        assert results == []


# ---------------------------------------------------------------------------
# parse_trivy_output
# ---------------------------------------------------------------------------

class TestParseTrivyOutput:
    def test_returns_list(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert isinstance(results, list)

    def test_correct_count_for_target(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert len(results) == 2

    def test_vuln_dict_keys(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        vuln = results[0]
        assert set(vuln.keys()) == {"scanner", "rule_id", "severity", "message", "file_path", "start_line", "end_line", "metadata"}

    def test_scanner_name(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert all(v["scanner"] == "trivy" for v in results)

    def test_rule_id_is_cve(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert results[0]["rule_id"] == "CVE-2021-33503"

    def test_severity(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert results[0]["severity"] == "HIGH"
        assert results[1]["severity"] == "MEDIUM"

    def test_message_uses_title(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert results[0]["message"] == "urllib3: ReDoS in the parsing of authority part of URL"

    def test_file_path_is_target(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert all(v["file_path"] == "requirements.txt" for v in results)

    def test_line_numbers_are_one(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert all(v["start_line"] == 1 for v in results)
        assert all(v["end_line"] == 1 for v in results)

    def test_metadata_resource_is_pkg_name(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "requirements.txt")
        assert results[0]["metadata"] == {"resource": "urllib3"}
        assert results[1]["metadata"] == {"resource": "setuptools"}

    def test_different_target(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "Pipfile.lock")
        assert len(results) == 1
        assert results[0]["rule_id"] == "CVE-2023-32681"

    def test_no_matching_target(self):
        results = parse_trivy_output(TRIVY_OUTPUT, "unknown.txt")
        assert results == []

    def test_none_vulnerabilities_skipped(self):
        # Result with Vulnerabilities=None should not raise and should return []
        results = parse_trivy_output(TRIVY_OUTPUT, "no-vulns.txt")
        assert results == []

    def test_empty_results(self):
        results = parse_trivy_output({"Results": []}, "requirements.txt")
        assert results == []

    def test_message_falls_back_to_description(self):
        data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2099-9999",
                            "Severity": "LOW",
                            # No "Title" key — use Description
                            "Description": "Some description here.",
                            "PkgName": "somelib",
                        }
                    ],
                }
            ]
        }
        results = parse_trivy_output(data, "requirements.txt")
        assert results[0]["message"] == "Some description here."

    def test_message_empty_when_no_title_or_description(self):
        data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2099-0001",
                            "Severity": "LOW",
                            "PkgName": "emptylib",
                        }
                    ],
                }
            ]
        }
        results = parse_trivy_output(data, "requirements.txt")
        assert results[0]["message"] == ""
