import httpx
from pathlib import Path
from typing import Optional
from .config import get_api_url


class SecRemediatorClient:
    def __init__(self, api_url: Optional[str] = None):
        self.api_url = api_url or get_api_url()

    def upload_scan(
        self,
        archive_path: str,
        project_name: str,
        author: str,
        scanners: list[str],
        timeout: int = 60,
    ) -> dict:
        """POST /api/v1/scan/upload"""
        with open(archive_path, "rb") as f:
            response = httpx.post(
                f"{self.api_url}/api/v1/scan/upload",
                files={"file": (Path(archive_path).name, f, "application/gzip")},
                data={
                    "project_name": project_name,
                    "author": author,
                    "scanners": ",".join(scanners),
                },
                timeout=timeout,
            )
        response.raise_for_status()
        return response.json()

    def get_scan(self, scan_id: str) -> dict:
        """GET /api/v1/scans/{scan_id}"""
        response = httpx.get(f"{self.api_url}/api/v1/scans/{scan_id}", timeout=30)
        response.raise_for_status()
        return response.json()

    def list_scans(self) -> list:
        """GET /api/v1/scans"""
        response = httpx.get(f"{self.api_url}/api/v1/scans", timeout=30)
        response.raise_for_status()
        return response.json()

    def request_remediation(self, scan_id: str, vuln_id: str) -> dict:
        """POST /api/v1/scan/{scan_id}/remediate/{vuln_id}"""
        response = httpx.post(
            f"{self.api_url}/api/v1/scan/{scan_id}/remediate/{vuln_id}",
            timeout=120,
        )
        response.raise_for_status()
        return response.json()
