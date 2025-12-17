import json
import tempfile
import uuid
import os
from .storage import get_storage, S3StorageService, LocalStorageService
from ..config import settings
from ..logger import get_logger

logger = get_logger(__name__)

class ResultService:
    def __init__(self):
        # We need specific storage instances for results bucket if using S3
        if settings.APP_ENV == "local" or settings.APP_ENV == "local_mock":
            self.storage = LocalStorageService(base_dir=os.path.join(settings.WORK_DIR, "results"))
        else:
            self.storage = S3StorageService(bucket=settings.S3_RESULTS_BUCKET_NAME)
        
    def save_scan_result(self, scan_id: str, data: dict) -> str:
        # Save as JSON
        key = f"scans/{scan_id}.json"
        
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            json.dump(data, f, indent=2)
            temp_path = f.name
            
        try:
            uri = self.storage.upload_file(temp_path, key)
            logger.info(f"Scan results saved to {uri}")
            return uri
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def get_all_scans(self) -> list[dict]:
        """Retrieves all scan results."""
        scan_files = self.storage.list_files("scans/")
        scans = []
        for key in scan_files:
            if not key.endswith(".json"):
                continue
            try:
                # Optimized: In production, better to have a DB index. 
                # Here we fetch each JSON.
                scan_data = self.get_scan(key.replace("scans/", "").replace(".json", ""))
                if scan_data:
                     # Minimal summary for list view
                    summary = {
                        "scan_id": scan_data.get("scan_id"),
                        "repo_url": scan_data.get("repo_url"),
                        "timestamp": scan_data.get("timestamp"),
                        "vuln_count": scan_data.get("summary", {}).get("total_vulnerabilities", 0),
                        "rem_count": scan_data.get("summary", {}).get("remediations_generated", 0),
                        "status": scan_data.get("status", "unknown")
                    }
                    scans.append(summary)
            except Exception as e:
                # Log error but continue so one bad file doesn't break list
                logger.warning(f"Skipping malformed scan file {key}: {e}")
                continue
        # Sort by timestamp desc
        scans.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return scans

    def get_scan(self, scan_id: str) -> dict:
        key = f"scans/{scan_id}.json"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            self.storage.download_file(key, temp_path)
            with open(temp_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to fetch scan {scan_id}: {e}")
            return None
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def delete_scan(self, scan_id: str):
        key = f"scans/{scan_id}.json"
        self.storage.delete_file(key)
        logger.info(f"Deleted scan result: {key}")

result_service = ResultService()
