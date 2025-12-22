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
        """
        Initializes the ResultService with the appropriate storage backend.
        Uses LocalStorageService for 'local' environments and S3StorageService for 'production'.
        """
        # We need specific storage instances for results bucket if using S3
        if settings.APP_ENV == "local" or settings.APP_ENV == "local_mock":
            self.storage = LocalStorageService(base_dir=os.path.join(settings.WORK_DIR, "results"))
        else:
            self.storage = S3StorageService(bucket=settings.S3_RESULTS_BUCKET_NAME)
        
    def save_scan_result(self, scan_id: str, data: dict) -> str:
        """
        Saves the scan result JSON to storage.

        Args:
            scan_id (str): The unique ID of the scan.
            data (dict): The complete scan data dictionary.

        Returns:
            str: The URI (local path or s3://) where the result was saved.
        """
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
                        "branch": scan_data.get("branch", "main"),
                        "commit_sha": scan_data.get("commit_sha"),
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
        """
        Retrieves a specific scan result by ID.

        Args:
            scan_id (str): The ID of the scan to fetch.

        Returns:
            dict: The scan result data, or None if not found or failed to fetch.
        """
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
        """
        Hard deletes a scan and its associated resources (artifacts, vector entries, result JSON).

        Args:
            scan_id (str): The ID of the scan to delete.
        """
        # 1. Fetch metadata to find linked resources (archive, vectors)
        scan_data = self.get_scan(scan_id)
        
        # 2. Delete Source Archive
        if scan_data and "archive_key" in scan_data:
            archive_key = scan_data["archive_key"]
            try:
                self.storage.delete_file(archive_key)
                logger.info(f"Deleted source archive: {archive_key}")
            except Exception as e:
                logger.warning(f"Failed to delete archive {archive_key}: {e}")
                
        # 3. Delete Vectors
        try:
            # Import here to avoid potential circular header issues if any
            from ..vector.store import get_vector_store
            vector_store = get_vector_store()
            vector_store.delete_scan(scan_id)
        except Exception as e:
             logger.warning(f"Failed to clean up vectors for {scan_id}: {e}")

        # 4. Delete Result JSON
        key = f"scans/{scan_id}.json"
        self.storage.delete_file(key)
        logger.info(f"Deleted scan result: {key}")

result_service = ResultService()
