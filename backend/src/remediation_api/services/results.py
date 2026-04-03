import json
import tempfile
import threading
import uuid
import os
from pathlib import Path
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

        # Per-scan locks to prevent concurrent read-modify-write races on scan JSON files.
        self._scan_locks: dict[str, threading.Lock] = {}
        self._scan_locks_guard = threading.Lock()

    def _get_scan_lock(self, scan_id: str) -> threading.Lock:
        with self._scan_locks_guard:
            if scan_id not in self._scan_locks:
                self._scan_locks[scan_id] = threading.Lock()
            return self._scan_locks[scan_id]
        
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
                scan_data = self.get_scan(key.replace("scans/", "").replace(".json", ""))
                if scan_data:
                    # Hide revalidation sub-scans from the list
                    if scan_data.get("source") == "revalidation":
                        continue
                     # Minimal summary for list view
                    summary = {
                        "scan_id": scan_data.get("scan_id"),
                        "project_name": scan_data.get("project_name"),
                        "author": scan_data.get("author"),
                        "source": scan_data.get("source"),
                        "repo_url": scan_data.get("repo_url"),
                        "branch": scan_data.get("branch", "main"),
                        "commit_sha": scan_data.get("commit_sha"),
                        "timestamp": scan_data.get("timestamp"),
                        "vuln_count": scan_data.get("summary", {}).get("total_vulnerabilities", 0),
                        "rem_count": scan_data.get("summary", {}).get("remediations_generated", 0),
                        "status": scan_data.get("status", "unknown"),
                        "scanner_jobs": scan_data.get("scanner_jobs", []),
                        "summary": scan_data.get("summary", {}),
                        "revalidation_summary": scan_data.get("revalidation_summary"),
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

    def set_vuln_remediation_pending(self, scan_id: str, vuln_id: str) -> None:
        """Mark a vulnerability as having remediation in-flight."""
        with self._get_scan_lock(scan_id):
            scan_data = self.get_scan(scan_id)
            if not scan_data:
                logger.warning(f"set_vuln_remediation_pending: scan {scan_id} not found, skipping")
                return
            pending = scan_data.setdefault("pending_remediations", [])
            if vuln_id not in pending:
                pending.append(vuln_id)
            self.save_scan_result(scan_id, scan_data)

    def clear_vuln_remediation_pending(self, scan_id: str, vuln_id: str) -> None:
        """Remove a vulnerability from the pending remediation list."""
        with self._get_scan_lock(scan_id):
            scan_data = self.get_scan(scan_id)
            if not scan_data:
                logger.warning(f"clear_vuln_remediation_pending: scan {scan_id} not found, skipping")
                return
            scan_data["pending_remediations"] = [v for v in scan_data.get("pending_remediations", []) if v != vuln_id]
            self.save_scan_result(scan_id, scan_data)

    def append_remediation(self, scan_id: str, vuln_id: str, rem_data: dict) -> None:
        """Atomically append a completed remediation and remove it from pending."""
        with self._get_scan_lock(scan_id):
            scan_data = self.get_scan(scan_id)
            if not scan_data:
                logger.warning(f"append_remediation: scan {scan_id} not found, skipping")
                return
            rems = scan_data.setdefault("remediations", [])
            if not any(r.get("vulnerability_id") == vuln_id for r in rems):
                rems.append(rem_data)
            scan_data["remediations"] = rems
            scan_data["summary"]["remediations_generated"] = len(rems)
            scan_data["pending_remediations"] = [v for v in scan_data.get("pending_remediations", []) if v != vuln_id]
            self.save_scan_result(scan_id, scan_data)

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
                
        # vector store removed — autonomous agent uses no RAG cache

        # 3. Delete Result JSON
        key = f"scans/{scan_id}.json"
        self.storage.delete_file(key)
        logger.info(f"Deleted scan result: {key}")

    def save_conversation_log(
        self,
        scan_id: str,
        vuln_id: str,
        messages: list,
        vuln_meta: dict | None = None,
        remediation_meta: dict | None = None,
        iteration_log: list | None = None,
    ) -> Path:
        """Save a human-readable LLM conversation log for a single vulnerability."""
        conv_dir = Path(settings.WORK_DIR) / "conversations" / scan_id
        conv_dir.mkdir(parents=True, exist_ok=True)
        log_path = conv_dir / f"{vuln_id}.txt"

        sep = "=" * 72
        thin = "─" * 72
        lines = [
            f"{sep}\n",
            f"VULNERABILITY REMEDIATION LOG\n",
            f"Scan ID:  {scan_id}\n",
            f"Vuln ID:  {vuln_id}\n",
        ]
        if vuln_meta:
            lines += [
                f"Rule:     {vuln_meta.get('rule_id', '')}\n",
                f"Severity: {vuln_meta.get('severity', '')}\n",
                f"File:     {vuln_meta.get('file_path', '')}:{vuln_meta.get('start_line', '')}\n",
                f"Message:  {vuln_meta.get('message', '')}\n",
            ]
        if remediation_meta:
            lines += [
                f"\nOUTCOME\n",
                f"{thin}\n",
                f"Summary:        {remediation_meta.get('summary', '')}\n",
                f"Confidence:     {remediation_meta.get('confidence_score', '')}\n",
                f"False positive: {remediation_meta.get('is_false_positive', '')}\n",
                f"Iterations used: {remediation_meta.get('iterations_used', '?')} / {remediation_meta.get('max_iterations', '?')}\n",
            ]
            if remediation_meta.get("code_changes"):
                lines.append("Code changes:\n")
                for ch in remediation_meta["code_changes"]:
                    lines.append(f"  {ch.get('file_path')} lines {ch.get('start_line')}–{ch.get('end_line')}: {ch.get('description', '')}\n")

        # Per-iteration breakdown
        if iteration_log:
            lines += [f"\nITERATION BREAKDOWN\n", f"{thin}\n"]
            for entry in iteration_log:
                n = entry.get("iteration", "?")
                actions = entry.get("actions", [])
                validation = entry.get("validation_results", {})
                reasoning = entry.get("reasoning", "")
                lines.append(f"  Iteration {n}:\n")
                lines.append(f"    Actions:    {', '.join(actions) if actions else '(none)'}\n")
                lines.append(f"    Validation: {json.dumps(validation)}\n")
                if reasoning:
                    lines.append(f"    Reasoning:  {reasoning[:200]}\n")

        lines += [f"\nLLM CONVERSATION\n", f"{sep}\n\n"]

        max_iters = remediation_meta.get("max_iterations", "?") if remediation_meta else "?"
        for i, msg in enumerate(messages, 1):
            role = msg.get("role", "unknown").upper()
            role_label = role
            if msg.get("iteration"):
                role_label += f"  [iteration {msg['iteration']} of {max_iters}]"
            lines.append(f"[{i}] {role_label}\n")
            if msg.get("content"):
                lines.append(f"    {msg['content']}\n")
            for tc in msg.get("tool_calls", []):
                in_str = json.dumps(tc.get("input", {}), indent=6)
                out_str = tc.get("output", "")[:2000]
                lines.append(f"    [call] {tc['tool']}(\n")
                lines.append(f"             in:  {in_str}\n")
                lines.append(f"             out: {out_str}\n")
                lines.append(f"           )\n")
            lines.append("\n")

        log_path.write_text("".join(lines), encoding="utf-8")
        logger.info(f"Conversation log saved to {log_path}")
        return log_path


result_service = ResultService()
