import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
from ..services.scanner import scanner_service
from ..services.github import github_service
from ..services.queue import queue_service
from ..services.results import result_service
from ..models.scan import Vulnerability
from ..models.remediation import RemediationResponse
from .generator import generator_agent
from .evaluator import evaluator_agent
from ..vector.store import get_vector_store
from ..config import settings
from ..logger import get_logger

logger = get_logger(__name__)

class Orchestrator:
    def __init__(self):
        self.vector_store = get_vector_store()
        
    async def ingest_scan(self, repo_url: str, commit_sha: Optional[str] = None, scanner_types: List[str] = ["semgrep"]) -> Dict[str, Any]:
        """Ingestion API: Downloads source, uploads to S3, queues job."""
        
        # 1. Download & Archive
        archive_key = await github_service.download_and_store(repo_url, commit_sha)
        
        scan_id = str(uuid.uuid4())
        
        # 2. Construct Message
        message = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "archive_key": archive_key,
            "scanner_types": scanner_types,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # 3. Send to Queue
        msg_id = queue_service.send_message(message)
        
        # 4. Save Initial Status
        initial_result = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "timestamp": message["timestamp"],
            "status": "queued",
            "scanner_types": scanner_types,
            "summary": {"total_vulnerabilities": 0, "remediations_generated": 0}
        }
        result_service.save_scan_result(scan_id, initial_result)
        
        return {
            "scan_id": scan_id,
            "message_id": msg_id,
            "status": "queued"
        }

    async def process_scan_job(self, job: Dict[str, Any]):
        """Worker Logic: Processes a scan job from the queue."""
        scan_id = job["scan_id"]
        repo_url = job["repo_url"]
        archive_key = job["archive_key"]
        scanner_types = job.get("scanner_types", ["semgrep"])
        
        logger.info(f"Processing Scan {scan_id} with {scanner_types}")
        
        # 0. Update Status to In Progress
        in_progress_result = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "in_progress",
            "scanner_types": scanner_types,
             "summary": {"total_vulnerabilities": 0, "remediations_generated": 0}
        }
        result_service.save_scan_result(scan_id, in_progress_result)

        all_vulnerabilities = []
        
        # 1. Run Scanners
        for scanner in scanner_types:
            # Run scan (extracts archive internally)
            # We run in thread to avoid blocking loop
            result = await asyncio.to_thread(scanner_service.run_scan, archive_key, repo_url, scanner)
            all_vulnerabilities.extend(result.vulnerabilities)
            
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities in Scan {scan_id}.")
        
        # 2. Save Results (WITHOUT REMEDIATION)
        final_result = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed",
            "vulnerabilities": [v.model_dump() for v in all_vulnerabilities],
            "remediations": [], # Intentionally empty
            "scanner_types": scanner_types,
            "summary": {
                "total_vulnerabilities": len(all_vulnerabilities),
                "remediations_generated": 0
            }
        }
        
        result_service.save_scan_result(scan_id, final_result)
        logger.info(f"Scan {scan_id} complete. Results saved (No auto-remediation).")

    async def remediate_vulnerability(self, scan_id: str, vuln_id: str) -> Optional[RemediationResponse]:
        """On-Demand: Generates a remediation for a specific vulnerability."""
        scan_data = result_service.get_scan(scan_id)
        if not scan_data:
            raise ValueError("Scan not found")
            
        vulnerabilities = scan_data.get("vulnerabilities", [])
        target_vuln = next((v for v in vulnerabilities if v.get("id") == vuln_id), None)
        
        if not target_vuln:
            raise ValueError("Vulnerability not found")
            
        # Check if already exists
        remediations = scan_data.get("remediations", [])
        # If exists, return it (idempotent)
        existing = next((r for r in remediations if r.get("vulnerability_id") == target_vuln["rule_id"]), None)
        if existing:
            return existing
            
        # Reconstruct Vulnerability Object
        vuln_obj = Vulnerability(**target_vuln)
        
        # Process (Pass repo_url to construct link)
        rem_response = await self._process_vulnerability(vuln_obj, scan_data["repo_url"])
        
        if rem_response:
            # Save back to DB
            remediations.append(rem_response.model_dump())
            scan_data["remediations"] = remediations
            scan_data["summary"]["remediations_generated"] = len(remediations)
            result_service.save_scan_result(scan_id, scan_data)
            
        return rem_response
        
    async def batch_remediate_scan(self, scan_id: str):
        """On-Demand: Generates remediations for ALL missing ones."""
        scan_data = result_service.get_scan(scan_id)
        if not scan_data:
            return
            
        vulnerabilities = scan_data.get("vulnerabilities", [])
        
        # Only process those that don't match an existing remediation
        # Note: mapping is vuln.rule_id -> remediation.vulnerability_id (a bit mismatch in naming, but logic holds)
        # Actually, let's just iterate and call _process
        
        current_rems = scan_data.get("remediations", [])
        existing_rule_ids = {r["vulnerability_id"] for r in current_rems}
        
        logger.info(f"Batch remediation for {scan_id}: {len(vulnerabilities)} vulns")
        
        # Iterate
        new_rems = []
        for v_dict in vulnerabilities:
            if v_dict["rule_id"] in existing_rule_ids:
                continue
                
            vuln_obj = Vulnerability(**v_dict)
            try:
                rem = await self._process_vulnerability(vuln_obj, scan_data["repo_url"])
                if rem:
                    new_rems.append(rem.model_dump())
                    # Optimization: Save periodically or at end? 
                    # For safety, let's append as we go but save at end to reduce IO maybe? 
                    # Or save every time for progress updates.
            except Exception as e:
                logger.error(f"Failed to remediate {vuln_obj.id}: {e}")

        # Update final
        if new_rems:
            scan_data["remediations"].extend(new_rems)
            scan_data["summary"]["remediations_generated"] = len(scan_data["remediations"])
            result_service.save_scan_result(scan_id, scan_data)

    async def _process_vulnerability(self, vuln: Vulnerability, repo_url: str) -> Optional[RemediationResponse]:
        # Construct GitHub Link
        # Assuming default branch if not specified (we can improve this by storing commit_sha in scan result)
        # For now, simplistic URL construction
        github_link = None
        if "github.com" in repo_url:
            # simple parse, ideally we store 'commit_sha' in ScanResult
            # But currently `repo_url` in scan result is just the base URL
            clean_repo = repo_url.rstrip(".git")
            # We don't easily have the relative path from the archive unless scanner provides it correctly.
            # Scanner provides absolute path in /tmp/... 
            # We need to strip the temp dir to get relative path.
            # But `file_path` in vuln object usually comes from scanner.
            # Let's trust the `file_path` is somewhat relative or we can hint the LLM.
            # Actually Checkov gives absolute paths in local runs.
            # We can try to infer relative path if we knew the root.
            # For now, let's just pass what we have, or "HEAD"
            github_link = f"{clean_repo}/blob/HEAD/{vuln.file_path.lstrip('/')}#L{vuln.start_line}-L{vuln.end_line}"

        # 1. Check Vector Store
        embedding = [0.0] * 1536 
        existing = await asyncio.to_thread(self.vector_store.search, embedding)
        
        feedback = None
        
        if existing:
            logger.info(f"Vector hit for {vuln.rule_id}. Evaluating guidance...")
            # Feed to Evaluator as requested by user
            evaluation = await asyncio.to_thread(
                evaluator_agent.evaluate_fix, vuln, existing
            )
            
            logger.info(f"[Evaluator] Score: {evaluation.confidence_score} | Feedback: {evaluation.feedback}")

            if evaluation.confidence_score >= settings.CONFIDENCE_THRESHOLD:
                logger.info(f"Vector guidance sufficient. Returning cached.")
                return existing
            else:
                logger.info(f"Vector guidance insufficient. Proceeding to generation.")
                feedback = f"Previous attempt found in vector store was insufficient: {evaluation.feedback}"
        
        # 2. Generator Loop
        for attempt in range(settings.MAX_RETRIES + 1):
            try:
                # Generator (Run in thread)
                remediation = await asyncio.to_thread(
                    generator_agent.generate_fix, vuln, feedback, github_link
                )
                
                # Evaluator (Run in thread)
                evaluation = await asyncio.to_thread(
                    evaluator_agent.evaluate_fix, vuln, remediation
                )
                
                logger.info(f"[Evaluator] Cycle {attempt+1}/{settings.MAX_RETRIES+1} | Score: {evaluation.confidence_score} | Feedback: {evaluation.feedback}")
                
                if evaluation.confidence_score >= settings.CONFIDENCE_THRESHOLD:
                    # Success - Store result
                    # Update remediation object with evaluator's confidence and FP judgment
                    remediation.confidence_score = evaluation.confidence_score
                    remediation.is_false_positive = evaluation.is_false_positive
                    
                    await asyncio.to_thread(
                        self.vector_store.store, 
                        embedding, 
                        remediation, 
                        {"vuln_id": vuln.id, "rule_id": vuln.rule_id}
                    )
                    return remediation
                
                feedback = evaluation.feedback # Feedback loop
                
            except Exception as e:
                logger.error(f"Error in remediation loop for {vuln.id}: {e}", exc_info=True)
                # Log error
                pass
                
        return None

orchestrator = Orchestrator()
