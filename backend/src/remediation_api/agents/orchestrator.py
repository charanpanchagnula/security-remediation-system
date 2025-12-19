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
        archive_key, resolved_sha = await github_service.download_and_store(repo_url, commit_sha)
        
        scan_id = str(uuid.uuid4())
        
        # 2. Construct Message
        # We pass the resolved SHA to the worker so it knows exactly what was scanned
        message = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "commit_sha": resolved_sha,
            "branch": commit_sha if commit_sha else "main", # Pass explicitly if possible
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
            "branch": "main" if not commit_sha else commit_sha,  # Use input as branch name if provided
            "commit_sha": resolved_sha, # Use resolved hash
            "archive_key": archive_key, # Persist for deletion
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
        commit_sha = job.get("commit_sha")
        branch = job.get("branch", "main")
        archive_key = job["archive_key"]
        scanner_types = job.get("scanner_types", ["semgrep"])
        
        logger.info(f"Processing Scan {scan_id} with {scanner_types}")
        
        # 0. Update Status to In Progress
        in_progress_result = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "branch": branch,
            "commit_sha": commit_sha,
            "archive_key": archive_key, # Persist
            "timestamp": datetime.utcnow().isoformat(),
            "status": "in_progress",
            "scanner_types": scanner_types,
             "summary": {"total_vulnerabilities": 0, "remediations_generated": 0}
        }
        result_service.save_scan_result(scan_id, in_progress_result)

        all_vulnerabilities = []
        
        # 1. Run Scanners
        # 1. Run Scanners in Parallel
        logger.info(f"Running scanners in parallel: {scanner_types}")
        
        # Create a list of awaitable tasks
        scan_tasks = [
            asyncio.to_thread(scanner_service.run_scan, archive_key, repo_url, scanner)
            for scanner in scanner_types
        ]
        
        # Execute in parallel
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Scanner {scanner_types[idx]} failed: {res}")
            else:
                all_vulnerabilities.extend(res.vulnerabilities)
            
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities in Scan {scan_id}.")
        
        # 2. Save Results (WITHOUT REMEDIATION)
        final_result = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "branch": branch,
            "commit_sha": commit_sha,
            "archive_key": archive_key, # Persist
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
            return RemediationResponse(**existing)
            
        # Reconstruct Vulnerability Object
        vuln_obj = Vulnerability(**target_vuln)
        
        # Process (Pass git_ref for accurate links)
        git_ref = scan_data.get("commit_sha") or scan_data.get("branch") or "main"
        rem_response = await self._process_vulnerability(vuln_obj, scan_data["repo_url"], scan_id, git_ref)
        
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
                git_ref = scan_data.get("commit_sha") or scan_data.get("branch") or "main"
                rem = await self._process_vulnerability(vuln_obj, scan_data["repo_url"], scan_id, git_ref)
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

    async def _process_vulnerability(self, vuln: Vulnerability, repo_url: str, scan_id: str, git_ref: str = "main") -> Optional[RemediationResponse]:
        # Construct GitHub Link
        # Use provided git_ref (commit_sha or branch)
        github_link = None
        if "github.com" in repo_url:
            clean_repo = repo_url.rstrip(".git").rstrip("/")
            # Use the exact git_ref for permalinks
            github_link = f"{clean_repo}/blob/{git_ref}/{vuln.file_path.lstrip('/')}#L{vuln.start_line}-L{vuln.end_line}"

        # 1. Search Vector Store (Pass text directly, Agno handles embedding)
        # Construct a rich query
        query_text = f"{vuln.rule_id} {vuln.message}\n{vuln.code_snippet}"
        
        hits = await asyncio.to_thread(self.vector_store.search, query_text)
        
        reference_remediation = None
        feedback = None
        
        if hits:
            best_hit = hits[0] # List[Dict]
            logger.info(f"Agno Knowledge Hit: Score {best_hit['score']}")
            
            try:
                # Deserialize the stored JSON back to object
                cached_rem_json = best_hit["remediation"]
                existing_rem = RemediationResponse.model_validate_json(cached_rem_json)
                
                # Check Score (Using Agno/LanceDB score. NOTE: LanceDB is distance, Agno might invert it.
                # For now, let's rely on success of retrieval implying relevance, but check Evaluator.)
                
                # Evaluate if the retrieved fix is completely valid AS IS
                evaluation = await asyncio.to_thread(
                    evaluator_agent.evaluate_fix, vuln, existing_rem
                )
                
                logger.info(f"[Evaluator] Score: {evaluation.confidence_score} | Feedback: {evaluation.feedback}")

                if evaluation.confidence_score >= settings.CONFIDENCE_THRESHOLD:
                    logger.info(f"Vector guidance sufficient. Returning cached.")
                    return existing_rem
                else:
                    logger.info(f"Vector guidance insufficient. Proceeding to generation with context.")
                    reference_remediation = existing_rem
                    feedback = f"Previous similar fix was found but rejected for this specific context: {evaluation.feedback}"
            except Exception as e:
                logger.error(f"Failed to process vector hit: {e}")
        
        # 3. Generator Loop
        for attempt in range(settings.MAX_RETRIES + 1):
            try:
                # Generator (Run in thread)
                remediation = await asyncio.to_thread(
                    generator_agent.generate_fix, vuln, feedback, github_link, reference_remediation
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
                    
                    # Store new embedding for future
                    await asyncio.to_thread(
                        self.vector_store.store, 
                        vuln.rule_id,
                        remediation.model_dump_json(),
                        vuln.code_snippet,
                        scan_id
                    )
                    return remediation
                
                feedback = evaluation.feedback # Feedback loop
                # Clear reference after first attempt to avoid biasing if it was totally wrong
                reference_remediation = None 
                
                feedback = evaluation.feedback # Feedback loop
                
            except Exception as e:
                logger.error(f"Error in remediation loop for {vuln.id}: {e}", exc_info=True)
                # Log error
                pass
                
        return None

orchestrator = Orchestrator()
