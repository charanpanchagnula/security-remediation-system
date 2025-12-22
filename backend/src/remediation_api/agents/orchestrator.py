import asyncio
from pathlib import Path
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
        """
        API Entry Point: Initiates the scanning process.
        
        1. Clones and archives the repository.
        2. Resolves the commit SHA.
        3. Queues a scan job for the worker.
        4. Creates an initial 'queued' result entry.

        Args:
            repo_url (str): The Git repository URL.
            commit_sha (Optional[str]): Specific commit to scan. Defaults to HEAD.
            scanner_types (List[str]): List of scanners to run (semgrep, checkov, etc.).

        Returns:
            Dict[str, Any]: A dict containing scan_id, status, and message_id.
        """
        
        # Download and archive the repository content for scanning

        archive_key, resolved_sha = await github_service.download_and_store(repo_url, commit_sha)
        
        scan_id = str(uuid.uuid4())
        
        # Construct the message payload
        # Note: We pass the resolved SHA to ensure workers scan the exact same commit
        message = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "commit_sha": resolved_sha,
            "branch": commit_sha if commit_sha else "main", # Pass explicitly if possible
            "archive_key": archive_key,
            "scanner_types": scanner_types,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # 3. Queue the job and save the initial 'queued' status
        msg_id = queue_service.send_message(message)
        
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
        """
        Worker Entry Point: Processes a dequeued scan job.
        
        1. Updates status to 'in_progress'.
        2. Runs selected scanners in parallel.
        3. Aggregates vulnerabilities.
        4. Saves the final result (without auto-remediation).

        Args:
            job (Dict[str, Any]): The job payload from the queue.
        """
        scan_id = job["scan_id"]
        repo_url = job["repo_url"]
        commit_sha = job.get("commit_sha")
        branch = job.get("branch", "main")
        archive_key = job["archive_key"]
        scanner_types = job.get("scanner_types", ["semgrep"])
        
        logger.info(f"Processing Scan {scan_id} with {scanner_types}")
        
        # Update status to 'in_progress' and run scanners
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
        
        # Run all requested scanners in parallel
        # Actually, we run sequentially to save memory, but now we reuse the workspace
        
        tmp_dir = None
        results = []
        
        try:
            logger.info("Preparing workspace for scan...")
            tmp_dir = await scanner_service.prepare_workspace(archive_key)
            extract_dir = Path(tmp_dir.name) / "source"
            
            for scanner in scanner_types:
                try:
                    # Run scan on the prepared directory
                    vulns = await scanner_service.scan_directory(extract_dir, repo_url, scanner)
                    results.append(vulns)
                except Exception as e:
                    results.append(e)
                    
        except Exception as e:
            logger.error(f"Failed to prepare workspace or run scans: {e}")
            # If critical failure, ensures we don't crash the worker loop entirely?
            # Or perhaps assume partial failure is handled below.
            if not results:
                 # If we didn't even start scanners, log it
                 logger.error("No scans performed due to setup failure.")
        finally:
            if tmp_dir:
                await asyncio.to_thread(tmp_dir.cleanup)
        
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Scanner {scanner_types[idx]} failed: {res}")
            else:
                all_vulnerabilities.extend(res)
            
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities in Scan {scan_id}.")
        
        # Save the final scan results (remediation is triggered on-demand later)
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
        """
        On-Demand Remediation: Triggers the Agentic Loop for a single finding.
        
        1. Fetches the scan result.
        2. Identifies the target vulnerability.
        3. Checks for existing remediations (idempotency).
        4. Calls _process_vulnerability to generate/retrieve a fix.
        5. Updates the persistent result.

        Args:
            scan_id (str): The scan ID.
            vuln_id (str): The specific vulnerability ID to fix.

        Returns:
            Optional[RemediationResponse]: The generated or retrieved remediation.
        """
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
        # Fix: Check against vulnerability_id (UUID), not rule_id
        existing = next((r for r in remediations if r.get("vulnerability_id") == target_vuln["id"]), None)
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
        """
        On-Demand Batch Remediation: Generates fixes for ALL vulnerabilities in a scan.
        Skips vulnerabilities that already have a remediation.

        Args:
            scan_id (str): The scan ID to process.
        """
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
        """
        The Core Agentic Loop:
        1. RAG: Searches Vector Store for similar past fixes.
        2. Evaluate: If a hit is found, evaluates its applicability.
        3. Generate: If no hit or rejected, uses LLM to generate a new fix.
        4. Verify: Evaluates the generated fix.
        5. Learn: Stores high-confidence fixes back into Vector Store.

        Args:
            vuln (Vulnerability): The vulnerability to fix.
            repo_url (str): The repo URL (for context).
            scan_id (str): The scan ID.
            git_ref (str): Commit SHA or branch for permalinks.

        Returns:
            Optional[RemediationResponse]: The approved remediation, or None if failed.
        """
        # Construct GitHub Link
        # Use provided git_ref (commit_sha or branch)
        github_link = None
        if "github.com" in repo_url:
            clean_repo = repo_url.rstrip(".git").rstrip("/")
            # Use the exact git_ref for permalinks
            github_link = f"{clean_repo}/blob/{git_ref}/{vuln.file_path.lstrip('/')}#L{vuln.start_line}-L{vuln.end_line}"

        # 1. Search Vector Store for relevant context
        # Agno/LanceDB handles the embedding generation internally
        query_text = f"{vuln.rule_id} {vuln.message}\n{vuln.code_snippet}"
        
        logger.info(f"🔍 [Vector Search] Searching for context. Rule: {vuln.rule_id}")
        logger.debug(f"🔍 [Vector Search] Query: {query_text[:100]}...")

        hits = await asyncio.to_thread(
            self.vector_store.search, 
            query_text, 
            limit=1, 
            filters={"scanner": vuln.scanner}
        )
        
        reference_remediation = None
        feedback = None
        
        if hits:
            best_hit = hits[0] # List[Dict]
            logger.info(f"✅ [Vector Search] Hit Found! Score: {best_hit['score']}")
            logger.info(f"✅ [Vector Search] Cached Remediation ID: {best_hit.get('rule_id')}")
            
            try:
                # Deserialize the stored JSON back to object
                cached_rem_json = best_hit["remediation"]
                existing_rem = RemediationResponse.model_validate_json(cached_rem_json)
                
                # Check Score (Using Agno/LanceDB score. NOTE: LanceDB is distance, Agno might invert it.
                # For now, let's rely on success of retrieval implying relevance, but check Evaluator.)
                
                # Evaluate if the retrieved fix is completely valid for the current context

                evaluation = await asyncio.to_thread(
                    evaluator_agent.evaluate_fix, vuln, existing_rem
                )
                
                logger.info(f"[Evaluator] Score: {evaluation.confidence_score} | Feedback: {evaluation.feedback}")

                if evaluation.confidence_score >= settings.CONFIDENCE_THRESHOLD:
                    logger.info(f"Vector guidance sufficient. Returning cached.")
                    # CRITICAL: Overwrite ID to match current vulnerability UUID for UI mapping
                    existing_rem.vulnerability_id = vuln.id
                    return existing_rem
                else:
                    logger.info(f"Vector guidance insufficient. Proceeding to generation with context.")
                    reference_remediation = existing_rem
                    feedback = f"Previous similar fix was found but rejected for this specific context: {evaluation.feedback}"
            except Exception as e:
                logger.error(f"Failed to process vector hit: {e}")
        
        # 2. Generator Loop: Agentic Cycle of Generate -> Evaluate -> Refine
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
                        scan_id,
                        vuln.scanner
                    )
                    # CRITICAL: Overwrite ID to match current vulnerability UUID for UI mapping
                    # (Generator might produce random/rule ID)
                    remediation.vulnerability_id = vuln.id
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
