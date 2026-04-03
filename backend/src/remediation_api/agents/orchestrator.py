import asyncio
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
from ..services.scanner import scanner_service
from ..services.github import github_service
from ..services.queue import queue_service
from ..services.results import result_service
from ..models.scan import Vulnerability
from ..models.remediation import RemediationResponse, CodeChange
from .autonomous_agent import AutonomousRemediatorAgent
from ..config import settings
from ..logger import get_logger
from ..services.memory_service import load_agent_context, consolidate_learnings

logger = get_logger(__name__)

_SEMGREP_SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "NOTE": "LOW"}

class Orchestrator:
    def __init__(self):
        pass
        
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

    async def ingest_upload(
        self,
        archive_path: str,
        project_name: str,
        author: str,
        source: str,
        scanner_types: List[str]
    ) -> Dict[str, Any]:
        """
        Entry point for CLI/MCP uploads.
        Accepts a pre-saved local tar.gz, stores it, and queues a scan job.
        Bypasses github_service entirely.
        """
        import os
        from ..services.storage import get_storage

        scan_id = str(uuid.uuid4())
        storage = get_storage()

        # Store the uploaded archive under a consistent key
        archive_key = f"archives/upload-{scan_id}.tar.gz"
        storage.upload_file(archive_path, archive_key)

        try:
            os.remove(archive_path)
        except Exception:
            pass

        scanner_jobs = [
            {"scanner": s, "status": "queued", "internal_scan_id": None, "vuln_count": 0}
            for s in scanner_types
        ]

        message = {
            "scan_id": scan_id,
            "repo_url": f"local://{project_name}",
            "commit_sha": None,
            "branch": "local",
            "archive_key": archive_key,
            "scanner_types": scanner_types,
            "timestamp": datetime.utcnow().isoformat(),
        }

        msg_id = queue_service.send_message(message)

        initial_result = {
            "scan_id": scan_id,
            "project_name": project_name,
            "author": author,
            "source": source,
            "repo_url": f"local://{project_name}",
            "branch": "local",
            "commit_sha": None,
            "archive_key": archive_key,
            "timestamp": message["timestamp"],
            "status": "queued",
            "scanner_types": scanner_types,
            "scanner_jobs": scanner_jobs,
            "vulnerabilities": [],
            "remediations": [],
            "summary": {"total_vulnerabilities": 0, "remediations_generated": 0},
        }
        result_service.save_scan_result(scan_id, initial_result)

        return {"scan_id": scan_id, "message_id": msg_id, "status": "queued"}

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

        # Load existing record to preserve audit fields (project_name, author, source, scanner_jobs)
        existing = result_service.get_scan(scan_id) or {}

        # Update status to 'in_progress' and run scanners
        in_progress_result = {
            **existing,
            "scan_id": scan_id,
            "repo_url": repo_url,
            "branch": branch,
            "commit_sha": commit_sha,
            "archive_key": archive_key,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "in_progress",
            "scanner_types": scanner_types,
            "summary": {"total_vulnerabilities": 0, "remediations_generated": 0},
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

        # Persist workspace for autonomous remediation (copy before tmp cleanup)
        persistent_workspace = None
        try:
            if tmp_dir and extract_dir.exists():
                persistent_workspace = Path(settings.WORK_DIR) / "workspaces" / scan_id
                shutil.copytree(str(extract_dir), str(persistent_workspace), dirs_exist_ok=True)
                logger.info(f"Workspace persisted to {persistent_workspace}")
        except Exception as e:
            logger.warning(f"Failed to persist workspace for {scan_id}: {e}")
            persistent_workspace = None

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
            **existing,
            "scan_id": scan_id,
            "repo_url": repo_url,
            "branch": branch,
            "commit_sha": commit_sha,
            "archive_key": archive_key,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed",
            "vulnerabilities": [v.model_dump() for v in all_vulnerabilities],
            "remediations": [],
            "scanner_types": scanner_types,
            "work_dir": str(persistent_workspace) if persistent_workspace else str(extract_dir),
            "summary": {
                "total_vulnerabilities": len(all_vulnerabilities),
                "remediations_generated": 0,
            },
        }
        
        result_service.save_scan_result(scan_id, final_result)
        logger.info(f"Scan {scan_id} complete. Results saved (No auto-remediation).")

        # Clean up the source archive now that scanning is done
        try:
            from ..services.storage import get_storage
            get_storage().delete_file(archive_key)
            logger.info(f"Deleted source archive after scan: {archive_key}")
        except Exception as e:
            logger.warning(f"Could not delete archive {archive_key}: {e}")

    async def remediate_vulnerability(self, scan_id: str, vuln_id: str) -> Optional[RemediationResponse]:
        """Trigger autonomous remediation for a single vulnerability. Raises ValueError if workspace unavailable."""
        scan_data = result_service.get_scan(scan_id)
        if not scan_data:
            raise ValueError("Scan not found")

        vulnerabilities = scan_data.get("vulnerabilities", [])
        target_vuln = next((v for v in vulnerabilities if v.get("id") == vuln_id), None)
        if not target_vuln:
            raise ValueError("Vulnerability not found")

        remediations = scan_data.get("remediations", [])
        existing = next((r for r in remediations if r.get("vulnerability_id") == target_vuln["id"]), None)
        if existing:
            return RemediationResponse(**existing)

        vuln_obj = Vulnerability(**target_vuln)
        work_dir = scan_data.get("work_dir", "")
        if not work_dir or not Path(work_dir).exists():
            raise ValueError(f"Workspace not available for scan {scan_id} — re-run the scan to generate a workspace")

        project_id = scan_data.get("project_name", "")
        rem_response = await self._process_vulnerability_autonomous(vuln_obj, work_dir, scan_id, project_id)

        if rem_response:
            result_service.append_remediation(scan_id, vuln_id, rem_response.model_dump())

        return rem_response
        
    async def batch_remediate_scan(self, scan_id: str):
        """Trigger autonomous remediation for all un-remediated vulnerabilities in a scan."""
        scan_data = result_service.get_scan(scan_id)
        if not scan_data:
            return

        work_dir = scan_data.get("work_dir", "")
        if not work_dir or not Path(work_dir).exists():
            raise ValueError(f"Workspace not available for scan {scan_id}")

        vulnerabilities = scan_data.get("vulnerabilities", [])
        existing_vuln_ids = {r["vulnerability_id"] for r in scan_data.get("remediations", [])}
        pending = [v for v in vulnerabilities if v["id"] not in existing_vuln_ids]
        total = len(vulnerabilities)
        semaphore = asyncio.Semaphore(settings.MAX_PARALLEL_REMEDIATIONS)

        project_id = scan_data.get("project_name", "")

        async def _remediate_one(v_dict):
            async with semaphore:
                vuln_obj = Vulnerability(**v_dict)
                try:
                    rem = await self._process_vulnerability_autonomous(vuln_obj, work_dir, scan_id, project_id)
                    if rem:
                        result_service.append_remediation(scan_id, vuln_obj.id, rem.model_dump())
                        logger.info(f"Remediated {vuln_obj.id}")
                except Exception as e:
                    logger.error(f"Failed to remediate {vuln_obj.id}: {e}")

        await asyncio.gather(*[_remediate_one(v) for v in pending])

    async def revalidate_scan(self, scan_id: str):
        """
        Server-side batch revalidation: apply all patches to a temp workspace copy,
        run a new scan, then persist per-vuln PASS/FAIL status onto each remediation.
        """
        import tarfile
        import tempfile
        from ..services.storage import get_storage

        scan_data = result_service.get_scan(scan_id)
        if not scan_data:
            logger.error(f"revalidate_scan: scan {scan_id} not found")
            return

        work_dir = scan_data.get("work_dir", "")
        if not work_dir or not Path(work_dir).exists():
            logger.error(f"revalidate_scan: workspace not available for {scan_id}")
            return

        remediations = scan_data.get("remediations", [])
        if not remediations:
            logger.info(f"revalidate_scan: no remediations for {scan_id}, skipping")
            return

        reval_scan_id = str(uuid.uuid4())

        with tempfile.TemporaryDirectory() as tmp:
            patched_dir = Path(tmp) / "patched"
            shutil.copytree(work_dir, str(patched_dir))

            # Apply all patches to the temp copy
            for rem in remediations:
                for change in rem.get("code_changes", []):
                    target = (patched_dir / change["file_path"].lstrip("/")).resolve()
                    if not str(target).startswith(str(patched_dir.resolve())):
                        logger.warning(f"revalidate_scan: skipping path that escapes patched_dir: {change['file_path']}")
                        continue
                    if not target.exists():
                        continue
                    lines = target.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
                    s = change["start_line"] - 1
                    e = change["end_line"]
                    new_lines = [change["new_code"] + "\n"] if change["new_code"] else []
                    lines[s:e] = new_lines
                    target.write_text("".join(lines), encoding="utf-8")

            # Create tar.gz of patched dir and store it
            archive_path = Path(tmp) / f"reval-{reval_scan_id}.tar.gz"
            with tarfile.open(str(archive_path), "w:gz") as tar:
                tar.add(str(patched_dir), arcname=".")

            archive_key = f"archives/reval-{reval_scan_id}.tar.gz"
            get_storage().upload_file(str(archive_path), archive_key)

        scanner_types = scan_data.get("scanner_types", ["semgrep"])

        # Register the new scan and process it inline (no queue)
        initial_result = {
            "scan_id": reval_scan_id,
            "project_name": f"revalidation_{scan_id[:8]}",
            "author": "security-pipeline-revalidation",
            "source": "revalidation",
            "repo_url": f"revalidation://{scan_id}",
            "branch": "revalidation",
            "commit_sha": None,
            "archive_key": archive_key,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "queued",
            "scanner_types": scanner_types,
            "vulnerabilities": [],
            "remediations": [],
            "summary": {"total_vulnerabilities": 0, "remediations_generated": 0},
        }
        result_service.save_scan_result(reval_scan_id, initial_result)

        job = {
            "scan_id": reval_scan_id,
            "repo_url": f"revalidation://{scan_id}",
            "commit_sha": None,
            "branch": "revalidation",
            "archive_key": archive_key,
            "scanner_types": scanner_types,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await self.process_scan_job(job)

        reval_data = result_service.get_scan(reval_scan_id)
        if not reval_data:
            logger.error(f"revalidate_scan: reval scan {reval_scan_id} not found after processing")
            return

        reval_vulns = reval_data.get("vulnerabilities", [])

        # Re-read scan_data to pick up any concurrent remediations
        fresh = result_service.get_scan(scan_id) or scan_data
        fresh_rems = fresh.get("remediations", [])
        orig_vulns_by_id = {v["id"]: v for v in fresh.get("vulnerabilities", [])}

        for rem in fresh_rems:
            vuln_id = rem.get("vulnerability_id")
            orig_vuln = orig_vulns_by_id.get(vuln_id)
            if not orig_vuln:
                continue

            # False positives have no code changes by design — the original finding will
            # always persist in the patched codebase, so FAIL_STILL_VULNERABLE would be
            # misleading. Mark them explicitly instead of running the FAIL/PASS logic.
            if rem.get("is_false_positive"):
                rem["revalidation_status"] = "FALSE_POSITIVE"
                rem["revalidation_scan_id"] = reval_scan_id
                continue

            patched_files = [c["file_path"] for c in rem.get("code_changes", [])]

            # Baseline: issues that already existed in the original scan for patched files.
            # Only findings NOT in this baseline count as patch-introduced new issues.
            orig_baseline = {
                (v.get("rule_id"), v.get("file_path"), v.get("start_line"))
                for v in fresh.get("vulnerabilities", [])
                if v.get("file_path") in patched_files
            }

            original_still_present = any(
                v.get("rule_id") == orig_vuln.get("rule_id")
                and v.get("file_path") == orig_vuln.get("file_path")
                and v.get("start_line") == orig_vuln.get("start_line")
                for v in reval_vulns
            )
            new_issues = [
                v for v in reval_vulns
                if v.get("file_path") in patched_files
                and (v.get("rule_id"), v.get("file_path"), v.get("start_line")) not in orig_baseline
                and not (
                    v.get("rule_id") == orig_vuln.get("rule_id")
                    and v.get("file_path") == orig_vuln.get("file_path")
                    and v.get("start_line") == orig_vuln.get("start_line")
                )
            ]

            if original_still_present and new_issues:
                status = "FAIL_BOTH"
            elif original_still_present:
                status = "FAIL_STILL_VULNERABLE"
            elif new_issues:
                status = "FAIL_NEW_ISSUES"
            else:
                status = "PASS"

            rem["revalidation_status"] = status
            rem["revalidation_scan_id"] = reval_scan_id

        fresh["remediations"] = fresh_rems

        # Build a human-readable top-level summary of revalidation results
        status_counts: Dict[str, int] = {}
        for rem in fresh_rems:
            s = rem.get("revalidation_status")
            if s:
                status_counts[s] = status_counts.get(s, 0) + 1
        total_rems = len(fresh_rems)
        passed = status_counts.get("PASS", 0)
        false_positives = status_counts.get("FALSE_POSITIVE", 0)
        # FALSE_POSITIVE entries are correct analysis, not failures — exclude from fail count
        failed = sum(v for k, v in status_counts.items() if k not in ("PASS", "FALSE_POSITIVE"))
        # Pass rate denominator: only actual patches (PASS + real FAILs), not FPs
        validated = passed + failed
        fresh["revalidation_summary"] = {
            "revalidation_scan_id": reval_scan_id,
            "total_patches": total_rems,
            "passed": passed,
            "false_positives": false_positives,
            "failed": failed,
            "pass_rate": f"{round(passed / validated * 100)}%" if validated else "n/a",
            "by_status": status_counts,
        }

        result_service.save_scan_result(scan_id, fresh)
        logger.info(f"revalidate_scan complete for {scan_id}: reval_scan_id={reval_scan_id}")

        try:
            consolidate_learnings(fresh)
        except Exception as e:
            logger.warning(f"[memory] consolidate_learnings failed (non-fatal): {e}")

    async def _process_vulnerability_autonomous(
        self,
        vuln: Vulnerability,
        work_dir: str,
        scan_id: str,
        project_id: str = "",
    ) -> Optional[RemediationResponse]:
        """
        Multi-turn autonomous remediation using AutonomousRemediatorAgent.
        Reads source files via tools, applies patches to sandbox, validates
        (syntax + security rescan), and refines iteratively.
        """
        agent = AutonomousRemediatorAgent(
            model_id=settings.REMEDIATION_MODEL,
            max_iterations=settings.MAX_ITERATIONS,
        )
        vuln_dict = {
            "scanner": vuln.scanner,
            "rule_id": vuln.rule_id,
            "severity": vuln.severity,
            "message": vuln.message,
            "file_path": vuln.file_path,
            "start_line": vuln.start_line,
            "end_line": vuln.end_line,
        }
        memory_context = load_agent_context(
            scanner=vuln.scanner,
            rule_id=vuln.rule_id,
            project_id=project_id,
        )
        if memory_context:
            logger.info(f"[memory] injecting context for rule={vuln.rule_id}")
        try:
            patch_dict, iteration_log, llm_messages = await asyncio.to_thread(
                agent.remediate, vuln_dict, work_dir, memory_context
            )
            code_changes = [
                CodeChange(**c) for c in patch_dict.get("code_changes", [])
            ]
            severity = vuln.severity if vuln.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL") \
                else _SEMGREP_SEVERITY_MAP.get(vuln.severity.upper(), "MEDIUM")
            rem_response = RemediationResponse(
                vulnerability_id=vuln.id,
                severity=severity,
                summary=patch_dict.get("summary", ""),
                explanation=patch_dict.get("summary", ""),
                code_changes=code_changes,
                security_implications=patch_dict.get("security_implications", []),
                evaluation_concerns=patch_dict.get("evaluation_concerns", []),
                is_false_positive=patch_dict.get("is_false_positive", False),
                confidence_score=patch_dict.get("confidence_score", 0.0),
                iterations_used=len(iteration_log),
                max_iterations=settings.MAX_ITERATIONS,
            )
            # Save human-readable conversation log (txt file per vuln under conversations/{scan_id}/)
            try:
                vuln_meta = {
                    "rule_id": vuln.rule_id,
                    "severity": vuln.severity,
                    "file_path": vuln.file_path,
                    "start_line": vuln.start_line,
                    "message": vuln.message,
                }
                remediation_meta = {
                    "summary": rem_response.summary,
                    "confidence_score": rem_response.confidence_score,
                    "is_false_positive": rem_response.is_false_positive,
                    "code_changes": [c.model_dump() for c in rem_response.code_changes],
                    "iterations_used": len(iteration_log),
                    "max_iterations": settings.MAX_ITERATIONS,
                }
                result_service.save_conversation_log(
                    scan_id, vuln.id, llm_messages,
                    vuln_meta=vuln_meta,
                    remediation_meta=remediation_meta,
                    iteration_log=iteration_log,
                )
            except Exception as e:
                logger.warning(f"Failed to save conversation log for {vuln.id}: {e}")
            return rem_response
        except Exception as e:
            logger.error(f"Autonomous remediation failed for {vuln.id}: {e}", exc_info=True)
            return None

orchestrator = Orchestrator()
