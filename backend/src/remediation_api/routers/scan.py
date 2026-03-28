import shutil
from pathlib import Path
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from ..agents.orchestrator import orchestrator
from ..services.results import result_service
from ..config import settings
from ..logger import get_logger

logger = get_logger(__name__)

router = APIRouter()

class ScanRequest(BaseModel):
    repo_url: str
    commit_sha: Optional[str] = None
    scanner_types: List[str] = ["semgrep", "checkov", "trivy"]

@router.post("/scan", response_model=Dict[str, Any])
async def trigger_scan(request: ScanRequest):
    logger.info(f"Received scan request for {request.repo_url} (commit: {request.commit_sha})")
    try:
        result = await orchestrator.ingest_scan(
            request.repo_url, 
            request.commit_sha,
            request.scanner_types
        )
        logger.info(f"Scan ingested successfully: {result}")
        return result
    except Exception as e:
        logger.error(f"Scan ingestion failed: {e}", exc_info=True)
        if "Failed to clone" in str(e):
             raise HTTPException(status_code=400, detail=f"Could not clone repository. Check URL or visibility. Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/{scan_id}/remediate/{vuln_id}")
async def remediate_vuln_endpoint(scan_id: str, vuln_id: str, background_tasks: BackgroundTasks):
    """Triggers remediation for a single vulnerability. Returns immediately."""
    scan_data = result_service.get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Idempotent: already completed
    existing = next(
        (r for r in scan_data.get("remediations", []) if r.get("vulnerability_id") == vuln_id),
        None,
    )
    if existing:
        return {"status": "completed", "vuln_id": vuln_id}

    # Idempotent: already queued
    if vuln_id in scan_data.get("pending_remediations", []):
        return {"status": "pending", "vuln_id": vuln_id}

    result_service.set_vuln_remediation_pending(scan_id, vuln_id)
    logger.info(f"Queued remediation for vuln {vuln_id} in scan {scan_id}")

    async def _run():
        try:
            await orchestrator.remediate_vulnerability(scan_id, vuln_id)
        finally:
            result_service.clear_vuln_remediation_pending(scan_id, vuln_id)

    background_tasks.add_task(_run)
    return {"status": "pending", "vuln_id": vuln_id}

@router.post("/scan/{scan_id}/remediate-all")
async def batch_remediate_endpoint(scan_id: str, background_tasks: BackgroundTasks):
    """Triggers remediation for ALL vulnerabilities in background."""
    try:
        background_tasks.add_task(orchestrator.batch_remediate_scan, scan_id)
        return {"status": "started", "message": "Batch remediation started in background"}
    except Exception as e:
        logger.error(f"Batch remediation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scans", response_model=List[Dict[str, Any]])
async def list_scans():
    """List all past scans."""
    try:
        return result_service.get_all_scans()
    except Exception as e:
        logger.error(f"Failed to list scans: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve scans")

@router.get("/scans/{scan_id}", response_model=Dict[str, Any])
async def get_scan(scan_id: str):
    """Get detailed scan result."""
    result = result_service.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@router.get("/scans/{scan_id}/vulnerabilities/{vuln_id}", response_model=Dict[str, Any])
async def get_vulnerability(scan_id: str, vuln_id: str):
    """Get full details for a specific vulnerability."""
    result = result_service.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    vuln = next((v for v in result.get("vulnerabilities", []) if v.get("id") == vuln_id), None)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan result."""
    try:
        result_service.delete_scan(scan_id)
        # Clean up persistent workspace if it exists
        workspace = Path(settings.WORK_DIR) / "workspaces" / scan_id
        if workspace.exists():
            shutil.rmtree(str(workspace), ignore_errors=True)
        return {"status": "deleted", "scan_id": scan_id}
    except Exception as e:
        logger.error(f"Failed to delete scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete scan")
