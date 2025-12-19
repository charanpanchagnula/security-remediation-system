from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from ..agents.orchestrator import orchestrator
from ..services.results import result_service
from ..logger import get_logger

logger = get_logger(__name__)

router = APIRouter()

class ScanRequest(BaseModel):
    repo_url: str
    commit_sha: Optional[str] = None
    scanner_types: List[str] = ["semgrep", "checkov"]

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
        logger.error(f"Scan ingestion failed: {e}")
        if "Failed to clone" in str(e):
             raise HTTPException(status_code=400, detail=f"Could not clone repository. Check URL or visibility. Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/{scan_id}/remediate/{vuln_id}")
async def remediate_vuln_endpoint(scan_id: str, vuln_id: str, background_tasks: BackgroundTasks):
    """Triggers remediation for a single vulnerability."""
    try:
        # We run this in background so UI returns immediately? 
        # User wants "progress bar". If I return immediately, they need to poll.
        # If I await it, they wait but see loading. 
        # DeepSeek takes 10-20s. Awaiting is probably okay for single item.
        logger.info(f"Remediating vuln {vuln_id} for scan {scan_id}")
        result = await orchestrator.remediate_vulnerability(scan_id, vuln_id)
        if not result:
            raise HTTPException(status_code=404, detail="Remediation could not be generated")
        return result.model_dump()
    except Exception as e:
        logger.error(f"Remediation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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

@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan result."""
    try:
        result_service.delete_scan(scan_id)
        return {"status": "deleted", "scan_id": scan_id}
    except Exception as e:
        logger.error(f"Failed to delete scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete scan")
