import os
import tempfile
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import List
from ..agents.orchestrator import orchestrator
from ..logger import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.post("/scan/upload")
async def upload_scan(
    file: UploadFile = File(..., description="tar.gz archive of the project directory"),
    project_name: str = Form(..., description="Project name for audit trail"),
    author: str = Form(default="unknown", description="Developer identity"),
    scanners: str = Form(default="semgrep,checkov,trivy", description="Comma-separated scanner list"),
):
    """
    Accept a local directory archive and queue a scan.
    Used by the CLI and MCP server instead of the GitHub-URL-based endpoint.
    """
    scanner_types = [s.strip() for s in scanners.split(",") if s.strip()]
    if not scanner_types:
        raise HTTPException(status_code=400, detail="At least one scanner must be specified")

    content = await file.read()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    logger.info(
        f"Upload received: project='{project_name}' author='{author}' "
        f"size={len(content)}B scanners={scanner_types}"
    )

    try:
        result = await orchestrator.ingest_upload(
            archive_path=tmp_path,
            project_name=project_name,
            author=author,
            source="cli",
            scanner_types=scanner_types,
        )
        return result
    except Exception as e:
        logger.error(f"Upload scan ingestion failed: {e}", exc_info=True)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(status_code=500, detail=str(e))
