from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
import os
from .routers import scan, health
from .config import settings
from .logger import get_logger
from .worker import run_worker

logger = get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Launch worker background task
    logger.info("Starting background worker task...")
    worker_task = asyncio.create_task(run_worker())
    
    yield
    
    # Shutdown: Cancel worker task
    logger.info("Stopping background worker task...")
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        logger.info("Worker task cancelled successfully")

app = FastAPI(
    title="Security Remediation Intelligence API",
    description="Agentic security remediation system API",
    version="0.1.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for local dev; restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        is_health_check = request.url.path == "/health"
        
        # Log start only if not health check
        if not is_health_check:
            logger.info(f"REQUEST START: {request.method} {request.url.path} from {request.client.host if request.client else 'unknown'}")
        
        try:
            response = await call_next(request)
            
            # Log end only if not health check OR if health check failed (non-2xx)
            if not is_health_check or not (200 <= response.status_code < 300):
                logger.info(f"REQUEST END: {request.method} {request.url.path} - Status: {response.status_code}")
                
            return response
        except Exception as e:
            logger.error(f"REQUEST FAILED: {request.method} {request.url.path} - Error: {e}", exc_info=True)
            raise

app.add_middleware(LoggingMiddleware)

# Include Routers
app.include_router(health.router, tags=["Health"])
app.include_router(scan.router, prefix="/api/v1", tags=["Scan"])

# --- Static Frontend Serving ---
# Path to built frontend (next.js 'out' directory)
# In Docker, this will be /app/backend/src/remediation_api/static
static_dir = Path(__file__).parent / "static"

if static_dir.exists():
    app.mount("/_next", StaticFiles(directory=str(static_dir / "_next")), name="next-static")
    
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # Debug logging
        logger.info(f"Serving path: {full_path}")
        
        # 1. Check if the path exists as a static file
        file_path = static_dir / full_path.lstrip("/")
        
        # If it's a directory, look for index.html (Next.js with trailingSlash: true creates folders)
        if file_path.is_dir():
            index_path = file_path / "index.html"
            logger.info(f"Checking index path: {index_path}")
            if index_path.exists():
                logger.info(f"Serving index file: {index_path}")
                return FileResponse(index_path)
        
        # If it's a file that exists, serve it
        if file_path.is_file():
            logger.info(f"Serving static file: {file_path}")
            return FileResponse(file_path)
            
        # 2. SPA Fallback: Serve the main index.html for all other routes
        # This allows Next.js client-side routing to take over.
        logger.warning(f"File not found: {file_path}. Serving SPA fallback.")
        return FileResponse(static_dir / "index.html")
else:
    logger.warning(f"Static directory not found at {static_dir}. Frontend will not be served by API.")

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting API server on port 8000 (Env: {settings.APP_ENV})")
    uvicorn.run(app, host="0.0.0.0", port=8000)
