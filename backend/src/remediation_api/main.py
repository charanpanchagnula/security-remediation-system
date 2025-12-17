from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import scan, health
from .config import settings
from .logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Security Remediation Intelligence API",
    description="Agentic security remediation system API",
    version="0.1.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all for local dev; restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health.router, tags=["Health"])
app.include_router(scan.router, prefix="/api/v1", tags=["Scan"])

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting API server on port 8000 (Env: {settings.APP_ENV})")
    uvicorn.run(app, host="0.0.0.0", port=8000)
