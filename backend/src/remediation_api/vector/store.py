from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel
from ..models.remediation import RemediationResponse
from ..config import settings
from ..services.storage import get_storage
from ..logger import get_logger

logger = get_logger(__name__)

class VectorEntry(BaseModel):
    id: str
    embedding: List[float]
    metadata: Dict[str, Any]

class VectorStore(ABC):
    @abstractmethod
    def search(self, embedding: List[float], threshold: float = 0.85) -> Optional[RemediationResponse]:
        """Search for similar remediation."""
        pass
        
    @abstractmethod
    def store(self, embedding: List[float], remediation: RemediationResponse, metadata: Dict[str, Any]):
        """Store remediation with embedding."""
        pass

class LocalVectorStore(VectorStore):
    """Simple JSON-based store for local dev."""
    def __init__(self):
        self.file_path = Path(settings.WORK_DIR) / "vector_store.json"
        
    def _load(self) -> List[VectorEntry]:
        if not self.file_path.exists():
            return []
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
                return [VectorEntry(**item) for item in data]
        except Exception:
            return []

    def _save(self, entries: List[VectorEntry]):
        with open(self.file_path, "w") as f:
            json.dump([e.model_dump() for e in entries], f, indent=2)

    def search(self, embedding: List[float], threshold: float = 0.85) -> Optional[RemediationResponse]:
        # Local mock: Real cosine similarity check would go here.
        # For now, we return None to force generation, 
        # or we could implement a basic dot product if we had numpy.
        # We'll just mock a "miss" for now.
        return None

    def store(self, embedding: List[float], remediation: RemediationResponse, metadata: Dict[str, Any]):
        entries = self._load()
        entry = VectorEntry(
            id=str(uuid.uuid4()),
            embedding=embedding,
            metadata={
                **metadata,
                "remediation": remediation.model_dump(),
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        entries.append(entry)
        entries.append(entry)
        self._save(entries)
        logger.info(f"Stored valid remediation for {metadata.get('rule_id')} in local vector store.")

class S3VectorStore(VectorStore):
    """S3 implementation for production."""
    def __init__(self):
        self.storage = get_storage()
        self.bucket = settings.S3_VECTOR_BUCKET_NAME
        
    def search(self, embedding: List[float], threshold: float = 0.85) -> Optional[RemediationResponse]:
        # User Logic: "get the object from s3 vectors"
        # Since we don't have a real Vector DB URI yet, we'll try to fetch a "known good" remediation 
        # based on a deterministic key (e.g., rule_id hash) from a "vectors" folder.
        # This is a placeholder for the actual Vector DB logic.
        
        # NOTE: In a real system, you'd pass the embedding to a vector DB (Pinecone, Opensearch).
        # Here, we simulate a "hit" if a file exists for the rule_id/vuln signature.
        # We need the rule_id which isn't passed in 'search', but usually vector search is purely semantic.
        # For this requirement, we'll assume we can't find it purely by embedding in this S3 implementation 
        # without an external index. 
        # So we return None for now, OR we could accept metadata in search() (interface change required).
        
        # User asked: "get the object from s3 vectors... feed it to evaluator"
        # I will keep returning None here unless I change the interface to accept rule_id.
        # BUT, the user also said "placeholder functionality for s3 vector interaction".
        
        # BUT, the user also said "placeholder functionality for s3 vector interaction".
        
        logger.info("Searching S3 Vector Store (Placeholder)... Miss.")
        return None

    def store(self, embedding: List[float], remediation: RemediationResponse, metadata: Dict[str, Any]):
        # Store as JSON in S3
        # Key structure: vectors/{rule_id}/{uuid}.json
        rule_id = metadata.get("rule_id", "unknown_rule")
        key = f"vectors/{rule_id}/{uuid.uuid4()}.json"
        
        data = {
            "embedding": embedding,
            "remediation": remediation.model_dump(),
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Create temp file and upload
        tmp_path = f"/tmp/{uuid.uuid4()}.json"
        with open(tmp_path, "w") as f:
            json.dump(data, f)
            
        try:
            self.storage.upload_file(tmp_path, key)
            logger.info(f"Stored remediation vector in S3: {key}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

def get_vector_store() -> VectorStore:
    if settings.APP_ENV == "local":
        return LocalVectorStore()
    return S3VectorStore()
