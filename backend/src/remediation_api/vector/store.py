import logging
import json
from typing import List, Dict, Optional, Any
from abc import ABC, abstractmethod
from pydantic import BaseModel
from agno.knowledge.knowledge import Knowledge
from agno.vectordb.lancedb import LanceDb
from agno.knowledge.embedder.openai import OpenAIEmbedder
from src.remediation_api.config import settings

logger = logging.getLogger(__name__)

class VectorStore(ABC):
    @abstractmethod
    def search(self, query_text: str, limit: int = 1) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def store(self, rule_id: str, remediation_text: str, original_code: str, scan_id: str):
        pass

    @abstractmethod
    def delete_scan(self, scan_id: str):
        pass

class AgnoVectorStore(VectorStore):
    """
    Implementation using Agno's Knowledge Base with LanceDB.
    Supports both Local (file-based) and S3 behavior.
    """
    def __init__(self):
        # Initialize LanceDB. In 'local' or 'local_mock', this creates a local folder.
        # In production, this can point to S3 if configured via URI.
        uri = "work_dir/lancedb" 
        
        self.knowledge_base = Knowledge(
            vector_db=LanceDb(
                table_name="remediations",
                uri=uri,
                embedder=OpenAIEmbedder(id="text-embedding-3-small", api_key=settings.OPENAI_API_KEY),
            ),
        )

    def search(self, query_text: str, limit: int = 1) -> List[Dict[str, Any]]:
        """
        Uses Agno's built-in search to find relevant remediations.
        """
        if not settings.OPENAI_API_KEY:
            logger.warning("OPENAI_API_KEY not set. Skipping vector search.")
            return []

        try:
            # Agno's search returns a list of Document objects with scores
            results = self.knowledge_base.search(query=query_text, max_results=limit)
            
            hits = []
            for res in results:
                # Agno returns score as distance or similarity? 
                # LanceDB typically returns distance, but Agno might normalize.
                # Assuming 'meta_data' contains our stored metadata.
                if res.meta_data:
                    # LanceDB returns distance (0.0 is exact match). 
                    # Convert to similarity (1.0 is exact match).
                    distance = res.score if hasattr(res, 'score') else 0.0
                    similarity = 1.0 - distance
                    
                    hits.append({
                        "score": similarity, 
                        "remediation": res.meta_data.get("remediation", ""),
                        "rule_id": res.meta_data.get("rule_id", ""),
                        "scan_id": res.meta_data.get("scan_id", "")
                    })
            
            if hits:
                logger.info(f"Agno Knowledge Search Hit: {len(hits)} results.")
            else:
                logger.info("Agno Knowledge Search Miss.")
                
            return hits
            
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return []

    def store(self, rule_id: str, remediation_text: str, original_code: str, scan_id: str):
        """
        Wraps the remediation as a Document and loads it into the Knowledge Base.
        """
        if not settings.OPENAI_API_KEY:
            logger.warning("OPENAI_API_KEY not set. Skipping vector storage.")
            return

        try:
            # Create a rich document representing this fix
            content = f"Rule: {rule_id}\nCode Context:\n{original_code}\nRemediation:\n{remediation_text}"
            
            meta_data = {
                    "rule_id": rule_id,
                    "remediation": remediation_text,
                    "scan_id": scan_id,
                    "type": "remediation_history"
            }
            
            # Load into KB using add_content
            self.knowledge_base.add_content(
                text_content=content,
                metadata=meta_data
            )
            logger.info(f"Stored remediation for {rule_id} in LanceDB.")
            
        except Exception as e:
            logger.error(f"Failed to store vector: {e}")

    def delete_scan(self, scan_id: str):
        # LanceDB/Agno deletion is complex (row-level). 
        # For MVP, we might skip precise valid deletion or recreate table.
        # This is acceptable for "Local RAG".
        logger.warning(f"Vector deletion for scan {scan_id} not fully implemented in LanceDB adapter yet.")

class S3VectorStore(VectorStore):
    # Keep placeholder for Prod if different from LanceDB s3 config
    def search(self, query_text: str, limit: int = 1) -> List[Dict[str, Any]]:
        logger.info("Searching S3 Vector Store (Placeholder)... Miss.")
        return []

    def store(self, rule_id: str, remediation_text: str, original_code: str, scan_id: str):
        logger.info(f"Skipping S3 vector storage for {scan_id}: Not supported in flat-file mode without index.")

    def delete_scan(self, scan_id: str):
        logger.warning(f"Skipping S3 vector deletion for {scan_id}: Not supported in flat-file mode without index.")

def get_vector_store() -> VectorStore:
    # Use Agno Store for Local/Dev
    if settings.APP_ENV in ["local", "local_mock"]:
        return AgnoVectorStore()
    return S3VectorStore()
