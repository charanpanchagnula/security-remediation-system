import logging
import json
from typing import List, Dict, Optional, Any
from abc import ABC, abstractmethod
import boto3
import uuid
from datetime import datetime
from pydantic import BaseModel
from agno.knowledge.knowledge import Knowledge
# from agno.vectordb.lancedb import LanceDb # Moved to local import
from agno.knowledge.embedder.openai import OpenAIEmbedder
from src.remediation_api.config import settings
from src.remediation_api.logger import get_logger

logger = get_logger(__name__)

class VectorStore(ABC):
    @abstractmethod
    def search(self, query_text: str, limit: int = 1, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def store(self, rule_id: str, remediation_text: str, original_code: str, scan_id: str, scanner_type: str):
        pass

    @abstractmethod
    def delete_scan(self, scan_id: str):
        pass

class AgnoVectorStore(VectorStore):
    """
    Implementation using Agno's Knowledge Base with LanceDB.
    """
    def __init__(self, db_uri: str = "work_dir/lancedb"):
        """
        Initializes the Agno Knowledge Base with LanceDB.

        Args:
            db_uri (str): The path to the LanceDB directory. Defaults to "work_dir/lancedb".
        """
        try:
            from agno.vectordb.lancedb import LanceDb
        except ImportError:
            logger.error("lancedb module not found. Please install with `pip install lancedb`")
            raise

        self.db_uri = db_uri
        
        self.knowledge_base = Knowledge(
            vector_db=LanceDb(
                table_name="remediations",
                uri=self.db_uri,
                embedder=OpenAIEmbedder(id="text-embedding-3-small", api_key=settings.OPENAI_API_KEY),
            ),
        )

    def search(self, query_text: str, limit: int = 1, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Uses Agno's built-in search to find relevant remediations.
        Converts distance scores to similarity (1.0 - distance).

        Args:
            query_text (str): The search query (usually code/context).
            limit (int): The maximum number of results to return.
            filters (Optional[Dict]): Metadata filters (e.g. {'scanner': 'semgrep'}).

        Returns:
            List[Dict[str, Any]]: List of matches containing score, remediation, and rule_id.
        """
        if not settings.OPENAI_API_KEY:
            logger.warning("OPENAI_API_KEY not set. Skipping vector search.")
            return []

        try:
            # Agno's search returns a list of Document objects with scores
            results = self.knowledge_base.search(query=query_text, max_results=limit)
            
            hits = []
            for res in results:
                if res.meta_data:
                    # LanceDB returns distance. Convert to similarity.
                    distance = res.score if hasattr(res, 'score') else 0.0
                    similarity = 1.0 - distance

                    match = True
                    if filters:
                        for key, value in filters.items():
                            if res.meta_data.get(key) != value:
                                match = False
                                break
                    
                    if match:
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

    def store(self, rule_id: str, remediation_text: str, original_code: str, scan_id: str, scanner_type: str):
        """
        Wraps the remediation as a Document and loads it into the Knowledge Base (LanceDB).

        Args:
            rule_id (str): The scanner rule ID associated with the fix.
            remediation_text (str): The generated fix/explanation.
            original_code (str): The original vulnerable code snippet (for context).
            scan_id (str): The original scan ID.
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
                    "scanner": scanner_type,
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
    """
    Native AWS S3 Vectors Implementation.
    Uses the 's3vectors' boto3 client to interact with AWS S3 Vector Buckets.
    Stateless and Serverless.
    """
    def __init__(self):
        self.bucket = settings.S3_VECTOR_BUCKET_NAME
        self.metadata_bucket = settings.S3_RESULTS_BUCKET_NAME # Use standard bucket for offload
        self.index_name = "remediations" 
        try:
            self.client = boto3.client("s3vectors", region_name=settings.AWS_REGION)
            logger.info("Successfully initialized s3vectors client.")
        except Exception as e:
            logger.error(f"Failed to initialize s3vectors client: {e}")
            self.client = None
            
        try:
            self.s3_client = boto3.client("s3", region_name=settings.AWS_REGION)
            logger.info("Successfully initialized standard s3 client for vector store.")
        except Exception as e:
            logger.error(f"Failed to initialize standard s3 client: {e}")
            self.s3_client = None

        self.embedder = OpenAIEmbedder(id="text-embedding-3-small", api_key=settings.OPENAI_API_KEY)

    def store(self, rule_id: str, remediation_text: str, original_code: str, scan_id: str, scanner_type: str):
        """
        Stores a vector representing a remediation plan, with offloading for large content.

        Architecture:
        1. Generates an embedding for the remediation context.
        2. Offloads the full `remediation_text` (JSON) to a standard S3 bucket.
           Constraint: S3 Vectors/OpenSearch metadata is often limited (e.g., 2KB).
        3. Stores the embedding in the S3 Vector Store, including a pointer (`s3_key`) to the offloaded file.
        """
        if not settings.OPENAI_API_KEY:
            logger.warning("OPENAI_API_KEY not set. Skipping vector storage.")
            return

        if not self.client:
            logger.error("S3 Vectors client not initialized. Cannot store vector.")
            return

        try:
            # 1. Generate Embedding from content context
            content = f"Rule: {rule_id}\nCode Context:\n{original_code}\nRemediation:\n{remediation_text}"
            embedding = self.embedder.get_embedding(content)
            
            # 2. Prepare Payload identifiers
            vector_id = str(uuid.uuid4())
            
            # 3. Offload Metadata to Standard S3
            # We store the full large remediation artifact here.
            metadata_key = f"vectors/metadata/{vector_id}.json"
            
            if self.s3_client and self.metadata_bucket:
                try:
                    self.s3_client.put_object(
                        Bucket=self.metadata_bucket,
                        Key=metadata_key,
                        Body=remediation_text,
                        ContentType="application/json"
                    )
                    # Offload successful, proceed to vector storage
                except Exception as s3_e:
                    logger.error(f"Failed to offload metadata to S3: {s3_e}")
                    # If offload fails, we abort to prevent 'ghost' vectors pointing to nothing.
                    return 
            else:
                 logger.warning(f"S3 Client or Bucket not available. Skipping offload. s3_client={bool(self.s3_client)}, bucket={self.metadata_bucket}") 

            # 4. Put Vector into Index
            # We persist the `s3_key` in the potentially filterable metadata.
            self.client.put_vectors(
                vectorBucketName=self.bucket,
                indexName=self.index_name,
                vectors=[
                    {
                        "key": vector_id,
                        "data": {
                            "float32": embedding
                        },
                        "metadata": {
                            # Key metadata used for search filtering and retrieval
                            "rule_id": rule_id,
                            "s3_key": metadata_key, # Pointer to full content
                            "scan_id": scan_id,
                            "scanner": scanner_type,
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    }
                ]
            )
            # Success (logging silenced to reduce noise)
            
        except Exception as e:
            logger.error(f"Failed to store vector via S3 Vectors: {e}")

    def search(self, query_text: str, limit: int = 1, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Searches for remediations using semantic similarity.

        Flow:
        1. Embeds the user query.
        2. Queries S3 Vectors for nearest neighbors.
        3. Resolves the full remediation content by fetching the offloaded file from S3 using `s3_key`.
        """
        if not settings.OPENAI_API_KEY:
            return []
            
        if not self.client:
            logger.error("S3 Vectors client not initialized. Cannot search vectors.")
            return []

        try:
            # 1. Embed Query
            query_vec = self.embedder.get_embedding(query_text)
            
            # 2. Query S3 Vectors
            query_params = {
                "vectorBucketName": self.bucket,
                "indexName": self.index_name,
                "queryVector": {
                    "float32": query_vec
                },
                "topK": limit,
                "returnMetadata": True # Critical: Request metadata to get the s3_key
            }
            
            if filters:
                query_params["filter"] = filters

            response = self.client.query_vectors(**query_params)
            
            results = []
            
            # 3. Parse and Rehydrate
            # Iterate through lowercase 'vectors' list from API response
            for hit in response.get("vectors", []):
                meta = hit.get("metadata", {})
                remediation_content = meta.get("remediation", "") 
                
                # Retrieve offloaded content from S3
                s3_key = meta.get("s3_key")
                if s3_key and self.s3_client and self.metadata_bucket:
                    try:
                        s3_obj = self.s3_client.get_object(Bucket=self.metadata_bucket, Key=s3_key)
                        remediation_content = s3_obj["Body"].read().decode("utf-8")
                    except Exception as s3_e:
                        logger.error(f"Failed to retrieve offloaded metadata from {s3_key}: {s3_e}")
                        # Graceful degradation: return match without content if retrieval fails.
                
                results.append({
                    "score": hit.get("score", 0.0), 
                    "remediation": remediation_content, 
                    "rule_id": meta.get("rule_id", ""),
                    "scan_id": meta.get("scan_id", "")
                })
            
            if results:
                logger.info(f"S3 Vector Search Hit: {len(results)} results")
            
            return results

        except Exception as e:
            logger.error(f"S3 Vector Search failed: {e}")
            return []



    def delete_scan(self, scan_id: str):
        """
        Deletes vectors for a scan. 
        """
        logger.warning(f"Deletion logic for {scan_id} is pending S3 Vectors 'DeleteByQuery' availability.")


def get_vector_store() -> VectorStore:
    # Use Agno Store for Local/Dev
    if settings.APP_ENV in ["local", "local_mock"]:
        return AgnoVectorStore()
    return S3VectorStore()
