from abc import ABC, abstractmethod
import os
import shutil
import boto3
from ..config import settings
from ..logger import get_logger

logger = get_logger(__name__)

class StorageService(ABC):
    @abstractmethod
    def upload_file(self, file_path: str, key: str) -> str:
        """Uploads a file and returns the URI/path."""
        pass
    
    @abstractmethod
    def download_file(self, key: str, destination_path: str):
        """Downloads a file from storage."""
        pass

    @abstractmethod
    def list_files(self, prefix: str) -> list[str]:
        """Lists files with the given prefix."""
        pass

    @abstractmethod
    def delete_file(self, key: str):
        """Deletes a file."""
        pass

class LocalStorageService(StorageService):
    def __init__(self, base_dir: str = "local_storage"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)
        
    def upload_file(self, file_path: str, key: str) -> str:
        dest_path = os.path.join(self.base_dir, key)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(file_path, dest_path)
        logger.debug(f"Local storage upload: {file_path} -> {dest_path}")
        return dest_path

    def download_file(self, key: str, destination_path: str):
        source_path = os.path.join(self.base_dir, key)
        shutil.copy2(source_path, destination_path)

    def list_files(self, prefix: str) -> list[str]:
        # For local, prefix is a subdir
        search_path = os.path.join(self.base_dir, prefix)
        if not os.path.exists(search_path):
            return []
            
        files = []
        for root, _, filenames in os.walk(search_path):
            for filename in filenames:
                # Return relative key from base_dir
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, self.base_dir)
                files.append(rel_path)
        return files

    def delete_file(self, key: str):
        target_path = os.path.join(self.base_dir, key)
        if os.path.exists(target_path):
            os.remove(target_path)
            logger.debug(f"Deleted local file: {target_path}")

class S3StorageService(StorageService):
    def __init__(self, bucket: str = None):
        self.s3 = boto3.client(
            "s3", 
            region_name=settings.AWS_REGION
        )
        self.bucket = bucket or settings.S3_SOURCE_BUCKET_NAME
        
    def upload_file(self, file_path: str, key: str) -> str:
        self.s3.upload_file(file_path, self.bucket, key)
        logger.info(f"S3 upload: {file_path} -> s3://{self.bucket}/{key}")
        return f"s3://{self.bucket}/{key}"

    def download_file(self, key: str, destination_path: str):
        self.s3.download_file(self.bucket, key, destination_path)

    def list_files(self, prefix: str) -> list[str]:
        response = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        if "Contents" not in response:
            return []
        return [obj["Key"] for obj in response["Contents"]]

    def delete_file(self, key: str):
        self.s3.delete_object(Bucket=self.bucket, Key=key)
        logger.info(f"Deleted S3 file: s3://{self.bucket}/{key}")

def get_storage() -> StorageService:
    if settings.APP_ENV in ["local", "local_mock"]:
        return LocalStorageService()
    return S3StorageService()
