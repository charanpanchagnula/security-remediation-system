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

    @abstractmethod
    def upload_directory(self, local_path: str, prefix: str):
        """Uploads a directory recursively."""
        pass

    @abstractmethod
    def download_directory(self, prefix: str, local_path: str):
        """Downloads a directory recursively."""
        pass

class LocalStorageService(StorageService):
    def __init__(self, base_dir: str = "local_storage"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)
        
    def upload_file(self, file_path: str, key: str) -> str:
        """
        Uploads a file to the local storage directory.

        Args:
            file_path (str): The absolute path to the source file.
            key (str): The relative path (key) where the file should be stored.

        Returns:
            str: The absolute path to the stored file.
        """
        dest_path = os.path.join(self.base_dir, key)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.copy2(file_path, dest_path)
        logger.debug(f"Local storage upload: {file_path} -> {dest_path}")
        return dest_path

    def download_file(self, key: str, destination_path: str):
        """
        Downloads a file from local storage to a destination path.

        Args:
            key (str): The relative path (key) of the file in storage.
            destination_path (str): The absolute path where the file should be saved.
        """
        source_path = os.path.join(self.base_dir, key)
        shutil.copy2(source_path, destination_path)

    def list_files(self, prefix: str) -> list[str]:
        """
        Lists all files in local storage starting with the given prefix.

        Args:
            prefix (str): The directory prefix to search within.

        Returns:
            list[str]: A list of relative file paths (keys).
        """
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
        """
        Deletes a file from local storage.

        Args:
            key (str): The relative path (key) of the file to delete.
        """
        target_path = os.path.join(self.base_dir, key)
        if os.path.exists(target_path):
            os.remove(target_path)
            logger.debug(f"Deleted local file: {target_path}")
        else:
            logger.warning(f"File to delete not found: {target_path}")

    def upload_directory(self, local_path: str, prefix: str):
        """
        Recursively copies a local directory to storage.

        Args:
            local_path (str): The source directory path.
            prefix (str): The destination directory prefix in storage.
        """
        # Local to local copy
        dest_path = os.path.join(self.base_dir, prefix)
        if os.path.exists(dest_path):
            shutil.rmtree(dest_path)
        shutil.copytree(local_path, dest_path)
        logger.debug(f"Local dir copy: {local_path} -> {dest_path}")

    def download_directory(self, prefix: str, local_path: str):
        """
        Recursively downloads a directory from storage to a local path.

        Args:
            prefix (str): The source directory prefix in storage.
            local_path (str): The destination local directory path.
        """
        # Local to local copy
        source_path = os.path.join(self.base_dir, prefix)
        if os.path.exists(local_path):
            shutil.rmtree(local_path)
        shutil.copytree(source_path, local_path)
        logger.debug(f"Local dir copy: {source_path} -> {local_path}")

class S3StorageService(StorageService):
    def __init__(self, bucket: str = None):
        self.s3 = boto3.client(
            "s3", 
            region_name=settings.AWS_REGION
        )
        self.bucket = bucket or settings.S3_SOURCE_BUCKET_NAME
        
    def upload_file(self, file_path: str, key: str) -> str:
        """
        Uploads a file to the configured S3 bucket.

        Args:
            file_path (str): The absolute path to the local file.
            key (str): The S3 object key.

        Returns:
            str: The S3 URI of the uploaded file.
        """
        self.s3.upload_file(file_path, self.bucket, key)
        logger.info(f"S3 upload: {file_path} -> s3://{self.bucket}/{key}")
        return f"s3://{self.bucket}/{key}"

    def download_file(self, key: str, destination_path: str):
        """
        Downloads an object from S3 to a local file.

        Args:
            key (str): The S3 object key.
            destination_path (str): The local destination path.
        """
        self.s3.download_file(self.bucket, key, destination_path)

    def list_files(self, prefix: str) -> list[str]:
        """
        Lists all objects in the S3 bucket with the given prefix.

        Args:
            prefix (str): The S3 prefix to filter by.

        Returns:
            list[str]: A list of object keys.
        """
        response = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        if "Contents" not in response:
            return []
        return [obj["Key"] for obj in response["Contents"]]

    def delete_file(self, key: str):
        """
        Deletes an object from the S3 bucket.

        Args:
            key (str): The S3 object key.
        """
        self.s3.delete_object(Bucket=self.bucket, Key=key)
        logger.info(f"Deleted S3 file: s3://{self.bucket}/{key}")

    def upload_directory(self, local_path: str, prefix: str):
        """
        Recursively uploads a local directory to S3.

        Args:
            local_path (str): The local source directory.
            prefix (str): The S3 prefix to upload to.
        """
        for root, _, files in os.walk(local_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, local_path)
                s3_key = os.path.join(prefix, rel_path).replace("\\", "/") # Ensure forward slashes
                self.s3.upload_file(full_path, self.bucket, s3_key)
        logger.info(f"Uploaded directory {local_path} to s3://{self.bucket}/{prefix}")

    def download_directory(self, prefix: str, local_path: str):
        """
        Recursively downloads an S3 directory to a local path.

        Args:
            prefix (str): The S3 prefix to match.
            local_path (str): The local destination directory.
        """
        paginator = self.s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']
                rel_path = os.path.relpath(key, prefix)
                dest_path = os.path.join(local_path, rel_path)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                self.s3.download_file(self.bucket, key, dest_path)
        logger.info(f"Downloaded s3://{self.bucket}/{prefix} to {local_path}")

def get_storage() -> StorageService:
    if settings.APP_ENV in ["local", "local_mock"]:
        return LocalStorageService()
    return S3StorageService()
