import os
import shutil
import uuid
import subprocess
import tarfile
from pathlib import Path
from typing import Optional
from .storage import get_storage
from ..config import settings
from ..logger import get_logger

logger = get_logger(__name__)

class GitHubService:
    def __init__(self):
        self.storage = get_storage()
        self.work_dir = Path(settings.WORK_DIR)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def _parse_repo_url(self, repo_url: str):
        """Extracts owner and repo from URL."""
        # Handles https://github.com/owner/repo
        parts = repo_url.rstrip("/").split("/")
        return parts[-2], parts[-1]

    async def download_and_store(self, repo_url: str, commit_sha: Optional[str] = None) -> str:
        owner, repo = self._parse_repo_url(repo_url)
        
        # Unique ID for this scan/download op
        scan_id = str(uuid.uuid4())
        clone_dir = self.work_dir / scan_id / "source"
        
        # Ensure parent dir exists
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        
        # Construct Git Command
        # Use simple clone with depth 1 if no commit_sha, otherwise fetch specific
        try:
            if commit_sha:
                # Clone full (or partial) then checkout
                # Optimization: clone specific branch? Hard if commit_sha is just hash.
                # Safer: clone, then checkout.
                logger.info(f"Cloning {repo_url} (checking out {commit_sha})...")
                subprocess.run(["git", "clone", repo_url, str(clone_dir)], check=True, capture_output=True)
                subprocess.run(["git", "checkout", commit_sha], cwd=clone_dir, check=True, capture_output=True)
            else:
                # Shallow clone default branch
                logger.info(f"Cloning {repo_url} (default branch)...")
                subprocess.run(["git", "clone", "--depth", "1", repo_url, str(clone_dir)], check=True, capture_output=True)
                
            # Remove .git directory to save space/time and avoid scanning it
            git_dir = clone_dir / ".git"
            if git_dir.exists():
                shutil.rmtree(git_dir)
                
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode() if e.stderr else str(e)
            logger.error(f"Git clone failed: {error_msg}")
            # Cleanup
            if clone_dir.parent.exists():
                shutil.rmtree(clone_dir.parent)
            raise Exception(f"Failed to clone repository: {error_msg}")

        # Create .tar.gz
        archive_name = f"{owner}-{repo}-{scan_id}.tar.gz"
        archive_path = self.work_dir / archive_name
        
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(clone_dir, arcname=".")
            
        # Upload to storage
        storage_key = f"archives/{archive_name}"
        stored_path = self.storage.upload_file(str(archive_path), storage_key)
        logger.info(f"Repository stored at {stored_path}")
        
        # Cleanup
        try:
            shutil.rmtree(clone_dir.parent)
            os.remove(archive_path)
        except Exception:
            pass # Best effort cleanup
            
        return storage_key

github_service = GitHubService()
