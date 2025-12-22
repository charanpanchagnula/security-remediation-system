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
        """
        Extracts owner and repo name from a standard GitHub URL.

        Args:
            repo_url (str): The full GitHub URL (e.g., https://github.com/owner/repo).

        Returns:
            tuple[str, str]: (owner, repo_name)
        """
        # Handles https://github.com/owner/repo
        parts = repo_url.rstrip("/").split("/")
        return parts[-2], parts[-1]

    async def download_and_store(self, repo_url: str, commit_sha: Optional[str] = None) -> tuple[str, str]:
        """
        Downloads a repository via GitHub API as a tarball, and uploads it to storage.
        
        Args:
            repo_url (str): The GitHub repository URL.
            commit_sha (Optional[str]): The specific commit to checkout. If None, uses default branch (via API).

        Returns:
            tuple[str, str]: (storage_key, resolved_commit_sha)
        """
        import httpx
        
        owner, repo = self._parse_repo_url(repo_url)
        
        # Unique ID for this scan/download op
        scan_id = str(uuid.uuid4())
        archive_name = f"{owner}-{repo}-{scan_id}.tar.gz"
        archive_path = self.work_dir / archive_name
        
        # Determine the ref (SHA or main/master)
        # If commit_sha is provided, use it. Otherwise, we can ask API for default branch or just use 'main' as fallback
        # Better: Use the API to get the default branch SHA first if not provided, to ensure we have a SHA to return.
        
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Security-Remediation-System"
        }
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

        resolved_sha = commit_sha

        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
            # 1. Resolve SHA if missing
            if not resolved_sha:
                try:
                    logger.info(f"Resolving default branch for {owner}/{repo}")
                    resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
                    resp.raise_for_status()
                    default_branch = resp.json().get("default_branch", "main")
                    
                    # Get SHA of default branch
                    resp_ref = await client.get(f"https://api.github.com/repos/{owner}/{repo}/commits/{default_branch}")
                    resp_ref.raise_for_status()
                    resolved_sha = resp_ref.json()["sha"]
                    logger.info(f"Resolved default branch '{default_branch}' to {resolved_sha}")
                except Exception as e:
                    logger.error(f"Failed to resolve default branch: {e}")
                    raise Exception(f"Failed to get repository info: {str(e)}")

            # 2. Download Tarball
            # API: GET /repos/{owner}/{repo}/tarball/{ref}
            download_url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{resolved_sha}"
            logger.info(f"Downloading source from {download_url}...")
            
            try:
                async with client.stream("GET", download_url) as response:
                    response.raise_for_status()
                    with open(archive_path, "wb") as f:
                        async for chunk in response.aiter_bytes():
                            f.write(chunk)
            except Exception as e:
                logger.error(f"Failed to download repository: {e}")
                # Analyze error (e.g., 404, 401)
                raise Exception(f"Failed to download repository archive: {str(e)}")

        # 3. Upload to storage (S3)
        # The storage service expects a path to a file
        storage_key = f"archives/{archive_name}"
        stored_path = self.storage.upload_file(str(archive_path), storage_key)
        logger.info(f"Repository stored at {stored_path}")
        
        # Cleanup local file
        try:
            os.remove(archive_path)
        except Exception:
            pass
            
        return storage_key, resolved_sha

github_service = GitHubService()