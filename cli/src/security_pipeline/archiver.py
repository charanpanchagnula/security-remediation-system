import os
import tarfile
import tempfile
from pathlib import Path

EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".next", "dist", "build",
}


def create_archive(source_dir: str) -> str:
    """
    Creates a tar.gz of source_dir, skipping common noise directories.
    Symlinks are never followed to prevent path traversal outside source_dir.
    Returns the path to the temp archive file (caller must delete it).
    """
    source_path = Path(source_dir).resolve()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
    tmp.close()

    try:
        with tarfile.open(tmp.name, "w:gz") as tar:
            for item in source_path.rglob("*"):
                # Skip excluded dirs
                if any(part in EXCLUDE_DIRS for part in item.parts):
                    continue
                # Never follow symlinks — they could point outside source_dir
                if item.is_symlink() or not item.is_file():
                    continue
                tar.add(item, arcname=str(item.relative_to(source_path)))
    except Exception:
        # Clean up the temp file if archiving fails so the caller never sees a
        # partial archive and we don't leak temp files.
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise

    return tmp.name
