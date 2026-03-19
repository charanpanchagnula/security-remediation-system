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
    Returns the path to the temp archive file (caller must delete it).
    """
    source_path = Path(source_dir).resolve()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
    tmp.close()

    with tarfile.open(tmp.name, "w:gz") as tar:
        for item in source_path.rglob("*"):
            # Skip excluded dirs
            if any(part in EXCLUDE_DIRS for part in item.parts):
                continue
            if item.is_file():
                tar.add(item, arcname=str(item.relative_to(source_path)))

    return tmp.name
