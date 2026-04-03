"""
Memory store — local filesystem backend.

Interface mirrors S3 (get / put / exists / list_prefix) so swapping to
an S3MemoryStore (or a Java S3 client) requires no changes to callers.

Layout under base_dir/memory/:
  INDEX.md                          — always-loaded global pointer index
  global/rules/<scanner>__<rule>.md — per-rule learnings (cross-project)
  projects/<project_id>/INDEX.md    — per-project pointers
"""
from pathlib import Path
from typing import Optional

from ..config import settings


class MemoryStore:
    def __init__(self, base_dir: Optional[str] = None):
        self._base = Path(base_dir or settings.WORK_DIR) / "memory"
        self._base.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Core operations (map 1-to-1 with S3 ListObjectsV2 / GetObject / PutObject)
    # ------------------------------------------------------------------ #

    def get(self, key: str) -> Optional[str]:
        """Return file content at key, or None if it does not exist."""
        path = self._base / key
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")

    def put(self, key: str, content: str) -> None:
        """Write content at key, creating parent directories as needed."""
        path = self._base / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def exists(self, key: str) -> bool:
        return (self._base / key).exists()

    def list_prefix(self, prefix: str) -> list[str]:
        """Return all keys whose path starts with prefix."""
        prefix_path = self._base / prefix
        if not prefix_path.exists():
            return []
        return [
            str(p.relative_to(self._base))
            for p in prefix_path.rglob("*")
            if p.is_file()
        ]


memory_store = MemoryStore()
