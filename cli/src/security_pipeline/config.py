import json
import shutil
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path.home() / ".security-pipeline"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history.json"
ARCHIVES_DIR = CONFIG_DIR / "archives"

DEFAULT_CONFIG = {
    "api_url": "http://localhost:8000",
}


def load_config() -> dict:
    CONFIG_DIR.mkdir(exist_ok=True)
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    return json.loads(CONFIG_FILE.read_text())


def get_api_url() -> str:
    return load_config().get("api_url", DEFAULT_CONFIG["api_url"])


def load_history() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text())
    except Exception:
        return []


def save_to_history(entry: dict):
    CONFIG_DIR.mkdir(exist_ok=True)
    history = load_history()
    history.insert(0, entry)
    HISTORY_FILE.write_text(json.dumps(history[:100], indent=2))


def save_archive(scan_id: str, archive_path: str) -> str:
    """Persist the scan archive so revalidation can use it later."""
    ARCHIVES_DIR.mkdir(exist_ok=True)
    dest = ARCHIVES_DIR / f"{scan_id}.tar.gz"
    shutil.copy2(archive_path, dest)
    return str(dest)


def get_archive_path(scan_id: str) -> Optional[str]:
    path = ARCHIVES_DIR / f"{scan_id}.tar.gz"
    return str(path) if path.exists() else None
