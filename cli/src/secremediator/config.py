import json
from pathlib import Path

CONFIG_DIR = Path.home() / ".secremediator"
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history.json"

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
