#!/usr/bin/env bash
# Installs the secremediator MCP server into Claude Code's config.
# Usage: ./install-plugin.sh [--api-url http://localhost:8000]

set -euo pipefail

API_URL="${SECREMEDIATOR_API_URL:-http://localhost:8000}"
CONFIG_FILE="${HOME}/.claude/claude_desktop_config.json"

# Parse --api-url flag
while [[ $# -gt 0 ]]; do
  case $1 in
    --api-url) API_URL="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# Resolve secremediator-mcp command path
MCP_CMD=$(which secremediator-mcp 2>/dev/null || echo "")
if [[ -z "$MCP_CMD" ]]; then
  echo "ERROR: secremediator-mcp not found in PATH."
  echo "Install first: uv tool install . (from the cli/ directory)"
  exit 1
fi

mkdir -p "$(dirname "$CONFIG_FILE")"

# Create config file if it doesn't exist
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo '{"mcpServers":{}}' > "$CONFIG_FILE"
fi

# Add or update secremediator entry using Python (avoids jq dependency)
python3 - <<PYEOF
import json, os, sys

config_path = os.path.expanduser("$CONFIG_FILE")
mcp_cmd = "$MCP_CMD"
api_url = "$API_URL"

with open(config_path) as f:
    config = json.load(f)

config.setdefault("mcpServers", {})["secremediator"] = {
    "command": mcp_cmd,
    "env": {
        "SECREMEDIATOR_API_URL": api_url,
        "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", ""),
    }
}

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print(f"✓ secremediator MCP server registered in {config_path}")
print(f"  API URL: {api_url}")
print(f"  Command: {mcp_cmd}")
print()
print("Restart Claude Code to pick up the change.")
PYEOF
