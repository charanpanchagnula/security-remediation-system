#!/usr/bin/env bash
# secremediator pre-push warning hook
# Warns (never blocks) when unpatched security findings exist before git push.
# Claude Code passes tool input via TOOL_INPUT env var as JSON.

# Only warn on git push commands
if [ -z "$TOOL_INPUT" ]; then
    exit 0
fi

# Check if this is a git push command
COMMAND=$(echo "$TOOL_INPUT" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('command', ''))" 2>/dev/null || echo "")
case "$COMMAND" in
    *"git push"*)
        ;;
    *)
        exit 0
        ;;
esac

# Find .security-scan/sessions/ in CWD or parents
find_sessions_dir() {
    local dir="$PWD"
    while [ "$dir" != "/" ]; do
        if [ -d "$dir/.security-scan/sessions" ]; then
            echo "$dir/.security-scan/sessions"
            return 0
        fi
        dir=$(dirname "$dir")
    done
    return 1
}

SESSIONS_DIR=$(find_sessions_dir)
if [ -z "$SESSIONS_DIR" ]; then
    exit 0
fi

# Find the most recent session file
LATEST_SESSION=$(ls -t "$SESSIONS_DIR"/*.json 2>/dev/null | head -1)
if [ -z "$LATEST_SESSION" ]; then
    exit 0
fi

# Parse session to count unpatched findings
python3 - "$LATEST_SESSION" <<'PYEOF'
import sys, json

session_file = sys.argv[1]
try:
    with open(session_file) as f:
        session = json.load(f)
except Exception:
    sys.exit(0)

scan_id = session.get("scan_id", "unknown")
vuln_ids = session.get("vulnerability_ids", [])
remediation_status = session.get("remediation_status", {})

total = len(vuln_ids)
patched = sum(1 for v in vuln_ids if remediation_status.get(v) == "applied")
unpatched = total - patched

if unpatched > 0:
    print(f"\n⚠️  secremediator: {unpatched} of {total} findings not yet patched (scan: {scan_id[:8]}...)")
    print(f"   Review patches : secremediator results {scan_id}")
    print(f"   Apply patches  : secremediator apply {scan_id} --all")
    print(f"   Or run pipeline: secremediator run .")
    print()
PYEOF

# Always exit 0 — this hook warns but never blocks
exit 0
