#!/usr/bin/env bash
# security-pipeline pre-push warning hook
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

# Parse session to count unpatched findings with severity breakdown
python3 - "$LATEST_SESSION" <<'PYEOF'
import sys, json, os

session_file = sys.argv[1]
try:
    with open(session_file) as f:
        session = json.load(f)
except Exception:
    sys.exit(0)

scan_id = session.get("scan_id", "unknown")
remediation_status = session.get("remediation_status", {})

# Use full vulnerability objects when available (preferred — includes severity)
vulns = session.get("vulnerabilities", [])
if vulns:
    total = len(vulns)
    unpatched_vulns = [v for v in vulns if remediation_status.get(v["id"]) != "applied"]
    unpatched = len(unpatched_vulns)

    # Severity breakdown of unpatched findings
    severity_counts = {}
    for v in unpatched_vulns:
        sev = v.get("severity", "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
else:
    # Fallback to IDs-only (older session format)
    vuln_ids = session.get("vulnerability_ids", [])
    total = len(vuln_ids)
    unpatched = sum(1 for v in vuln_ids if remediation_status.get(v) != "applied")
    severity_counts = {}

if unpatched == 0:
    sys.exit(0)

print(f"\n⚠️  security-pipeline: {unpatched} of {total} findings not yet patched (scan: {scan_id[:8]}...)")

# Show severity breakdown if available
priority_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR", "WARNING"]
shown = []
for sev in priority_order:
    if sev in severity_counts:
        shown.append(f"{severity_counts[sev]} {sev}")
other_sevs = {k: v for k, v in severity_counts.items() if k not in priority_order}
for sev, count in other_sevs.items():
    shown.append(f"{count} {sev}")
if shown:
    print(f"   Breakdown: {', '.join(shown)}")

# Check for generated reports
patches_dir = os.path.join(os.path.dirname(os.path.dirname(session_file)), "patches", scan_id)
reports = []
for sev in ("CRITICAL", "HIGH"):
    report = os.path.join(patches_dir, f"REPORT-{sev}.md")
    if os.path.exists(report):
        reports.append(f"REPORT-{sev}.md")
if reports:
    print(f"   Reports:   {', '.join(reports)} in .security-scan/patches/{scan_id[:8]}...")

print(f"   Review    : security-pipeline results {scan_id}")
print(f"   Apply     : security-pipeline apply {scan_id} --all")
print(f"   Re-scan   : security-pipeline run .")
print()
PYEOF

# Always exit 0 — this hook warns but never blocks
exit 0
