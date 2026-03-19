# security-pipeline CLI

Local security scanning CLI and Claude Code MCP plugin for the Security Remediation System.

## Prerequisites

- Python 3.12+
- uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Security Remediation System API running (see docker-compose.yml in repo root)

## Install

```bash
cd cli
uv tool install --editable . --force
```

## Usage

```bash
# Full pipeline: scan → patch → revalidate → reports
security-pipeline run ./my-project

# Or step by step:
security-pipeline scan ./my-project --scanners semgrep,checkov
security-pipeline status
security-pipeline results <scan_id>
security-pipeline remediate-all <scan_id>
security-pipeline apply <scan_id> --all
```

## Output

After `run` or `remediate-all`, these files are written to the scanned repo:

```
.security-scan/                        # gitignored automatically
├── sessions/
│   └── <scan_id>.json                 # scan metadata + full vulnerability details
└── patches/
    └── <scan_id>/
        ├── REPORT-CRITICAL.md         # generated when CRITICAL findings exist
        ├── REPORT-HIGH.md             # generated when HIGH findings exist
        └── <vuln_id>/
            ├── patch.json             # AI-generated code changes
            └── revalidation.json      # PASS / FAIL_* from batch revalidation
```

**Reports** include: rule ID, file/line, vulnerability message, patch summary, confidence score, before/after code diff, revalidation status, security implications, and evaluation concerns.

**Sessions** store the full vulnerability list (severity, rule, file, scanner) and track which patches have been applied.

## Special handling

- **Lock files** (`uv.lock`, `poetry.lock`, `package-lock.json`, etc.) — skipped automatically; fix dependency CVEs via your package manager
- **False positives** — when local Claude flags a finding as unexploitable, it's excluded from patching and noted in reports
- **Evaluation concerns** — recorded in patches when Claude has partial confidence; visible in REPORT-*.md

## Claude Code Integration

### Option A — Install the plugin (recommended)

```bash
./install-plugin.sh [--api-url http://localhost:8000]
```

This registers the MCP server in `~/.claude/claude_desktop_config.json`. Restart Claude Code after running.

The plugin includes:
- **11 MCP tools** for scanning, patching, and applying fixes
- **Skill** `/security-pipeline:security-scan` for guided workflows
- **Pre-push hook** that warns when unpatched findings exist before `git push`

### Option B — Manual MCP setup

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-pipeline": {
      "command": "security-pipeline-mcp",
      "env": {
        "SECURITY_PIPELINE_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

### Install the skill

```bash
mkdir -p ~/.claude/skills
cp cli/skills/security-scan.md ~/.claude/skills/
```

Restart Claude Code, then use `/security-scan` in any conversation.

## Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `SECURITY_PIPELINE_API_URL` | `http://localhost:8000` | Backend API URL |
| `ANTHROPIC_API_KEY` | (from env) | Used by local Claude for patch generation; picked up automatically |

The CLI also stores config and scan history in `~/.security-pipeline/`:

```bash
# Override API URL persistently
echo '{"api_url": "https://your-internal-api.company.com"}' > ~/.security-pipeline/config.json
```
