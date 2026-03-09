# secremediator CLI

Local security scanning CLI and Claude Code MCP plugin for the Security Remediation System.

## Prerequisites

- Python 3.12+
- uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Security Remediation System API running (see docker-compose.yml in repo root)

## Install

```bash
cd cli
uv venv
uv pip install -e .
```

## Usage

```bash
# Scan a directory
secremediator scan ./my-project --scanners semgrep,checkov

# Check all your scans
secremediator status

# View results
secremediator results <scan_id>
```

## Claude Code Integration

### 1. Install the MCP server

The MCP server is installed automatically when you run `uv pip install -e .`.

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secremediator": {
      "command": "secremediator-mcp",
      "env": {
        "SECREMEDIATOR_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

### 2. Install the skill

```bash
mkdir -p ~/.claude/skills
cp cli/skills/security-scan.md ~/.claude/skills/
```

Restart Claude Code. Then use `/security-scan` in any conversation.

## Configuration

The CLI stores config and scan history in `~/.secremediator/`.

To point the CLI at a different API instance:

```bash
# Edit ~/.secremediator/config.json
{ "api_url": "https://your-internal-api.company.com" }
```
