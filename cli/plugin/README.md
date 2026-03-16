# secremediator Claude Code Plugin

A Claude Code plugin that bundles the `secremediator` MCP server, security scan skill, and pre-push warning hook into one installable unit.

## What it includes

- **MCP Server** — 11 tools for security scanning, remediation, and patch management
- **Skill** — `/secremediator:security-scan` — guided security scan workflow (quick mode or manual)
- **Hook** — Pre-push warning when unpatched security findings exist in `.security-scan/`

## Prerequisites

1. **Backend running** — the secremediator API backend must be accessible:
   ```bash
   export SECREMEDIATOR_API_URL=http://localhost:8000
   ```

2. **CLI installed** — `secremediator-mcp` must be in PATH:
   ```bash
   pip install secremediator
   # or
   uv tool install secremediator
   ```

## Installation

```bash
claude --plugin-dir path/to/cli/plugin
```

Or add to your Claude Code settings:
```json
{
  "plugins": ["path/to/cli/plugin"]
}
```

## Usage

### Quick security scan

Use the skill: `/secremediator:security-scan`

Or call the MCP tool directly: `run_full_pipeline`

### Apply generated patches

```bash
secremediator apply <scan_id> --all
```

### View findings

```bash
secremediator results <scan_id>
```

## MCP Tools Reference

| Tool | Description |
|------|-------------|
| `run_full_pipeline` | Archive → submit → poll → patch all → revalidate in one call |
| `run_security_scan` | Submit directory for scanning, returns scan_id immediately |
| `poll_scan_status` | Lightweight status check (use while waiting for scan to complete) |
| `get_scan_results` | Full findings with remediations for a completed scan |
| `get_vulnerability_detail` | Deep detail for a specific vulnerability |
| `request_remediation` | Queue AI remediation for a specific vulnerability |
| `remediate_all` | Run full remediation loop for a completed scan |
| `apply_remediation` | Apply a single generated patch to files on disk |
| `apply_all_remediations` | Apply all passing patches for a scan |
| `sync_sessions` | Refresh session state from backend for all sessions in .security-scan/ |
| `list_scans` | List all scans from local history |

## Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `SECREMEDIATOR_API_URL` | `http://localhost:8000` | Backend API URL |

## Patch Storage

Patches are stored locally in the scanned repository (gitignored by default):

```
.security-scan/
├── sessions/          # scan metadata and status
│   └── <scan_id>.json
└── patches/           # generated patches and revalidation results
    └── <scan_id>/
        └── <vuln_id>/
            ├── patch.json
            └── revalidation.json
```
