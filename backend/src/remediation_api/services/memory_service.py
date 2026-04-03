"""
Memory service — reads and writes the agent memory layer.

Two public functions:
  load_agent_context(scanner, rule_id, project_id) -> str
      Call before running an agent. Returns a memory block to prepend
      to the agent prompt. Empty string if no memories exist yet.

  consolidate_learnings(scan_data) -> None
      Call once after revalidate_scan completes. Reads every revalidated
      remediation, extracts a learning entry, and appends it to the
      appropriate rule memory file. Updates the global INDEX.md.

Memory is stored via MemoryStore (filesystem locally, S3 in production).
The key schema is:
  INDEX.md                           global pointer index (≤200 lines)
  global/rules/{scanner}__{rule}.md  per-rule knowledge, cross-project
  projects/{project_id}/INDEX.md     per-project pointers (future use)
"""
import threading
from datetime import datetime, timezone
from typing import Optional

from .memory_store import memory_store
from ..logger import get_logger

logger = get_logger(__name__)

_memory_lock = threading.Lock()

_MAX_INDEX_LINES = 200


# ------------------------------------------------------------------ #
# Key helpers
# ------------------------------------------------------------------ #

def _rule_key(scanner: str, rule_id: str) -> str:
    """Stable S3-safe key for a scanner+rule pair."""
    safe_rule = rule_id.replace("/", "__")
    safe_scanner = scanner.replace("/", "__")
    return f"global/rules/{safe_scanner}__{safe_rule}.md"


def _project_index_key(project_id: str) -> str:
    safe = project_id.replace("/", "_").replace(" ", "_")
    return f"projects/{safe}/INDEX.md"


# ------------------------------------------------------------------ #
# Public: load context for agent
# ------------------------------------------------------------------ #

def load_agent_context(scanner: str, rule_id: str, project_id: str) -> str:
    """
    Build the memory context string to prepend to the agent prompt.
    Returns an empty string on first encounter (no memories yet).
    """
    parts: list[str] = []

    rule_content = memory_store.get(_rule_key(scanner, rule_id))
    if rule_content:
        parts.append(rule_content)

    proj_content = memory_store.get(_project_index_key(project_id))
    if proj_content:
        parts.append(proj_content)

    if not parts:
        return ""

    body = "\n\n---\n\n".join(parts)
    return (
        "## Prior Knowledge From Previous Scans\n\n"
        f"{body}\n\n"
        "Apply these learnings when planning your fix. "
        "Always verify file paths and patterns against the actual codebase "
        "before acting — memories can be stale.\n\n"
    )


# ------------------------------------------------------------------ #
# Public: consolidate learnings after revalidation
# ------------------------------------------------------------------ #

def consolidate_learnings(scan_data: dict) -> None:
    """
    Extract one learning entry per revalidated remediation and append it
    to the matching rule memory file. Creates the file on first encounter.
    Updates the global INDEX.md for any newly created rule files.
    """
    remediations = scan_data.get("remediations", [])
    vulns_by_id = {v["id"]: v for v in scan_data.get("vulnerabilities", [])}
    project_id = scan_data.get("project_name", "unknown")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    new_rule_keys: set[tuple[str, str, str]] = set()

    for rem in remediations:
        status = rem.get("revalidation_status")
        if not status:
            continue

        vuln_id_key = rem.get("vulnerability_id", "")
        vuln = vulns_by_id.get(vuln_id_key)
        if vuln is None:
            logger.warning(f"[memory] consolidate_learnings: vuln {vuln_id_key!r} not found in scan, skipping")
            continue
        scanner = vuln.get("scanner", "unknown")
        rule_id = vuln.get("rule_id", "")
        if not rule_id:
            continue

        learning = _build_learning_entry(rem, vuln, status, project_id, today)
        if not learning:
            continue

        key = _rule_key(scanner, rule_id)
        _append_to_rule_memory(key, rule_id, scanner, learning, today)
        new_rule_keys.add((key, scanner, rule_id))

    for key, scanner, rule_id in new_rule_keys:
        _ensure_indexed(key, scanner, rule_id)

    logger.info(
        f"[memory] consolidate_learnings complete — "
        f"{len(new_rule_keys)} rule file(s) updated for scan {scan_data.get('scan_id', '?')}"
    )


# ------------------------------------------------------------------ #
# Internal helpers
# ------------------------------------------------------------------ #

def _build_learning_entry(
    rem: dict,
    vuln: dict,
    status: str,
    project_id: str,
    today: str,
) -> Optional[str]:
    summary = (rem.get("summary") or rem.get("explanation") or "").strip()
    file_path = vuln.get("file_path", "?")
    changes = rem.get("code_changes", [])
    files_modified = sorted({c.get("file_path", "") for c in changes if c.get("file_path")})

    if status == "FALSE_POSITIVE" or (status == "PASS" and rem.get("is_false_positive")):
        return (
            f"### False Positive [{today}] project={project_id}\n"
            f"- Flagged file: `{file_path}`\n"
            f"- Agent reasoning: {summary}\n"
            f"- Action taken: no code change (correctly identified as false positive)"
        )

    if status == "PASS":
        files_str = ", ".join(f"`{f}`" for f in files_modified) or "none"
        return (
            f"### Successful Fix [{today}] project={project_id}\n"
            f"- Flagged file: `{file_path}`\n"
            f"- Fix applied: {summary}\n"
            f"- Files modified: {files_str}"
        )

    if status in ("FAIL_STILL_VULNERABLE", "FAIL_NEW_ISSUES", "FAIL_BOTH"):
        files_str = ", ".join(f"`{f}`" for f in files_modified) or "none"
        return (
            f"### Failed Attempt [{today}] status={status} project={project_id}\n"
            f"- Flagged file: `{file_path}`\n"
            f"- Attempted: {summary}\n"
            f"- Files touched: {files_str}\n"
            f"- Outcome: {status} — avoid repeating this approach"
        )

    return None


def _append_to_rule_memory(
    key: str,
    rule_id: str,
    scanner: str,
    learning: str,
    today: str,
) -> None:
    with _memory_lock:
        existing = memory_store.get(key)

        if existing is None:
            content = (
                f"---\n"
                f"rule_id: {rule_id}\n"
                f"scanner: {scanner}\n"
                f"created: {today}\n"
                f"last_updated: {today}\n"
                f"---\n\n"
                f"# Rule Memory: {rule_id}\n\n"
                f"{learning}\n"
            )
        else:
            # Update last_updated in frontmatter
            lines = existing.splitlines()
            for i, line in enumerate(lines):
                if line.startswith("last_updated:"):
                    lines[i] = f"last_updated: {today}"
                    break
            content = "\n".join(lines) + f"\n\n{learning}\n"

        memory_store.put(key, content)


def _ensure_indexed(key: str, scanner: str, rule_id: str) -> None:
    """Add a pointer to the global INDEX.md if not already present."""
    with _memory_lock:
        index = memory_store.get("INDEX.md") or "# Memory Index\n\n"
        if key in index:
            return

        entry = f"- [{scanner}/{rule_id}]({key})"
        index = index.rstrip() + f"\n{entry}\n"

        # Enforce the 200-line cap (silent truncation, same as Claude Code)
        lines = index.splitlines()
        if len(lines) > _MAX_INDEX_LINES:
            lines = lines[:_MAX_INDEX_LINES]
            index = "\n".join(lines) + "\n"

        memory_store.put("INDEX.md", index)
