"""
LocalClaudeRemediator: generates security patches by calling the Anthropic API
directly from the CLI, bypassing the backend remediation engine.

Activated via --use-local-claude flag on the remediate-all command.

# TODO Phase 4: upgrade to multi-turn conversation loop
#   Turn 1 — Analyze: is this a real vulnerability? what is the root cause?
#   Turn 2 — Strategize: what fix approach? any tradeoffs?
#   Turn 3 — Generate: produce the patch JSON
#   Turn 4 — Evaluate: does the patch look correct? any regressions?
#   This mirrors the backend orchestrator/generator/evaluator agent pattern.
"""
import json
import anthropic
from typing import Optional


PATCH_SCHEMA = """{
  "summary": "one-line description of the fix",
  "confidence_score": 0.0 to 1.0,
  "is_false_positive": true or false,
  "code_changes": [
    {
      "file_path": "relative/path/to/file.py",
      "start_line": N,
      "end_line": N,
      "original_code": "exact lines being replaced",
      "new_code": "replacement lines",
      "description": "why this change fixes the issue"
    }
  ],
  "security_implications": ["list of security notes"]
}"""


class LocalClaudeRemediator:
    """
    Uses the Anthropic Python SDK to generate a remediation patch for a
    single vulnerability. Returns a dict matching the patch.json schema.
    """

    def __init__(self, model: str = "claude-sonnet-4-5"):
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        self.model = model

    def generate_patch(self, vulnerability: dict, source_code: str) -> dict:
        """
        Single-turn: send vulnerability context + code to Claude, get patch JSON back.
        Raises ValueError if Claude returns unparseable JSON.
        """
        prompt = self._build_prompt(vulnerability, source_code)
        message = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        text = message.content[0].text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            patch = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Claude returned non-JSON response: {e}\n{text[:200]}")
        return patch

    def _build_prompt(self, vuln: dict, source_code: str) -> str:
        return f"""You are a security engineer. Analyze this vulnerability and produce a fix.

Vulnerability:
- Scanner: {vuln.get('scanner')}
- Rule: {vuln.get('rule_id')}
- Severity: {vuln.get('severity')}
- Message: {vuln.get('message')}
- File: {vuln.get('file_path')}
- Lines: {vuln.get('start_line')}–{vuln.get('end_line')}

Code:
{source_code}

Respond with ONLY a JSON object matching this schema (no markdown, no explanation):
{PATCH_SCHEMA}"""
