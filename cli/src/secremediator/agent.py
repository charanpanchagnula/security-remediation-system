"""
LocalClaudeRemediator: generates security patches via a 4-turn conversation loop.

Turn 1 — Analyze:    Is this a real vulnerability? What is the root cause?
Turn 2 — Strategize: What fix approach? Any tradeoffs?
Turn 3 — Generate:   Produce the patch JSON.
Turn 4 — Evaluate:   Does the patch look correct? Any regressions?

This mirrors the backend orchestrator/generator/evaluator agent pattern.
Activated via --use-local-claude flag on the remediate-all command.
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

EVALUATE_SCHEMA = """{
  "approved": true or false,
  "concerns": ["list of concerns, empty if approved"]
}"""


class LocalClaudeRemediator:
    """
    Uses the Anthropic Python SDK with a 4-turn conversation to generate a
    remediation patch for a single vulnerability.
    Returns a dict matching the patch.json schema.
    """

    def __init__(self, model: str = "claude-sonnet-4-5"):
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        self.model = model

    def generate_patch(self, vulnerability: dict, source_code: str) -> dict:
        """
        4-turn loop: Analyze → Strategize → Generate → Evaluate.
        Short-circuits to false-positive result if Turn 1 determines FP.
        Raises ValueError if Turn 4 rejects the patch or JSON is unparseable.
        """
        messages = []

        # Turn 1 — Analyze
        messages.append({"role": "user", "content": self._analyze_prompt(vulnerability, source_code)})
        analysis = self._call(messages, max_tokens=1024)
        messages.append({"role": "assistant", "content": analysis})

        # Short-circuit: false positive detected in analysis
        if any(phrase in analysis.lower() for phrase in ["false positive", "not a vulnerability", "not exploitable"]):
            return {
                "summary": f"False positive: {analysis[:200]}",
                "confidence_score": 1.0,
                "is_false_positive": True,
                "code_changes": [],
                "security_implications": [],
            }

        # Turn 2 — Strategize
        messages.append({"role": "user", "content": (
            "Good analysis. Now describe your fix strategy. "
            "What approach will you use? What are the tradeoffs? "
            "Respond in plain text — no JSON yet."
        )})
        strategy = self._call(messages, max_tokens=1024)
        messages.append({"role": "assistant", "content": strategy})

        # Turn 3 — Generate
        messages.append({"role": "user", "content": (
            f"Now produce the patch. Respond with ONLY a JSON object matching this schema "
            f"(no markdown, no explanation):\n{PATCH_SCHEMA}"
        )})
        raw_patch = self._call(messages, max_tokens=2048)
        messages.append({"role": "assistant", "content": raw_patch})
        patch = self._parse_json(raw_patch)

        # Turn 4 — Evaluate
        messages.append({"role": "user", "content": (
            f"Review the patch you just produced. Does it correctly fix the vulnerability "
            f"without introducing regressions? Respond with ONLY a JSON object:\n{EVALUATE_SCHEMA}"
        )})
        raw_eval = self._call(messages, max_tokens=1024)
        evaluation = self._parse_json(raw_eval)

        if not evaluation.get("approved", False):
            concerns = evaluation.get("concerns", [])
            raise ValueError(f"Patch rejected by evaluator: {'; '.join(concerns)}")

        return patch

    def _call(self, messages: list, max_tokens: int) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=messages,
        )
        return response.content[0].text.strip()

    def _parse_json(self, text: str) -> dict:
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError as e:
            raise ValueError(f"Claude returned non-JSON: {e}\n{text[:200]}")

    def _analyze_prompt(self, vuln: dict, source_code: str) -> str:
        return f"""You are a security engineer performing a code review.

Vulnerability report:
- Scanner: {vuln.get('scanner')}
- Rule: {vuln.get('rule_id')}
- Severity: {vuln.get('severity')}
- Message: {vuln.get('message')}
- File: {vuln.get('file_path')}
- Lines: {vuln.get('start_line')}–{vuln.get('end_line')}

Code:
{source_code}

Analyze this finding:
1. Is this a real vulnerability or a false positive? Why?
2. What is the root cause?
3. What is the potential impact?

Respond in plain text."""
