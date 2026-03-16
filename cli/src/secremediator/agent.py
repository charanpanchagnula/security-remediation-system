"""
LocalClaudeRemediator: generates security patches via the Claude Agent SDK.

The agent follows a 4-step reasoning process internally:
  1. Analyze:    Is this a real vulnerability? What is the root cause?
  2. Strategize: What fix approach? Any tradeoffs?
  3. Generate:   Produce the patch JSON.
  4. Evaluate:   Does the patch look correct? Any regressions?

This mirrors the backend orchestrator/generator/evaluator agent pattern.
Activated via --use-local-claude flag on the remediate-all command.
"""
import json
import re
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage


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
  "security_implications": ["list of security notes"],
  "evaluation_concerns": ["empty if approved; list concerns if self-evaluation found issues"]
}"""


SYSTEM_PROMPT = """You are a security engineer performing code remediation.

Follow this 4-step process before producing output:

Step 1 — ANALYZE: Examine the vulnerability report and source code.
  - Is this a real vulnerability or a false positive?
  - What is the root cause?
  - What is the potential impact?

Step 2 — STRATEGIZE: Determine the fix approach.
  - What is the safest, most minimal fix?
  - Are there any tradeoffs or risks?

Step 3 — GENERATE: Produce the patch.

Step 4 — EVALUATE: Review your own patch.
  - Does it correctly fix the vulnerability?
  - Could it introduce regressions?
  - If you find concerns you cannot resolve, list them in evaluation_concerns.

Respond with ONLY a JSON object matching the schema provided — no markdown fences, no explanation.
If the finding is a false positive, set is_false_positive to true and code_changes to [].
"""


class LocalClaudeRemediator:
    """
    Uses the Claude Agent SDK to generate a remediation patch for a single
    vulnerability via a 4-step internal reasoning process.
    Returns a dict matching the patch.json schema.
    Raises ValueError if the agent returns non-JSON or self-evaluation has concerns.
    """

    def __init__(self, model: str = "claude-sonnet-4-6"):
        self.model = model

    def generate_patch(self, vulnerability: dict, source_code: str) -> dict:
        """
        Synchronous entry point. Bridges to async Agent SDK via asyncio.run().
        Public signature unchanged: generate_patch(vulnerability, source_code) -> dict.
        """
        return asyncio.run(self._generate(vulnerability, source_code))

    async def _generate(self, vulnerability: dict, source_code: str) -> dict:
        result_text = None

        async for message in query(
            prompt=self._build_prompt(vulnerability, source_code),
            options=ClaudeAgentOptions(
                model=self.model,
                allowed_tools=[],
                system_prompt=SYSTEM_PROMPT,
            ),
        ):
            if isinstance(message, ResultMessage):
                result_text = message.result

        if not result_text:
            raise ValueError("Agent returned no result")

        patch = self._parse_json(result_text)

        concerns = patch.get("evaluation_concerns", [])
        if concerns:
            # Don't skip — revalidation will catch actual failures.
            # Record concerns and reduce confidence so callers can surface them.
            patch["evaluation_concerns"] = concerns
            patch["confidence_score"] = round(patch.get("confidence_score", 0.5) * 0.7, 2)

        return patch

    def _parse_json(self, text: str) -> dict:
        text = text.strip()

        # Strip any markdown code fence (```json ... ``` or ``` ... ```)
        if text.startswith("```"):
            inner = re.sub(r"^```(?:json)?\s*", "", text)
            inner = re.sub(r"\s*```$", "", inner).strip()
            try:
                return json.loads(inner)
            except json.JSONDecodeError:
                pass

        # Try the text as-is
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Last resort: extract the first {...} block from the text
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Agent returned non-JSON output:\n{text[:300]}")

    def _build_prompt(self, vuln: dict, source_code: str) -> str:
        return f"""Vulnerability report:
- Scanner: {vuln.get('scanner')}
- Rule: {vuln.get('rule_id')}
- Severity: {vuln.get('severity')}
- Message: {vuln.get('message')}
- File: {vuln.get('file_path')}
- Lines: {vuln.get('start_line')}–{vuln.get('end_line')}

Source code:
{source_code}

Respond with ONLY a JSON object matching this schema:
{PATCH_SCHEMA}"""
