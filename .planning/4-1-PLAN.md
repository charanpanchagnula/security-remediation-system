<task type="auto">
  <name>Upgrade LocalClaudeRemediator to multi-turn conversation loop</name>
  <files>
    cli/src/secremediator/agent.py
  </files>
  <action>
    Rewrite cli/src/secremediator/agent.py. Public API stays identical.

    Replace the entire file with:

    ```python
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
    ```
  </action>
  <verify>
    cd cli
    source .venv/bin/activate
    # Verify import and class structure
    python -c "
    from src.secremediator.agent import LocalClaudeRemediator
    import inspect
    src = inspect.getsource(LocalClaudeRemediator.generate_patch)
    assert '_analyze_prompt' in src
    assert 'Strategize' in src
    assert 'Evaluate' in src
    assert 'approved' in src
    print('PASS: multi-turn loop structure present')
    "
    # Verify false-positive short-circuit (no API call needed)
    python -c "
    from unittest.mock import patch, MagicMock
    from src.secremediator.agent import LocalClaudeRemediator
    r = LocalClaudeRemediator()
    mock_resp = MagicMock()
    mock_resp.content = [MagicMock(text='This is a false positive — not exploitable.')]
    with patch.object(r.client.messages, 'create', return_value=mock_resp) as m:
        result = r.generate_patch({'scanner': 'semgrep', 'rule_id': 'test', 'severity': 'HIGH',
                                   'message': 'test', 'file_path': 'foo.py',
                                   'start_line': 1, 'end_line': 1}, 'code here')
    assert result['is_false_positive'] == True
    assert m.call_count == 1, f'Expected 1 API call for FP short-circuit, got {m.call_count}'
    print('PASS: false-positive short-circuit works (1 API call)')
    "
  </verify>
  <done>
    - agent.py has 4-turn loop: Analyze → Strategize → Generate → Evaluate
    - generate_patch() public signature unchanged
    - False positive detected in Turn 1 short-circuits (returns immediately, no further turns)
    - Turn 4 rejection raises ValueError with concerns
    - Single-turn TODO comment replaced with descriptive module docstring
    - _call() helper centralises API calls; _parse_json() handles fence stripping
  </done>
</task>
