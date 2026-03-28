"""
MultiTurnRemediator: iterative multi-turn patch generation via Claude Agent SDK.

Unlike LocalClaudeRemediator (single-shot, no tools), this agent runs a SINGLE
multi-turn conversation where Claude uses tools to:
  1. Read source files (Read/Write/Edit/Grep/Glob tools)
  2. Generate a patch
  3. Apply the patch in a temp sandbox and run validation (Bash tool)
  4. Refine the patch if validation fails
  5. Repeat within the same conversation (full memory of prior turns)

Output format is backward-compatible with LocalClaudeRemediator.generate_patch().
"""
import json
import re
import asyncio
from dataclasses import dataclass
from typing import Optional

try:
    from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage
    CLAUDE_SDK_AVAILABLE = True
except ImportError:
    CLAUDE_SDK_AVAILABLE = False


@dataclass
class IterationEntry:
    iteration: int
    actions: list[str]
    patch_proposed: Optional[dict]
    validation_results: dict
    reasoning: str

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "actions": self.actions,
            "patch_proposed": self.patch_proposed,
            "validation_results": self.validation_results,
            "reasoning": self.reasoning,
        }


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
  "evaluation_concerns": ["empty if approved; list concerns if unresolved"],
  "iteration_log": [
    {"iteration": N, "actions": [...], "patch_proposed": {...},
     "validation_results": {...}, "reasoning": "..."}
  ]
}"""

SYSTEM_PROMPT = """You are an autonomous security remediation engineer.

Fix the given vulnerability using your tools in a single multi-turn conversation.
You have full memory of all prior tool calls and their results throughout this conversation.

## Workflow (use tools across as many turns as needed, up to MAX_ITERATIONS cycles):

**Each cycle:**
1. ANALYZE: Use Read/Grep/Glob to read the flagged file and any related files.
2. GENERATE: Formulate a patch (what lines to change and how).
3. VALIDATE: Use Bash to apply the patch in a temp sandbox and run validation:
   a. Copy the project: cp -r WORK_DIR /tmp/sandbox_fix
   b. Apply patch: edit files in /tmp/sandbox_fix
   c. compile_code — python -m py_compile, terraform validate, node --check
   d. run_linter — flake8, tflint, eslint (skip if not installed)
   e. run_static_analysis — semgrep --config=auto (skip if not installed)
   f. run_tests — pytest, npm test (skip if no test suite found)
   g. run_security_scan — semgrep/checkov/trivy on the patched code
   h. Clean up: rm -rf /tmp/sandbox_fix
4. EVALUATE: If all checks pass → finalize. If not → refine using what you learned and repeat.

## Rules:
- NEVER modify files in the original work_dir — always sandbox
- Only fix the flagged vulnerability, no unrelated changes
- Skip validation steps that don't apply (no test suite = skip run_tests)

## Output (after final cycle):
Respond with ONLY a JSON object — no markdown fences, no explanation.
The iteration_log field records every cycle's actions and results (you fill this in).
"""


class MultiTurnRemediator:
    def __init__(self, model: str = "claude-sonnet-4-6", max_iterations: int = 6):
        self.model = model
        self.max_iterations = max_iterations

    def remediate(self, vulnerability: dict, work_dir: str) -> tuple[dict, list]:
        """
        Run one multi-turn conversation where Claude uses tools to generate and
        validate a patch iteratively. Returns (patch_dict, iteration_log).
        patch_dict is backward-compatible with LocalClaudeRemediator.generate_patch().
        Raises RuntimeError if claude_agent_sdk unavailable.
        Raises ValueError if agent returns no result or non-JSON.
        """
        if not CLAUDE_SDK_AVAILABLE:
            raise RuntimeError(
                "claude_agent_sdk is not available. "
                "Multi-turn mode requires Claude Code as the host process."
            )
        return asyncio.run(self._run(vulnerability, work_dir))

    async def _run(self, vulnerability: dict, work_dir: str) -> tuple:
        result_text = None
        async for message in query(
            prompt=self._build_prompt(vulnerability, work_dir),
            options=ClaudeAgentOptions(
                model=self.model,
                system_prompt=SYSTEM_PROMPT,
                allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
                max_turns=self.max_iterations * 10,  # ~10 SDK turns per cycle: read, analyze, bash, validate
            ),
        ):
            if isinstance(message, ResultMessage):
                result_text = message.result

        if not result_text:
            raise ValueError("Agent returned no result")

        patch = self._parse_json(result_text)
        log = patch.pop("iteration_log", [])
        if not isinstance(log, list):
            log = []
        return patch, log

    def _build_prompt(self, vuln: dict, work_dir: str) -> str:
        scanner = vuln.get("scanner", "")
        fix_guidance = {
            "semgrep": "Replace the vulnerable code pattern with a secure equivalent (e.g. parameterized queries, safe APIs).",
            "checkov": "Add or modify Terraform resource attributes to satisfy the security control.",
            "trivy": "Update the vulnerable package to the minimum safe version in the manifest.",
        }.get(scanner, "Produce a minimal, correct fix.")

        return f"""## Vulnerability to fix

- Scanner: {vuln.get('scanner')}
- Rule: {vuln.get('rule_id')}
- Severity: {vuln.get('severity')}
- Message: {vuln.get('message')}
- File: {vuln.get('file_path')}
- Lines: {vuln.get('start_line')}–{vuln.get('end_line')}
- Fix guidance: {fix_guidance}

## Working directory (read-only source — sandbox modifications in /tmp/sandbox_fix)
{work_dir}

## Constraints
- Maximum cycles: {self.max_iterations}
- Only fix the flagged vulnerability — no unrelated changes
- Use your tools: Read to explore, Bash to validate in sandbox

## Output schema (respond with ONLY this JSON, no markdown):
{PATCH_SCHEMA}"""

    def _parse_json(self, text: str) -> dict:
        text = text.strip()
        if text.startswith("```"):
            inner = re.sub(r"^```(?:json)?\s*", "", text)
            inner = re.sub(r"\s*```$", "", inner).strip()
            try:
                return json.loads(inner)
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        raise ValueError(f"Agent returned non-JSON output:\n{text[:300]}")
