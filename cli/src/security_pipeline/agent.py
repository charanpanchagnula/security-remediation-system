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

try:
    from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage
    CLAUDE_SDK_AVAILABLE = True
except ImportError:
    CLAUDE_SDK_AVAILABLE = False


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


SYSTEM_PROMPT = """You are a remediation engineer focused on producing minimal, safe code patches.

Follow this 4-step process before producing output:

Step 1 — ANALYZE: Examine the vulnerability report and source code.
  Determine whether this is a real vulnerability, a false positive, or an inapplicable best practice.
  Use these criteria:

  Mark as FALSE POSITIVE (is_false_positive: true) if ANY of the following apply:
  - The scanner has misidentified the code construct (e.g., flagging a non-applicable resource type).
  - The control is a disaster-recovery or operational-availability requirement (e.g., cross-region
    replication, multi-AZ, backup retention) rather than a security control that prevents unauthorized
    access, data breach, or exploitation.
  - The control is a cost-management or lifecycle-hygiene practice (e.g., object expiry, storage-class
    transitions) with no direct security impact.
  - The control is an audit/monitoring nice-to-have (e.g., event notifications, access logging to a
    secondary bucket) and the codebase context (file path, project name, surrounding code) indicates a
    non-production, development, or internal tooling environment.
  - A compensating control already exists elsewhere in the visible source (e.g., versioning is already
    configured in a sibling resource in the same file).

  Mark as REAL (is_false_positive: false) if the finding represents a direct security risk:
  - Exposed secrets or credentials.
  - Missing encryption-at-rest or in-transit for sensitive data.
  - Overly permissive access controls (public buckets, wildcard IAM, open security groups).
  - Missing input validation or injection risk.
  - Mutable artifact tags that allow supply-chain substitution.
  - Missing access controls that could allow privilege escalation.

  Use the file path and project name to infer environment and sensitivity. A finding that would be
  critical in a production financial system may be inapplicable in a dev/internal tooling module.
  When in doubt, prefer marking as REAL (is_false_positive: false) over FALSE POSITIVE — it is
  safer to produce a fix that can be reviewed than to silently dismiss a genuine risk.

Step 2 — STRATEGIZE: Determine the fix approach.
  - What is the safest, most minimal fix?
  - Are there any tradeoffs or risks?

Step 3 — GENERATE: Produce the patch.

Step 4 — EVALUATE: Review your own patch.
  - Does it correctly fix the vulnerability?
  - Could it introduce regressions?
  - If you find concerns you cannot resolve, list them in evaluation_concerns.

Before the JSON, write one sentence stating the root cause of the vulnerability.
Then respond with ONLY a JSON object matching the schema provided — no markdown fences, no explanation beyond that one sentence.
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
        Raises RuntimeError if claude_agent_sdk is unavailable (not running inside Claude Code).
        """
        if not CLAUDE_SDK_AVAILABLE:
            raise RuntimeError(
                "claude_agent_sdk is not available. "
                "Local Claude patch generation requires Claude Code as the host process. "
                "Pass use_backend_engine=true to use the server-side AI engine instead."
            )
        return asyncio.run(self._generate(vulnerability, source_code))

    async def _generate(self, vulnerability: dict, source_code: str) -> dict:
        result_text = None

        async for message in query(
            prompt=self._build_prompt(vulnerability, source_code),
            options=ClaudeAgentOptions(
                model=self.model,
                allowed_tools=[],
                system_prompt=SYSTEM_PROMPT,
                max_turns=3,
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
        file_path = vuln.get('file_path', '')
        start_line = vuln.get('start_line', 0)
        end_line = vuln.get('end_line', 0)

        # Derive scanner context from scanner name and file extension
        scanner = vuln.get('scanner', '')
        ext = file_path.rsplit('.', 1)[-1] if '.' in file_path else ''
        scanner_context = {
            'semgrep': 'SAST scanner detecting code-level vulnerabilities in application source.',
            'checkov': 'IaC scanner detecting misconfigurations in Terraform/CloudFormation/Kubernetes.',
            'trivy': 'SCA scanner detecting known CVEs in dependency manifests (requirements.txt, package-lock.json).',
        }.get(scanner, f'Security scanner ({scanner})')
        file_context = {
            'tf': 'Terraform infrastructure-as-code',
            'py': 'Python source code',
            'txt': 'Python dependency manifest',
            'json': 'JSON dependency manifest (package-lock)',
        }.get(ext, f'{ext} file')

        # Annotate the flagged lines within the full file so the LLM has complete context
        lines = source_code.splitlines()
        annotated = []
        for i, line in enumerate(lines, start=1):
            if start_line <= i <= end_line:
                annotated.append(f"{i:4d} >>> {line}")  # mark flagged lines
            else:
                annotated.append(f"{i:4d}     {line}")
        code_section = "\n".join(annotated)

        fix_guidance = {
            'semgrep': 'Replace the vulnerable code pattern with a secure equivalent (e.g., parameterized queries, safe APIs).',
            'checkov': 'Add or modify Terraform resource attributes/blocks to satisfy the security control. A separate linked resource may be required.',
            'trivy': 'Update the vulnerable package to the minimum safe version in the manifest.',
        }.get(scanner, 'Produce a minimal, correct fix.')

        return f"""# Scanner context
{scanner_context} File type: {file_context}.
Fix guidance: {fix_guidance}

Vulnerability report:
- Scanner: {vuln.get('scanner')}
- Rule: {vuln.get('rule_id')}
- Severity: {vuln.get('severity')}
- Message: {vuln.get('message')}
- File: {file_path}
- Flagged lines: {start_line}–{end_line} (marked with >>> below)
- Resource: {vuln.get('metadata', {}).get('resource', 'unknown')}

Full file ({file_path}):
{code_section}

Respond with ONLY a JSON object matching this schema:
{PATCH_SCHEMA}"""
