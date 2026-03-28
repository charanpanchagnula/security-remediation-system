"""
AutonomousRemediatorAgent: multi-turn tool-calling remediation using Agno + DeepSeek.
Does NOT require claude_agent_sdk. Works on any server with DeepSeek/Anthropic API access.
"""
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from agno.agent import Agent
from agno.tools import Toolkit

from ..config import settings
from ..logger import get_logger
from ..services.llm_provider import get_provider

logger = get_logger(__name__)


class _IterationState:
    """Shared mutable state updated by toolkit tools during the agent loop."""

    def __init__(self):
        self.entries: list[dict] = []
        self._iteration: int = 0
        self._actions: list[str] = []
        self._validation: dict = {}
        self._last_patch: Optional[dict] = None

    def record_action(self, action: str):
        self._actions.append(action)

    def record_validation(self, results: dict, patch: Optional[dict] = None):
        self._validation.update(results)
        if patch:
            self._last_patch = patch

    def commit(self, reasoning: str = ""):
        self._iteration += 1
        self.entries.append({
            "iteration": self._iteration,
            "actions": list(self._actions),
            "patch_proposed": self._last_patch,
            "validation_results": dict(self._validation),
            "reasoning": reasoning,
        })
        self._actions = []
        self._validation = {}
        self._last_patch = None


class RemediationToolkit(Toolkit):
    """Six tools exposed to the Agno agent for iterative remediation."""

    def __init__(self, work_dir: str, scanner: str, state: _IterationState):
        super().__init__(name="remediation_tools")
        self.work_dir = Path(work_dir).resolve()
        self.sandbox_dir = Path(tempfile.mkdtemp(prefix="sandbox_"))
        try:
            shutil.copytree(str(self.work_dir), str(self.sandbox_dir), dirs_exist_ok=True)
        except Exception:
            shutil.rmtree(str(self.sandbox_dir), ignore_errors=True)
            raise
        self.scanner = scanner
        self.state = state
        for fn in (
            self.read_file,
            self.search_code,
            self.list_files,
            self.apply_patch,
            self.validate_and_scan,
            self.rollback,
        ):
            self.register(fn)

    # --- tools ---

    def read_file(self, path: str) -> str:
        """Read a source file from the working directory. path is relative to work_dir."""
        self.state.record_action(f"read_file({path})")
        try:
            return (self.work_dir / path).read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return f"ERROR: file not found: {path}"
        except Exception as e:
            return f"ERROR: {e}"

    def search_code(self, query: str, path: str = ".") -> str:
        """Search for a code pattern using ripgrep. Returns matching lines with file:line context."""
        self.state.record_action(f"search_code({query!r})")
        search_path = (self.work_dir / path).resolve()
        if not str(search_path).startswith(str(self.work_dir.resolve())):
            return "ERROR: path escapes working directory"
        result = subprocess.run(
            ["rg", "--json", "-n", query, str(search_path)],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode not in (0, 1):  # 1 = no matches (not an error)
            return f"ERROR: {result.stderr[:200]}"
        lines = []
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                if obj.get("type") == "match":
                    d = obj["data"]
                    lines.append(f"{d['path']['text']}:{d['line_number']}: {d['lines']['text'].rstrip()}")
            except Exception:
                pass
        return "\n".join(lines) if lines else "(no matches)"

    def list_files(self, pattern: str = "**/*") -> str:
        """List files in the working directory matching a glob pattern."""
        self.state.record_action(f"list_files({pattern})")
        try:
            files = sorted(str(p.relative_to(self.work_dir)) for p in self.work_dir.glob(pattern) if p.is_file())
            return "\n".join(files[:200]) or "(no files matched)"
        except Exception as e:
            return f"ERROR: {e}"

    def apply_patch(self, file_path: str, original_code: str, new_code: str) -> str:
        """Apply a code change to the sandbox copy of file_path. Never touches work_dir."""
        self.state.record_action(f"apply_patch({file_path})")
        target = (self.sandbox_dir / file_path).resolve()
        if not str(target).startswith(str(self.sandbox_dir.resolve())):
            return f"ERROR: file_path escapes sandbox: {file_path}"
        try:
            if not target.exists():
                return f"ERROR: file not found in sandbox: {file_path}"
            content = target.read_text(encoding="utf-8", errors="replace")
            if original_code not in content:
                return f"ERROR: original_code not found verbatim in {file_path}. Check indentation/whitespace."
            target.write_text(content.replace(original_code, new_code, 1), encoding="utf-8")
            return f"OK: patch applied to {file_path} in sandbox"
        except Exception as e:
            return f"ERROR: {e}"

    def validate_and_scan(self, file_path: str) -> str:
        """Run syntax check + security rescan on the sandboxed file. Returns JSON result dict."""
        self.state.record_action(f"validate_and_scan({file_path})")
        results: dict[str, str] = {}
        target = self.sandbox_dir / file_path

        # Syntax check
        if file_path.endswith(".py"):
            r = subprocess.run(
                ["python3", "-m", "py_compile", str(target)],
                capture_output=True, text=True, timeout=10
            )
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        elif file_path.endswith((".js", ".ts")):
            r = subprocess.run(
                ["node", "--check", str(target)],
                capture_output=True, text=True, timeout=10
            )
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        elif file_path.endswith(".tf"):
            r = subprocess.run(
                ["terraform", "validate", "-json"],
                capture_output=True, text=True, cwd=str(target.parent), timeout=30
            )
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        else:
            results["syntax"] = "skipped (unknown file type)"

        # Security rescan
        results["security_scan"] = self._rescan(target, file_path)

        self.state.record_validation(results)
        self.state.commit()
        return json.dumps(results)

    def rollback(self) -> str:
        """Reset the sandbox to a clean copy of work_dir."""
        self.state.record_action("rollback")
        try:
            shutil.rmtree(str(self.sandbox_dir))
            shutil.copytree(str(self.work_dir), str(self.sandbox_dir), dirs_exist_ok=True)
            return "OK: sandbox reset to original"
        except Exception as e:
            return f"ERROR: {e}"

    def cleanup(self):
        """Remove sandbox directory. Call after agent is done."""
        try:
            shutil.rmtree(str(self.sandbox_dir), ignore_errors=True)
        except Exception:
            pass

    # --- private ---

    def _rescan(self, target: Path, file_path: str) -> str:
        try:
            if self.scanner == "semgrep":
                r = subprocess.run(
                    ["semgrep", "scan", "--json", "--config=auto", str(target)],
                    capture_output=True, text=True, timeout=60
                )
                if not r.stdout.strip() and r.returncode not in (0, 1):
                    return f"WARN: semgrep exited {r.returncode} with no output — result unreliable"
                data = json.loads(r.stdout) if r.stdout.strip() else {}
                findings = data.get("results", [])
                if not findings:
                    return "PASS (0 findings)"
                summaries = [f"{f['check_id']} line {f['start']['line']}" for f in findings[:5]]
                return f"FAIL ({len(findings)} findings): {'; '.join(summaries)}"
            elif self.scanner == "checkov":
                r = subprocess.run(
                    ["checkov", "-f", str(target), "--output", "json", "--quiet"],
                    capture_output=True, text=True, timeout=60
                )
                if not r.stdout.strip() and r.returncode not in (0, 1):
                    return f"WARN: checkov exited {r.returncode} with no output — result unreliable"
                data = json.loads(r.stdout) if r.stdout.strip() else {}
                failed = (data.get("summary", {}) or {}).get("failed", 0)
                return "PASS" if failed == 0 else f"FAIL ({failed} checks failed)"
            elif self.scanner == "trivy":
                r = subprocess.run(
                    ["trivy", "fs", "--format", "json", "--quiet", str(target)],
                    capture_output=True, text=True, timeout=60
                )
                if not r.stdout.strip() and r.returncode not in (0, 1):
                    return f"WARN: trivy exited {r.returncode} with no output — result unreliable"
                data = json.loads(r.stdout) if r.stdout.strip() else {}
                vulns = sum(len(res.get("Vulnerabilities") or []) for res in data.get("Results", []))
                return "PASS" if vulns == 0 else f"FAIL ({vulns} vulnerabilities found)"
            else:
                return f"skipped (unknown scanner: {self.scanner})"
        except FileNotFoundError:
            return f"skipped ({self.scanner} CLI not found)"
        except Exception as e:
            return f"ERROR: {e}"


_SYSTEM_PROMPT = """You are an autonomous security remediation engineer.

Your task: fix a security vulnerability iteratively using the tools provided.

## Workflow (repeat up to {max_iterations} times):

1. ANALYZE: Use read_file, search_code, list_files to understand the codebase.
   For complex vulnerabilities (multi-file, Terraform modules, imports), read ALL related files first.

2. GENERATE: Formulate the minimal correct patch.

3. APPLY: Call apply_patch for each file that needs changing. Multi-file patches are fine —
   call apply_patch once per file. Keep original_code EXACTLY as it appears (indentation, newlines).

4. VALIDATE: Call validate_and_scan on each patched file. Read the JSON result.

5. EVALUATE:
   - If security_scan=PASS and syntax=ok → you are done. Output the final JSON.
   - If validation fails → call rollback, analyze the error, refine, and repeat.

## Output (LAST message, after all tool calls):
Respond with ONLY a JSON object:
{{
  "summary": "one-line description of the fix",
  "confidence_score": 0.0-1.0,
  "is_false_positive": true/false,
  "code_changes": [
    {{
      "file_path": "relative/path",
      "start_line": N, "end_line": N,
      "original_code": "exact lines replaced",
      "new_code": "replacement",
      "description": "why this fixes the issue"
    }}
  ],
  "security_implications": ["list"],
  "evaluation_concerns": ["empty if clean"]
}}

Never output intermediate JSON. Only the final response is the JSON object.
"""


class AutonomousRemediatorAgent:
    def __init__(self, model_id: str = "deepseek-chat", max_iterations: int = 6):
        self.model_id = model_id
        self.max_iterations = max_iterations

    def remediate(self, vulnerability: dict, work_dir: str) -> tuple[dict, list]:
        """
        Run multi-turn tool-calling remediation.
        Returns (patch_dict, iteration_log).
        patch_dict is compatible with RemediationResponse.code_changes schema.
        Raises ValueError if agent returns no result or non-JSON.
        """
        state = _IterationState()
        scanner = vulnerability.get("scanner", "semgrep")
        toolkit = RemediationToolkit(work_dir=work_dir, scanner=scanner, state=state)
        try:
            agent = Agent(
                model=get_provider().get_model(self.model_id),
                tools=[toolkit],
                system_prompt=_SYSTEM_PROMPT.format(max_iterations=self.max_iterations),
                markdown=False,
            )
            response = agent.run(self._build_prompt(vulnerability, work_dir))
            result_text = self._extract_text(response)
            patch = self._parse_json(result_text)
            return patch, state.entries
        finally:
            toolkit.cleanup()

    def _build_prompt(self, vuln: dict, work_dir: str) -> str:
        scanner = vuln.get("scanner", "")
        fix_hint = {
            "semgrep": "Replace the vulnerable pattern with a secure equivalent.",
            "checkov": "Add or fix Terraform attributes to satisfy the control.",
            "trivy":   "Update the vulnerable package to the minimum safe version.",
        }.get(scanner, "Produce a minimal, correct fix.")
        return (
            f"## Vulnerability\n"
            f"- Scanner: {vuln.get('scanner')}\n"
            f"- Rule: {vuln.get('rule_id')}\n"
            f"- Severity: {vuln.get('severity')}\n"
            f"- Message: {vuln.get('message')}\n"
            f"- File: {vuln.get('file_path')}\n"
            f"- Lines: {vuln.get('start_line')}–{vuln.get('end_line')}\n"
            f"- Fix hint: {fix_hint}\n\n"
            f"## Working directory (READ-ONLY — use sandbox via apply_patch)\n"
            f"{work_dir}\n\n"
            f"## Constraints\n"
            f"- Max {self.max_iterations} validate_and_scan calls\n"
            f"- Only fix the flagged vulnerability — no unrelated changes\n"
        )

    @staticmethod
    def _extract_text(response) -> str:
        """Extract text from Agno RunResponse (content attr or str)."""
        if hasattr(response, "content") and isinstance(response.content, str):
            return response.content
        return str(response)

    @staticmethod
    def _parse_json(text: str) -> dict:
        text = text.strip()
        # Strip markdown fences
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text).strip()
        # Direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Extract first {...} block
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        raise ValueError(f"Agent returned non-JSON output:\n{text[:300]}")


autonomous_remediator = AutonomousRemediatorAgent()
