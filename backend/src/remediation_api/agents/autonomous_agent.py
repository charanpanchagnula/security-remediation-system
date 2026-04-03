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
        self._tool_calls: list[dict] = []

    def record_action(self, action: str):
        self._actions.append(action)

    def log_tool_call(self, tool: str, input_args: dict, output: str):
        """Record full tool call I/O for the current iteration (output capped at 2000 chars)."""
        self._tool_calls.append({
            "tool": tool,
            "input": input_args,
            "output": output[:2000] if len(output) > 2000 else output,
        })

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
            "tool_calls": list(self._tool_calls),
        })
        self._actions = []
        self._validation = {}
        self._last_patch = None
        self._tool_calls = []


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
            self.read_file_lines,
            self.search_code,
            self.list_files,
            self.apply_patch,
            self.validate_and_scan,
            self.rollback,
        ):
            self.register(fn)

    # --- tools ---

    def read_file(self, path: str) -> str:
        """Read a source file (capped at 300 lines). Use read_file_lines for large files."""
        self.state.record_action(f"read_file({path})")
        _MAX_LINES = 300
        try:
            target = (self.work_dir / path).resolve()
            if not str(target).startswith(str(self.work_dir.resolve())):
                return "ERROR: path escapes working directory"
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) <= _MAX_LINES:
                result = "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines))
            else:
                result = (
                    "\n".join(f"{i+1}: {l}" for i, l in enumerate(lines[:_MAX_LINES]))
                    + f"\n... [{len(lines) - _MAX_LINES} more lines — use read_file_lines(path, start, end) to read specific ranges]"
                )
        except FileNotFoundError:
            result = f"ERROR: file not found: {path}"
        except Exception as e:
            result = f"ERROR: {e}"
        self.state.log_tool_call("read_file", {"path": path}, result)
        return result

    def read_file_lines(self, path: str, start_line: int, end_line: int) -> str:
        """Read specific lines from a file (1-indexed, inclusive). Use for large files."""
        self.state.record_action(f"read_file_lines({path}, {start_line}, {end_line})")
        try:
            target = (self.work_dir / path).resolve()
            if not str(target).startswith(str(self.work_dir.resolve())):
                return "ERROR: path escapes working directory"
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            s = max(0, start_line - 1)
            e = min(len(lines), end_line)
            result = "\n".join(f"{i+s+1}: {l}" for i, l in enumerate(lines[s:e]))
            if not result:
                result = f"(no lines in range {start_line}–{end_line})"
        except FileNotFoundError:
            result = f"ERROR: file not found: {path}"
        except Exception as e:
            result = f"ERROR: {e}"
        self.state.log_tool_call("read_file_lines", {"path": path, "start_line": start_line, "end_line": end_line}, result)
        return result

    def search_code(self, query: str, path: str = ".") -> str:
        """Search for a code pattern using ripgrep. Returns matching lines with file:line context."""
        self.state.record_action(f"search_code({query!r})")
        search_path = (self.work_dir / path).resolve()
        if not str(search_path).startswith(str(self.work_dir.resolve())):
            return "ERROR: path escapes working directory"
        # Try ripgrep first, fall back to grep
        try:
            result = subprocess.run(
                ["rg", "--json", "-n", "--", query, str(search_path)],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode not in (0, 1):
                raise FileNotFoundError("rg failed")
            lines = []
            for line in result.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    if obj.get("type") == "match":
                        d = obj["data"]
                        lines.append(f"{d['path']['text']}:{d['line_number']}: {d['lines']['text'].rstrip()}")
                except Exception:
                    pass
            result_str = "\n".join(lines) if lines else "(no matches)"
        except FileNotFoundError:
            result = subprocess.run(
                ["grep", "-rn", "--", query, str(search_path)],
                capture_output=True, text=True, timeout=15
            )
            result_str = result.stdout.strip() or "(no matches)"
        self.state.log_tool_call("search_code", {"query": query, "path": path}, result_str)
        return result_str

    def list_files(self, pattern: str = "**/*") -> str:
        """List files in the working directory matching a glob pattern."""
        self.state.record_action(f"list_files({pattern})")
        try:
            files = sorted(str(p.relative_to(self.work_dir)) for p in self.work_dir.glob(pattern) if p.is_file())
            result = "\n".join(files[:200]) or "(no files matched)"
        except Exception as e:
            result = f"ERROR: {e}"
        self.state.log_tool_call("list_files", {"pattern": pattern}, result)
        return result

    def apply_patch(self, file_path: str, original_code: str, new_code: str) -> str:
        """Apply a code change to the sandbox copy of file_path. Never touches work_dir."""
        self.state.record_action(f"apply_patch({file_path})")
        target = (self.sandbox_dir / file_path).resolve()
        if not str(target).startswith(str(self.sandbox_dir.resolve())):
            return f"ERROR: file_path escapes sandbox: {file_path}"
        try:
            if not target.exists():
                result = f"ERROR: file not found in sandbox: {file_path}"
            else:
                content = target.read_text(encoding="utf-8", errors="replace")
                if original_code not in content:
                    result = f"ERROR: original_code not found verbatim in {file_path}. Check indentation/whitespace."
                else:
                    target.write_text(content.replace(original_code, new_code, 1), encoding="utf-8")
                    result = f"OK: patch applied to {file_path} in sandbox"
        except Exception as e:
            result = f"ERROR: {e}"
        self.state.log_tool_call("apply_patch", {"file_path": file_path, "original_code": original_code, "new_code": new_code}, result)
        return result

    def validate_and_scan(self, file_path: str) -> str:
        """Run syntax check on the sandboxed file. Returns JSON result dict.
        Security validation happens in the final batch revalidation scan (server-side),
        not per-iteration, to avoid expensive scanner calls during the agent loop."""
        self.state.record_action(f"validate_and_scan({file_path})")
        results: dict[str, str] = {}
        target = self.sandbox_dir / file_path

        if file_path.endswith(".py"):
            r = subprocess.run(
                ["python3", "-m", "py_compile", str(target)],
                capture_output=True, text=True, timeout=10
            )
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        elif file_path.endswith((".js", ".ts", ".mjs", ".cjs")):
            r = subprocess.run(
                ["node", "--check", str(target)],
                capture_output=True, text=True, timeout=10
            )
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        elif file_path.endswith(".rb"):
            r = subprocess.run(["ruby", "-c", str(target)], capture_output=True, text=True, timeout=10)
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        elif file_path.endswith(".go"):
            r = subprocess.run(["go", "vet", str(target)], capture_output=True, text=True, timeout=15, cwd=str(target.parent))
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        elif file_path.endswith((".tf", ".hcl")):
            r = subprocess.run(["terraform", "validate", "-json"], capture_output=True, text=True, cwd=str(target.parent), timeout=30)
            results["syntax"] = "ok" if r.returncode == 0 else f"FAIL: {r.stderr.strip()[:300]}"
        elif file_path.endswith((".yaml", ".yml", ".json")):
            try:
                import yaml
                yaml.safe_load(target.read_text()) if file_path.endswith((".yaml", ".yml")) else json.loads(target.read_text())
                results["syntax"] = "ok"
            except Exception as e:
                results["syntax"] = f"FAIL: {str(e)[:300]}"
        else:
            results["syntax"] = "ok (syntax check not available for this file type)"

        self.state.record_validation(results)
        result_str = json.dumps(results)
        self.state.log_tool_call("validate_and_scan", {"file_path": file_path}, result_str)
        self.state.commit()
        return result_str

    def rollback(self) -> str:
        """Reset the sandbox to a clean copy of work_dir."""
        self.state.record_action("rollback")
        try:
            shutil.rmtree(str(self.sandbox_dir))
            shutil.copytree(str(self.work_dir), str(self.sandbox_dir), dirs_exist_ok=True)
            result = "OK: sandbox reset to original"
        except Exception as e:
            result = f"ERROR: {e}"
        self.state.log_tool_call("rollback", {}, result)
        return result

    def cleanup(self):
        """Remove sandbox directory. Call after agent is done."""
        try:
            shutil.rmtree(str(self.sandbox_dir), ignore_errors=True)
        except Exception:
            pass


_SYSTEM_PROMPT = """You are an autonomous security remediation engineer.

Your task: fix a security vulnerability iteratively using the tools provided.

## Workflow (repeat up to {max_iterations} times):

1. ANALYZE: Use read_file, read_file_lines, search_code, list_files to understand the codebase.
   read_file shows up to 300 lines. For large files, use read_file_lines(path, start, end) to read
   specific line ranges. The vulnerability location is given in the prompt — read_file_lines around
   those lines is usually sufficient. For complex vulnerabilities (multi-file, imports), read related files too.

2. GENERATE: Formulate the minimal correct patch. Key rules:
   - For dependency version upgrades (pom.xml, package.json, go.mod, requirements.txt, Gemfile):
     ALWAYS upgrade to the ABSOLUTE LATEST stable version, not just the minimum fixed version.
     Minimum fixed versions frequently have their own CVEs discovered later.
   - For GitHub Actions workflows (CKV2_GHA_1): add `permissions: read-all` at the top-level
     workflow scope AND at each job scope if jobs are defined. Read the file first to see its structure.
   - Only modify files directly related to the vulnerability. Do NOT touch unrelated files.

3. APPLY: Call apply_patch for each file that needs changing. Multi-file patches are fine —
   call apply_patch once per file. Keep original_code EXACTLY as it appears (indentation, newlines).

4. VALIDATE: Call validate_and_scan on each patched file to check syntax only.
   - If syntax FAIL → rollback and fix.
   - If syntax ok → proceed to step 5.
   - For XML/YAML/JSON files, validate_and_scan also checks parse validity — always run it.

5. REASON: Before outputting the final JSON, explicitly reason about:
   - Root cause: does the patch address the actual vulnerability or just mask it?
   - Coverage: are all code paths that trigger this vulnerability fixed?
   - Bypass: can an attacker still reach the unsafe operation via a different path?
   - New risk: does the fix introduce a new vulnerability or break security properties?
   - Scope: does the patch touch ONLY the necessary files? Unnecessary changes cause false positives.
   Only output the final JSON once confident the patch is correct.

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
  "evaluation_concerns": ["empty if clean"],
  "security_reasoning": {{
    "root_cause_addressed": "...",
    "coverage": "...",
    "bypass_risk": "...",
    "new_risk": "..."
  }}
}}

Never output intermediate JSON. Only the final response is the JSON object.
"""


class AutonomousRemediatorAgent:
    def __init__(self, model_id: str = "deepseek-chat", max_iterations: int = 6):
        self.model_id = model_id
        self.max_iterations = max_iterations

    def remediate(self, vulnerability: dict, work_dir: str, memory_context: str = "") -> tuple[dict, list, list]:
        """
        Run multi-turn tool-calling remediation.
        Returns (patch_dict, iteration_log, llm_messages).
        iteration_log: per-validate_and_scan-call entries with full tool I/O.
        llm_messages: manually constructed conversation showing prompt → tool calls → response.
        Raises ValueError if agent returns no result or non-JSON.
        """
        state = _IterationState()
        scanner = vulnerability.get("scanner", "semgrep")
        prompt = self._build_prompt(vulnerability, work_dir, memory_context)
        toolkit = RemediationToolkit(work_dir=work_dir, scanner=scanner, state=state)
        try:
            agent = Agent(
                model=get_provider().get_model(self.model_id),
                tools=[toolkit],
                instructions=_SYSTEM_PROMPT.format(max_iterations=self.max_iterations),
                markdown=False,
            )
            response = agent.run(prompt)
            result_text = self._extract_text(response)
            try:
                patch = self._parse_json(result_text)
            except ValueError:
                # Model output reasoning text without JSON — do a recovery call
                result_text = self._recover_json(result_text, vulnerability)
                patch = self._parse_json(result_text)

            # Flush any uncommitted tool calls (agent finished without calling validate_and_scan)
            if state._tool_calls or state._actions:
                state.commit(reasoning="agent completed without explicit validation call")

            llm_messages = self._build_llm_messages(
                system_prompt=_SYSTEM_PROMPT.format(max_iterations=self.max_iterations),
                user_prompt=prompt,
                response=response,
                result_text=result_text,
                state=state,
            )
            logger.info(f"[autonomous] llm_messages={len(llm_messages)} iteration_log={len(state.entries)}")
            return patch, state.entries, llm_messages
        finally:
            toolkit.cleanup()

    @staticmethod
    def _build_llm_messages(
        system_prompt: str,
        user_prompt: str,
        response,
        result_text: str,
        state: "_IterationState",
    ) -> list:
        """
        Build a human-readable conversation log from what we know:
          system → user → [tool calls per iteration] → assistant final response.

        Agno doesn't expose intermediate messages without a database, so we
        reconstruct the conversation from the prompt, the tool call log captured
        in _IterationState, and the final response text.
        """
        messages = []

        # 1. System prompt
        messages.append({"role": "system", "content": system_prompt})

        # 2. User prompt (vulnerability description)
        messages.append({"role": "user", "content": user_prompt})

        # 3. One assistant turn per iteration showing tool calls made
        for entry in state.entries:
            tool_calls = entry.get("tool_calls", [])
            reasoning = entry.get("reasoning", "")
            if tool_calls or reasoning:
                msg: dict = {"role": "assistant", "iteration": entry["iteration"]}
                if reasoning:
                    msg["reasoning"] = reasoning
                if tool_calls:
                    msg["tool_calls"] = tool_calls
                messages.append(msg)

        # 4. Top-level reasoning from the model (e.g. DeepSeek CoT)
        top_reasoning = getattr(response, "reasoning_content", None)

        # 5. Final assistant response (the JSON output)
        final: dict = {"role": "assistant", "content": result_text}
        if top_reasoning:
            final["reasoning"] = top_reasoning
        messages.append(final)

        return messages

    def _build_prompt(self, vuln: dict, work_dir: str, memory_context: str = "") -> str:
        scanner = vuln.get("scanner", "")
        fix_hint = {
            "semgrep": "Replace the vulnerable pattern with a secure equivalent.",
            "checkov": "Add or fix Terraform attributes to satisfy the control.",
            "trivy":   "Update the vulnerable package to the minimum safe version.",
        }.get(scanner, "Produce a minimal, correct fix.")
        vuln_block = (
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
        if memory_context:
            return memory_context + vuln_block
        return vuln_block

    def _recover_json(self, analysis_text: str, vulnerability: dict) -> str:
        """
        Recovery call: the agent produced analysis text but no JSON.
        Ask the model directly to format the analysis as the required JSON.
        """
        from openai import OpenAI
        from ..config import settings

        logger.warning(f"[autonomous] JSON parse failed, attempting recovery call for {vulnerability.get('rule_id')}")

        recovery_prompt = (
            f"You analyzed a security vulnerability and produced the following analysis:\n\n"
            f"{analysis_text[:3000]}\n\n"
            f"Now output ONLY the JSON result object (no other text):\n"
            f'{{\n'
            f'  "summary": "one-line description of the fix",\n'
            f'  "confidence_score": 0.0-1.0,\n'
            f'  "is_false_positive": true/false,\n'
            f'  "code_changes": [{{\n'
            f'    "file_path": "relative/path",\n'
            f'    "start_line": N, "end_line": N,\n'
            f'    "original_code": "exact lines replaced",\n'
            f'    "new_code": "replacement",\n'
            f'    "description": "why this fixes the issue"\n'
            f'  }}],\n'
            f'  "security_implications": [],\n'
            f'  "evaluation_concerns": []\n'
            f'}}'
        )
        try:
            client = OpenAI(api_key=settings.DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")
            resp = client.chat.completions.create(
                model=self.model_id,
                messages=[{"role": "user", "content": recovery_prompt}],
                temperature=0,
                max_tokens=2000,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"[autonomous] Recovery call failed: {e}")
            raise ValueError(f"Agent returned non-JSON output and recovery failed: {e}")

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
        fenced = re.sub(r"^```(?:json)?\s*", "", text)
        fenced = re.sub(r"\s*```\s*$", "", fenced).strip()
        try:
            return json.loads(fenced)
        except json.JSONDecodeError:
            pass

        # Direct parse of original text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try all {...} blocks from last to first — the final output JSON is at the end
        candidates = list(re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL))
        for match in reversed(candidates):
            try:
                parsed = json.loads(match.group())
                # Must look like a remediation response
                if "code_changes" in parsed or "summary" in parsed or "is_false_positive" in parsed:
                    return parsed
            except json.JSONDecodeError:
                pass

        # Last resort: greedy match from last '{' that contains 'summary' or 'code_changes'
        last_brace = text.rfind("{")
        if last_brace != -1:
            try:
                return json.loads(text[last_brace:])
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Agent returned non-JSON output:\n{text[:300]}")


autonomous_remediator = AutonomousRemediatorAgent()
