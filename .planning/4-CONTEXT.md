# Phase 4 Context — Multi-turn Reasoning Remediation

## Phase Boundary

Upgrade `LocalClaudeRemediator` in `cli/src/secremediator/agent.py` from single-turn to a
4-turn conversation loop. No changes to CLI commands, MCP tools, or backend services.
`generate_patch()` public API stays identical — callers see no difference.

## Implementation Decisions

- **4-turn loop (locked):** Analyze → Strategize → Generate → Evaluate
  - Turn 1 Analyze: Is this a real vulnerability? What is the root cause?
  - Turn 2 Strategize: What fix approach? Any tradeoffs? (returns plain text, not JSON)
  - Turn 3 Generate: Produce the patch JSON (same PATCH_SCHEMA as today)
  - Turn 4 Evaluate: Does the patch look correct? Any regressions? Returns `{"approved": bool, "concerns": [...]}`

- **Conversation state:** Use Anthropic SDK `messages` list — accumulate all turns in one list,
  pass full history on each call. No external state storage.

- **Backward compat (locked):** `generate_patch(vulnerability, source_code) -> dict` signature
  unchanged. The multi-turn logic is entirely internal.

- **False positive handling:** If Turn 1 Analyze concludes `is_false_positive: true`,
  short-circuit — skip turns 2-4 and return `{"is_false_positive": true, "code_changes": [], "confidence_score": 1.0, "summary": "False positive: <reason>", "security_implications": []}`.

- **Evaluate rejection handling:** If Turn 4 returns `approved: false`, raise `ValueError` with
  concerns list so `remediate-all` logs it as a patch failure (existing error path).

- **Remove single-turn TODO comment:** Replace the `# TODO Phase 4` block at the top of agent.py
  with a module docstring describing the multi-turn loop.

- **Class rename:** Keep `LocalClaudeRemediator` — no rename.

- **Token budget:** max_tokens=1024 for Analyze/Strategize/Evaluate turns; 2048 for Generate.

## Gray Areas Resolved

- **Strategize response format** — plain text prose (not JSON), appended to conversation history as assistant turn
- **Evaluate schema** — `{"approved": bool, "concerns": ["..."]}` simple flat object
- **What if Evaluate approves but patch JSON is malformed?** — JSON parse error is raised as ValueError (same as today); Evaluate only gates semantic correctness
- **Model** — same `claude-sonnet-4-5` default, passed through from constructor
