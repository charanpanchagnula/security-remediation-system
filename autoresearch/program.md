# Autoresearch Program: Agent Prompt Optimization Loop

You are a Claude Code agent executing a structured research loop to improve the security remediation agent's prompt quality. Follow these instructions exactly and in order.

---

## 0. Prerequisites

You are running inside the repository at `/Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system`.

The two files you are allowed to modify are:
- `cli/src/security_pipeline/agent.py` — contains `SYSTEM_PROMPT` and `_build_prompt`
- `cli/skills/security-scan.md` — the skill document for the security scanner

Do NOT modify any other file. Off-limits paths:
- `autoresearch/eval_harness.py`
- `autoresearch/benchmark/` (any file)
- The `PATCH_SCHEMA` constant in `agent.py`
- Any test or CI configuration

---

## 1. Setup

### 1.1 Read the mutation targets

Read both files in full before proceeding:

```
cli/src/security_pipeline/agent.py
cli/skills/security-scan.md
```

Understand the structure of `SYSTEM_PROMPT`, `_build_prompt`, and `ClaudeAgentOptions` (model, allowed_tools, system_prompt, and optionally effort, max_turns, max_thinking_tokens, fallback_model).

### 1.2 Create the research branch

Run:
```bash
git checkout -b autoresearch/<tag>
```

Replace `<tag>` with a short slug describing this session, e.g. `autoresearch/run-2026-03-19`.

### 1.3 Establish the baseline

Run the evaluation harness from the repo root and capture its output:
```bash
cd /Users/charan/Desktop/CharanProjectsAI/MLAIOps/security-remediation-system
python autoresearch/eval_harness.py > autoresearch/run_baseline.log 2>&1
```

Extract the baseline score:
```bash
grep "^COMPOSITE_SCORE:" autoresearch/run_baseline.log
```

Record that value — this is your **baseline composite score**. Call it `BASELINE`.

If the harness crashes (non-zero exit, no COMPOSITE_SCORE line), stop and report the error. Do not proceed with a broken harness.

**Note:** The current baseline may show 11 of 15 cases as 'skip' — this means semgrep/checkov rules did not fire on the seed code snippets. The composite score will reflect only the scored cases (typically trivy CVE cases). This is expected; improvements to the remediator will still be measured on the scored subset.

### 1.4 Initialize results.tsv

Create the file `autoresearch/results.tsv` with this header line (tab-separated):
```
run	axis	description	composite_score	status
```

Then append the baseline row:
```
0	baseline	unmodified agent	<BASELINE value>	kept
```

`results.tsv` is untracked (do not `git add` it). It is your working log only.

---

## 2. In-Scope Mutation Axes

You have exactly five axes to experiment with. Each run mutates exactly one axis. Never combine axes in a single run.

### Axis A — Persona
**Target**: `SYSTEM_PROMPT` in `cli/src/security_pipeline/agent.py`

Modify the opening role description. Examples to try (one per run):
- "You are a senior SAST analyst specializing in infrastructure-as-code security."
- "You are a remediation engineer focused on producing minimal, safe code patches."
- "You are an application security consultant performing code review and remediation."
- "You are a security architect evaluating cloud infrastructure vulnerabilities."

Keep all 4-step reasoning instructions intact. Only change the first sentence/role line.

### Axis B — Reasoning Depth
**Target**: `_build_prompt` in `cli/src/security_pipeline/agent.py`

Add or modify chain-of-thought instructions in the prompt body. Examples:
- Add a line: `Before producing JSON, write out your reasoning for each of the 4 steps as internal comments.`
- Add: `Explain your root cause analysis for Step 1 in one sentence before the JSON.`
- Modify the prompt to ask the model to cite the specific CWE or OWASP category.
- Add a final instruction: `If you are uncertain, lower confidence_score below 0.5 and explain in evaluation_concerns.`

### Axis C — Context Injection
**Target**: `_build_prompt` in `cli/src/security_pipeline/agent.py`

Inject additional context into the prompt string returned by `_build_prompt`. Examples:
- Prepend a brief scanner description: `# Scanner context\nCheckov scans IaC files for misconfigurations.\n\n`
- Inject the language/file type inferred from `file_path` extension.
- Add a section listing common false positive patterns for the detected scanner.
- Append a brief note about the project environment inferred from the file path.

### Axis D — False Positive Criteria
**Target**: `SYSTEM_PROMPT` in `cli/src/security_pipeline/agent.py`

Adjust the criteria for marking a finding as `is_false_positive: true`. Try:
- **Conservative FP filtering**: Tighten the criteria — only mark as FP if the scanner explicitly misidentified the resource type. Remove or restrict the DR/operational-availability exception.
- **Aggressive FP filtering**: Expand the criteria — add "low-severity findings in non-production paths" as an FP condition.
- **Reordered criteria**: Move the most discriminating criteria (exposed secrets, public buckets) to the top of the REAL list with explicit "never FP" wording.
- **Threshold-based**: Add explicit wording like "When in doubt, prefer marking as REAL over FALSE POSITIVE."

### Axis E — Hyperparameters
**Target**: `ClaudeAgentOptions` constructor call in `_generate` in `cli/src/security_pipeline/agent.py`

Modify model-level parameters. Examples:
- Set `effort='low'` for faster, less thorough reasoning; `effort='high'` or `effort='max'` for deeper analysis.
- Add `max_turns=3` to limit the number of agent turns (useful to reduce latency and cost).
- Add `max_thinking_tokens=5000` to allow extended internal reasoning before producing output.
- Set `fallback_model='claude-haiku-4-5'` to specify a cheaper fallback if the primary model is unavailable.
- Try a different `model` string such as `claude-opus-4-5`.

Note: `ClaudeAgentOptions` accepts `model`, `allowed_tools`, `system_prompt`, `effort`, `max_turns`, `max_thinking_tokens`, `fallback_model`, and other SDK-documented parameters. Do NOT use `temperature` or `max_tokens` — those are not valid parameters for this SDK.

---

## 3. Research Loop (N = 20 runs)

Repeat the following steps 20 times (run numbers 1 through 20).

### Step A — Verify clean state

Before each run, confirm the working tree is clean:
```bash
git status
```

If there are uncommitted changes, run:
```bash
git stash
```

and note it in your log. If `git stash` fails, STOP and report.

### Step B — Select and apply one mutation

Pick an axis and a specific mutation. Distribute mutations across all 5 axes. A suggested distribution for 20 runs:
- Axis A (Persona): runs 1, 6, 11, 16
- Axis B (Reasoning depth): runs 2, 7, 12, 17
- Axis C (Context injection): runs 3, 8, 13, 18
- Axis D (FP criteria): runs 4, 9, 14, 19
- Axis E (Hyperparams): runs 5, 10, 15, 20

Apply the mutation by editing the target file. Make one focused change only.

### Step C — Commit the mutation

```bash
git add cli/src/security_pipeline/agent.py
# Also stage cli/skills/security-scan.md if you modified it
git commit -m "autoresearch: run <N> axis <X> — <one-line description>"
```

Example: `autoresearch: run 3 axis C — inject scanner type context into prompt`

### Step D — Run the harness

```bash
python autoresearch/eval_harness.py > autoresearch/run_${N}.log 2>&1; HARNESS_EXIT=$?
```

(Where `N` is the current run number, e.g. `run_1.log`, `run_2.log`, etc. This preserves a per-run log history.)

### Step E — Extract the score

```bash
grep "^COMPOSITE_SCORE:" autoresearch/run_${N}.log
```

If `HARNESS_EXIT` is non-zero **or** the `COMPOSITE_SCORE:` line is missing, treat the score as `0.0` and go to Step F (Error handling). Do not proceed to Step G or Step H.

### Step F — Error handling

If `HARNESS_EXIT` is non-zero or the harness produced no COMPOSITE_SCORE line:
1. Log the run to `results.tsv` with `composite_score=0.0` and `status=error`.
2. Run:
   ```bash
   git reset --hard HEAD~1
   ```
3. If `git reset` fails, STOP immediately and report: "FATAL: git reset failed, manual intervention required."
4. Do not execute Step G or Step H for this iteration — return directly to Step A for the next run.

### Step G — Keep or revert

Let `PREV` be the `composite_score` value from the most recent row in `results.tsv` where `status=kept` (for run 1, this will be the baseline row with `run=0`). Derive it from `results.tsv` each time so that after consecutive reverts the correct reference score is always used.

- If `new_score >= PREV`: **keep** the commit. Log `status=kept`.
- If `new_score < PREV`: **revert** the commit:
  ```bash
  git reset --hard HEAD~1
  ```
  Log `status=reverted`.

If a revert fails, STOP immediately and report: "FATAL: git reset failed after score comparison."

### Step H — Log to results.tsv

Append one tab-separated row to `autoresearch/results.tsv`:
```
<run_number>	<axis_letter>	<short description of mutation>	<composite_score>	<kept|reverted|error>
```

Example rows:
```
1	A	persona: SAST analyst role	0.7833	kept
2	B	added root cause reasoning instruction	0.7650	reverted
3	C	injected scanner type context	0.8012	kept
```

Do NOT `git add` or commit `results.tsv`.

---

## 4. Completion

After 20 runs:

1. Print a summary table of all rows from `results.tsv`.
2. Report the final composite score (last kept score) vs the baseline.
3. List which mutations were kept and which were reverted.
4. If the final score is higher than baseline, report the net improvement.
5. Leave the branch in its final state (do not merge or push).

---

## 5. Safety Rules

- Never modify `autoresearch/eval_harness.py`, `autoresearch/benchmark/`, or the `PATCH_SCHEMA` constant.
- Never commit `results.tsv`.
- Never combine mutations from two axes in a single run.
- Never skip the `git reset --hard HEAD~1` step when reverting — always verify the reset succeeded with `git status` before continuing.
- If at any point `git reset --hard HEAD~1` exits with a non-zero code, STOP and report the failure. Do not attempt to continue.
- Keep each commit message in the format: `autoresearch: run <N> axis <X> — <description>`

---

## 6. results.tsv Format Reference

File: `autoresearch/results.tsv` (untracked, tab-separated)

| Column | Type | Description |
|---|---|---|
| `run` | integer | 0 = baseline, 1–20 = loop iterations |
| `axis` | string | `baseline`, `A`, `B`, `C`, `D`, or `E` |
| `description` | string | One-line description of the mutation applied |
| `composite_score` | float | Value from `COMPOSITE_SCORE:` line, e.g. `0.7833` |
| `status` | string | `kept`, `reverted`, or `error` |

Example file contents:
```
run	axis	description	composite_score	status
0	baseline	unmodified agent	0.7500	kept
1	A	persona: SAST analyst role	0.7833	kept
2	B	added root cause reasoning instruction	0.7650	reverted
3	C	injected scanner type context	0.8012	kept
```
