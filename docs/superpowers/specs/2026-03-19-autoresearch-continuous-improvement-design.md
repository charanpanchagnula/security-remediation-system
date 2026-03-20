# Autoresearch Continuous Improvement Loop — Design Spec

**Date:** 2026-03-19
**Status:** Draft
**Scope:** Personal laptop prototype (Python). Enterprise Java port is a future concern.

---

## Overview

An autoresearch-style session-based optimization loop that iteratively improves the system prompt, user prompt template, skill instructions, and hyperparameters of the security remediation engine. When invoked, the agent runs N experiments autonomously — each experiment mutates `agent.py` or `skills/security-scan.md`, evaluates on a fixed benchmark, keeps the change if the composite score improves, reverts if not. Results are logged to `results.tsv`.

The design is a direct structural adaptation of Karpathy's autoresearch repo, domain-swapped from LLM training optimization to security remediation prompt optimization.

---

## Directory Structure

```
security-remediation-system/
├── cli/                                      # existing — unchanged structurally
│   └── src/security_pipeline/
│       ├── agent.py                          # THE FILE THE AGENT MODIFIES
│       └── ...
├── skills/
│   └── security-scan.md                      # ALSO IN AGENT'S MODIFICATION SCOPE
└── autoresearch/                             # NEW
    ├── eval_harness.py                       # fixed — agent cannot modify (like prepare.py)
    ├── program.md                            # human-editable research instructions
    ├── results.tsv                           # untracked — experiment log
    └── benchmark/                           # fixed curated dataset — agent cannot modify
        ├── semgrep/                          # SAST cases (~50 cases)
        ├── checkov/                          # IaC cases (~45 cases)
        └── trivy/                            # SCA/container cases (~35 cases)
```

**Total benchmark target:** ~130 curated cases from known vulnerable repos.

---

## File Role Mapping

| autoresearch (Karpathy) | Security Autoresearch | Who edits |
|---|---|---|
| `train.py` | `cli/src/security_pipeline/agent.py` + `skills/security-scan.md` | Agent |
| `program.md` | `autoresearch/program.md` | Human |
| `prepare.py` | `autoresearch/eval_harness.py` | Nobody — fixed |
| `results.tsv` | `autoresearch/results.tsv` | Agent (untracked by git) |

---

## Benchmark Dataset

### Sources
Curated from known publicly vulnerable repositories — not LLM-generated. Scanner must fire on every case (validated at eval_harness.py startup before any experiment runs).

**Sources by scanner:**
- **semgrep:** OWASP WebGoat, DVWA, PyGoat, juice-shop
- **checkov:** terragoat, cfngoat, kaimonkey
- **trivy:** intentionally vulnerable Dockerfiles, packages with known CVEs

### Case Format

Each benchmark case is a JSON file. Fields map directly to the vulnerability dict that `_build_prompt()` consumes:

```json
{
  "id": "semgrep_sql_injection_001",
  "scanner": "semgrep",
  "vuln_type": "sql-injection",
  "language": "python",
  "file_path": "app/db.py",
  "vulnerable_code": "query = 'SELECT * FROM users WHERE id = ' + user_id\ndb.execute(query)",
  "expected_rule_id": "python.django.security.audit.raw-query",
  "expected_severity": "HIGH",
  "message": "SQL injection vulnerability: user input concatenated directly into query",
  "start_line": 1,
  "end_line": 2
}
```

`eval_harness.py` writes `vulnerable_code` to a real temp file, runs the scanner CLI on it, and builds the vulnerability dict from the **actual scanner output** — not the pre-filled case fields. The pre-filled fields are only used to validate the scanner fires (step 3) and for human-readable labels in results.tsv.

### Coverage by Scanner

**Semgrep SAST — ~50 cases (Python, Java, JavaScript, Go)**

| Category | Rules |
|---|---|
| Injection | SQL injection, command injection, LDAP injection, template injection, XPath injection |
| Web | XSS (reflected/stored/DOM), open redirect, SSRF, XXE, missing CSRF protection |
| Auth/Crypto | Hardcoded secrets, weak hashing (MD5/SHA1), weak cipher (DES/RC4), insecure random, JWT none-alg |
| File/Path | Path traversal, zip slip, unsafe file permissions, arbitrary file write |
| Code Quality | Insecure deserialization, unsafe regex (ReDoS), prototype pollution (JS), dynamic code execution injection |

**Checkov IaC — ~45 cases (Terraform, CloudFormation, Kubernetes, Dockerfile)**

| Category | Rules |
|---|---|
| AWS S3 | Public ACL, no encryption, no versioning, no access logging, no MFA delete |
| AWS IAM | Wildcard `*` actions, no MFA on root, overly permissive role trust, no boundary policy |
| AWS Networking | SG open ingress 0.0.0.0/0 on all ports, SG open egress, NACLs unrestricted |
| AWS Compute | EC2 public IP, IMDSv1 enabled, unencrypted EBS, unencrypted AMI |
| AWS Data | RDS publicly accessible, no encryption, no backup retention, no deletion protection |
| AWS Observability | CloudTrail not enabled, no log file validation, no CloudWatch alarms |
| Kubernetes | Privileged containers, hostPID/hostNetwork, no resource limits, root user, no network policy |
| Dockerfile | Running as root, ADD instead of COPY, no health check, secrets in ENV |

**Trivy SCA/Container — ~35 cases**

| Category | Rules |
|---|---|
| Python CVEs | Pillow RCE, cryptography low versions, PyYAML unsafe load, urllib3 redirect, Jinja2 SSTI |
| Java CVEs | Log4Shell (log4j 2.x), Spring4Shell, Commons-Text StringLookup, Jackson-databind |
| JS CVEs | Lodash prototype pollution, Axios SSRF, Moment.js ReDoS, vm2 sandbox escape |
| Go CVEs | golang.org/x/net HTTP smuggling, golang.org/x/crypto weak curves |
| Container | Ubuntu 18.04/20.04 base (EOL), Debian Buster CVEs, Alpine 3.12 known vulns |

**Note:** Taint/dataflow analysis is excluded — semgrep OSS does not support taint mode (Pro feature).

---

## eval_harness.py Design

### Scanner invocation
Scanners run as **local CLIs** for experiment speed — no Docker/backend required:
- `semgrep` — `pip install semgrep`
- `checkov` — `pip install checkov`
- `trivy` — `brew install trivy`

### API invocation — uses LocalClaudeRemediator directly

`eval_harness.py` imports and uses `LocalClaudeRemediator` from `agent.py` directly — the same class used in production. The `claude_agent_sdk` it relies on works by calling the `claude` CLI, which is installed on the machine and authenticated. This means `eval_harness.py` runs fine as a plain `python eval_harness.py` subprocess — no separate API key required, no Claude Code host process required.

```python
import sys
sys.path.insert(0, "../cli/src")
from security_pipeline.agent import LocalClaudeRemediator
```

This means `eval_harness.py` always uses the **current version of `SYSTEM_PROMPT` and `_build_prompt()`** from `agent.py` at runtime, so every experiment correctly reflects whatever the agent committed in step 3.

### Per-case evaluation flow

```
1. Write vulnerable_code to a real temp file on disk (e.g. /tmp/eval_case_001/app/db.py)
2. Run scanner CLI on the temp file → get actual scanner output (JSON)
3. Parse scanner output → find the finding that matches expected_rule_id
   - If expected_rule_id not found: skip this case (broken case, not a failed experiment)
4. Build vuln dict from the actual scanner output (rule_id, message, severity,
   start_line, end_line from the real scan result — not the pre-filled case fields)
5. Load agent.py dynamically, call _build_prompt(vuln_dict, source_code)
6. Call Claude API directly with SYSTEM_PROMPT and the built prompt
7. Parse JSON patch from response
8. Apply patch to the temp file
9. Re-scan: run scanner CLI on the patched temp file
10. Score the case
11. Clean up temp directory
```

The pre-filled fields in the benchmark case JSON (`message`, `start_line`, `end_line`, `expected_rule_id`) are used only for:
- **Step 3 validation** — confirming the scanner fires before trusting the case
- **Case identification** — human-readable labels for results.tsv descriptions

The vuln dict Claude receives always comes from actual scanner output, matching production behavior.

### Scoring formula

```
fix_success      = 1.0 if expected_rule_id no longer fires, else 0.0
no_regression    = 1.0 if no new findings introduced, else 0.0
patch_minimality = 1.0 - (lines_changed / original_file_lines)
                   where original_file_lines = len(vulnerable_code.splitlines())
                   capped: lines_changed = min(lines_changed, original_file_lines)

composite = (0.6 * fix_success) + (0.2 * no_regression) + (0.2 * patch_minimality)
```

**Anti-gaming note:** `original_file_lines` is the denominator (fixed at case definition time, not at patch time). Appending or expanding the file does not improve the score — any line added counts as a changed line. Lines are diffed against the original `vulnerable_code`, not the patched file size.

Composite score is averaged across all valid cases.

### Public interface and log output

```python
def run_full_eval() -> float:
    """Returns composite score 0.0–1.0. Higher is better."""
    ...
    print(f"COMPOSITE_SCORE: {score:.6f}")   # always the final stdout line
    return score
```

When run as a subprocess (`python eval_harness.py > run.log 2>&1`), the agent reads the score with:

```bash
grep "^COMPOSITE_SCORE:" run.log
```

This is the only stdout line that matches this prefix, making parsing unambiguous.

---

## program.md Design

### Setup block (run once per session)
1. Verify the repo is on a clean state: run `git status` — working tree must be clean
2. Verify you are NOT on `main` — create branch `autoresearch/<tag>` (e.g. `mar19`) from `main`
3. Read in-scope files: `agent.py`, `skills/security-scan.md`
4. Read fixed files for context only: `eval_harness.py` (do not modify), `benchmark/` (do not modify)
5. Run baseline: `python eval_harness.py > run.log 2>&1`, read `grep "^COMPOSITE_SCORE:" run.log`
6. Initialize `results.tsv` with header row + baseline entry

### What the agent CAN modify
- `SYSTEM_PROMPT` in `agent.py` — persona, false-positive rules, reasoning steps, output constraints
- `_build_prompt()` in `agent.py` — how vulnerability context and source code are formatted into the user prompt
- `skills/security-scan.md` — the skill instructions the human uses to invoke the pipeline
- Hyperparameters at the top of `agent.py`: temperature (0.0–0.5), retry count (1–3), diff strategy (minimal vs full rewrite)

### What the agent CANNOT modify
- `eval_harness.py` — ground truth scoring function
- `benchmark/` — fixed curated dataset
- The patch JSON schema — revalidation pipeline depends on it

### Mutation axes (explicit guidance to prevent random drift)

| Axis | Options |
|---|---|
| A — System prompt persona | Security auditor / compiler-aware / minimal-diff enforcer |
| B — Reasoning depth | Silent fix / explain-then-fix / multi-step CoT |
| C — Context injection | Flagged lines only / full file / file + surrounding module |
| D — False-positive criteria | Tighten / loosen FP rules |
| E — Hyperparameters | Temperature 0.0–0.5, retry count 1–3 |

### Experiment loop (N experiments per invocation, default 20)

```
PRECONDITION: repo is on autoresearch/<tag> branch, working tree clean

FOR i in 1..N:
  1. Verify clean git state: `git status` must show no uncommitted changes
  2. Pick one mutation axis — make one focused change to agent.py or skills/security-scan.md
  3. Commit: `git add <changed_file> && git commit -m "<axis>: <description>"`
  4. Run eval:  `python eval_harness.py > run.log 2>&1`
  5. Read score: `grep "^COMPOSITE_SCORE:" run.log` → extract float
  6. If score > best_score:
       best_score = score
       status = "keep"   (do NOT reset — stay on this commit)
     Else:
       status = "discard"
       `git reset --hard HEAD~1`   (revert exactly one commit)
  7. Append to results.tsv: <short_commit_hash>\t<score>\t<status>\t<description>
  8. Continue

END: print summary — best score, delta from baseline, which axes improved
```

**Error handling:**
- If `eval_harness.py` crashes (exit code non-zero or COMPOSITE_SCORE not found in log): log status as `crash`, run `git reset --hard HEAD~1`, continue
- If `git reset` fails: STOP immediately, print error, do not continue — human intervention required

### results.tsv format (tab-separated, not comma-separated)

```
commit	score	status	description
a1b2c3d	0.710000	keep	baseline
b2c3d4e	0.760000	keep	tightened FP rules for IaC monitoring controls
c3d4e5f	0.730000	discard	switched to explain-then-fix reasoning
d4e5f6g	0.780000	keep	flagged lines only context — reduced over-modification
```

---

## Git Branch Strategy

```
main                    # stable production config — agent never touches this
autoresearch/mar19      # experiment branch for this session
autoresearch/mar20      # next session starts fresh from main
```

Winning `agent.py` config is reviewed by the human, then manually merged to `main`.

---

## Integration with Existing Codebase

`eval_harness.py` dynamically imports `agent.py` at runtime to read `SYSTEM_PROMPT` and `_build_prompt()`, then calls the Anthropic API directly. No Claude Agent SDK, no Docker, no backend required for the research loop.

Dependency: `claude` CLI must be installed and authenticated (standard Claude Code setup — no additional API key required).

The production `LocalClaudeRemediator` in `agent.py` is used as-is. Eval harness and production pipeline share the same remediator class.

---

## Invocation

No CLI command needed. Invoked conversationally inside Claude Code:

```
"Read program.md and kick off a new autoresearch run, 20 experiments."
```

The agent reads `program.md`, creates the branch, establishes baseline, and runs the experiment loop autonomously.

---

## What You Get Per Session

- `results.tsv` — all N experiments with scores, statuses, descriptions
- Winning `agent.py` on the experiment branch
- Agent summary of which mutation axes drove improvement
- Baseline vs best score delta — measurable progress metric

---

## Out of Scope

- Taint/dataflow analysis (semgrep OSS limitation — revisit later)
- Backend-driven scanning in the eval loop (local CLIs used for speed)
- Continuous/daemon mode (session-based invocation only)
- Java port (prototype in Python first)
- Population-based / genetic algorithm optimization (hill-climbing sufficient to start)
