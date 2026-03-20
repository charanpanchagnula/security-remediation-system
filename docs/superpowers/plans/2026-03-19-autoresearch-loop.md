# Autoresearch Continuous Improvement Loop — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a session-based autoresearch loop that experiments with agent.py prompts against a fixed benchmark of 15 seed cases (5 per scanner), measuring remediation quality via composite score.

**Architecture:** `eval_harness.py` orchestrates scan→remediate→rescan→score using real scanner CLIs and `LocalClaudeRemediator`. `program.md` instructs the Claude Code agent to mutate `agent.py`, commit, run the harness, keep or revert based on score. Scanner parsing in `scanner_parsers.py`, patch application in `patch_applier.py`.

**Tech Stack:** Python 3.11+, claude_agent_sdk (existing), semgrep (pip), checkov (pip), trivy (brew), pytest, uv

---

## File Map

| File | Role |
|---|---|
| `autoresearch/scanner_parsers.py` | Run scanner CLIs, parse JSON output → vuln dicts |
| `autoresearch/patch_applier.py` | Apply patch JSON code_changes to source strings |
| `autoresearch/eval_harness.py` | Orchestrate scan→patch→rescan→score, print COMPOSITE_SCORE |
| `autoresearch/program.md` | Agent research instructions — mutation axes, loop, results.tsv |
| `autoresearch/benchmark/semgrep/*.json` | 5 seed SAST cases |
| `autoresearch/benchmark/checkov/*.json` | 5 seed IaC cases |
| `autoresearch/benchmark/trivy/*.json` | 5 seed SCA cases |
| `autoresearch/pyproject.toml` | deps (pytest; scanners installed separately) |
| `autoresearch/tests/test_scanner_parsers.py` | Unit tests |
| `autoresearch/tests/test_patch_applier.py` | Unit tests |
| `autoresearch/tests/test_eval_harness.py` | Unit tests for scoring |

---

## Task 1: Scaffold

- [ ] Create dirs: `autoresearch/{benchmark/{semgrep,checkov,trivy},tests}`
- [ ] Create `autoresearch/pyproject.toml` with pytest dev dep, python>=3.11
- [ ] `uv sync` in autoresearch/ — verify clean
- [ ] Commit: `chore: scaffold autoresearch directory`

---

## Task 2: scanner_parsers.py

**TDD.** Three parsers: `parse_semgrep_output`, `parse_checkov_output`, `parse_trivy_output` (pure functions taking dict+file_path, returning list of vuln dicts). Plus `run_semgrep/run_checkov/run_trivy` which write code to temp file, run CLI, return parsed results.

Vuln dict format (matches `_build_prompt()` in agent.py):
```python
{"scanner": str, "rule_id": str, "severity": str, "message": str,
 "file_path": str, "start_line": int, "end_line": int, "metadata": {"resource": str}}
```

Semgrep CLI: `semgrep --config auto <tmp_file> --json --quiet`
Checkov CLI: `checkov -f <tmp_file> --output json --quiet`
Trivy CLI: `trivy fs --format json --quiet <tmp_dir>`

All subprocess calls: `timeout=60`, catch `TimeoutExpired/JSONDecodeError/FileNotFoundError` → return `[]`.

Semgrep severity map: `{"WARNING": "MEDIUM", "ERROR": "HIGH", "INFO": "LOW"}`

- [ ] Write tests for all 5 parse functions (use fixture dicts, no subprocess needed)
- [ ] Run — verify fail
- [ ] Implement
- [ ] Run — verify pass
- [ ] Commit: `feat: add scanner parsers for semgrep, checkov, trivy`

---

## Task 3: patch_applier.py

Two functions:
- `apply_patch(source_code: str, change: dict) -> str` — replace lines `start_line..end_line` (1-indexed) with `change["new_code"]`. Raise `ValueError("out of range")` if line range invalid.
- `count_changed_lines(original: str, patched: str) -> int` — use `difflib.SequenceMatcher` to count non-equal lines.

- [ ] Write tests (valid replace, surrounding lines preserved, invalid range raises, zero diff, nonzero diff)
- [ ] Run — verify fail
- [ ] Implement
- [ ] Run — verify pass
- [ ] Commit: `feat: add patch applier`

---

## Task 4: Seed benchmark cases (15 JSON files)

Each case has: `id, scanner, vuln_type, language, file_path, expected_rule_id, expected_severity, message, start_line, end_line, vulnerable_code`

**5 semgrep cases:**
- `sql_injection_001` — f-string SQL query, rule: `python.lang.security.audit.formatted-sql-query.formatted-sql-query`
- `path_traversal_001` — `open(os.path.join('/uploads', filename))`, rule: `python.lang.security.audit.path-traversal.path-traversal-open`
- `command_injection_001` — `subprocess.run(..., shell=True)`, rule: `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`
- `hardcoded_secret_001` — `SECRET_KEY = 'hardcoded...'`, rule: `generic.secrets.security.detected-generic-secret.detected-generic-secret`
- `xss_001` — Flask `make_response(f'<h1>Hello {name}</h1>')`, rule: `python.flask.security.xss.reflected-xss-all-config.reflected-xss-all-config`

**5 checkov cases (Terraform):**
- `s3_public_acl_001` — `acl = "public-read"`, rule: `CKV_AWS_20`
- `sg_open_ingress_001` — SSH from `0.0.0.0/0`, rule: `CKV_AWS_25`
- `s3_no_encryption_001` — S3 bucket no server_side_encryption_configuration, rule: `CKV_AWS_19`
- `iam_wildcard_001` — `Action = "*", Resource = "*"`, rule: `CKV_AWS_40`
- `rds_public_001` — `publicly_accessible = true`, rule: `CKV_AWS_17`

**5 trivy cases (requirements.txt / package-lock.json):**
- `pillow_cve_001` — `Pillow==9.0.0`, CVE: `CVE-2023-44271`
- `pyyaml_cve_001` — `PyYAML==5.3.1`, CVE: `CVE-2020-14343`
- `requests_cve_001` — `requests==2.29.0`, CVE: `CVE-2023-32681`
- `cryptography_cve_001` — `cryptography==41.0.4`, CVE: `CVE-2023-49083`
- `lodash_cve_001` — `lodash@4.17.20` in package-lock.json, CVE: `CVE-2021-23337`

- [ ] Create all 15 JSON files
- [ ] Validate: `for f in benchmark/**/*.json; do python3 -m json.tool "$f" > /dev/null && echo OK; done`
- [ ] Commit: `feat: add 15 seed benchmark cases`

---

## Task 5: eval_harness.py

Public interface: `run_full_harness()` — loads cases, runs each via `run_case()`, computes aggregate, prints `COMPOSITE_SCORE: <float>` as final stdout line.

```python
# Scoring
fix_success      = 1.0 if expected_rule_id gone post-patch else 0.0
no_regression    = 1.0 if no new rule_ids introduced else 0.0
patch_minimality = 1.0 - min(lines_changed, original_lines) / original_lines
composite        = 0.6*fix_success + 0.2*no_regression + 0.2*patch_minimality
```

`run_case(case, remediator)` returns dict with `{id, status, score}`. Statuses: `ok | skip | error | patch_error | false_positive`.

Skip (don't score) when pre-scan doesn't detect `expected_rule_id` — broken case, not a failed experiment.

Imports `LocalClaudeRemediator` from `../cli/src` via `sys.path.insert`.

`if __name__ == "__main__": run_full_harness()`

- [ ] Write unit tests for `compute_score` weights, `load_benchmark_cases`, `find_matching_vuln`, `run_case` skip behavior (mock scanner returns empty list)
- [ ] Run — verify fail
- [ ] Implement
- [ ] Run all tests: `uv run pytest tests/ -v` — verify all pass
- [ ] Commit: `feat: add eval harness`

---

## Task 6: program.md

Write agent instructions covering:
1. Setup: create branch `autoresearch/<tag>`, read agent.py + skill, establish baseline, init results.tsv
2. In-scope: agent.py (SYSTEM_PROMPT, _build_prompt, temperature, retry), skills/security-scan.md
3. Off-limits: eval_harness.py, benchmark/, patch schema
4. Mutation axes A–E (persona, reasoning depth, context injection, FP criteria, hyperparams)
5. Loop (N=20): verify clean state → mutate one axis → commit → `python eval_harness.py > run.log 2>&1` → `grep "^COMPOSITE_SCORE:" run.log` → keep or `git reset --hard HEAD~1` → log to results.tsv → repeat
6. Error handling: crash → log + reset + continue; reset failure → STOP
7. results.tsv format (tab-separated, untracked)

- [ ] Write program.md
- [ ] Commit: `feat: add program.md research instructions`

---

## Task 7: Integration smoke test

- [ ] Verify scanners installed: `semgrep --version && checkov --version && trivy --version`
- [ ] Run one scanner manually against seed case code to confirm rule fires
- [ ] Run full unit suite: `uv run pytest tests/ -v` — all pass
- [ ] Run baseline: `python eval_harness.py > run.log 2>&1 && grep "COMPOSITE_SCORE:" run.log`
- [ ] Commit: `chore: autoresearch integration verified`

---

## Adding more benchmark cases later

1. Find vulnerable snippet from OWASP WebGoat, terragoat, cfngoat, PyGoat
2. Run scanner manually, copy exact rule_id from output
3. Add JSON to `benchmark/<scanner>/`
4. Re-run harness — verify case is scored not skipped

Target: 50 semgrep + 45 checkov + 35 trivy cases.
