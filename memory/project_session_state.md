---
name: Session state — PyGoat scan + memory system
description: Current work state as of 2026-04-03 — PyGoat failures diagnosed, memory system implemented, both need follow-through
type: project
---

## PyGoat Scan Status
Scan ID: 49fb5c6a-383c-42c4-9833-18ab2d5e54ea
Backend: Docker port 8000
Pass rate: 82% (89/108 revalidated). 19 failures remain.

### All 19 failures diagnosed — fixes NOT yet applied

**6 × False positives stuck as FAIL_STILL_VULNERABLE**
Root cause: orchestrator.revalidate_scan does not check is_false_positive before marking status.
Fix needed: in orchestrator.py revalidate_scan(), before the original_still_present check, add:
  if rem.get("is_false_positive"): status = "PASS"; <skip to next rem>
vids: f52bc14b, 83baad04, a6d2e77a, 497dbc2b, de02938a, 805673a9

**4 × app.py cascading FAIL_NEW_ISSUES**
Root cause: vid=ab33a7c7 adds import os (shifts lines 1-5 → 1 element), then patches line 123 leaving app.run(host='0.0.0.0',port=5000) at line 125. This new position is not in orig_baseline → counted as new issue for ALL remediations that touch app.py.
Fixes needed in remediation code_changes (update JSON in results store):
- vid=53bdf8cb: line 123 new_code → `    app.run(port=5000)` (removes BOTH debug AND host)
- vid=ab33a7c7: set code_changes=[] (53bdf8cb handles it, no import os needed)
- vid=fd33a491, vid=21b56e73: will auto-PASS once app.run fix removes the cascading finding

**7 × HTML templates FAIL_STILL_VULNERABLE — wrong paths**
Root cause: agent used short paths like templates/CMD/cmd_lab.html but actual paths are introduction/templates/Lab/CMD/cmd_lab.html. Orchestrator skips patches for non-existent files.
Fixes needed (update file_path in code_changes for each):
- vid=88e31991: templates/CMD/cmd_lab.html → introduction/templates/Lab/CMD/cmd_lab.html (remove cmd_lab2 change, let 1e510bea handle it)
- vid=1e510bea: templates/CMD/cmd_lab2.html → introduction/templates/Lab/CMD/cmd_lab2.html
- vid=4f2f34bd: templates/otp.html → introduction/templates/Lab/BrokenAuth/otp.html (line 18)
- vid=08c4dd8b: templates/A9/a9_lab.html → introduction/templates/Lab/A9/a9_lab.html (line 10)
- vid=a5a4e568: templates/a1_broken_access_lab_2.html → introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_2.html AND templates/a1_broken_access_lab_1.html → introduction/templates/Lab_2021/A1_BrokenAccessControl/broken_access_lab_1.html
- vid=45d6494f: path already correct (introduction/templates/Lab/A9/a9_lab2.html) — investigate why still failing
- vid=d6d6031a: ssrf_discussion.html — agent used method="get" workaround, semgrep still flags. Need actual {% csrf_token %} fix at lines 125,130,135,140 (revalidation found these, original was at 36,70)

**1 × insec_des_lab FAIL_NEW_ISSUES**
Root cause: vid=0ee14242 also modified templates/index.html (description text), shifting CSRF finding lines → counted as new issue.
Fix: remove templates/index.html from code_changes of vid=0ee14242. Keep main.py changes only.

**1 × mitre.py FAIL_NEW_ISSUES**
Root cause: vid=83210b0b touches app.py:86 (sha256 fix). app.py is in patched_files. After ab33a7c7's broken patch, avoid_app_run_with_bad_host appears at line 125 → new issue. Will auto-PASS once ab33a7c7 code_changes=[] fixes the cascade.

### Fix approach
All fixes are updates to the remediation records in the results store (JSON), then re-run revalidation:
curl -s -X POST http://localhost:8000/api/v1/scans/49fb5c6a-383c-42c4-9833-18ab2d5e54ea/revalidate

Results store location (inside Docker): JSON file managed by result_service.
To patch code_changes directly: read scan JSON, update specific remediation entries, write back.

Revalidation scan ID (last run): 065a8257-41fe-423e-8252-f5a71c320830

## Memory System — IMPLEMENTED
New files:
- backend/src/remediation_api/services/memory_store.py (filesystem abstraction)
- backend/src/remediation_api/services/memory_service.py (load_agent_context + consolidate_learnings)

Modified files:
- orchestrator.py: imports memory_service, passes project_id to agent, calls consolidate_learnings at end of revalidate_scan
- autonomous_agent.py: remediate() and _build_prompt() accept memory_context, prepended to prompt

Tested locally across 2 simulated scans — works correctly.
Still TODO: fix the false-positive orchestrator logic (see above) which is ALSO needed for PyGoat.

## Next session priorities
1. Fix orchestrator.py is_false_positive → PASS logic
2. Patch the 19 remediation records (results store JSON) with correct code_changes
3. Re-run revalidation → target 100%
