# Release baseline (before v0.2.0 changes) — 2026-11-20 10:37 CET

Reproduced in this session, before changing behaviour:

| Claim from v0.1.0 handover | Reproduced? | Observation |
|---|---|---|
| Project at `/home/claude/argos-defense` | yes | Starlette + SQLite + Jinja2 app, `src/argos`, 26 rules, tests, docs, `.venv` (system-site-packages) |
| Git state | **no repository** | not a git repo; no commits, no tags → version 0.2.0 is unused |
| 75 tests pass | yes | `python -m pytest` → 75 passed (21.6 s) |
| 15 synthetic scenarios pass | yes | `scripts/validate.py` → 15/15 |
| AUTH-003 alerts on 12k random events | yes | 27 ARG-AUTH-003 alerts (denominator was raw events, not identities — see AUTH_RULE_EVALUATION.md) |
| import → analyze → alert → evidence → export | yes | CLI: ingest identity fixture → 5 alerts → AUTH-002 alert → 5 evidence events (`ev:fb385fb1e59fb9f0:13…`) → JSON and HTML report written; HTTP/UI path covered by `test_web_e2e.py` (passed) |
| Browser form fix (Referrer-Policy same-origin) | yes (in code + regression assertion) | rechecked again after changes (see RELEASE_VALIDATION.md) |
| EP-002 fixed by fixture vantage change | partially | change was in a handcrafted native test; adapter-level review done in v0.2.0 |
| Session token not in reports/docs | yes | grep of the token value in `reports/` and `docs/` found nothing |
| LICENSE placeholder | yes | LICENSE contained only an Apache-2.0 notice, no full text |
| PyInstaller available locally | **no** | not installed; this sandbox cannot reach PyPI → native builds only possible on CI runners |
| GitHub access from this session | **no** | API answers "No linked GitHub account"; repository creation/push blocked until the owner connects GitHub |
