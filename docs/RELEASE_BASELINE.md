# Release baseline

## Baseline 2 — 2026-11-20 13:30 CET (before the remediation pass)
Environment: Linux x86_64 sandbox, Python 3.13.18 (`.venv`, system site-packages), no PyPI access; GitHub reachable via the session proxy (branch push yes, tag push previously HTTP 403, repository-settings writes blocked).

| Item | Observed |
|---|---|
| Local / remote `main` | `2919529a48055d2367679fe993a3aabeaa5be4ec` (identical), clean working tree |
| Tags / releases | none / none (no drafts) |
| Repository visibility | **public** (`private: false`) — changed outside this session since the previous check; branch protection: none |
| Last CI on 2919529 | run 44723021193 success; release dry run 44719465528 (commit 93fb079) success on 4 native targets |
| `python -m pytest` | **110 passed** (32.3 s) |
| CLI workflow | `demo` → 425 events, 29 alerts → `alerts` → `report --format json` written |
| Audit findings (`scripts/audit_repro.py`) | F01–F13 all reproduced on this commit (F06: migration backup copy contained no tables because committed data was still in the WAL) |

## Baseline 1 — 2026-11-20 10:37 CET (before v0.2.0 work)
Reproduced claims of the v0.1.0 handover: 75 tests, 15/15 scenarios, AUTH-003 27 alerts on random data (27/300 identities), CLI workflow; no git repository; no GitHub access.
