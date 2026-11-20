# BUILD_STATE (checkpoint, final for this session — 2026-11-20 ~11:10 CET)

Project root: /home/claude/argos-defense · ARTEX: reference/ARTEX tag v0.6.0, commit a13c68cb7078d43b66fb398db3d610e513b6d77a

## Environment facts
Linux x86_64, Python 3.13.18, git 2.43. GitHub reachable via git; **PyPI unreachable** → FastAPI could not be installed; built on Starlette 1.7 (pre-installed). venv `.venv` created with `--system-site-packages`, editable install offline. Headless Chrome + Playwright available → used for UI check.

## Capability status
| Capability | Status |
|---|---|
| ARTEX clone at pinned commit, static review, fingerprint catalogue | IMPLEMENTED_AND_TESTED (review = docs; fingerprints tested on synthetic data only) |
| Native JSONL / Splunk JSON+CSV (mapping) / Sysmon XML / Zeek conn,http,dns adapters | IMPLEMENTED_AND_TESTED (synthetic files) |
| Idempotent import, rejects with reasons, tz handling, size limits, retained originals + SHA-256 | IMPLEMENTED_AND_TESTED |
| Entities with key strength, observed vs inferred relationships | IMPLEMENTED_AND_TESTED |
| 26 YAML rules, 8 families + IOC, restricted operators, overrides | IMPLEMENTED_AND_TESTED |
| Registry, IOC validity, observed-history baseline with abstention | IMPLEMENTED_AND_TESTED |
| Six-dimension assessment, confidence caps, heuristic scores | IMPLEMENTED_AND_TESTED |
| Web UI (overview, import, queue+filters, alert detail, evidence, entities, rules, notes/status) | IMPLEMENTED_AND_TESTED (HTTP e2e + headless Chrome on Linux) |
| Token auth, Host/Origin/CSRF, CSP, escaping, CSV formula neutralization, XXE/path defenses | IMPLEMENTED_AND_TESTED |
| JSON/HTML/CSV export, CLI (doctor, demo, ingest, analyze, serve, report, cases, alerts, rules, attest, note) | IMPLEMENTED_AND_TESTED |
| Optional LLM explainer: validation logic | IMPLEMENTED_AND_TESTED (simulated provider only) |
| Optional LLM explainer: Ollama provider | IMPLEMENTED_NOT_VERIFIED (no model available) |
| scripts/start.sh | IMPLEMENTED_AND_TESTED (Linux) |
| scripts/start.ps1 | IMPLEMENTED_NOT_VERIFIED (no Windows) |
| FastAPI | BLOCKED (PyPI unreachable) — Starlette used instead |
| Google Cloud "ARTEX and Friends" source review | BLOCKED (server error on fetch) |
| SPL / Sigma translations | NOT_IMPLEMENTED (optional extension) |
| Binary EVTX, PCAP, live connectors, process-environment fingerprint (FP-006) | NOT_IMPLEMENTED |

## Results
pytest 75 passed · validate.py 15/15 scenarios · 12k events: ingest ~3.1 s, analysis ~7.6 s · Chrome check 0 console errors.

## v0.2.0 session checkpoints (2026-11-20)
- 10:37 baseline reproduced (docs/RELEASE_BASELINE.md). No git repo existed; no GitHub credentials in session (owner asked to link + grant app access).
- 11:2x AUTH-003 v2 + AUTH-004 + source_history; labeled tuning/held-out eval (docs/AUTH_RULE_EVALUATION.md). EP-002 adapter-level provenance tests + ambiguous-vantage rejection. ARTEX FP independence review (X03 weak). 90+ tests pass.
- 11:4x rules/config moved to src/argos/resources; platform data dir; start launcher; /api/shutdown; schema meta + v1 migration; Apache-2.0 full text; notices; ARTEX manifest. Wheel install verified outside checkout.
- Next: PyInstaller spec + smoke test + workflows (pinned SHAs), docs, git init/commit, then GitHub publish when access exists.
- 11:0x GitHub app installed by owner; repo CSTHUESP/argos-defense (private, empty) attached; pushed main. CI run 44715570390 green (7 jobs).
- Release dry runs: 44716220769 (Windows spec tzdata TOC bug; others 30/30), 44716998681 (Windows cp1252 output crash + harness hang), 44719465528 (after fixes).
- Proxy limits: artifact/blob downloads blocked from session -> verification via job logs; repo settings writes blocked (description must be set by owner).

## v0.3.0 remediation pass checkpoints (2026-11-20, see docs/AUDIT_REMEDIATION.md)
- 13:30 Baseline 2 recorded (docs/RELEASE_BASELINE.md); F01–F13 reproduced with scripts/audit_repro.py. Repo found PUBLIC (not changed).
- 14:xx Schema v3 (input revisions, run snapshots, jobs, watch checkpoints, status history); F01–F10 implemented;
  backup/restore (argos/backup.py), jobs (argos/jobs.py), watcher (argos/watch.py), run comparison (reporting/compare.py),
  original-record retrieval (evidence/original.py); CLI: inputs/activate/coverage/runs/compare-runs/status/backup/verify-backup/restore/watch.
  pytest 148 passed. tests/conftest.py now uses a private config copy (a test previously wrote into packaged defaults — reverted).
- Next: F11/F12/F13 (release preflight, asset contract + negative tests, content-hash fingerprint), packaging launcher tests,
  evaluation protocol v2, benchmarks, Sigma/SPL review, dependency locks/audit, docs, CI, release.
- 14:20 F11–F13 done (preflight, release contract, verify_release, content fingerprint); eval v2 frozen; reserved set inspected once (13:04Z, c5304de);
  benchmarks 12k/100k ok, 1M analysis OOM-killed → 300k limit; hashed locks from deps runs; Sigma `|re|i` fix; docs updated for 0.3.0.
  EVTX: BLOCKED (PyPI unreachable locally; executing a git-cloned parser was not permitted in the session; no genuine Sysmon EVTX sample).
- Next: CI green on final main SHA → release.yml dry run (explicit sha) → create-tag.yml dispatch (tag push from session returns 403) with publish=true → verify.
- 14:51 RELEASED v0.3.0: tag v0.3.0 (annotated, created by create-tag.yml run 44746672484) → d538dba9f16d1a109f2f5b446c5df3737024d4aa;
  CI 44745620187 green (6 OS/Python jobs + wheel/sdist); release.yml 44746694912: 4 native builds (46/46 Windows, 48/48 Linux, 48/48 macOS arm64, 48/48 macOS x64),
  contract gate 27 assets, draft + uploaded-byte verification, 6 build-provenance attestations verified, published 13:50:57Z, all 27 public download URLs HTTP 200.
  Independently re-checked from the session: SHA256SUMS sha256 b080263f… equals the gate's pre-upload value; release-manifest.json matches it.
- Open: desktop acceptance (no desktops), EVTX (blocked), Splunk/Sigma backend, real Ollama, genuine exports, repo description/branch+tag protection (settings writes refused).
