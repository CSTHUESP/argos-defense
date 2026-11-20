# Release validation — v0.2.0

**Experimental detection; real-world accuracy not measured.** This document records what was actually checked for the v0.2.0 software release. Results for the tagged release run itself are published with the release (`release-manifest.json`, `smoke-<target>.json`, `smoke-<target>.log`) and summarised in the release notes after publication.

## Source tests
| Where | Result |
|---|---|
| Build sandbox (Linux, Python 3.13.18) | `python -m pytest` → **110 passed** |
| CI run [44715570390](https://github.com/CSTHUESP/argos-defense/actions/runs/44715570390) (commit a55f50b) | 109 passed on each of ubuntu-22.04 (py3.11/3.12/3.13), windows-2022 (py3.12), macos-15 (py3.12), macos-15-intel (py3.12); wheel + sdist installed and run outside the checkout |
| CI runs on later commits | see the Actions tab; the release workflow re-runs the full suite on every native runner before packaging |

Suite composition: ingestion and vendor-format edge cases (23), rules with positive/negative cases per family + exports (33), acceptance scenarios 1–15 (15), security/LLM-layer (14), simulated Ollama endpoint (5), adapter-level provenance (6), launcher/data-dir/migration (9), held-out auth evaluation (1), web end-to-end through a real server (4), 12k-event batch (1).

## Synthetic scenario and rule evaluation
- `scripts/validate.py`: **15/15** demo scenarios (ground truth in `fixtures/ground_truth/`, never imported).
- `scripts/auth_eval.py` (unit: identity sequence): held-out benign sequences alerted **81/180 (v1) → 41/180 (v0.2.0)**, malicious **120/120 → 120/120**; residual cases and the non-blind M4 figure are documented in `AUTH_RULE_EVALUATION.md`.
- These are synthetic results only. They validate the prototype's scenarios, not real-world accuracy.

## Native packages (dry run of the release workflow on commit 93fb079)
Run [44719465528](https://github.com/CSTHUESP/argos-defense/actions/runs/44719465528) (`release.yml`, `dry_run=true`): built, extracted and smoke-tested each package on its own runner, then ran the release gate (all 4 targets present, same commit, smoke-tested on the exact archive bytes) → **passed** (23 files in SHA256SUMS).

| Target | Runner (image version) | Native smoke test | Notes |
|---|---|---|---|
| windows-x86_64 | windows-2022 (20261111.635) | **30/30 PASS**, frozen=True | executable-bit check not applicable on Windows |
| linux-x86_64 | ubuntu-22.04 (20261103.629) | **31/31 PASS**, frozen=True | |
| macos-arm64 | macos-15 → image macos-15-arm64 (20261111.635) | **31/31 PASS**, frozen=True | runner.arch ARM64 verified |
| macos-x86_64 | macos-15-intel → image macos-15 (20260819.586) | **31/31 PASS**, frozen=True | runner.arch X64 verified |

Smoke-test coverage per target: see `docs/PACKAGING.md`. Includes a real Chromium browser submitting the login, create-case, multipart import, analyze and note forms against the native executable; HTML export download; restart persistence; bundle immutability; IANA time-zone resolution; token absent from logs.

### Defects found by the native runs and fixed before tagging
| Run | Platform | Defect | Fix |
|---|---|---|---|
| 44716220769 | Windows | PyInstaller spec appended `collect_data_files("tzdata")` (2-tuples) to `a.datas` (3-tuple TOC) → build crash | pass tzdata data files via `Analysis(datas=…)` |
| 44716998681 | Windows | redirected stdout uses cp1252 → `doctor` crashed printing a non-ASCII data path; harness crashed on the same and left the server running (13-minute step) | UTF-8 output when redirected (`cli._utf8_when_redirected`), regression test with `PYTHONIOENCODING=cp1252`; harness forces UTF-8 and kills leftover servers |
| local harness run | all | upload file names with non-ASCII letters were rejected | Unicode-aware safe-name pattern (separators, `..`, control characters still rejected) |
| v0.1.0 Chrome check | browser | `Referrer-Policy: no-referrer` → `Origin: null` on form posts | `same-origin` (regression assertion kept; native smoke re-verifies real form posts on all 4 targets) |

## What these results do NOT establish
- The packages were tested only on GitHub-hosted runner images (Windows Server 2022, Ubuntu 22.04, macOS 15 arm64/x86_64). Windows 10/11 desktop, other distributions and older macOS releases are not tested.
- No genuine vendor exports were tested; adapter tests use synthetic, schema-shaped data built from documented field names.
- The real Ollama integration was not exercised (simulated endpoint only).
- Sigma/SPL exports were not executed in Splunk or a Sigma backend.
- No code signing beyond macOS ad-hoc signatures, no notarization, and no GitHub attestations (private repository).
