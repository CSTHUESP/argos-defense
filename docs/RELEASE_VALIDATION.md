# Release validation — v0.3.1 (prepared; see status below)

**Experimental detection; real-world accuracy not measured.** This document describes the gates a release must pass and the results observed while preparing 0.3.0. Evidence for the final release commit itself (CI run, native runs, uploaded-byte verification) is produced by the workflows and published with the release (`release-manifest.json`, `smoke-<target>.json/.log`, the Actions logs); it cannot be committed here because this file is part of that commit.

## v0.3.1 status
- **Code:** complete locally on branch `v0.3.1-local`.
- **Remote:** nothing was pushed, dispatched or uploaded. The repository is currently **public**, while the owner's configured audience is **private**; publishing into the conflicting audience was not authorized. CI runs, native builds, the v0.3.1 tag and the release therefore do **not** exist yet.
- **Private-repository Git authentication (R09):** implemented and statically tested. A real private-repository run is pending until the repository is private.
- **Attestations:** the release workflow generates them only for public repositories. For a private repository on the current plan, the manifest records "not generated".
- **Immutable releases:** v0.3.0 is not immutable (`immutable: false`). Changing the repository setting was refused from this session.
- **Protections:** `main` is unprotected and there is no tag ruleset. Settings writes are refused from this session.

## Mandatory gates
1. Source tests on Linux (Python 3.11/3.12/3.13), Windows, macOS arm64 and macOS x86_64 (`ci.yml`), plus rule validation, `doctor`, `scripts/validate.py` and wheel/sdist installation outside the checkout.
2. Shared preflight (`packaging/release_preflight.py`): tag → one full SHA, semantic version, version agreement, release notes, `main` ancestry, successful CI for that SHA.
3. Native build and smoke test per target on its own runner (docs/PACKAGING.md), source tests repeated on each native runner.
4. Release contract (`packaging/release_contract.py`, 27 assets) — see the negative tests in `tests/test_release_contract.py`.
5. Draft created with `--verify-tag`; downloaded bytes verified against expectations retained before upload; attestations verified when generated.
6. Before publication: tag and draft bytes verified again; after publication: published assets downloaded and verified again.

A failure in any gate stops the workflow; no `continue-on-error`, no prerelease shortcut.

## Results observed while preparing 0.3.0
| Check | Where | Result |
|---|---|---|
| `python -m pytest` | build sandbox (Linux x86_64, Python 3.13.18) | 187 passed, 1 skipped (Windows-only ACL test) |
| `scripts/validate.py` | sandbox | 15/15 synthetic demo scenarios |
| `scripts/audit_repro.py` | sandbox | F01–F13: all reproduced on 2919529, none reproduced after the changes (`docs/audit_repro_after.json`) |
| Native smoke harness against a non-frozen stand-in package | sandbox | 47/48 (the only failure is the expected `frozen=True` check); used to debug the new launcher/update/backup checks before CI |
| `scripts/eval_v2.py` reserved set | sandbox | see docs/EVALUATION_PROTOCOL.md |
| Benchmarks | sandbox | see docs/PERFORMANCE.md |
| Dependency audit | `deps.yml` runs 44742521205, 44743018079 | docs/DEPENDENCIES.md |

CI and release run URLs for the final commit are listed in the release's handover and in `release-manifest.json` (`workflow_run`).

## Repository protection
Branch protection and tag rulesets were not configured from this session: the session's GitHub access cannot change repository settings (the repository-description update was also refused). The workflow checks above therefore enforce release policy only for releases made through these workflows; they are not equivalent to enforced repository protection. Recommended owner settings: protect `main` (require the CI checks, no force-push) and add a tag ruleset for `v*` (no update/delete) — only where they do not lock out the sole maintainer.

## What these results do NOT establish
- Packages are tested only on GitHub-hosted runner images (Windows Server 2022, Ubuntu 22.04, macOS 15 arm64/x86_64). Windows 10/11 desktop, other distributions and macOS versions, and downloads with quarantine attributes are not tested (procedure in docs/PACKAGING.md).
- No genuine vendor exports; adapter tests use synthetic, schema-shaped data.
- Ollama integration exercised only against a simulated endpoint; Sigma/SPL not executed in a backend.
- No Authenticode or Developer ID signing, no notarization.

## History
### v0.2.0 native dry run (historical, commit 93fb079)
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
