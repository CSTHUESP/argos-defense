# Contributing to ARGOS Defense

Thank you for helping. ARGOS Defense is an **experimental** defensive investigation framework: it analyses telemetry you supply, flags suspicious behaviour and assesses automation and LLM involvement with explicit evidence and uncertainty. Contributions that make its conclusions more accurate, more explainable or easier to verify are the most valuable.

Start with the [roadmap](ROADMAP.md) and the [open issues](https://github.com/CSTHUESP/argos-defense/issues). Issues labelled `good first issue` are small and self-contained. Issues labelled `help wanted` need specialist knowledge or an environment the maintainers do not have (a Windows 11 desktop, a Splunk instance, a Sigma backend, genuine EVTX samples).

## Data you may contribute
- Use **synthetic** data, or samples you are explicitly authorized to publish, with a note on where they came from and under which terms.
- Synthetic data uses RFC 5737 addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.*` domains and invented names, and is labelled synthetic.
- **Never** put credentials, session tokens (`.session_token`), API keys, private investigation material, or employer/customer telemetry in issues, pull requests, fixtures, screenshots or logs. Sanitise before you paste. A public issue or PR is public forever.
- Security vulnerabilities do not go in public issues: see [SECURITY.md](SECURITY.md).

## Development setup
Python **3.11, 3.12 or 3.13** (CI tests all three on Linux, plus 3.12 on Windows and macOS arm64/x86_64).

```bash
git clone https://github.com/CSTHUESP/argos-defense && cd argos-defense
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-ci.lock
pip install --no-deps --no-build-isolation -e .
argos-defense doctor
```

Dependencies are pinned with hashes. To change one, edit `requirements.in` (runtime), `requirements-dev.in` or `requirements-build.in`, then regenerate `requirements.lock` / `requirements-ci.lock` with the `deps.yml` workflow (see [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md)). Do not hand-edit the lock files.

## Running checks
```bash
python -m pytest -q                    # full suite (one Windows-only ACL test is skipped elsewhere)
python -m pytest -q tests/test_v031_recovery.py   # a focused file
python -m argos rules                  # validate the rule files
python scripts/validate.py             # synthetic demo scenarios (15 checks)
python scripts/eval_v22.py run --set dev   # development evaluation (see below)
argos-defense demo && argos-defense start  # try the UI with the synthetic demo case
```
CI (`.github/workflows/ci.yml`) runs the rules check, `doctor`, the test suite and `scripts/validate.py` on every pull request, plus a wheel/sdist build installed outside the checkout. Pull-request CI has read-only permissions and no secrets; release jobs run only from tags created by maintainers.

Native packages can be built on your own OS: `python packaging/build_native.py --out dist-native`, then `python -m playwright install chromium` and `python packaging/smoke_test.py --archive dist-native/<archive>` ([docs/PACKAGING.md](docs/PACKAGING.md)).

## Where things are
| Path | Contents |
|---|---|
| `src/argos/ingest/` | file adapters (`adapters.py`) and the import pipeline: hashing, retained originals, revisions, rejects, finalization |
| `src/argos/normalize/` | field mapping and time-zone handling |
| `src/argos/detect/` | rule schema, operators and evaluation engine; Sigma/SPL export |
| `src/argos/resources/rules/detections/` | the YAML detection rules |
| `src/argos/correlate/`, `src/argos/entities/` | session/tool-call correlation keys, entities and relationships |
| `src/argos/evidence/` | six-dimension assessment, confidence caps, original-record lookup, redaction |
| `src/argos/watch.py`, `src/argos/jobs.py`, `src/argos/backup.py`, `src/argos/store.py` | directory watcher, analysis job queue, backup/restore, SQLite store and migrations |
| `src/argos/api/`, `src/argos/templates/` | local web UI and JSON API |
| `tests/` | pytest suite; `tests/test_v031*.py` hold the latest regression tests |
| `fixtures/` | synthetic fixtures and evaluation sets (`fixtures/ground_truth/` labels are never imported) |
| `scripts/` | validation, evaluation and benchmark scripts |
| `packaging/` | native build, smoke test, release preflight and release contract |
| `docs/` | detection model, threat model, evaluation protocol, remediation records |

## Pull requests
- Keep each PR focused on one problem; open an issue first for larger changes so the approach can be agreed.
- Fill in the PR template: problem, behaviour change, test evidence, documentation/migration impact, data confirmation.
- Behavioural changes need **both** a positive test (the intended behaviour happens) and a negative test (the wrong behaviour no longer happens, or a near miss is not flagged). A bug fix should include a regression test that fails without the fix.
- Do not change test expectations to make a change pass. Fix the cause, or explain a justified fixture correction in the PR.
- Update the relevant documentation and `CHANGELOG.md` (under an *Unreleased* heading).

### Changes to detection rules
- Every rule declares its observation vantage, required telemetry, reference type, alternatives, known false positives, sources and validation status; new rules start as `experimental` (confidence capped at low).
- Keep the six dimensions separate: threat activity, automation, LLM involvement, framework presence, purpose and entities. A rule must never conclude a person, group, nationality or exact model, and missing LLM evidence never means "human".
- Add positive and negative tests in `tests/test_rules.py` (or a new file), and check the effect on the development evaluation set.

### Changes to telemetry adapters
- Use synthetic or authorized, documented sample files; state which product/version and field documentation the fixture follows.
- Keep original-record locators exact, never fabricate missing fields, and report rejected records with a reason. Test malformed input, time zones and size limits.

### Changes to evidence handling, redaction and recovery
- Imported content is inert data: never execute, fetch or interpret it as instructions.
- Redaction applies to every output path, including error messages.
- Import, watcher and job changes must stay idempotent and crash-safe: add a failure-injection test that inspects persisted state after reopening the store (see `tests/test_v031_recovery.py`).

## Evaluation protocol and datasets
The current protocol is **eval-v2.2** ([docs/EVALUATION_PROTOCOL.md](docs/EVALUATION_PROTOCOL.md)). It is synthetic, generated by the same project that wrote the rules, so it is held-out validation of a synthetic corpus, not a measure of real-world accuracy.

| Dataset | Status |
|---|---|
| `fixtures/eval_v2_2/dev` | development data: use it freely while working on rules |
| `fixtures/eval_v2_2/reserved` | **frozen reserved set**: do not tune against it. Every run is appended to `docs/eval_v2_2_inspection_log.jsonl`; it was inspected once for v0.3.1 |
| `fixtures/eval_v2_1`, `fixtures/eval_v2` | already inspected: **reused development data**, not a holdout |

If a change is tuned on the reserved set, that set becomes development data and a new reserved set (new seeds, new protocol version) is required. Report development results in the PR; maintainers decide when the reserved set is run.

## Releases
Releases are made by maintainers through `.github/workflows/create-tag.yml` and `release.yml` (shared preflight, native builds and smoke tests on each platform, release contract, uploaded-byte verification). Published tags are never moved and published assets are never replaced; a correction gets a new version.

## License
By contributing you agree that your contribution is licensed under the project's license, Apache-2.0 ([LICENSE](LICENSE)). Do not copy code from ARTEX (AGPL-3.0) or other incompatible sources into ARGOS; `reference/ARTEX` is retrieved separately for research only (`scripts/fetch_artex_reference.sh`).
