# Validation

> v0.2.0 status: see **RELEASE_VALIDATION.md** (110 tests, native package smoke tests on 4 targets) and **AUTH_RULE_EVALUATION.md**. The section below is the original v0.1.0 record, kept for history.

## v0.1.0 record (2026-11-20, Linux sandbox, Python 3.13.18)

**Scope:** synthetic scenarios only. Real-world attack-detection accuracy is **NOT MEASURED** (no independent labelled corpus). Source-derived patterns and synthetic tests do not establish production-validated detection.

## Automated tests — `python -m pytest` → **75 passed** (full log: `reports/pytest_output.txt`)
| File | Tests | Covers |
|---|---|---|
| test_ingest.py | 17 | adapters (native, Splunk JSON `result` wrapper, Splunk CSV mapping, Sysmon XML, Zeek conn/http/dns + uid), idempotent re-import, identical distinct records kept, out-of-order, ambiguous timestamps (reject vs explicit `assume_tz`), malformed records with reasons, size limits, hostile names, XXE, case boundaries, synthetic/real separation, retained originals + hashes |
| test_rules.py | 24 | positive **and** negative per family (1–8), baseline abstention and prior-only history, registry expiry and non-suppressible credential changes, ARTEX corroboration rules, rule-schema rejection of code/unknown operators/unsafe YAML |
| test_acceptance.py | 15 | acceptance scenarios 1–8, 12–15 (+ attestation and rule-version history) |
| test_security.py | 14 | acceptance 11 (prompt-injection inert, HTML escaped, CSV formulas), redaction, optional LLM layer with a **SIMULATED** provider |
| test_web_e2e.py | 4 | acceptance 16 through a real uvicorn server: auth, Host, Origin, CSRF, UI import → analyze → alert → evidence → notes/status → JSON/HTML/CSV export, bearer API, restart persistence; CLI refuses non-loopback bind |
| test_perf.py | 1 | 12,000-event batch |

Acceptance mapping: 1 `test_01_same_trace…` · 2 `test_02…` · 3 `test_03…` · 4 `test_04…` · 5 `test_05…` · 6 `test_06…` · 7 `test_07…` · 8 `test_08…` · 9 `test_ingest.py` (idempotent, out-of-order, tz, missing fields, malformed) · 10 `test_identical_distinct_records_are_kept` · 11 `test_security.py` + hostile path/XXE tests · 12 `test_12…` · 13 `test_13…` · 14 `test_14…`, `test_14b…` · 15 `test_15…`, `test_15b…` · 16 `test_web_e2e.py::test_16…` + browser check below.

## Scenario validation — `python scripts/validate.py` → **15 / 15 scenarios pass** (`reports/validation_results.json`)
Ground truth lives in `fixtures/ground_truth/` and is never imported. Results on the demo set:
- Authorized scanner, CI health checks, nightly backup → visible but dispositioned `authorized_automation`, no framework attribution.
- Enumeration, port sweep, password spray from 203.0.113.50 → alerts; LLM = unknown.
- Slow account takeover (alice, hours apart) → ARG-AUTH-002 **high**, automation unknown.
- bob failures→success without data access → ARG-AUTH-003, follow-up check `absent_within_demonstrated_coverage`, no exfiltration hypothesis.
- carol behind bob's IP → separate entity (co-occurrence labelled inferred, not identity).
- SP credential add + multi-vault reads, web shell chain on web-01, archive + 700 MB upload on fileserver-02 (`possible_exfiltration`, explicitly not established).
- dev-ws-07 ARTEX agent → framework `corroborated_presence` (3 independent families), LLM `directly_observed` (audit records + same ProcessGuid), automation `mixed` (human approval record); responsibility "not established".
- Developer DNS to api.openai.com → informational, LLM `possible` only.
- `ARTEX` in User-Agent → weak, low confidence, no corroboration.
- **Unexpected alerts in demo:** none. **Abstentions in demo:** none (baseline abstention is exercised in `test_sp002_insufficient_baseline_abstains`).
- **Discovered false positives on random background noise (12k events):** ARG-AUTH-003 × 27 (users with intermittent failures). Documented in DETECTION_MODEL.md.

## Performance (single run, `reports/perf_bulk_12k.json`)
12,000 native events, chunk size 1,000: ingest 3.0–3.2 s, analysis 7.6 s, Python tracemalloc peak ≈ 85 MB, RSS delta ≈ 167 MB (2 vCPU sandbox). Analysis loads a case's events in memory; no guarantee for other machines or sizes.

## Live startup and browser verification
- `scripts/start.sh --port 8789` → doctor OK → server on 127.0.0.1:8789.
- `scripts/ui_check_playwright.py` (Playwright + headless Google Chrome, **automated, Linux only**): login redirect, overview, case banner, re-analyze button, filtered queue, alert detail with 6 dimensions, note escaping, evidence/original record, entities with inferred-relationship labelling, rule catalog, import with CSV mapping field, HTML export download; **0 console errors**. Screenshots: `reports/ui_screenshots/`.
- Bug found only by the real browser and fixed: `Referrer-Policy: no-referrer` made Chrome send `Origin: null` on form posts, so every form was rejected. Now `same-origin`; regression assertion added to the e2e test.

## Not verified
Windows / PowerShell launcher (written, not executed); macOS; real Splunk, Sysmon or Zeek exports from production systems (only synthetic files shaped per vendor field names); Ollama integration (no model available — only the simulated provider is tested); FastAPI (not installable offline; Starlette used directly).
