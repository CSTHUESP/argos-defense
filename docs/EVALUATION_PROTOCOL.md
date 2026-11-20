# Evaluation protocols — synthetic held-out validation

## Current: eval-v2.2 (v0.3.1 follow-up, FU5)
**What changed:** the eval-v2.1 scorer matched a ground-truth chain by call string and process GUID plus unit membership. An injected alert pairing a chain's model request with an execution from **another collector and session** that reused the same call string (or the same process GUID on another host) was accepted as correct, and it marked the real chain as detected. `tests/test_eval_v22.py::test_v21_scorer_accepted_the_mismatch_regression_evidence` records this.

eval-v2.2 (`scripts/eval_v22.py`):
- Every ground-truth chain has a stable `chain_id` and names its exact source records: the model request and the execution records, as `<fixture file>:<1-based line>`. They are resolved when the data is frozen.
- At evaluation time each stored event is mapped back to its record through the input's original file name and `record_no`. The run aborts if any labelled record is missing.
- An alert may claim `directly_observed` only if its evidence contains that chain's model record **and** one of that chain's execution records. Call strings, process GUIDs, sessions and unit tags are never used for this.
- A chain counts as detected only through such an alert. A mismatched alert gets no credit, even when a correct alert exists for the same chain.
- The scorer still does not use the production correlator.

**New scenario N6:** a valid chain in collector A (session A). In `collector_b.jsonl` (session B, another host) there is an unrelated tool execution with the **same call string**, plus a process start with the **same process GUID** string.

**Injection tests** (`tests/test_eval_v22.py`):
- Same call string, different collector/session → 1 overclaim, chain not detected.
- Reused process GUID on another host → 1 overclaim, chain not detected.
- A bad alert and a good alert together → only the bad one is an overclaim, and the chain is detected once.
- A frozen-label check that every chain record points at the right kind of record.

**Data:**
- Location: `fixtures/eval_v2_2/{dev,reserved}` with the manifest `fixtures/eval_v2_2/MANIFEST.json`.
- Development set: seed 303, 12 per scenario, 4,184 events, 321 units.
- Reserved set: seed 8853, 20 per scenario, 7,413 events, 535 units.
- Newly generated with new seeds. The same author wrote the rules and the generator, so this is **synthetic held-out validation only**.
- The eval-v2.1 and eval-v2.0 sets (`fixtures/eval_v2_1`, `fixtures/eval_v2`) were inspected during earlier passes and are now **reused development data**.

**Process record:**
1. Implemented FU1–FU5. No rule or rule configuration was changed (rules hash `a0dba54b8a5fcef5`, unchanged since eval-v2.1).
2. Ran the dev set: 0 overclaims in 433 alerts; 59 of 59 chains (`reports/eval_v22_dev.json`).
3. Froze the generator, labels, data and evaluator in local commit `844b3cf`.
4. Ran the reserved set **once**: 2026-11-20T17:29:03Z, commit `844b3cf`, rules and evaluator clean (`docs/eval_v2_2_inspection_log.jsonl`). Results are in `reports/eval_v22_reserved.json`. Nothing was changed afterwards.

### Reserved-set results (eval-v2.2, first inspection)
Threat side:
- Benign units with a low-or-higher alert: **110 of 320**: B2 20, B7 20, B8 20, N5 20, N6 20, B4 9, B3 1. (N5 and N6 are legitimate agent chains, correctly reported at low severity as observed model-driven tool use.)
- Benign units with any alert: 190 of 320. Benign alerts per benign unit-day: 0.219.
- Detection by scenario: M1, M2, M3, M4, M6, M7, M8 and M10 each 20/20; M9 18/20; H 15/15; **M5 0/20** (known gap).
- Hidden-origin triplets with identical conclusions: 5/5.

Attribution side, exact-record scoring:
- Alerts scored: 714.
- **LLM overclaims: 0**, including the N1, N3, N4, N5 and N6 negatives.
- Framework errors: 0. Identity errors: 0.
- Labelled chains directly observed: **96 of 96**.

Burden: 133.5 alerts per 100 units; median 1 and maximum 13 per unit; 3.1 % at low confidence; 0 abstentions. B8 produced 188 alerts for 20 units.

These figures describe this synthetic corpus only. They are not real-world false-positive or detection rates.

---

## Historical: eval-v2.1 (v0.3.1 candidate `13686bb`) — now reused development data
**What changed (R06):** the eval-v2.0 scorer allowed `directly_observed` for a whole unit whenever the unit contained any `model_interaction` or `tool_execution` record. That could not count a wrong attribution as an error. eval-v2.1 (`scripts/eval_v21.py`) scores **each alert**:
- Labels list each unit's ground-truth model→execution **chains** (tool call id + executed process GUID).
- An alert may claim `directly_observed` only if its own evidence contains a model record **and** an execution record of the same labelled chain.
- `possible` requires model records or AI-provider traffic in the alert's evidence.
- Framework levels other than `unknown`, and any identity conclusions, are counted as errors.
- The scorer does not use the production correlator. A test enforces that it never calls `derive()` and never uses session or call keys.
- Injected wrong predictions are proven to be counted (`tests/test_eval_v21.py`).

**New scenarios (attribution negatives):**
- N1: tool execution and process without a model record.
- N2: model request without an execution.
- N3: mismatched call ids.
- N4: two independent collectors reusing the same local session and call ids, in two separate input files.
- N5: a mixed unit with a valid chain plus an unrelated scheduled tool execution on the same host.

All other scenarios are unchanged from eval-v2.0.

**Data:**
- Location: `fixtures/eval_v2_1/{dev,reserved}/events.jsonl` + `collector_b.jsonl` + `labels.json`, with the frozen manifest `fixtures/eval_v2_1/MANIFEST.json`.
- Development set: seed 202, 12 per scenario, 4,125 events, 309 units.
- Reserved set: seed 7741, 20 per scenario, 7,306 events, 515 units.
- Generated by the same author who wrote the rules: this is **synthetic held-out validation**, not external or real-world validation.
- The eval-v2.0 sets (`fixtures/eval_v2`) informed this pass and are now **reused development data**, not a holdout.

**Process record:**
1. Implemented the R01–R09 changes. The only rule change was ARG-AUTH-003 v3: an explicit event family for its follow-up check, which coverage semantics required (R05). No rule was tuned on eval data.
2. Ran the dev set:
   - v0.3.1 code: 0 LLM overclaims.
   - Same scorer on the **v0.3.0 code** (`ARGOS_EVAL_SRC=<v0.3.0 worktree>/src`): **12 LLM overclaims**, all N4 independent-collector units. This shows the scorer detects the R04 defect that the eval-v2.0 scorer could not.
3. Froze the generator, labels, rules and evaluator in local commit `8060244`.
4. Ran the reserved set **once**: 2026-11-20T14:53:43Z, rules hash `a0dba54b8a5fcef5`, no files modified (`docs/eval_v2_1_inspection_log.jsonl`). Nothing was changed afterwards.

### Reserved-set results (eval-v2.1, first inspection; scorer later found defective, see eval-v2.2)
Threat side — units are identity/host/application sequences:
- Benign units with a low-or-higher alert: **90 of 300**. Benign units with any alert: 170 of 300. Benign alerts per benign unit-day: 0.200.
- New N-scenario units: N1, N3 and N4 alert at informational severity only (automation evidence); N2 does not alert; N5 alerts at low severity for its valid chain (20 of 20).
- Remaining benign low-or-higher alerts are as in v2.0: B2 (20), B7 (20), B8 (20), B4 (7) and B3 (3).
- Detection by scenario: M1, M2, M3, M4, M6, M7, M8 and M10 each 20/20; M9 19/20; H 15/15; **M5 (source rotation interleaved with the real user) 0/20** (known gap).
- Identical traces with hidden origins human, script and LLM agent: 5/5 triplets gave identical conclusions.

Attribution side — scored per alert, independent ground truth:
- Alerts scored: 646.
- **LLM overclaims: 0.** This includes the N1, N3, N4 and N5 negatives.
- Framework errors: 0. Identity errors: 0.
- Labelled chains directly observed: 79 of 79 (none missed).

Burden:
- 125.4 alerts per 100 units; median 1 and maximum 13 per unit; 3.9 % of alerts at low confidence; 0 abstentions.
- Legitimate developer agents still dominate the burden: B8 produced 197 alerts for 20 units, and N5 produced 80 for 20. A legitimate model-use observation is not a malicious finding, but it costs review time.

These figures describe this synthetic corpus only. They are not real-world false-positive or detection rates.

---

## Historical: eval-v2.0 (v0.3.0) — now reused development data

**What this is:** a frozen, versioned synthetic evaluation with separate development and reserved sets. The same author wrote the rules and the generator, so the result is **synthetic held-out validation**. It is not independent validation and says nothing about real-world false-positive or detection rates.

## Data
- Generator: `scripts/eval_v2.py` (`freeze` writes `fixtures/eval_v2/{dev,reserved}/events.jsonl` + `labels.json` and `fixtures/eval_v2/MANIFEST.json` with SHA-256 of every file). `run` refuses to evaluate if a file differs from the manifest.
- Development set: seed 101, 12 units per scenario, 6 days, 3,945 events, 249 units. May be inspected and used for tuning.
- Reserved set: seed 9277, 20 units per scenario, 7 days, 6,942 events, 415 units; different parameter ranges (failure counts, spacing, failure probability, device counts, stale-device fix probability, spray width, NAT size). Every run is appended to `docs/eval_v2_inspection_log.jsonl` (time, commit, rules hash, whether rule files were modified, purpose, summary).
- Units are identity/host/application sequences. Identifiers carry an opaque tag (`uNNNN`) so alerts can be mapped back; **labels are never imported**. Each unit has a **threat** label (benign/malicious) and a separate **origin** label (human/script/llm_agent); origin never determines the expected LLM result — only records that are actually present do.
- Provenance class of all data: *generated schema-shaped synthetic fixtures*. No published examples, genuine vendor exports or organizational pilot data were used (none was available; using an employer's systems was explicitly out of scope).

## Scenarios
Benign: B1 typos then success · B2 5–9 typos from a previously successful own device · B3 multi-device intermittent sign-ins · B4 stale saved credential failing hourly · B5 several users behind one NAT · B6 hourly service-principal automation reading its own vault · B7 administrative credential rotation (SP sign-in + successful credential add) · B8 developer AI coding assistant (model tool calls with call ids → tool executions → `git` processes) · B9 background AI-provider DNS traffic · B10 incomplete telemetry (no source address).
Malicious: M1 fast guessing · M2 slow guessing (0.5–3.5 h apart) · M3 guessing interleaved with the real user's successes · M4 per-attempt source rotation · M5 rotation **and** interleaving · M6 SP credential add that fails · M7 SP credential add then reads of several vaults · M8 web shell (w3wp → cmd → external connection) · M9 password spray · M10 slow guessing without source addresses followed by a mailbox-rule change · H identical traces generated three times with hidden origins human/script/llm_agent (the correct LLM result is *unknown* and all three conclusions must be identical).

## Metrics
- Benign units with a low-or-higher alert, with any alert, benign alerts per benign unit-day.
- Detection by scenario: a malicious unit counts as detected if an alert from the scenario's expected rules covers it.
- Incorrect strongest LLM assertion: the strongest LLM level on a unit's alerts exceeds what the unit's records support (`directly_observed` only with model/tool audit records, `possible` only with AI-provider traffic or model records). Incorrect framework assertion: any framework level other than unknown.
- Abstention (abstained alerts / alerts), rule-status counts and records lacking required telemetry per rule (unavailable-rule view), and analyst review burden (alerts per 100 units, median/max per unit, share of low-confidence alerts).
Severity and confidence are reported separately; heuristic scores are not used as probabilities.

## Process record
1. Development runs on `dev` (several). Finding: M10 0/12 because ARG-AUTH-002 did not treat mailbox-rule creation as a sensitive action → ARG-AUTH-002 v3 adds mailbox-rule / mail-forwarding actions (public BEC guidance). Dev after the change: M10 12/12; other results unchanged. M5 (rotation + interleaving) stayed 0/12; no rule change was made for it.
2. Reserved set evaluated **once**, at 2026-11-20T13:04:37Z, commit `c5304de`, rules hash `f2f9eab78425bab3`, rule files unmodified (log entry 1). No rule was changed after that inspection. If a future change is tuned against these results, the reserved set must be reclassified as development data and a fresh reserved set generated with a new seed and protocol version.

## Results on the reserved set (first inspection)
| Scenario | Units | Low-or-higher alert | Any alert | Detected |
|---|---|---|---|---|
| B1 typos then success | 20 | 0 | 0 | — |
| B2 many typos, known device | 20 | 20 | 20 | — |
| B3 multi-device intermittent | 20 | 3 | 3 | — |
| B4 stale credential device | 20 | 5 | 5 | — |
| B5 shared egress | 20 | 0 | 0 | — |
| B6 service automation | 20 | 0 | 0 | — |
| B7 admin credential rotation | 20 | 20 | 20 | — |
| B8 developer AI assistant | 20 | 20 | 20 | — |
| B9 background AI traffic | 20 | 0 | 20 (informational) | — |
| B10 incomplete telemetry | 20 | 0 | 0 | — |
| **Benign total** | **200** | **68** | **88** | |
| M1 fast guessing | 20 | | | 20/20 |
| M2 slow guessing | 20 | | | 20/20 |
| M3 guessing + real user | 20 | | | 20/20 |
| M4 rotating sources | 20 | | | 20/20 |
| M5 rotating + interleaved | 20 | | | **0/20** |
| M6 SP credential add failed | 20 | | | 20/20 (reported as attempt) |
| M7 SP credential add + vault reads | 20 | | | 20/20 |
| M8 web shell | 20 | | | 20/20 |
| M9 password spray | 20 | | | 19/20 |
| M10 slow guessing, no source address | 20 | | | 20/20 (via ARG-AUTH-002) |
| H identical trace, hidden origin | 15 | | | 15/15; triplets identical 5/5 |

Other measures: incorrect strongest LLM assertions **0/415** units; incorrect framework assertions **0**; abstained alerts 0/494; benign alerts per benign unit-day 0.194; review burden 119 alerts per 100 units (median 1, max 13 per unit; B8 developer agents produce ~10 alerts each because each linked tool call is reported); low-confidence share 4.7 %. Rule status: 13 matched, 3 evaluable without match, 13 without candidate records. Records lacking required telemetry are counted per rule (e.g. ARG-AUTH-003/004: 1,730 authentication records without `src_ip` or `user`, mostly service-principal sign-ins and the B10/M10 units).

Interpretation:
- B2, B4 and some B3 alerts are the known ambiguity of failures followed by success; B2 is surfaced at low confidence ("known source").
- B7 is correct behaviour detection without context: a legitimate credential rotation looks like ARG-SP-001; change-ticket context would resolve it.
- B8 alerts are *correct* LLM observations (the developer's agent really issued model tool calls) at low/informational severity; they show the review burden of a legitimate AI assistant, not a false LLM attribution.
- M5 remains a known gap (neither ARG-AUTH-003 nor -004 matches when the real user's successes interleave with rotating-source guessing).
- M9: one spray unit was not matched. It was deliberately not investigated against the reserved data, so the set stays unused for tuning; the cause should be studied on development data.

## Historical v0.2.0 evaluation
The earlier `scripts/auth_eval.py` results remain as recorded in docs/AUTH_RULE_EVALUATION.md (benign 81/180 → 41/180, malicious 120/120 on that held-out set; the final rotating-source result there was not blind). Those are sequence-level synthetic measurements on a different dataset and are not comparable to the numbers above.
