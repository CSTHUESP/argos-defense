# Evaluation protocol v2 (eval-v2.0) — synthetic held-out validation

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
