# Evaluation of the failures-then-success authentication rules (v0.2.0)

**Scope:** synthetic, labeled identity sequences only. Real-world false-positive and detection rates are **NOT MEASURED**.
Reproduce: `python scripts/auth_eval.py --write-fixtures --json reports/auth_eval_results.json` and `pytest tests/test_auth_eval.py`.

## Why the v0.1.0 number was misleading
v0.1.0 reported "27 ARG-AUTH-003 alerts on 12,000 random background events". The relevant unit is an **identity sequence**, not a raw event: that bulk set contains 2,400 authentication events for **300 identities**, so the observation was 27 of 300 identities alerted, on a generator that assigns a random source IP to every event and fails one third of sign-ins. It was never a validated false-positive rate.

## Root causes found (v1)
Inspecting the 27 alerts showed sequences such as `FFFFSFFSSFFS` with failures from 5–6 unrelated source addresses:
1. **Non-consecutive counting:** successes between failures did not reset the count, so ordinary intermittent failures accumulated to 5.
2. **Source mixing:** failures from unrelated devices/networks were combined with a success from yet another source.
3. Identity grouping (tenant + account) and tenant boundaries were correct (verified by scenario B6). Authorized-automation exceptions do not apply to authentication rules (by design; never suppressible). The rule used an explicit threshold, not a learned baseline, so no baseline assumption was involved.
4. Outcome normalization was exact-match only; vendor words such as `Failed`/`SUCCEEDED` became `unknown`. v0.2.0 maps a small set of unambiguous synonyms (numeric vendor codes are **not** interpreted).

## Changes
- **ARG-AUTH-003 v2:** group by tenant + account + **source**; requires an **uninterrupted** run (new engine option `reset_where`) of ≥5 failures from that source, then success from the same source; speed is not required (slow guessing still matches). New `source_history` context: if the success source already succeeded for this identity *before* the run (prior events only), confidence is capped at **low** — the alert is kept, not suppressed.
- **ARG-AUTH-004 v1 (new):** uninterrupted run of ≥5 failures from ≥3 distinct sources (any success resets), then success. Restores detection of per-attempt source rotation that v2 alone lost (scenario M4).
- Records without `src_ip` are no longer silently ignored: they are counted as `missing_required_telemetry` and listed as a case limitation.
- Threshold (5) and window (24 h) are unchanged from v1.

## Data sets
`fixtures/auth_eval/{tuning,heldout}.jsonl`, labels in `fixtures/ground_truth/auth_eval_{tuning,heldout}.json`.
Held-out differs from tuning in seed, scenario counts (30 vs 20 per scenario), failure counts, spacing, failure probability (0.45 vs 0.35), device count (4 vs 3), address pools, and a 50 % chance that the stale-password device is finally updated (0 % in tuning).

| Scenario | Label | Description |
|---|---|---|
| B1 | benign | 1–4 typos then success, own address |
| B2 | benign | 5–9 typos then success from the user's own, previously successful device (hard case) |
| B3 | benign | 8–20 sign-ins over a day from 3–4 own devices, random failures |
| B4 | benign | device with stale saved password failing hourly while the user works normally from a browser |
| B5 | benign | several users behind one NAT with occasional failures |
| B6 | benign | failures in one tenant, success in another tenant, same username |
| M1 | malicious | fast guessing from one source, then success |
| M2 | malicious | slow guessing (0.5–3.5 h apart), then success |
| M3 | malicious | guessing from attacker source interleaved with the real user's successes, then success |
| M4 | malicious | every attempt from a different source, success from yet another |

## Results (identity sequences alerted by AUTH-003, or AUTH-003 + AUTH-004 for v2)

| Scenario | Tuning v1 | Tuning v2 | **Held-out v1** | **Held-out v2** | v2 alert confidence (held-out) |
|---|---|---|---|---|---|
| B1 typo then success | 0/20 | 0/20 | 0/30 | 0/30 | — |
| B2 many typos, own device | 20/20 | 20/20 | 30/30 | 30/30 | low ×30 |
| B3 intermittent multi-device | 5/20 | 1/20 | 21/30 | 2/30 | medium ×2 |
| B4 stale password device | 15/20 | 0/20 | 30/30 | 9/30 | medium ×9 |
| B5 shared NAT | 0/20 | 0/20 | 0/30 | 0/30 | — |
| B6 cross-tenant username | 0/20 | 0/20 | 0/30 | 0/30 | — |
| **benign total** | **40/120** | **21/120** | **81/180** | **41/180** | |
| M1 fast guessing | 20/20 | 20/20 | 30/30 | 30/30 | medium |
| M2 slow guessing | 20/20 | 20/20 | 30/30 | 30/30 | medium |
| M3 guessing + legit user | 20/20 | 20/20 | 30/30 | 30/30 | medium |
| M4 rotating sources | 20/20 | 20/20 | 30/30 | 30/30 | medium |
| **malicious total** | **80/80** | **80/80** | **120/120** | **120/120** | |

Process honesty note: AUTH-003 v2 alone was run once on the held-out set (M4 = 0/30) before AUTH-004 was written. AUTH-004 was designed from the tuning-set M4 result (0/20), but the held-out M4 figure for the final rule set is therefore **not blind**. All other held-out scenarios were not used for design.

Residual benign alerts: B2 (own device, repeated typos) is indistinguishable from guessing without device/MFA context; it is surfaced at low confidence with the "known source" rationale. B4 alerts when the stale device is finally updated (no earlier success from that device in the case) — a known ambiguity.
Known gap: an attacker who both rotates sources **and** interleaves with the real user's successes is matched by neither rule.

## Random background set (12,000 events, 300 identities)
v1: ARG-AUTH-003 alerted 27/300 identities. v0.2.0: ARG-AUTH-003 0/300, ARG-AUTH-004 3/300 (random per-event source addresses make multi-source failure runs common in this generator). This set has no labels and is not a false-positive-rate measurement.
