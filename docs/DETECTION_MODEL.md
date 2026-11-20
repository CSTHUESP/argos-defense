# Detection model

## Pipeline
`case` → import (adapters, normalization, quality warnings, rejects) → analysis run (`analysis.py`):
coverage per vantage → entities/relationships → each YAML rule (if its vantage is present) →
matches → evaluator (`evidence/assess.py`: confidence caps, registry, IOC validity, absence checks,
missing visibility) → alerts (upserted by deterministic id) → case assessment → stored with run versions.

## Six separate dimensions
| Dim | Values | Set by |
|---|---|---|
| A Threat | severity (informational…critical) + suspicion (informational / suspicious / likely_malicious) | rule; IOC expiry lowers to informational |
| B Automation | unknown, consistent_with_automation, observed_automation, observed_manual_component, mixed | rule contribution; registry match = observed (configured); case: manual + automation ⇒ mixed |
| C LLM | unknown, possible, directly_observed | only family-6 rules and ARTEX-X04; AI-provider connection ⇒ *possible* only; *directly_observed* needs model-audit records linked to execution (same session or ProcessGuid) |
| D Framework | unknown, consistent_with, corroborated_presence, (corroborated_execution never automatic) | family-7 rules (experimental) + case-level corroboration (≥2 independent families on one host) |
| E Purpose | observed_action + hypothesis + stage (indicator / attempt / observed_success) | rule; stage adjusted by observed outcomes |
| F Entities | typed entities with key strength (strong / weak / infrastructure) | `entities/extract.py` |

No dimension is derived from another. Missing LLM evidence leaves C = unknown (never "human").

## Confidence (qualitative, documented criteria)
Start at the rule's `base_confidence`, then apply caps (lowest wins):
1. `experimental` rule → max **low**.
2. Any cited input with provenance `unverified` (all imports by default) → max **medium**; statements are "according to the supplied records". Only an analyst attestation recorded *outside* the file (`argos attest`, UI) lifts this cap. Fields inside a file are ignored (`self_declared_trust_field_ignored`).
3. Grouping on a weak key (user without tenant/domain) → max **medium**.
4. Only expired IOC matches → max **low**, severity informational.
5. Insufficient baseline → **insufficient_evidence** and the alert is marked `abstained`.
**high** therefore requires a non-experimental rule with high base confidence, strong keys and attested provenance.

## Heuristic evidence score (not a probability)
Case-level per dimension: Σ over **distinct evidence families** of the max weight in that family (low 0.2, medium 0.5, high 1.0). 300 identical DNS lookups count once (test 14).

## Rules
26 rules in `rules/detections/*.yaml` covering the 8 required families + IOC context. Schema (`detect/rules.py`, pydantic, `extra=forbid`): id, version, title, description, family, status, validation_status, observation_vantage, required_telemetry, select, group_by, window_s, aggregate (`each | threshold | sequence | baseline`), reference, severity, base_confidence, contributes (per dimension), evidence_family, required_evidence, explanation, alternatives, false_positives, missing_visibility_hints, resolving_data, sources, suppressible_by_registry, absence_check, fingerprint.
Operators (closed set): eq, ne, in, not_in, contains, not_contains, startswith, endswith, regex (≤200 chars), gt/gte/lt/lte, exists, not_exists, cidr, not_cidr, ioc_valid, ioc_any. YAML via `safe_load`; no eval, no code, no shell.
Thresholds are overridable in `config/rule_overrides.yaml` (`rule_id: {dotted.path: value}`); the override file is part of the rules hash.

## Anomaly references
Every rule declares `reference.type`: `explicit_threshold`, `configured_expected` (registry), `observed_history`, or `not_applicable`. The only history rule (ARG-SP-002) uses windows strictly **before** the evaluated window, requires ≥24 covered prior windows and otherwise abstains with "insufficient baseline". No labels or future events are used.

## Authorized automation registry (`config/authorized_automation.yaml`)
Entry: id, description, owner (descriptive), match (src_ip CIDR, host, user, app_id, process_name), scope (event_kinds, rule_families), schedule (days, UTC hours), expires. An alert is dispositioned `authorized_automation` only if **every** evidence event matches. Partial matches stay open with a note. Rules with `suppressible_by_registry: false` (auth chains, SP credential/permission changes, persistence, multi-vault reads) are never covered. Suppressed alerts remain visible (filter "show authorized automation").

## IOCs (`rules/iocs/*.yaml`)
Each entry: value, type, source, observed_date, valid_from, valid_until, context. Validity is evaluated at **event time** (`cutoff_used: event_time`). Expired matches are context only. IOCs never produce attribution or blocking.

## Correlation keys and time
All windows use event time after sorting (file order irrelevant). Groups use strong keys (tenant+user, tenant+app_id, host+ProcessGuid, session_id, host+proc_link). Sequences require step order in event time; temporal proximity alone never links different entities. Correlation is always within one case.

## Reproducibility
Event id = sha256(case, file sha256, format, record no). Alert id = sha256(case, rule id, rule version, group, first event id). Re-analysis updates alerts in place; alerts no longer produced (e.g. after a rule version change) are kept with `current=0`; notes and analyst status live in separate tables. Each run stores the input manifest and engine/schema/parser/rules/config/registry/IOC hashes.

## Known false-positive pattern found in validation
ARG-AUTH-003 (≥5 failures then success within 24 h) fired 27 times on 12k random background events where users fail intermittently. It is a "suspicious / medium" credential-access hypothesis, not a compromise verdict; tune `aggregate.steps.0.min_count` or the window for your environment.
