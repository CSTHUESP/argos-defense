# Inspiration map (ARTEX → ARGOS)

All ARTEX references are to commit `a13c68cb7078d43b66fb398db3d610e513b6d77a` (tag v0.6.0). **No ARTEX code was copied**; every adaptation is an independent Python implementation (ARTEX is Go/TypeScript, AGPL-3.0).

| ARTEX idea | Source | Original purpose | Defensive adaptation in ARGOS | Reuse |
|---|---|---|---|---|
| Task → planner → intents → workers | `agent/planner.go`, `agent/worker.go`, `server/orchestration.go` | split an offensive goal into parallel exploration intents | deterministic pipeline: case (task) → analyzers over local case data → correlator/entities → rule detectors → evaluator → report (`analysis.py`). No LLM agents in the core. | independent |
| Exploration graph (nodes + typed edges) | `db/schema.sql` exploration_nodes/edges | record intents, facts, findings and their derivation | entities + relationships tables with `basis` = observed vs inferred (`entities/extract.py`); alerts link rule_ids → event_ids → evidence_refs | independent |
| Facts "observed vs inferred" + adversarial gate | worker prompt in `agent/worker.go` | force agents to disprove a finding before reporting | every alert lists alternatives, false positives, counter-visibility, confidence rationale; purpose separates observed action from hypothesis | independent |
| Content-addressed evidence store, verified copies | `evidence/store.go` | keep finding evidence independent of disposable traffic | originals copied read-only under `data/cases/<case>/originals/<sha256>`, `evidence_ref = ev:<sha16>:<record>`; documented as integrity aid, not chain of custody | independent |
| LLM call recording keyed by session/task/worker | `llmrec/llmrec.go`, `llm_records` | audit model usage and cost | `agent_or_model_audit` vantage; `model_interaction`/`tool_execution` events; ARG-LLM-002/003 link model tool-calls to executions | independent |
| Session id naming `exp<N>-…` | worker/planner/main/goals/compaction | prompt-cache keys, transcripts | experimental fingerprint ARTEX-FP-004 (ARG-ARTEX-X04) | independent |
| Recording MITM proxy + CA | `traffic/traffic.go`, `agent/worker.go proxyEnv` | capture target traffic as evidence | experimental fingerprints FP-002/FP-003 | independent |
| Human approval (intercept ask/decide, decided_by) | `intercept/intercept.go`, `db/intercept.go` | human-in-the-loop for risky tools | `human_approval` event kind → "observed manual component"; automation dimension can become `mixed` | independent |
| Run metadata / versioned outcomes | `server/task_outcome.go`, `server/task_archives.go` | reproducible task archives | analysis runs with manifest hash + engine/parser/rule/config/registry/IOC versions; alerts deterministic & idempotent; history kept | independent |
| Secret masking / redaction in notifications | `notify/mask.go`, `notify/redact_test.go` | avoid leaking secrets | `evidence/redact.py` applied to UI and exports | independent |
| Scope allow-lists / target gate | `guard/guard.go`, `intercept/target_exempt.go` | keep attacks in scope | authorized-automation registry with scope, schedule, expiry; never covers credential/permission/persistence rules | independent |
