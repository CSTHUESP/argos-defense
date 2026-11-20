# ARTEX static source review

| Item | Value |
|---|---|
| Repository | https://github.com/BaaRai/ARTEX (README describes it as an English-translated fork of ARTEX by Autumn-27, AGPL-3.0) |
| Tag | `v0.6.0` (annotated tag object `1a7c664f14f882d76f7bcc9722eb85731c855df2`) |
| Commit examined | **`a13c68cb7078d43b66fb398db3d610e513b6d77a`** (2026-11-12T00:17:29+01:00, "Merge pull request #191 … release-0.6.0") |
| Checkout | `reference/ARTEX` (local only, excluded from git and from all packages; pinned in `reference/ARTEX.manifest.json`, retrieve with `scripts/fetch_artex_reference.sh`) |
| Accessed | 2026-11-20 |
| Method | Static reading only (grep / sed). **Nothing was built, executed, installed or tested**: no binaries, installers, scripts, containers, submodules or ARTEX tests were run. The ARGOS application imports none of it. |
| Trust | README, comments, prompts, SKILL.md files and strings were treated as untrusted data. |

## Modules inspected

| Area | Files (commit a13c68cb) | What they do (as read) |
|---|---|---|
| Planning / orchestration | `agent/planner.go`, `agent/mainagent.go`, `server/orchestration.go`, `server/engine.go`, `agent/goals.go` | Planner turns a goal into *intents*; main agent and planner have transcript sessions `exp<N>-planner`, `exp<N>-main[-s<N>]`. |
| Workers / tool execution | `agent/worker.go`, `agent/tools.go`, `agent/toolcatalog.go` | One worker per intent (session `exp<N>-worker-i<intent>`); tool commands run as subprocesses whose env is built by `proxyEnv()` (HTTP(S)_PROXY/ALL_PROXY → recording proxy, NODE_USE_ENV_PROXY=1, CA vars). The Bash/WebFetch tool implementations live in the external module `github.com/Autumn-27/norma` (go.mod), which is **not vendored and was not reviewed**. |
| Evidence graph | `db/schema.sql` (`exploration_nodes`, `exploration_edges`), `agent/finding_recorder.go`, `agent/finding_workflow.go` | Node kinds begin/goal/intent/fact/finding/hint/digest; edges spawns/derived_from/yields/proves/covers. Worker prompt requires "observed vs inferred" confidence and an *adversarial gate* (reachability, preconditions, controls, scope, simpler explanation) before a finding. |
| Traffic capture | `traffic/traffic.go`, `traffic/evidence.go`, `traffic/archive.go`, `server/traffic_ingest.go` | go-mitmproxy based recording proxy (default `127.0.0.1:8788`), CA stored at `<dir>/_ca/mitmproxy-ca-cert.pem`. |
| Evidence store | `evidence/store.go` | Content-addressed (hash) evidence bodies, verified on read, frozen copies for exports, GC with grace period. |
| LLM recording | `llmrec/llmrec.go`, `llmrec/capture.go`, `db/commands.go` (`llm_records`) | Every model call recorded with ts, model, profile, session_id, task_id, worker lane, tokens, status, request/response bodies. |
| Provider config | `agent/provider.go`, `db/schema.sql` (`llm_profiles`), `config.example.json` | `ARTEX_LLM_*` env vars; optional `session_header_key` (default `''`) sends the session id to the provider; optional custom User-Agent (default empty → Go default UA, see `agent/user_agent_test.go`). |
| Human-in-the-loop | `intercept/intercept.go`, `db/intercept.go` | allow/deny/ask rules on tool calls; pending approvals with `decided_by`, `decision_source`. |
| Scope guard | `guard/guard.go`, `intercept/target_exempt.go`, `SECURITY.md` | Target gate / allow-lists; SECURITY.md states scope enforcement depends on configuration. |
| Logging / notify | `server/logsink.go`, `notify/*` (redaction, masking, SSRF checks) | Server logs to DB; notification channels with secret masking. |
| Entry point | `cmd/artex/main.go` | Flags `-addr 127.0.0.1:8787`, `-proxy 127.0.0.1:8788`; env `ARTEX_JWT_KEY_DIR`, `ARTEX_TRUSTED_PROXIES`. |

## Candidate fingerprints

All fingerprints: URL base `https://github.com/BaaRai/ARTEX/blob/a13c68cb7078d43b66fb398db3d610e513b6d77a/`, commit `a13c68cb…`, covered version **v0.6.0 only** (other forks, ARTEX PRO and later versions unknown). **None is observable from victim-side traffic.** Validation status for all: **experimental — source-derived, never validated against real telemetry.**

| ID | File / location | Observed pattern | Required vantage | Required telemetry | Spoofability | Benign overlap | Used? |
|---|---|---|---|---|---|---|---|
| ARTEX-FP-001 | `cmd/artex/main.go` flags (~L53-55) | controller binary `artex`; listens 127.0.0.1:8787, proxy 127.0.0.1:8788 | managed_endpoint **on the controller host** | process_image, host (sockets would help; not ingested) | trivial (rename/flags) | authorized pentest teams; any binary named artex | rule ARG-ARTEX-X01 |
| ARTEX-FP-002 | `agent/worker.go` `proxyEnv()` (~L216-236) | tool subprocesses under the controller; env HTTP(S)_PROXY/ALL_PROXY=recording proxy, NODE_USE_ENV_PROXY=1, SSL_CERT_FILE etc. | managed_endpoint (controller) | parent_image (env vars rarely collected) | trivial | Burp/mitmproxy tool chains | rule ARG-ARTEX-X02 (parent only) |
| ARTEX-FP-003 | `traffic/traffic.go` `CACertPath()` (L354-355) | file `…/_ca/mitmproxy-ca-cert.pem` | managed_endpoint (controller) | file_path | trivial | **very high** (standard mitmproxy name) | rule ARG-ARTEX-X03 v2 — weak, never corroborates |
| ARTEX-FP-004 | `agent/worker.go:101`, `planner.go:519`, `mainagent.go:176-178`, `goals.go:124`, `compaction.go:96`, `server/side_questions.go:431`; header logic `agent/provider.go:457-460` | session ids `^exp\d+-(planner|main(-s\d+)?|worker-i\d+|goals|compactor|btw-.+)$` | agent_or_model_audit: a model gateway on the **controller's** egress path, and only if `session_header_key` is configured (default off) | session_id | trivial | low-moderate (generic prefix) | rule ARG-ARTEX-X04 |
| ARTEX-FP-005 | `agent/provider.go` UA override; `agent/user_agent_test.go` | provider calls use Go default UA `Go-http-client/…` unless configured | controller egress | user agent | trivial | enormous (all Go software) | **rejected** — not a fingerprint |
| ARTEX-FP-006 | `config/config.go`, `db/db.go`, `agent/provider.go` | env vars `ARTEX_PG_DSN`, `ARTEX_CONFIG`, `ARTEX_LLM_*` | managed_endpoint (controller) | process environment | trivial | low | **not implemented** (env telemetry not in supported formats) |
| ARTEX-FP-007 | `config.example.json` | PostgreSQL port 5433, user/db `artex` | controller / DB host | network or DB auth logs | trivial | moderate | **rejected** as standalone (generic port) |
| ARTEX-FP-008 | `agent/worker.go` `workerDefaultTmpl` | worker system prompt text ("executor (work agent) of a network-security platform's authorized penetration testing system…") | model gateway seeing request bodies | request body | trivial; template is DB-editable | low | **not implemented** (bodies not part of schema; privacy) |

Victim-side observations: ARTEX tools are ordinary programs (curl, python, nuclei, bbot, dnsx…) run from the controller; nothing in the reviewed code injects an ARTEX-specific header, User-Agent or path into target traffic. Victim-side detection therefore relies on **behaviour** (bursts, enumeration, auth sequences, cloud changes), which is generic and **cannot attribute ARTEX**. Text such as `ARTEX` in a UA/URL/filename is handled by ARG-ARTEX-W01 as a weak, spoofable indicator that never corroborates.

## v0.2.0 re-review (2026-11-20)
All file/line references were re-checked against commit `a13c68cb…`: `cmd/artex/main.go` L53/L55 (flags), binary name `build.sh` L207-208 and `install.sh` L112-115 (`build.sh` L210 allows an arbitrary `ARTEX_OUTPUT` name), `agent/worker.go` L101 (worker session id) and L215 (`proxyEnv`), `agent/planner.go` L519, `agent/mainagent.go` L176/L178, `agent/goals.go` L124, `agent/compaction.go` L96, `server/side_questions.go` L431, `agent/provider.go` L457 (session header only when configured), `traffic/traffic.go` L354-355 (CA path).

Independence findings:
- FP-001 (binary name) and FP-002 (child of that binary) observe the **same artifact** (the controller's image name); they share one independence family (`controller_process`) and never corroborate each other.
- FP-003 (`_ca/mitmproxy-ca-cert.pem`) is mitmproxy's standard file name. Benign overlap is very high, so in v0.2.0 (rule ARG-ARTEX-X03 v2) it is a weak indicator that **never** counts toward corroboration.
- FP-004 (gateway session naming) comes from a different vantage and artifact; with FP-001/002 on the same host it yields `corroborated_presence`.
- **No validated victim-side fingerprint was found in the reviewed version** (BaaRai/ARTEX v0.6.0). This is a statement about the reviewed code and the `norma` dependency's absence from review, not a claim that none could exist.
- Presence, execution of the framework, and responsibility for an incident remain separate: ARGOS reports at most `corroborated_presence`; execution and responsibility are reported as "not established".

Corroboration rule (implemented, `evidence/assess.py`): `corroborated_presence` requires ≥2 *independent* fingerprint families (in v0.2.0: `controller_process`, `model_session_naming`) on the **same host**. `corroborated_execution` / responsibility for a given activity is **never** inferred automatically.

## External sources (accessed 2026-11-20)

| Source | Status | Claims used |
|---|---|---|
| CERT-EU blog "From Penetration Testing to Cyber Threat — Beware of ARTEX" (2026-11-05) | read | ARTEX description; original repo withdrawn Oct 2026, public copies are forks; no concrete UA/port/header indicators published; lists T1595, T1588.002, T1190 |
| Microsoft Security blog, Storm-0940 / ARTEX / ConnectWise (2026-10-21, modified 2026-11-10) | read | password spray across tenants, OAuth app abuse, credential additions, Global Admin self-assignment, bulk Key Vault reads; "successful authentication does not by itself show data access"; telemetry = Entra/Graph/M365 logs. Attribution there is Microsoft's assessment; ARGOS does not reuse it |
| FBI FLASH-20261113-001 (TLP:CLEAR, 2026-11-13) | read (PDF via fetch tool) | behaviours (cloud credential testing, web shells, compressed bursts, iterative failures), LLM API destinations "to investigate in context", historical IOCs "verify before blocking". IOC values were **not** copied into ARGOS (transcription risk; ARGOS ships only a synthetic IOC set) |
| BaaRai/ARTEX SECURITY.md | read | offensive tool; scope enforcement configuration-dependent; no misuse-detection mechanism |
| Google Cloud blog "ARTEX and Friends" | **inaccessible** (server error on two attempts) | nothing used |
| GitHub release page v0.6.0 | not fetched; tag resolved via git | — |

MITRE ATT&CK IDs appear in ARGOS only where quoted from the sources above; none are invented.

Note: the claude.ai project also holds an uploaded `ARTEX-0.6.0/` copy. The git checkout at the pinned commit was used as the authoritative reference.
