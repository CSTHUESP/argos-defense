# ARGOS Defense 0.1.0

Local defensive investigation of **supplied telemetry files**. ARGOS imports logs, correlates them per case, runs declarative detection rules and explains what the evidence supports along six separate dimensions: **threat activity, automation, LLM involvement, framework (e.g. ARTEX), purpose, entities**. Uncertainty is part of every finding: ARGOS returns *unknown* / *insufficient evidence* rather than guessing, and never identifies a person, nationality, threat group or exact model from IPs, speed, language or style.

It is batch analysis — **not** a real-time sensor, EDR agent or live product integration — and performs no blocking, isolation, scanning or other response.

## Install (Linux/macOS)
```bash
cd argos-defense
python3 -m venv .venv                      # offline: python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements.lock # pinned versions verified in the build env
.venv/bin/pip install --no-deps --no-build-isolation -e .
source .venv/bin/activate
```
Or simply `scripts/start.sh --demo` (creates the venv if missing, runs doctor, builds the demo, starts the server).
Windows: `powershell -ExecutionPolicy Bypass -File scripts\start.ps1 -Demo` (the flag applies to that process only; nothing global is changed). **The PowerShell launcher was not tested** (built on Linux).

## Quick start (verified commands)
```bash
python -m argos doctor
python -m argos demo                                   # separate DEMO/SYNTHETIC case "demo-synthetic"
python -m argos serve --host 127.0.0.1 --port 8789     # prints http://127.0.0.1:8789/login?token=...
python -m argos report --case demo-synthetic --format html --output reports/demo.html
python -m pytest
```
Open the printed login URL (token also in `data/.session_token`). API clients use `Authorization: Bearer <token>`.

## Complete example with your own files
```bash
python -m argos ingest proxy.csv   --format splunk_csv  --profile proxy --case incident-42
python -m argos ingest signins.json --format splunk_json --profile auth  --case incident-42
python -m argos ingest sysmon.xml  --format sysmon_xml  --case incident-42
python -m argos ingest conn.log    --format zeek_jsonl  --zeek-log conn --case incident-42
python -m argos ingest audit.jsonl --format native_jsonl --case incident-42 --assume-tz Europe/Budapest
python -m argos analyze --case incident-42
python -m argos alerts  --case incident-42
python -m argos attest <input_id> --trust analyst_attested --note "exported by me from the IdP console on 2026-11-20"
python -m argos report  --case incident-42 --format json --output reports/incident-42.json
```
Workflow in the UI: **Import → case page → Analyze → Alert queue → alert → evidence → notes/status → Export JSON/HTML/CSV**.

## Supported formats
| Format | Adapter | Notes |
|---|---|---|
| ARGOS native JSONL | `native_jsonl` | all event kinds: http, dns, network_connection, process_start, file_create, authentication, cloud_operation, model_interaction, tool_execution, human_approval. Generic route for identity/cloud/agent-audit products **without** a specific adapter |
| Splunk JSON/JSONL export | `splunk_json` | records may be wrapped in `result`; profiles `proxy`, `auth`, `native` or a custom mapping |
| Splunk CSV export | `splunk_csv` | **explicit** mapping required (`--profile` or `--mapping file.yaml`) |
| Sysmon exported to XML | `sysmon_xml` | EventID 1, 3, 11, 22; other IDs rejected with reason. **Binary EVTX not supported** |
| Zeek JSON logs | `zeek_jsonl` | conn, http, dns; `uid` preserved |

No product has a live connector. Entra/M365/AWS/agent-gateway logs must be converted to the native schema or mapped via a Splunk export.

### Native schema (one JSON object per line)
Required: `event_time` (ISO-8601 with zone or epoch; zone-less needs `--assume-tz`), `event_kind`. Optional: `observation_vantage` (`victim_network|managed_endpoint|identity_cloud|agent_or_model_audit`; defaulted from kind with a warning), `action`, `outcome` (`success|failure|unknown`), `tenant_id`, `host`, `user`, `account_type`, `app_id`, `process_guid`, `process_id`, `process_image`, `process_command_line`, `parent_process_guid`, `parent_process_id`, `parent_image`, `session_id`, `correlation_id`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `http_method`, `http_host`, `http_uri`, `http_status`, `http_user_agent`, `dns_query`, `dns_rcode`, `resource`, `resource_type`, `file_path`, `bytes_src_to_dst`, `bytes_dst_to_src`, `bytes_basis` (**required to declare direction**), `model_provider`, `model_name_declared`, `model_tool_name`, `model_tool_input`, `linked_process_guid`, `message`. Unknown fields are ignored with a quality warning; self-declared trust fields are ignored. Missing fields stay null.
Stored per event additionally: `schema_version`, `event_id`, `original_timestamp`, `timestamp_note`, `ingested_at`, `source_type`, `source_format`, `quality_warnings`, `evidence_ref` (`ev:<sha16>:<record>`), `zeek_uid`.

### Byte-counter direction
Proxy profile: `cs_bytes` → `bytes_src_to_dst`, `sc_bytes` → `bytes_dst_to_src` per the W3C Extended Log Format prefix convention (cs = client-to-server); **check your proxy's documentation**. Zeek: `orig_bytes` originator→responder. Custom mappings must declare `bytes_basis` or are rejected.

## What ARGOS can and cannot conclude
- **Threat:** observed actions with severity; severity is independent of human/LLM origin (slow attacks alert).
- **Automation:** timing/volume ⇒ *consistent with automation*; agent audit records or the authorized registry ⇒ *observed*; human approval records ⇒ *manual component* / *mixed*. Absence of AI indicators never means "human".
- **LLM:** AI-provider connection ⇒ *possible* only. *Directly observed* requires model-audit records linked to execution (same session / ProcessGuid), and is stated "according to the supplied records". Victim-side traffic cannot see attacker-side model calls. Declared model names stay labelled as declared.
- **ARTEX/framework:** four experimental, source-derived fingerprints visible only on a host *running* ARTEX or a gateway on its egress path; text mentions are weak. Best case: *corroborated presence*. Responsibility for an activity is never inferred.
- **Purpose:** hypotheses with stage (indicator/attempt/observed success); volume or successful sign-in ≠ data theft.
- **Entities:** strong vs weak keys; shared IPs never merge accounts; account owner ≠ operator.

## Layout
```
reference/ARTEX   pinned ARTEX checkout (static, AGPL, never executed)
src/argos/{ingest,normalize,entities,correlate,detect,evidence,api,reporting,llm,templates,static}
rules/detections  26 YAML rules       rules/iocs  synthetic IOC set
config/           authorized_automation.yaml, rule_overrides.yaml
fixtures/         demo + acceptance data; ground_truth/ (never imported)
tests/  scripts/  docs/  data/ (runtime DB, originals, token)  reports/
```
(`correlate` logic lives in `detect/engine.py` grouping/sequence code; the package is a placeholder.)

## Privacy
Everything stays in `data/`. No telemetry, files, secrets or prompts leave the machine by default. The optional LLM explainer is **disabled**; it can be enabled for a local Ollama (`ARGOS_LLM_PROVIDER=ollama ARGOS_LLM_MODEL=...`); remote endpoints require `ARGOS_LLM_ALLOW_REMOTE=1`. Secrets are redacted (pattern-based) in UI and exports; originals keep them.

## Limitations (v0.1)
Batch files only; in-memory analysis per case (tested to 12k events); EVTX, Windows event formats other than Sysmon XML, PCAP and live connectors not supported; SPL/Sigma translations **not implemented**; single-user local auth; synthetic validation only — real-world accuracy NOT MEASURED. See docs/.

## Troubleshooting
- `doctor` reports a missing module → activate `.venv` or reinstall with `pip install -r requirements.lock`.
- Login shows "Host not allowed" → use `http://127.0.0.1:<port>` or `localhost`, not another hostname.
- Form says "CSRF token missing" → reload the page (session changed after restart; log in again with the token).
- Records rejected as "ambiguous timestamp" → re-import with `--assume-tz <zone>` after confirming the source zone.
- Port in use → `python -m argos serve --port 8790`.

## Docs
`docs/ARTEX_SOURCE_REVIEW.md`, `docs/INSPIRATION_MAP.md`, `docs/DETECTION_MODEL.md`, `docs/THREAT_MODEL.md`, `docs/VALIDATION.md`, `docs/BUILD_STATE.md`, `THIRD_PARTY_NOTICES.md`.
