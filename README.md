# ARGOS Defense

**Local defensive investigation framework for explainable analysis of suspicious, automated, and LLM-assisted activity.**

> **Experimental detection; real-world accuracy not measured.** All validation so far uses synthetic data.

[Español: README.es.md](README.es.md) · [Changelog](CHANGELOG.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

ARGOS Defense imports telemetry files you supply (proxy, identity, endpoint, network and AI-agent audit logs), correlates them per case, runs declarative detection rules and explains **what the evidence supports and what it does not**. It is built for a question that agentic offensive tools such as ARTEX make urgent: *is this activity automated, is an LLM involved, is a known framework present, what is the actor after, and which accounts, hosts and processes are involved?* ARGOS keeps those questions separate and answers *unknown* when the data cannot tell.

It is batch analysis on your own machine: not a real-time sensor, EDR agent or SIEM connector. It performs no blocking, isolation, scanning or other response. No data leaves the machine by default.

![Case assessment (synthetic demo)](docs/screenshots/02-case-assessment.png)

## Download

**v0.3.1** — [Release page](https://github.com/CSTHUESP/argos-defense/releases/tag/v0.3.1). The links below work only once v0.3.1 is published. Until then, the latest published version is [v0.3.0](https://github.com/CSTHUESP/argos-defense/releases/tag/v0.3.0); see [docs/RELEASE_VALIDATION.md](docs/RELEASE_VALIDATION.md) for the current state. Assets are published only after every package passed the release contract and the uploaded bytes were downloaded again and verified.

| Your system | Download | Built and smoke-tested on |
|---|---|---|
| Windows 10/11 or Server, 64-bit Intel/AMD | [ARGOS-Defense-0.3.1-windows-x86_64.zip](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-windows-x86_64.zip) | GitHub runner `windows-2022` (Windows Server 2022) |
| Linux, 64-bit Intel/AMD (glibc ≥ 2.35) | [ARGOS-Defense-0.3.1-linux-x86_64.tar.gz](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-linux-x86_64.tar.gz) | GitHub runner `ubuntu-22.04` |
| Mac with Apple Silicon (M1–M4) | [ARGOS-Defense-0.3.1-macos-arm64.zip](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-macos-arm64.zip) | GitHub runner `macos-15` (arm64) |
| Mac with Intel processor | [ARGOS-Defense-0.3.1-macos-x86_64.zip](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/ARGOS-Defense-0.3.1-macos-x86_64.zip) | GitHub runner `macos-15-intel` |
| Any OS with Python 3.11+ | [wheel](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/argos_defense-0.3.1-py3-none-any.whl) · [sdist](https://github.com/CSTHUESP/argos-defense/releases/download/v0.3.1/argos_defense-0.3.1.tar.gz) | CI on Ubuntu, Windows, macOS |

Also published: `SHA256SUMS`, `release-manifest.json` (commit, build environment, smoke-check results, signing status), per-platform CycloneDX SBOMs, build-info files and the native smoke-test results/logs. Verify a download with `sha256sum -c SHA256SUMS --ignore-missing` (Linux), `shasum -a 256 <file>` (macOS) or `Get-FileHash <file> -Algorithm SHA256` (PowerShell). When `release-manifest.json` lists GitHub artifact attestations, `gh attestation verify <file> --repo CSTHUESP/argos-defense` checks the build provenance.

The packages contain everything they need. No Python installation is required, and the core works offline.

**Tested baselines:** native packages are tested only on the GitHub-hosted runner images named above, including launch through the distributed launcher scripts. They were **not** tested on Windows 10/11 desktop editions, other Linux distributions or macOS versions, or after a normal browser download with quarantine attributes (SmartScreen/Gatekeeper behaviour is not verified). A manual acceptance procedure is in [docs/PACKAGING.md](docs/PACKAGING.md).

## Start

| | Steps |
|---|---|
| **Windows** | Extract the ZIP → double-click **`Start ARGOS Defense.cmd`**. SmartScreen may warn because the executable is not code-signed. Verify the file hash against `SHA256SUMS` first; whether to run unsigned software is your (or your organization’s) decision. Do not disable SmartScreen or antivirus. |
| **macOS** | Double-click the ZIP to extract it → double-click **`Start ARGOS Defense.command`**. The build is not notarized, so Gatekeeper may block the first launch. Open *System Settings → Privacy & Security* and click *Open Anyway* (Apple's documented procedure), then launch again. |
| **Linux** | `tar xzf ARGOS-Defense-0.3.1-linux-x86_64.tar.gz && ./ARGOS-Defense-0.3.1-linux-x86_64/start-argos-defense.sh` |

The launcher starts the local server on `http://127.0.0.1:8789` (loopback only) and opens your browser already logged in. Stop it with **Ctrl+C**, or by closing the terminal window.

Options (the same executable is under `argos-defense/`): `start --no-browser` prints the token-file location instead of opening a browser; `--port 0` picks a free port; `--data-dir <folder>` chooses where data lives. If the port is in use, ARGOS says so and exits.

### Authenticate
The session token is a random secret stored in `<data dir>/.session_token`. The launcher passes it to your browser. With `--no-browser`, open `http://127.0.0.1:<port>/login` and paste the token from that file. It is never printed unless you use `--show-token`.

## Try the demo (no private data, no API keys)
In a terminal inside the extracted folder:

```
argos-defense/argos-defense demo          # Windows: argos-defense\argos-defense.exe demo
```
Then start the UI. The **demo-synthetic** case (purple *DEMO/SYNTHETIC* banner) contains generated proxy, identity, Sysmon, Zeek, EDR and agent-audit data with RFC 5737 addresses. It covers an authorized scanner, a password spray, a slow account takeover, a web shell, a service-principal credential addition, an archive-and-upload, and a developer workstation running an LLM agent.

## Investigate your own data
1. **Import:** *Import* page → case, adapter, mapping profile (Splunk) and file. The result lists accepted, rejected and skipped records with the actual reasons. Optionally **declare collection coverage** (start, end, scope `all` / `tenant:<id>` / `host:<name>` / `app_id:<id>`, the **event kinds** the export is complete for, and how you know). ARGOS does not verify that declaration and labels it *analyst-declared*; without it, absence of follow-up activity is reported only as *not observed in the supplied records*. CLI: `argos-defense ingest FILE --format FORMAT --case CASE [--coverage-start … --coverage-end … --coverage-scope …]`.
2. **Correct an import:** if a file was imported with the wrong time zone or mapping, *Reprocess* it from the case page (CLI `ingest … --reprocess`). This creates a new **revision** from the retained original bytes; exactly one revision is active, older ones stay available (`argos-defense inputs --case CASE`, `activate <input_id>`), and a failed reprocess keeps the previous usable revision.
   Session and tool-call ids are linked only within one input file, or across inputs imported with the same `--collector-id` (import form: *Collector id*).
3. **Analyze:** case page → *Analyze / re-analyze*. Analysis runs as a background job with progress and *Cancel*; a cancelled or failed run never replaces the last successful one. Each run stores an immutable snapshot of its alerts, assessment, rules and configuration. CLI: `argos-defense analyze --case CASE`.
4. **Check what could run:** the case page lists per-rule eligibility (matched, evaluable/no match, no candidate records, missing required telemetry, insufficient history, vantage absent, disabled, processing error), per-source missing fields, rejects, declared coverage and observation gaps. A rule that could not run is not evidence of absence.
5. **Investigate:** *Alert queue* (filters for severity, confidence, activity, automation, LLM, framework) → alert page with the six dimensions, matched predicates, terminal action outcome, timeline, evidence references (each opens the normalized record and the **exact original record**, located by a format-aware locator and integrity-checked), alternatives, missing visibility and resolving data. Set a status with a **rationale** (history kept); add notes. Status is review feedback only: it does not retrain rules or suppress future activity.
6. **Compare runs:** *Compare runs* on the case page (CLI `argos-defense runs --case CASE`, `compare-runs RUN_A RUN_B`) shows added, removed and changed alerts and whether data, rules, configuration or engine differed between the runs.
7. **Export:** *Export JSON / HTML / Alerts CSV* for the latest or any earlier run (`argos-defense report --case CASE --format html [--run RUN]`). Exports come from the run's snapshot and state their basis.

**Secrets and raw evidence:** UI pages, API responses, exports, notes, status rationales, rejected-record excerpts and optional-LLM input are redacted (key-aware and pattern-based; not every secret format can be recognized). Original files are kept byte-for-byte in owner-private storage. An authenticated analyst can open one record's unredacted view explicitly (*Show raw* on the event page, `?raw=1`); that page is clearly labelled.

![Alert detail (synthetic demo)](docs/screenshots/04-alert-detail.png)

## The six evidence dimensions
| Dimension | Values | What it takes |
|---|---|---|
| A · Threat activity | severity + informational / suspicious / likely malicious | observed actions; independent of whether a human or an LLM acted (slow attacks still alert) |
| B · Automation | unknown · consistent with automation · observed automation · observed manual component · mixed | timing alone gives only "consistent"; agent audit records or the authorized-automation registry give "observed"; human-approval records give a manual component |
| C · LLM involvement | unknown · possible · directly observed | a connection to an AI provider gives "possible" only; "directly observed" needs a model tool request linked to the executed call by an explicit call id within a namespaced session, or to the endpoint process by ProcessGuid; a tool execution without a model record is automation only. Missing AI evidence never means "human". Victim-side traffic cannot see an attacker's model calls |
| D · Framework | unknown · consistent with · corroborated presence | experimental fingerprints; presence needs two independent artifacts on one host; execution and responsibility for an incident are never inferred |
| E · Purpose | observed action + terminal action outcome (success / failure / unknown) + hypothesis + stage (indicator / attempt / observed success / outcome unknown) | a hypothesis, not a fact; volume or a successful sign-in is not proof of data theft |
| F · Entities | accounts, service principals, devices, processes, sessions, tenants, IPs, domains | strong vs weak keys; a shared IP never merges accounts; who owns an account is not who controls it |

Confidence (insufficient / low / medium / high) is separate from severity and capped by documented rules. Experimental rules are capped at low, and imported files with unverified provenance at medium. Heuristic evidence scores count each distinct evidence family once and are **not probabilities**. ARGOS never names a person, nationality, threat group or exact model.

## ARGOS and ARTEX
- **Architectural inspiration:** ARGOS adapts ideas from ARTEX (BaaRai/ARTEX v0.6.0, commit `a13c68cb…`), an open-source LLM-driven offensive framework: task/intent orchestration, an evidence graph, observed-versus-inferred facts, LLM call recording and human-approval records. All of them are re-implemented independently for defence ([docs/INSPIRATION_MAP.md](docs/INSPIRATION_MAP.md)).
- **Experimental fingerprints:** a static source review found four candidate observables, all visible only on a machine *running* ARTEX or at a model gateway on its outbound path. **No validated victim-side fingerprint was found in the reviewed version** ([docs/ARTEX_SOURCE_REVIEW.md](docs/ARTEX_SOURCE_REVIEW.md)).
- **Reused code: none.** ARTEX (AGPL-3.0) is not bundled, imported or executed. A pinned manifest and `scripts/fetch_artex_reference.sh` retrieve the exact reviewed source for research.

## Supported inputs
| Adapter | Format | What it has been tested against |
|---|---|---|
| `native_jsonl` | ARGOS JSONL or JSON-array schema: HTTP, DNS, connections, processes, files, authentication, cloud operations, model interactions (`tool_call_id`, `model_tool_name`), tool executions (`tool_call_id`, `tool_name`), human approvals | synthetic fixtures |
| `splunk_json` | Splunk JSON/JSONL exports, including `result` wrappers and metadata lines; profiles `proxy`, `auth`, `native` or a custom mapping | schema-shaped fixtures built from documented field names |
| `splunk_csv` | Splunk CSV with an **explicit** mapping (BOM, quoted multi-line fields) | schema-shaped fixtures |
| `sysmon_xml` | Sysmon events 1/3/11/22 exported to XML, with or without a root element or namespace | schema-shaped fixtures |
| `zeek_jsonl` | Zeek JSON conn/http/dns logs (epoch or ISO `ts`, `uid` kept); TSV is rejected | schema-shaped fixtures |

**Continuous file ingestion (opt-in):** `argos-defense watch --case CASE --dir DIR --format native_jsonl [--pattern '*.jsonl']` tails line-oriented files in one explicitly named directory, read-only, with persisted checkpoints, partial-line handling, rotation detection, redelivery suppression and backpressure; `watch --status` shows freshness. It reuses the normal import pipeline. Each delivered byte range (source, file generation, offsets) is its own delivery: identical lines at different offsets or in different files are distinct occurrences, while re-polling or restarting never re-imports a range already completed; after an interrupted checkpoint update the exact committed range is re-delivered (hash-verified) before any appended data. It is not an EDR sensor, vendor connector or proof of continuous coverage, and it never starts by itself.

No genuine vendor or organizational exports have been tested. Binary EVTX, PCAP and live connectors are not supported (EVTX status: capability table). Field reference and byte-direction rules: [docs/DETECTION_MODEL.md](docs/DETECTION_MODEL.md).

## Data, privacy, updates, backups, uninstall
- **Data location:** Windows `%LOCALAPPDATA%\ARGOS Defense`, macOS `~/Library/Application Support/ARGOS Defense`, Linux `~/.local/share/argos-defense` (or `$XDG_DATA_HOME`), or `--data-dir` / `ARGOS_HOME`. Inside: `argos.sqlite3`, `cases/` (read-only copies of imported files), `config/` (registry and rule overrides), `reports/`, `backups/`, `logs/`, `.session_token`. Nothing is written inside the application folder (checked by content hash in the native smoke test).
- **Permissions:** directories ARGOS creates are owner-only (POSIX `0700`, files `0600`, originals `0400`; Windows: inheritance removed, access for you, SYSTEM and Administrators). `argos-defense doctor` reports existing locations that other local accounts can read and prints the fix; it does not change folders you created.
- **Privacy/offline:** no telemetry, no external calls. The optional LLM explainer is disabled by default and refuses remote endpoints unless explicitly allowed.
- **Update:** extract the new version next to the old one and start it; the data directory is reused. Older databases are migrated in one transaction after a verified backup (`argos.v<N>-backup.sqlite3`, made with SQLite's backup API). Runs from before 0.3.0 are kept and labelled *legacy (no snapshot)*. When upgrading from 0.3.0, watcher checkpoints become *legacy* and are re-identified conservatively, and coverage declared without event kinds covers only the event kinds present in that input.
- **Backup / restore:** `argos-defense backup [--output FILE.zip]` writes a zip with a consistent database snapshot, every retained original the database references (checked against its import hash), the configuration and a SHA-256 manifest; it works while ARGOS is running. If a referenced original is missing or altered, the backup fails, unless you pass `--allow-incomplete`, which writes a file marked `.INCOMPLETE`. `argos-defense verify-backup FILE.zip` reports database consistency and evidence completeness separately (exit code 6 = incomplete). `argos-defense --data-dir NEW_EMPTY_DIR restore FILE.zip` restores into an empty directory only, verifying hashes, integrity and row counts, and points every evidence reference at the new directory. Backups contain investigation data; store them accordingly.
- **One server per data directory:** a second `start`/`serve` on the same data directory refuses to run, and while a server is running, mutating CLI commands (`ingest`, `analyze`, …) ask you to use the UI/API instead (exit code 5).
- **Uninstall:** delete the extracted folder; delete the data directory to remove all data.

## Install from source (contributors)
```bash
git clone https://github.com/CSTHUESP/argos-defense && cd argos-defense
python3 -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-ci.lock && pip install --no-deps --no-build-isolation -e .
argos-defense doctor && argos-defense demo && argos-defense start
python -m pytest                       # full suite
python scripts/validate.py             # synthetic demo scenarios
python scripts/eval_v2.py run --set dev # synthetic development evaluation (docs/EVALUATION_PROTOCOL.md)
```
Native packaging: [docs/PACKAGING.md](docs/PACKAGING.md). Rule export to Sigma/SPL: `argos-defense export-rules --output DIR` ([docs/RULE_EXPORTS.md](docs/RULE_EXPORTS.md)).

## Architecture
```
files ─► adapters (native/Splunk/Sysmon/Zeek) ─► normalization + provenance (sha256, record no., vantage, tz)
      ─► SQLite case store ─► entities/relationships ─► YAML rules (each/threshold/sequence/baseline)
      ─► evaluator (confidence caps, registry, IOC validity, absence/source-history checks, missing visibility)
      ─► alerts + case assessment (6 dimensions) ─► Starlette UI / JSON API ─► JSON/HTML/CSV export
```

## Signing and integrity
| | Status |
|---|---|
| Windows Authenticode | **not signed** (no certificate available) |
| Apple Developer ID / notarization | **not signed / not notarized** (ad-hoc signature only) |
| GitHub artifact attestations (build provenance) | generated only when the repository is public; for a private repository on the current plan they are not available, and `release-manifest.json` records the actual status. An attestation is not OS code signing |
| Checksums | `SHA256SUMS` + `release-manifest.json`: integrity only, not proof of who published the files |

## Capability status (v0.3.1)
Implementation and verification are separate. Verification basis: **S** synthetic data, **R** native GitHub runner, **D** desktop machine, **B** real backend, **G** genuine export.

| Capability | Status | Basis |
|---|---|---|
| Import/normalize native, Splunk JSON/CSV, Sysmon XML, Zeek JSON; format-aware evidence locators | IMPLEMENTED_AND_VERIFIED | S |
| Import revisions / reprocessing with corrected options | IMPLEMENTED_AND_VERIFIED | S |
| 29 rules, six-dimension assessment, terminal action outcomes, declared coverage, entity-scoped baselines | IMPLEMENTED_AND_VERIFIED | S |
| Rule eligibility / data-quality diagnostics | IMPLEMENTED_AND_VERIFIED | S |
| Immutable run snapshots, per-run export, run comparison, status rationale history | IMPLEMENTED_AND_VERIFIED | S |
| Background analysis jobs (progress, cancel, per-case serialization, restart recovery) | IMPLEMENTED_AND_VERIFIED | S |
| Redaction (UI/API/exports/notes/rejects/LLM input) + explicit raw view | IMPLEMENTED_AND_VERIFIED for the tested formats; pattern limits remain | S |
| Owner-private storage, doctor permission checks | IMPLEMENTED_AND_VERIFIED (POSIX; Windows ACL in Windows CI) | R |
| Backup / verify / restore with evidence-inventory completeness; migration with verified backup (v0.2.0, v0.3.0 databases) | IMPLEMENTED_AND_VERIFIED | S |
| Opt-in read-only directory watcher (file-generation identity, durable checkpoints) | IMPLEMENTED_AND_VERIFIED (dedicated synthetic directory) | S |
| Native packages Windows x64 / Linux x64 / macOS arm64 / macOS x64 incl. launcher scripts, browser opening, update, backup/restore | v0.3.0: IMPLEMENTED_AND_VERIFIED on runner images. v0.3.1: built and smoke-tested only once released (see RELEASE_VALIDATION) | R |
| Desktop acceptance (Windows 11, macOS Gatekeeper with quarantine, other distributions) | IMPLEMENTED_NOT_EXTERNALLY_VERIFIED (procedure provided; no desktop available) | — |
| Sigma export (faithful subset) | IMPLEMENTED_AND_VERIFIED for structure and selection semantics against a reference matcher; not executed in a Sigma backend | S |
| SPL export | IMPLEMENTED_NOT_EXTERNALLY_VERIFIED (structure only; no Splunk instance) | — |
| Optional Ollama explainer | IMPLEMENTED_NOT_EXTERNALLY_VERIFIED (simulated provider only) | S |
| Binary EVTX import | BLOCKED_EXTERNAL_DEPENDENCY (parser could not be installed or executed in the build session; no genuine Sysmon EVTX sample) | — |
| Analysis of 300,000 events (stress profile: 9 event kinds, 15k users, low alert density) | IMPLEMENTED_AND_VERIFIED: 69 s, 2.8 GiB peak on 2 vCPU/7 GiB. Not a guarantee for alert-dense or larger-record cases | S |
| Analysis above 300,000 events per case | NOT_IMPLEMENTED_WITH_REASON (in-memory analysis; 1,000,000 events exceeded 7 GiB; refused with a clear error) | S |
| Global job admission (FIFO, default 1 running / 8 queued) and one server per data directory | IMPLEMENTED_AND_VERIFIED | S |
| PCAP, live EDR/SIEM connectors, automatic containment, universal human-vs-LLM classifier | NOT_IMPLEMENTED_WITH_REASON (out of scope) | — |
| Real-world detection accuracy | NOT MEASURED (no genuine labelled data) | — |

Validation details: [docs/RELEASE_VALIDATION.md](docs/RELEASE_VALIDATION.md), [docs/EVALUATION_PROTOCOL.md](docs/EVALUATION_PROTOCOL.md), [docs/AUDIT_REMEDIATION.md](docs/AUDIT_REMEDIATION.md), [docs/PERFORMANCE.md](docs/PERFORMANCE.md), [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md). Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Known limitations
Synthetic validation only, and the rule author also generated the evaluation data. On the eval-v2.2 reserved synthetic set the rules raised a low-or-higher alert for 110 of 320 benign units: repeated typos from a known device, legitimate credential rotation, some stale-credential and multi-device users, and legitimate developer AI agents (correctly reported as observed LLM tool use, at low severity). They missed all 20 attacks that rotate source addresses while interleaving with the real user's sign-ins. Alert-level LLM attribution, scored against exact source records, had 0 overclaims in 714 alerts on that set (synthetic only). Analysis is in memory: 300,000 events of a low-alert-density stress profile were measured at a 2.8 GiB peak; larger cases are refused. Redaction is key- and pattern-based. Declared coverage is the analyst's statement. Single local user; loopback UI without TLS.

## License
ARGOS Defense: Apache-2.0 ([LICENSE](LICENSE); basis in [docs/LICENSING.md](docs/LICENSING.md)). Third-party components keep their own licenses ([THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)). ARTEX (AGPL-3.0) is not distributed.
