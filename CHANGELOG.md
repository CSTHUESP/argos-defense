# Changelog

All notable changes. Versions follow semantic versioning; 0.x releases are experimental.
**Detection is experimental; real-world accuracy is not measured.**

## [0.3.1] - 2026-11-20
Corrective pass for review findings R01–R09 (docs/V031_REMEDIATION.md). Experimental detection; real-world accuracy not measured.

### Fixed
- **R01** Redaction propagates through lists and nested objects under sensitive keys. Original-record excerpts are redacted structurally (JSON keys, CSV headers, XML Data names); an unparseable excerpt is withheld rather than labelled redacted. Case create/list API, import results, job records, explainer output and error messages are redacted.
- **R02** Backups reconcile retained originals against the inventory in the database snapshot. Missing or altered evidence fails a normal backup (`--allow-incomplete` writes an explicitly incomplete one). Verification reports database consistency and evidence completeness separately. Restore rebases and verifies every reference.
- **R03** The watcher identifies file generations by device/inode, first line and consumed-tail hash. Distinct files no longer share a checkpoint, truncation starts a new generation, and checkpoints advance only after a durable import.
- **R04** LLM correlation keys are canonical JSON. The namespace is a declared collector id or the single input file, never a format label or placeholder. Ids are case-sensitive and delimiter-safe.
- **R05** Zero-count baseline windows and absence conclusions need declared coverage of the relevant event family; other families, entities or inputs never become zeros. ARG-AUTH-003 v3 states its follow-up family.
- **R06** New evaluation protocol eval-v2.1 with independent, alert-level attribution scoring and attribution-negative scenarios; injected errors are proven to be counted.
- **R07** The explainer redaction test now uses the real interface and fails if the provider is not called or redaction is bypassed.
- **R08** FIFO global job admission (default 1 running, 8 queued; HTTP 429 when full) and an OS-level lock enforcing one server per data directory. 300,000 events measured with a stress profile.
- **FU1** Error responses (import, failed analysis jobs, compare, explainer, rules) are redacted.
- **FU2** Processing/interrupted imports never satisfy completion; retries resume the same input exactly once; a failed reprocess keeps the previous revision.
- **FU3** Watcher delivery identity (source, generation, byte range) is separate from content identity; occurrence counts are independent of chunk size; repeated polls/restarts are reported as `redelivered`.
- **FU4** One cleanup invariant for every job terminal path; a failed job can no longer block the FIFO.
- **FU5** Evaluation protocol eval-v2.2 scores LLM attribution against exact source records; eval-v2.1 metrics are superseded.
- **R09** The release preflight authenticates Git remote reads with GH_TOKEN through environment-scoped Git configuration (needed for private repositories); the token never appears in argv or URLs.

### Changed / migration
- Watcher results: `duplicates`/`duplicate_segments` are replaced by `redelivered`/`redelivered_segments`; identical lines at different offsets or in different files are kept as distinct occurrences.
- Database schema v4 (from v3: watcher identity columns; v0.3.0 checkpoints marked legacy). Migration is transactional after a verified `argos.v3-backup.sqlite3`.
- A coverage declaration without event kinds covers only the event kinds present in that input. Declare `--coverage-kinds` to cover other families.
- Session/tool-call chains across separately imported files require the same `--collector-id`.
- `backup` exits 2 when evidence is missing (6 with `--allow-incomplete`); `verify-backup` exits 6 for an incomplete backup.
- Mutating CLI commands refuse while a server runs on the same data directory (exit 5).

## [0.3.0] - 2026-11-20
Correctness, data-safety and release-integrity pass (audit findings F01–F13, see docs/AUDIT_REMEDIATION.md).
0.2.0 was never published; this is the first published release.

### Fixed
- **F01** A generic tool execution plus the endpoint process no longer yields "directly observed" LLM involvement (ARG-LLM-003 v2 needs a model tool request; new ARG-AUTO-003 = automation only, LLM unknown).
- **F02** Model-to-execution chains require an explicit call id inside a namespaced session (`source_type|tenant|session_id`), the same tool name and case-sensitive identifiers (ARG-LLM-002 v2); unlinked same-session pairs are only "possible" (ARG-LLM-005).
- **F03** Action outcome comes from the terminal sequence step; failed or unknown credential changes are reported as attempts / outcome unknown (ARG-SP-001 v2, ARG-AUTH-002 v3).
- **F04** Observation span is no longer treated as collection coverage: per-input analyst-declared coverage (start/end/scope), entity-scoped baseline windows, explicit absence statuses, observation gaps.
- **F05** Key-aware recursive redaction (JSON strings, headers, URL credentials/query, CLI arguments, tokens, PEM keys) for UI, all API responses, exports, notes, status rationales, rejected excerpts and LLM input; explicit authenticated raw view.
- **F06** Migration backups use SQLite's online backup API with integrity and row-count verification; migration is transactional.
- **F07** Owner-private directories/files (POSIX modes, Windows ACLs); `doctor` reports unsafe locations.
- **F08** Versioned format-aware source locators (JSONL byte range, JSON-array index/pointer, CSV line span, XML element ordinal) and integrity-checked original-record retrieval.
- **F09** Immutable per-run alert/assessment/rule/configuration snapshots committed atomically; failed or cancelled runs never replace the last success; per-run export.
- **F10** Import revisions keyed by content + parser version + effective-options hash; explicit reprocess and activation.
- **F11** Shared release preflight for every release entry point; all builds pinned to the resolved commit; tag re-checked before draft and publication.
- **F12** Exact 27-asset release contract with per-platform required smoke-check identities, SBOM/wheel/sdist binding and independent uploaded-byte verification against pre-upload expectations.
- **F13** Bundle immutability check hashes file contents, modes and symlink targets.
- Sigma export of regex predicates now uses `|re|i` (native matching is case-insensitive).
- Windows: `icacls` output decoded from the OEM code page.

### Added
- Background analysis jobs with progress, cancellation, per-case serialization and restart recovery.
- Rule eligibility and data-quality diagnostics per rule and per source.
- Run comparison (UI, API, `compare-runs`) attributing changes to data, rules, configuration or engine; analyst status rationale history.
- `backup`, `verify-backup`, `restore` (verified zip of database snapshot, originals and configuration).
- Opt-in read-only directory watcher (`watch`) with checkpoints, partial-write, rotation, duplicate and backpressure handling and freshness reporting.
- Analysis size limit (default 300,000 events per case) based on measured memory use.
- Evaluation protocol v2 with frozen development and reserved synthetic sets and separate threat/origin labels (`scripts/eval_v2.py`, docs/EVALUATION_PROTOCOL.md).
- Benchmarks at 12k/100k/1M events with pre-declared budgets (docs/PERFORMANCE.md).
- Hashed universal dependency locks and a vulnerability-review workflow (docs/DEPENDENCIES.md); Sigma selection-semantics tests.
- Native smoke test now covers the distributed launchers, browser opening via `BROWSER`, update from a v0.2.0 database, backup/restore.

### Changed
- Database schema v3 (migrated automatically from v1/v2 with a verified backup). Legacy runs are kept and labelled "no snapshot".
- ARG-AUTH-002 v3 treats mailbox-rule / mail-forwarding changes as sensitive post-sign-in actions.

## [0.2.0] - 2026-11-20 (never published)
Prepared as the first packaged release; superseded by 0.3.0 before publication.

### Added
- Native packages (PyInstaller onedir) for Windows x86_64, Linux x86_64, macOS arm64 and macOS x86_64, each smoke-tested on its own CI runner from the extracted archive (CLI workflow, real browser form submission, export, restart persistence).
- `start` launcher (opens the browser; `--no-browser`, `--port 0`, clear occupied-port error), authenticated `POST /api/shutdown`, `server.json` runtime file, `--version`, `--data-dir`.
- Per-user application-data directory (Windows `%LOCALAPPDATA%\ARGOS Defense`, macOS `~/Library/Application Support/ARGOS Defense`, Linux `$XDG_DATA_HOME/argos-defense`); editable config copied on first run; database schema version table with v0.1 → v0.2 migration (backup kept).
- ARG-AUTH-004 (uninterrupted multi-source failures then success); `reset_where` run semantics and `source_history` context in the rule engine.
- Labeled tuning/held-out evaluation for the failures-then-success rules (`scripts/auth_eval.py`, `docs/AUTH_RULE_EVALUATION.md`).
- Sigma / Splunk SPL export for faithfully translatable rules (`export-rules`); unsupported temporal correlations listed explicitly.
- Format edge cases: Sysmon XML without root element (wevtutil/Get-WinEvent style) and without namespace, UTF-8 BOM, Splunk metadata lines and multi-value fields, CSV quoted newlines, Zeek ISO timestamps; Zeek TSV rejected with a clear reason.
- Conservative outcome synonyms (`Failed`→failure, `Succeeded`→success; numeric codes not interpreted).
- CI (`ci.yml`) and release (`release.yml`) workflows with SHA-pinned actions; SBOM (CycloneDX), SHA256SUMS, release manifest with native smoke-test results.
- Full Apache-2.0 license text, complete third-party notices, licensing basis, pinned ARTEX reference manifest and retrieval script.

### Changed
- ARG-AUTH-003 v2: per-source uninterrupted failure run, success from the same source; known-source context caps confidence at low. v1 alerted on 27/300 identities of a random background set; held-out benign sequences alerted 81/180 → 41/180 with all 120/120 malicious sequences still detected (synthetic only).
- ARG-ARTEX-X03 v2: the `mitmproxy-ca-cert.pem` file name no longer counts toward framework corroboration (standard mitmproxy name); corroboration now needs controller-process evidence plus model-gateway session naming on the same host.
- Native network-type records without a declared vantage default to `victim_network` with a warning; records that also carry endpoint process fields are rejected as ambiguous.
- Records lacking a rule's required fields are counted (`missing_required_telemetry`) and reported as case limitations instead of being silently skipped.
- Upload file names may contain non-ASCII letters (path separators, control characters and `..` are still rejected).
- `serve`/`start` no longer print the session token by default (`--show-token` to print a login URL).
- Rules and default config moved into the package (`src/argos/resources/`); CLI entry point `argos-defense`.
- psutil is a test-only dependency; tzdata and colorama added for Windows.

### Fixed
- Windows: time-zone names in `--assume-tz` require the `tzdata` package (now a Windows dependency).

## [0.1.0] - 2026-11-20 (unreleased prototype, not published)
Initial local prototype: Starlette/SQLite/Jinja2 app, native JSONL, Splunk JSON/CSV, Sysmon XML, Zeek JSON adapters, 26 YAML rules, six-dimension assessment, web UI, JSON/HTML/CSV export.
