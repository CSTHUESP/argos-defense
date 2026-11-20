# Changelog

All notable changes. Versions follow semantic versioning; 0.x releases are experimental.
**Detection is experimental; real-world accuracy is not measured.**

## [0.2.0] - 2026-11-20
First packaged GitHub release.

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
