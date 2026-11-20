# Threat model (ARGOS itself)

ARGOS is a local, single-analyst investigation tool that processes **hostile input** (attacker-influenced logs).

| Threat | Control | Verified by |
|---|---|---|
| Remote/other-origin access to the UI or API | binds 127.0.0.1 (CLI refuses non-loopback without hidden override); session token (0600 file) required for every non-public route; Host header allow-list (DNS rebinding) | `test_web_e2e.py` (401/303, Host 400, CLI refusal) |
| CSRF from a malicious web page | SameSite=Strict HttpOnly cookie; Origin/Referer must be the local origin for unsafe methods; per-session CSRF token in forms / `X-CSRF-Token`; `Origin: null` rejected | e2e: missing/wrong token, foreign and null origin → 403 |
| XSS via imported content | Jinja2 autoescape everywhere; strict CSP (`script-src 'self'`, no inline script); JS writes results with `textContent` | `test_security.py`, e2e (`<script>` rendered escaped), Chrome check |
| Path traversal / hostile uploads | filename allow-list, extension allow-list, `safe_join` under case dir, symlinks refused, size limits per file and per record | `test_ingest.py::test_hostile_filenames_rejected`, e2e upload of `../../etc/passwd.jsonl` |
| XXE / entity expansion | defusedxml with forbid_dtd/entities/external + DOCTYPE pre-check | `test_sysmon_xxe_and_doctype_rejected`, e2e |
| SQL injection | parameterised SQL only | code review |
| Unsafe YAML / rule code execution | `yaml.safe_load`; pydantic schema `extra=forbid`; closed operator set; regex length cap | `test_rules.py` (eval op, python tag, unknown fields) |
| CSV/formula injection in exports | cells starting with = + - @ tab CR are prefixed with `'` | `test_11_csv_export_neutralizes_formulas` |
| Prompt injection in evidence | the deterministic engine never interprets text; optional LLM receives alerts as delimited data and its output is schema-validated, must cite existing evidence refs, forbidden verdict-changing claims rejected | `test_11_prompt_injection_inert`, LLM tests (simulated provider) |
| Executing content from evidence | no code path executes, fetches or resolves anything from events | code review |
| Secret leakage | key-aware recursive redaction + patterns (JSON-in-string, quoted pairs, Authorization/Cookie, URL userinfo/query, CLI flags, token shapes, PEM) in every UI page, JSON API response, export, note, status rationale, rejected excerpt (redacted before truncation) and LLM input; raw single-record view only on explicit authenticated request, labelled; no telemetry sent externally; LLM disabled by default, remote endpoints refused unless `ARGOS_LLM_ALLOW_REMOTE=1` | `test_redaction`, `test_f05_*` |
| Secret leakage through structured evidence (v0.3.1, R01) | sensitive keys mask their entire value (lists, nested objects); original-record excerpts redacted structurally (JSON keys, CSV headers with strict parsing, XML Data names); unparseable excerpts withheld rather than labelled redacted; case metadata, import results, jobs and error messages redacted | `test_r01_*` (real HTTP routes and exports) |
| Incomplete or misleading backups (v0.3.1, R02) | evidence inventory derived from the database snapshot; missing/altered originals fail a normal backup; restored references always rebased and verified | `test_r02_*` |
| Resource exhaustion through concurrent analyses (v0.3.1, R08) | FIFO global admission (default 1 running, 8 queued); one server per data directory (OS file lock) | `test_r08_*` |
| Other local accounts reading case data | owner-private dirs/files (POSIX 0700/0600/0400; Windows ACL user+SYSTEM+Administrators on directories ARGOS creates); reports, backups, temp uploads and error log private; `doctor` flags unsafe existing locations | `test_f07_*` (POSIX CI, Windows CI) |
| Incomplete recovery copies | migration/backups via SQLite online backup API + integrity_check + row-count comparison; restore only into empty directories with hash verification and zip-slip rejection | `test_f06_*`, `test_backup_restore_roundtrip_with_relationships` |
| Misleading conclusions from overwritten history | immutable per-run snapshots; failed/cancelled runs never replace the last success | `test_f09_*` |
| Watcher abuse | opt-in only, explicit directory, read-only opens, symlinks skipped, line-oriented formats only, size/backpressure limits, contents imported as data | `test_watch_*` |
| Resource exhaustion | file and record size limits, max events per case, chunked inserts | `test_size_limit_enforced`, `test_record_size_limit` |
| Evidence tampering | read-only local copies + SHA-256 for **integrity checks only**; not tamper-proof, not a certified chain of custody | documented |
| Token disclosure via logs/CI | `serve`/`start` print only the token file path (`--show-token` opt-in); packaged smoke tests redact the token and assert it never appears in logs | `test_launcher.py`, `packaging/smoke_test.py` |
| Abuse of shutdown endpoint | `POST /api/shutdown` requires the token (bearer) or cookie + Origin + CSRF; only available when started by the launcher | `test_shutdown_requires_auth` |
| Writes into the application bundle | all mutable data in the user data dir; smoke test fingerprints the bundle before/after | `packaging/smoke_test.py` |
| Synthetic/real confusion | case-level `synthetic` flag; cannot reuse a name across kinds; banners on UI pages and exports | `test_synthetic_and_real_not_mixed`, e2e |

Out of scope / residual: administrators/root or malware running as the analyst can read the data directory and token (file permissions only stop other unprivileged accounts); multi-user authorization; TLS (loopback only); denial of service by very large legitimate cases (analysis limited to 300,000 events per case by default); redaction is key/pattern-based and can miss secrets under unusual names or free-text formats; analyst-declared coverage is not verified; local append-only tables and hashes are not tamper-proof custody.
