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
| Secret leakage | redaction of common secret patterns in UI/exports; no telemetry sent externally; LLM disabled by default, remote endpoints refused unless `ARGOS_LLM_ALLOW_REMOTE=1` | `test_redaction`, `test_secrets_redacted_in_export` |
| Resource exhaustion | file and record size limits, max events per case, chunked inserts | `test_size_limit_enforced`, `test_record_size_limit` |
| Evidence tampering | read-only local copies + SHA-256 for **integrity checks only**; not tamper-proof, not a certified chain of custody | documented |
| Synthetic/real confusion | case-level `synthetic` flag; cannot reuse a name across kinds; banners on UI pages and exports | `test_synthetic_and_real_not_mixed`, e2e |

Out of scope / residual: a local user with access to the data directory or token; multi-user authorization; TLS (loopback only); denial of service by very large legitimate cases (limited by config); redaction is pattern-based and can miss secrets.
