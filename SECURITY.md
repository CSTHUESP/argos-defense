# Security policy

## Supported versions
Only the latest 0.x release receives fixes. ARGOS Defense is experimental software for local investigation support.

## Reporting a vulnerability
Please report privately to the repository owner (GitHub private vulnerability reporting / a private issue to the owner). Include the version (`argos-defense --version`), platform, reproduction steps and **redacted** logs. Do not include real investigation data, credentials or session tokens.

## Security model (summary — details in docs/THREAT_MODEL.md)
- Binds to `127.0.0.1` by default; non-loopback binding requires a hidden override.
- Every non-public route requires the local session token (file `<data-dir>/.session_token`, mode 0600 where supported); browser sessions use HttpOnly SameSite=Strict cookies, Origin/Referer checks and per-session CSRF tokens; `Host` header allow-list against DNS rebinding.
- Imported data is treated as inert: escaped in HTML, formula-neutralized in CSV, never executed; XML DTD/entities rejected; YAML loaded safely; parameterised SQL.
- No telemetry leaves the machine by default. The optional LLM explainer is disabled; remote model endpoints need an explicit opt-in.
- The session token is not printed by default and is redacted from packaged smoke-test logs.

## Out of scope
ARGOS performs no blocking, isolation, scanning or other response. It does not identify people, groups, nationalities or exact models. Detection accuracy is not measured on real data.


## Local data protection (0.3.0)
- Data directories ARGOS creates are owner-only (POSIX 0700/0600, originals 0400; Windows ACL limited to the user, SYSTEM and Administrators). `argos-defense doctor` reports locations other local accounts can read. This protects against other unprivileged local accounts only; administrators/root and malware running as you can read the data.
- Redaction applies to every UI page, API response and export by default. The unredacted view of a single record (`?raw=1`) requires the same authentication and is labelled; do not share screenshots of it.
- Backups (`argos-defense backup`) contain full investigation data including original evidence; store and transfer them like the data directory itself.
- Report suspected vulnerabilities privately via GitHub security advisories for this repository rather than public issues.
