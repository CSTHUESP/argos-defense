# Security policy

## Supported versions
Only the latest 0.x release receives fixes. ARGOS Defense is experimental software for local investigation support.

## Reporting a vulnerability
Do **not** report vulnerabilities in a public issue, pull request or discussion.

1. **GitHub private vulnerability reporting, when it is shown.** If the repository's [Security tab](https://github.com/CSTHUESP/argos-defense/security) offers **Report a vulnerability**, use it. The report is visible only to you and the maintainers, and the fix can be coordinated in a private advisory. *Status: this repository setting was **not enabled** when last checked (2026-11-20), so the button may not be there yet.*
2. **Otherwise: ask for a private channel.** Open an issue with the [Security contact request (no details)](https://github.com/CSTHUESP/argos-defense/issues/new?template=security_contact.yml) form. It asks for nothing but two confirmations; do **not** add any technical details. A maintainer will then open a draft GitHub security advisory and add you as a collaborator, so the details stay private.

In the private channel, please include the version (`argos-defense --version`), platform, affected component, reproduction steps with **synthetic** data, impact, and **redacted** logs. Never include real investigation data, credentials or session tokens. There is no bug bounty and no guaranteed response time; reports are handled on a best-effort basis.

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
- Report suspected vulnerabilities through the private route above, not in public issues.
