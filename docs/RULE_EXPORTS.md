# Sigma and Splunk SPL exports

`argos-defense export-rules --output DIR [--target sigma|spl|all]` writes `DIR/sigma/*.yml`, `DIR/spl/*.spl` and `DIR/export-report.json`.

- **Verified:** YAML/structure checks for Sigma (required keys, selection + condition) and structural checks for SPL (balanced quotes, parentheses, backticks). Unit tests in `tests/test_rules.py`.
- **Not verified:** execution in Splunk or in any Sigma backend/converter. Treat exports as starting points to review.

## What is exported
| ARGOS construct | Sigma | SPL |
|---|---|---|
| `each` rule, single event kind with a Sigma log source (process_creation, file_event, network_connection, dns_query, proxy, dns) | yes | yes |
| `each` rule over several event kinds / OR-of-groups | no (needs several log sources) | yes |
| `threshold` (count / distinct / ratio in a sliding event-time window) | no | yes (`sort 0 _time | streamstats time_window=…`) |
| `threshold` with median inter-arrival (ARG-AUTO-001) | no | no — no faithful streamstats equivalent |
| `sequence` (ordered multi-step correlation, run resets) | no | no — not approximated |
| `baseline` (prior-history comparison) | no | no |
| IOC lookups (`ioc_any`/`ioc_valid`) | no | no |
| agent/model-audit and identity/cloud events | no Sigma log source used | yes |

## Field mapping
SPL uses the **ARGOS normalized field names** (e.g. data indexed from ARGOS JSON exports, or Splunk field aliases mapping your sourcetypes onto these names) and computes derived fields with `eval` (`process_name`, `parent_name`, `file_ext`, `domain`, `uri_path`, `http_status_class`, `remote`). Matching is case-insensitive via `lower()`/`match()` with escaped regular expressions.
Sigma field names: process_creation → `Image`, `ParentImage`, `CommandLine`, `User` (ARGOS basename predicates become `|endswith` with `\` and `/` prefixes); file_event → `TargetFilename`; network_connection → `DestinationIp`, `DestinationPort`, `SourceIp`; dns_query → `QueryName`; proxy → `c-uri`, `cs-host`, `c-useragent`, `sc-status`, `c-ip`, `cs-method`.
