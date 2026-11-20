# Roadmap

ARGOS Defense is an experimental defensive investigation framework for analysing supplied telemetry, identifying suspicious behaviour, and assessing automation and LLM involvement with explicit evidence and uncertainty. This roadmap separates what exists from what is still open. Nothing in the "help wanted" or "longer-term" lists is implemented or verified unless an issue or release note says so.

## Delivered (v0.3.1)
- File adapters: ARGOS native JSONL, Splunk JSON/CSV (with mapping profiles), Sysmon XML (events 1/3/11/22), Zeek JSON (conn/http/dns).
- Import pipeline with retained originals, SHA-256 integrity, rejects with reasons, revisions/reprocessing, and atomic finalization; opt-in read-only directory watcher with crash-safe checkpoints.
- 29 declarative YAML rules and a six-dimension assessment kept separate: threat activity, automation, LLM involvement, framework presence, purpose, and technical entities. Confidence is separate from severity; heuristic scores are not probabilities.
- Local authenticated web UI and JSON API, immutable run snapshots, run comparison, JSON/HTML/CSV export, redaction on all outputs, backup/verify/restore.
- Native packages for Windows x86_64, Linux x86_64, macOS arm64 and macOS x86_64, built and smoke-tested on GitHub-hosted runners; wheel and sdist.
- Synthetic evaluation protocol eval-v2.2 with exact-record attribution scoring.

## Known limitations
- **Validation is synthetic only.** The same project wrote the rules and generated the evaluation data. Real-world false-positive and detection rates are not measured.
- **Detection gap:** password guessing that rotates source addresses *and* interleaves with the real user's successful sign-ins was missed in all 20 reserved synthetic cases (scenario M5).
- Legitimate credential rotation, repeated typos from a known device and legitimate developer AI agents produce low-severity alerts that cost review time.
- Native packages are tested on GitHub runner images only, not on Windows 10/11 desktops, other Linux distributions or other macOS versions, and not after a browser download with quarantine attributes. Windows builds are not Authenticode-signed; macOS builds are ad-hoc signed only and not notarized.
- No binary EVTX import, PCAP or live connectors. Sigma/SPL exports have not been executed in a real backend. The optional Ollama explainer is tested only against a simulated endpoint.
- Analysis is in memory; cases above 300,000 events are refused. Single local user, loopback UI without TLS.

## Where help is welcome
- **Desktop validation:** run the manual acceptance procedure in [docs/PACKAGING.md](docs/PACKAGING.md) on Windows 10/11, other Linux distributions and macOS (including Gatekeeper with quarantine) and report results.
- **Format fixtures:** synthetic or authorized, documented samples for the supported formats (Splunk, Sysmon XML, Zeek), especially edge cases from real product versions.
- **Backend validation:** run the exported Sigma rules in a Sigma backend and the SPL exports in Splunk, and report mismatches with the ARGOS evaluation.
- **EVTX prerequisites:** evaluate a maintainable, license-compatible EVTX parser and collect authorized Sysmon EVTX samples so binary EVTX import can be designed and tested.
- **Authentication-detection gap (M5):** research signals that separate interleaved, source-rotating guessing from normal multi-device use without raising more benign alerts; propose a rule change with development-set results.
- **Documentation:** clearer walkthroughs, screenshots from the synthetic demo, and translations (a Spanish summary exists in [README.es.md](README.es.md)).

## Longer-term ideas (outside the current release scope)
- Streaming or on-disk analysis for cases larger than 300,000 events.
- Independent, externally labelled evaluation data and a pilot following [docs/PILOT_PROTOCOL.md](docs/PILOT_PROTOCOL.md).
- Additional adapters (e.g. cloud audit logs) and connectors, still without automatic containment.
- Optional OS code signing and notarization, if a signing identity becomes available.
