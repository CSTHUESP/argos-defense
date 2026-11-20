# Operational pilot protocol (prepared, NOT run)

No genuine telemetry was available or authorized for v0.3.1. This protocol is a plan for an organization that owns its data; it has not been executed, and no results exist.

1. **Authorization and data handling.** Use written authorization from the data owner. Process only on the owner's machines, with ARGOS's offline core; the optional LLM stays disabled. Record retention and the deletion date.
2. **Sources and coverage.** For each export, record the product and version, collection path, filters, sampling, time window, entity scope and known gaps. Declare collection coverage in ARGOS only for what the owner can confirm complete, with explicit event kinds. Keep the raw exports unchanged and record their SHA-256.
3. **Independent labels.** Before running ARGOS on the evaluation period, have analysts who will not tune rules label incidents and benign activity from independent evidence: tickets, change records, EDR verdicts, interviews. Keep **threat labels** (benign/malicious) separate from **origin labels** (human/script/LLM agent/unknown) and from **model-use ground truth** (gateway logs that link model calls to executions).
4. **Separate tuning from evaluation.** Use an earlier period or other entities for tuning (development). Freeze the rules, configuration and engine commit. Evaluate once on the later period, and log the inspection time and commit. Any tuning against the evaluation period turns it into development data.
5. **Measures.**
   - Detection by incident type.
   - Benign alerts per entity-day (state the denominator).
   - Alert-level LLM and framework attribution errors, scored against model-gateway ground truth.
   - Abstention and rule-unavailable rates, with reasons from the diagnostics.
   - Analyst review time per alert.
   Report severity and confidence separately, and never present heuristic scores as probabilities.
6. **Reporting.** Publish counts with denominators, blind spots (missing sources, unsupported formats), coverage limits and the exact versions. State clearly that results apply to that organization's environment only.
