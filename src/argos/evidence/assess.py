"""Turn rule matches into alerts with separate assessment dimensions, and
aggregate a case-level assessment. Confidence criteria are documented in
docs/DETECTION_MODEL.md and enforced here.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from argos.entities.extract import entities_for_event
from argos.models import (AUTOMATION_ORDER, CONF_ORDER, FRAMEWORK_ORDER, LLM_ORDER, SEVERITY_ORDER, VANTAGES)
from argos.normalize.timeutil import iso
from argos.detect.engine import MAX_EVIDENCE

FAMILY_WEIGHT = {"low": 0.2, "medium": 0.5, "high": 1.0, "insufficient_evidence": 0.0}


def _cap(conf: str, cap: str) -> str:
    return conf if CONF_ORDER.index(conf) <= CONF_ORDER.index(cap) else cap


def _alert_id(case_id, rule, group, first_event_id):
    raw = f"{case_id}|{rule.id}|{rule.version}|{sorted(group.items())}|{first_event_id}"
    return "al-" + hashlib.sha256(raw.encode()).hexdigest()[:20]


def _clean(v):
    return v if not isinstance(v, float) else round(v, 3)


def build_alert(m, case: dict, inputs: dict, coverage: dict, registry, all_events_by_group=None, absence_lookup=None) -> dict:
    rule = m.rule
    evs = m.events
    first, last = evs[0], evs[-1]
    c = rule.contributes
    rationale = []
    conf = rule.base_confidence
    rationale.append(f"rule base confidence '{rule.base_confidence}' (rule status {rule.status})")
    if rule.status == "experimental":
        conf = _cap(conf, "low")
        rationale.append("experimental rule: confidence capped at 'low' until validated")
    used_inputs = sorted({e["input_id"] for e in evs})
    prov = [{"input_id": i, "sha256": inputs[i]["sha256"], "original_name": inputs[i]["original_name"],
             "format": inputs[i]["format"], "parser_version": inputs[i]["parser_version"],
             "provenance_trust": inputs[i]["provenance_trust"], "provenance_note": inputs[i]["provenance_note"]} for i in used_inputs]
    if any(p["provenance_trust"] != "analyst_attested" for p in prov):
        conf = _cap(conf, "medium")
        rationale.append("evidence comes from imported records with unverified provenance: statements are observations "
                         "'according to the supplied records'; confidence capped at 'medium'")
    weak_keys = []
    for f, v in m.group.items():
        if f == "user" and not m.group.get("tenant_id"):
            weak_keys.append(f"user={v} without tenant/domain context")
    if weak_keys:
        conf = _cap(conf, "medium")
        rationale.append("grouping uses weak entity keys (" + "; ".join(weak_keys) + ")")
    baseline = m.baseline
    abstained = False
    if baseline and baseline.get("status") == "insufficient_baseline":
        conf = "insufficient_evidence"
        abstained = True
        rationale.append(f"insufficient baseline: {baseline['history_windows']} prior windows covered, "
                         f"{baseline['min_history_windows']} required; no learned normality is assumed")
    src_hist = (m.extra or {}).pop("_source_history", None)
    if src_hist and src_hist["status"] == "known_source":
        conf = _cap(conf, "low")
        rationale.append(f"source history: {src_hist['detail']} - consistent with the account's own device; confidence capped at 'low'")
    elif src_hist:
        rationale.append(f"source history: {src_hist['detail']}")
    ioc_hits = [h for e in evs for h in e.get("_ioc_hits", [])]
    severity = rule.severity
    if ioc_hits:
        if not any(h["valid_at_event_time"] for h in ioc_hits):
            conf = _cap(conf, "low")
            severity = "informational"
            rationale.append("only expired/out-of-validity IOC matches: historical context, not attribution or a blocking instruction")
    # registry
    reg = None
    disposition = "open"
    automation = c.automation or "unknown"
    automation_basis = "rule contribution" if c.automation else "no automation-specific evidence in this alert"
    if rule.suppressible_by_registry and registry is not None:
        reg = registry.evaluate(rule.family, evs)
        if reg and reg["covers_all"]:
            disposition = "authorized_automation"
            automation = "observed_automation"
            automation_basis = f"configured authorized automation entry {reg['entry_id']} (configured expectation, not detection)"
            rationale.append(f"all {reg['total_events']} events match authorized automation entry {reg['entry_id']} within scope/schedule")
        elif reg:
            rationale.append(f"authorized automation entry {reg['entry_id']} matched only {reg['matched_events']}/{reg['total_events']} "
                             "events; out-of-scope activity remains alerted")
    elif registry is not None and registry.evaluate(rule.family, evs) is None:
        pass
    # LLM dimension
    llm_level = c.llm or "unknown"
    llm_basis = []
    llm_limits = []
    audit_cov = coverage.get("agent_or_model_audit", {})
    if c.llm == "directly_observed":
        llm_basis.append("model interaction recorded by the supplied agent/model audit source - " + rule.title.replace("[EXPERIMENTAL] ", ""))
        if any(p["provenance_trust"] != "analyst_attested" for p in prov if p["format"] in ("native_jsonl", "splunk_json", "splunk_csv")):
            llm_limits.append("audit records have unverified provenance; their authenticity is not established by ARGOS")
    elif c.llm == "possible":
        llm_basis.append(rule.title + ": consistent with model involvement but no verifiable link between a model request and the "
                         "observed action (e.g. only a provider connection, or no call identifier)")
    else:
        if not audit_cov.get("event_count"):
            llm_limits.append("no agent/model audit telemetry supplied: LLM involvement is UNKNOWN (absence of AI indicators "
                              "does not establish human involvement)")
        else:
            inside = audit_cov["first_epoch"] <= first["event_epoch"] and last["event_epoch"] <= audit_cov["last_epoch"]
            if inside:
                llm_limits.append("agent/model audit records exist around this interval (observation span, not demonstrated complete "
                                  "collection) but none is linked to this activity; model use elsewhere (e.g. attacker-side) is not observable")
            else:
                llm_limits.append("no agent/model audit records were supplied for this alert's interval")
    if "victim_network" in rule.observation_vantage and c.llm != "directly_observed":
        llm_limits.append("victim-side traffic does not reveal calls an attacker makes to an LLM provider from another machine")
    # framework
    fw = None
    if c.framework:
        fw = {"name": c.framework.name, "level": c.framework.level, "fingerprint_ids": c.framework.fingerprint_ids,
              "independence_family": c.framework.independence_family,
              "basis": rule.description.strip().split("\n")[0],
              "limitations": ["installed or present software is not proof that it caused a specific activity",
                              "source-derived candidate; not validated against real telemetry"]}
        if c.framework.independence_family is None:
            fw["limitations"].append("trivially spoofable text indicator: never contributes to corroboration")
    # coverage & missing visibility
    missing = []
    for v in VANTAGES:
        cv = coverage.get(v, {})
        if not cv.get("event_count"):
            missing.append(f"{v}: telemetry unavailable (not supplied) - absence of evidence here is not evidence of absence")
    missing += rule.missing_visibility_hints
    absence = []
    if rule.absence_check and absence_lookup is not None:
        absence.append(absence_lookup(rule, m))
    entities = {}
    for e in evs[:MAX_EVIDENCE]:
        for etype, key, strength, display, role in entities_for_event(e):
            entities.setdefault((etype, key), {"etype": etype, "key": key, "strength": strength, "display": display, "role": role})
    evid = evs[:MAX_EVIDENCE]
    step_of = {}
    for sname, sevs in m.steps.items():
        for e in sevs:
            step_of[e["event_id"]] = sname
    group_txt = ", ".join(f"{k}={v}" for k, v in m.group.items()) or "(ungrouped)"
    counts = {"count": len(evs), "group": group_txt, "window_s": rule.window_s, **{k: _clean(v) for k, v in (m.extra or {}).items() if v is not None}}
    try:
        expl = rule.explanation.format(**counts)
    except (KeyError, IndexError, ValueError):
        expl = rule.explanation
    # F03: the action outcome comes from the TERMINAL step (or the matched events of single-event rules);
    # an earlier successful sign-in never makes a later failed change "successful".
    terminal_step = list(m.steps)[-1] if m.steps else None
    term_evs = m.steps[terminal_step] if terminal_step else evs
    t_out = {e.get("outcome") for e in term_evs}
    if t_out == {"success"}:
        terminal_outcome = "success"
    elif "success" in t_out and "failure" in t_out:
        terminal_outcome = "mixed"
    elif "failure" in t_out and "success" not in t_out:
        terminal_outcome = "failure" if t_out <= {"failure"} else "failure_or_unknown"
    else:
        terminal_outcome = "unknown"
    stage = c.purpose.stage
    if stage in ("attempt", "observed_success"):
        stage = {"success": "observed_success", "mixed": "observed_success", "failure": "attempt",
                 "failure_or_unknown": "attempt", "unknown": "attempt" if stage == "attempt" else "outcome_unknown"}[terminal_outcome]
    counts["terminal_outcome"] = terminal_outcome
    try:
        expl = rule.explanation.format(**counts)
    except (KeyError, IndexError, ValueError):
        expl = rule.explanation
    if terminal_step or terminal_outcome != "unknown":
        expl += f" Terminal action outcome: {terminal_outcome}" + (f" (step '{terminal_step}')." if terminal_step else ".")
    where = sorted({x for e in evs for x in (e.get("host"), e.get("http_host"), e.get("dst_ip"), e.get("tenant_id")) if x})[:10]
    alert = {
        "alert_id": _alert_id(case["case_id"], rule, m.group, first["event_id"]),
        "rule_id": rule.id, "rule_version": rule.version, "rule_title": rule.title, "rule_status": rule.status,
        "family": rule.family, "synthetic": bool(case["synthetic"]),
        "group": m.group, "first_time": first["event_time"], "last_time": last["event_time"], "event_count": len(evs),
        "disposition": disposition, "abstained": abstained,
        "what": rule.contributes.threat.activity, "where": where, "when": {"first": first["event_time"], "last": last["event_time"]},
        "why": expl,
        "threat": {"activity": c.threat.activity, "severity": severity, "suspicion": c.threat.suspicion},
        "automation": {"level": automation, "basis": automation_basis},
        "llm": {"level": llm_level, "basis": llm_basis, "limitations": llm_limits},
        "framework": fw or {"name": None, "level": "unknown", "basis": "no framework-specific evidence in this alert",
                             "limitations": ["speed, style, language, IP, User-Agent or filenames alone do not identify a framework"]},
        "purpose": {"observed_action": c.purpose.observed_action, "hypothesis": c.purpose.hypothesis, "stage": stage,
                    "action_outcome": {"terminal_step": terminal_step, "outcome": terminal_outcome,
                                       "basis": "outcome field of the terminal step's records" if terminal_step else "outcome field of the matched records"},
                    "note": "hypothesized objective, not an observed fact"},
        "entities": sorted(entities.values(), key=lambda x: (x["etype"], x["key"])),
        "confidence": conf, "confidence_rationale": rationale,
        "evidence": [{"event_id": e["event_id"], "evidence_ref": e["evidence_ref"], "event_time": e["event_time"],
                      "step": step_of.get(e["event_id"]), "input_id": e["input_id"], "record_no": e["record_no"]} for e in evid],
        "evidence_truncated": len(evs) > MAX_EVIDENCE,
        "event_ids": [e["event_id"] for e in evid], "evidence_refs": [e["evidence_ref"] for e in evid],
        "rule_ids": [rule.id],
        "matched_predicates": m.traces,
        "evidence_family": rule.evidence_family,
        "alternatives": rule.alternatives, "false_positives": rule.false_positives,
        "missing_visibility": missing, "resolving_data": rule.resolving_data,
        "reference": rule.reference.model_dump(), "baseline": baseline,
        "registry": reg, "ioc_matches": ioc_hits[:20], "absence_checks": absence, "source_history": src_hist,
        "provenance": prov,
        "recommendation": (rule.recommendation or "Review the cited records; no automatic response is performed by ARGOS.")
                          + " (Reviewable text only; ARGOS performs no blocking, isolation or other response.)",
    }
    return alert


def _max(order, vals, default):
    vals = [v for v in vals if v in order]
    return max(vals, key=order.index) if vals else default


def case_assessment(case: dict, alerts: list[dict], coverage: dict, rejects: int, rule_stats: dict) -> dict:
    live = [a for a in alerts if a["disposition"] != "authorized_automation" and not a["abstained"]]
    sev = _max(SEVERITY_ORDER, [a["threat"]["severity"] for a in live], "informational")
    autos = {a["automation"]["level"] for a in alerts}
    if "observed_manual_component" in autos and ("observed_automation" in autos or "consistent_with_automation" in autos):
        auto_level = "mixed"
    elif "observed_manual_component" in autos:
        auto_level = "observed_manual_component"
    else:
        auto_level = _max(AUTOMATION_ORDER, autos, "unknown")
    llm_level = _max(LLM_ORDER, [a["llm"]["level"] for a in live], "unknown")

    def family_scores(pred):
        fams = {}
        for a in alerts:
            if pred(a):
                f = a["evidence_family"]
                fams[f] = max(fams.get(f, 0.0), FAMILY_WEIGHT[a["confidence"]])
        return round(sum(fams.values()), 2), sorted(fams)

    llm_score, llm_fams = family_scores(lambda a: a["llm"]["level"] != "unknown")
    auto_score, auto_fams = family_scores(lambda a: a["automation"]["level"] != "unknown")
    # framework corroboration: >=2 independent fingerprint families on the same host
    fw = defaultdict(lambda: {"families": set(), "alerts": [], "hosts": defaultdict(set)})
    for a in alerts:
        f = a["framework"]
        if f.get("name"):
            d = fw[f["name"]]
            d["alerts"].append(a["alert_id"])
            if f.get("independence_family"):
                d["families"].add(f["independence_family"])
                for h in [e["key"] for e in a["entities"] if e["etype"] == "device"] or ["?"]:
                    d["hosts"][h].add(f["independence_family"])
    frameworks = []
    for name, d in fw.items():
        corroborated_hosts = [h for h, fams in d["hosts"].items() if len(fams) >= 2 and h != "?"]
        level = "corroborated_presence" if corroborated_hosts else "consistent_with"
        frameworks.append({"name": name, "level": level, "independent_families": sorted(d["families"]),
                           "corroborated_on_hosts": corroborated_hosts, "alerts": d["alerts"],
                           "presence": level,
                           "execution": "not established automatically (needs records tying the framework's process tree to the activity)",
                           "responsibility_for_activity": "not established (presence is not responsibility)",
                           "victim_side_fingerprint": "no validated victim-side fingerprint was found in the reviewed version (BaaRai/ARTEX v0.6.0, a13c68cb)",
                           "note": "framework candidates are experimental; see docs/ARTEX_SOURCE_REVIEW.md"})
    fw_level = _max(FRAMEWORK_ORDER, [f["level"] for f in frameworks], "unknown")
    purposes = defaultdict(lambda: {"count": 0, "stages": set()})
    for a in live:
        p = purposes[a["purpose"]["hypothesis"]]
        p["count"] += 1
        p["stages"].add(a["purpose"]["stage"])
    entity_index = {}
    for a in live:
        for e in a["entities"]:
            entity_index.setdefault((e["etype"], e["key"]), e)
    limitations = []
    for v in VANTAGES:
        if not coverage.get(v, {}).get("event_count"):
            limitations.append(f"{v} telemetry not supplied: conclusions that need it are UNKNOWN, not negative")
    if rejects:
        limitations.append(f"{rejects} input records were rejected (see data quality); they were not analysed")
    not_eval = sorted(r for r, s in rule_stats.items() if s.get("not_evaluable"))
    if not_eval:
        limitations.append(f"{len(not_eval)} rules not evaluable for lack of their observation vantage")
    for rid, st in sorted(rule_stats.items()):
        if st.get("missing_required_telemetry"):
            limitations.append(f"{rid}: {st['missing_required_telemetry']} candidate records lacked required fields and were not evaluated")
    limitations.append("synthetic or prototype validation only; real-world detection accuracy NOT MEASURED")
    return {
        "case_id": case["case_id"], "case_name": case["name"], "synthetic": bool(case["synthetic"]),
        "threat": {"max_severity": sev, "activities": sorted({a["threat"]["activity"] for a in live}),
                   "alert_count": len(alerts), "open_alerts": len(live),
                   "authorized_automation_alerts": sum(a["disposition"] == "authorized_automation" for a in alerts),
                   "abstentions": sum(a["abstained"] for a in alerts)},
        "automation": {"level": auto_level, "heuristic_evidence_score": auto_score, "evidence_families": auto_fams},
        "llm": {"level": llm_level, "heuristic_evidence_score": llm_score, "evidence_families": llm_fams,
                "note": "heuristic evidence score = sum over DISTINCT evidence families (duplicates count once); not a probability"},
        "framework": {"level": fw_level, "candidates": frameworks},
        "purpose": [{"hypothesis": k, "alerts": v["count"], "stages": sorted(v["stages"])} for k, v in sorted(purposes.items())],
        "entities": sorted(entity_index.values(), key=lambda x: (x["etype"], x["key"]))[:300],
        "attribution": {"person": "not assessed (out of scope: telemetry does not identify persons)",
                        "threat_group": "not assessed (no attribution from IPs, language, speed or style)",
                        "model": "not assessed unless verifiable model-audit records name it; declared names are labelled as declared"},
        "coverage": coverage, "limitations": limitations,
    }


def compute_coverage(events: list[dict], inputs: list[dict], rejects_by_input: dict) -> dict:
    """Observation SPAN per vantage (first..last record) plus analyst-declared collection coverage.
    A span is not proof of complete collection; see analysis.CoverageContext."""
    import json as _json
    declared = {i["input_id"]: _json.loads(i["coverage"]) for i in inputs if i.get("coverage")}
    cov = {}
    for v in VANTAGES:
        evs = [e for e in events if e["observation_vantage"] == v]
        if not evs:
            cov[v] = {"status": "unavailable", "event_count": 0}
            continue
        ins = sorted({e["input_id"] for e in evs})
        intervals = []
        for i in ins:
            ie = [e["event_epoch"] for e in evs if e["input_id"] == i]
            intervals.append({"input_id": i, "first": iso_from(min(ie)), "last": iso_from(max(ie)), "events": len(ie)})
        cov[v] = {"status": "present", "semantics": "observation span of supplied records (not demonstrated collection coverage)",
                  "declared_coverage": [{"input_id": i, **{k: declared[i][k] for k in ("start", "end", "scope", "basis")}} for i in ins if i in declared],
                  "event_count": len(evs), "first": evs[0]["event_time"], "last": evs[-1]["event_time"],
                  "first_epoch": evs[0]["event_epoch"], "last_epoch": evs[-1]["event_epoch"],
                  "event_kinds": sorted({e["event_kind"] for e in evs}), "intervals": intervals,
                  "rejected_records_in_inputs": sum(rejects_by_input.get(i, 0) for i in ins)}
    return cov


def iso_from(epoch: float) -> str:
    from datetime import datetime, timezone
    return iso(datetime.fromtimestamp(epoch, tz=timezone.utc))
