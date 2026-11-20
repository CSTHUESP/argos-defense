"""Analysis run orchestration (deterministic, reproducible, case-scoped).

task (case) -> analyzers query local case data -> correlator/entities ->
detectors (rules) -> evaluator (confidence/evidence checks) -> stored alerts
and a case assessment -> report generator.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter

from argos import ENGINE_VERSION, SCHEMA_VERSION, __version__
from argos.config import Settings
from argos.detect.context import IOCSet, Registry
from argos.detect.engine import evaluate_rule
from argos.detect.ops import Evaluator, derive
from argos.detect.rules import load_rules
from argos.entities.extract import build_entities
from argos.evidence.assess import build_alert, case_assessment, compute_coverage
from argos.normalize.timeutil import now_iso
from argos.store import Store


class AnalysisError(ValueError):
    pass


def load_context(settings: Settings):
    rules, rules_hash, errors = load_rules(settings.rules_dir, settings.config_dir / "rule_overrides.yaml")
    registry = Registry.load(settings.config_dir / "authorized_automation.yaml")
    iocs = IOCSet.load(settings.rules_dir / "iocs")
    return rules, rules_hash, errors, registry, iocs


def run_analysis(store: Store, settings: Settings, case_ref: str) -> dict:
    case = store.get_case(case_ref)
    if not case:
        raise AnalysisError(f"unknown case {case_ref!r}")
    rules, rules_hash, rule_errors, registry, iocs = load_context(settings)
    if rule_errors:
        raise AnalysisError("rule validation failed: " + "; ".join(rule_errors))
    inputs = {i["input_id"]: i for i in store.list_inputs(case["case_id"])}
    events = [derive(e) for e in store.iter_events(case["case_id"])]
    rejects = store.list_rejects(case["case_id"], limit=10_000_000)
    rej_by_input = Counter(r["input_id"] for r in rejects)
    manifest = sorted([{"input_id": i["input_id"], "sha256": i["sha256"], "format": i["format"], "parser_version": i["parser_version"],
                        "options": json.loads(i["options"]), "provenance_trust": i["provenance_trust"]} for i in inputs.values()],
                      key=lambda x: x["input_id"])
    manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    versions = {"argos": __version__, "engine": ENGINE_VERSION, "schema": SCHEMA_VERSION,
                "parsers": sorted({i["parser_version"] for i in inputs.values()}), "rules_hash": rules_hash,
                "rules": sorted(f"{r.id}@{r.version}" for r in rules), "config_hash": settings.config_hash(),
                "registry_hash": registry.digest, "ioc_hash": iocs.digest, "manifest_hash": manifest_hash}
    seq = store.next_run_seq(case["case_id"])
    started = now_iso()
    run_id = "run-" + hashlib.sha256(f"{case['case_id']}|{seq}|{started}".encode()).hexdigest()[:16]
    store.add_run({"run_id": run_id, "case_id": case["case_id"], "seq": seq, "started_at": started,
                   "manifest": manifest, "versions": versions})
    coverage = compute_coverage(events, list(inputs.values()), rej_by_input)
    ents, rels, links = build_entities(case["case_id"], events)
    store.replace_entities(case["case_id"], ents, rels, links)
    ev_fn = Evaluator(iocs)
    alerts, rule_stats = [], {}
    present_vantages = {v for v, c in coverage.items() if c.get("event_count")}

    def absence_lookup(rule, m):
        ac = rule.absence_check
        last = m.events[-1]
        cov = coverage.get(ac.vantage, {})
        end = last["event_epoch"] + ac.within_s
        hits = [e for e in events if last["event_epoch"] < e["event_epoch"] <= end
                and all(str(e.get(k) or "").lower() == str(v).lower() for k, v in m.group.items()
                        if ac.join_fields is None or k in ac.join_fields)
                and ev_fn.match(ac.where, e)]
        if hits:
            return {"label": ac.label, "status": "present", "event_ids": [e["event_id"] for e in hits[:20]]}
        if not cov.get("event_count"):
            return {"label": ac.label, "status": "not_assessable_telemetry_unavailable", "vantage": ac.vantage}
        if cov["last_epoch"] < end:
            return {"label": ac.label, "status": "absent_within_partial_coverage",
                    "detail": f"{ac.vantage} coverage ends {cov['last']} before the {ac.within_s}s follow-up window closes"}
        return {"label": ac.label, "status": "absent_within_demonstrated_coverage",
                "detail": f"no matching {ac.vantage} records within {ac.within_s}s after {last['event_time']} (coverage {cov['first']}..{cov['last']})"}

    def history_lookup(rule, m):
        sh = rule.source_history
        first = m.events[0]
        val = m.group.get(sh.field) or first.get(sh.field)
        keys = {k: str(first.get(k) or "").lower() for k in sh.join_fields}
        prior = [e for e in events if first["event_epoch"] - sh.lookback_s <= e["event_epoch"] < first["event_epoch"]
                 and all(str(e.get(k) or "").lower() == v for k, v in keys.items())]
        if not prior:
            return {"field": sh.field, "value": val, "status": "no_prior_history",
                    "detail": "no earlier records for this identity in the case; novelty of the source cannot be assessed"}
        known = [e for e in prior if str(e.get(sh.field) or "").lower() == str(val).lower() and ev_fn.match(sh.where, e)]
        if known:
            return {"field": sh.field, "value": val, "status": "known_source", "event_ids": [e["event_id"] for e in known[:10]],
                    "detail": f"this {sh.field} previously succeeded for the same identity ({len(known)} earlier record(s))"}
        return {"field": sh.field, "value": val, "status": "novel_source",
                "detail": f"no earlier success from this {sh.field} among {len(prior)} prior records for the identity"}

    for rule in rules:
        if not (set(rule.observation_vantage) & present_vantages):
            rule_stats[rule.id] = {"not_evaluable": True, "reason": "required observation vantage not present in case"}
            continue
        cov_start = {tuple(rule.observation_vantage): min((coverage[v]["first_epoch"] for v in rule.observation_vantage
                                                          if coverage.get(v, {}).get("event_count")), default=None)}
        matches, st = evaluate_rule(rule, events, ev_fn, cov_start)
        rule_stats[rule.id] = st
        for m in matches:
            if rule.source_history:
                m.extra["_source_history"] = history_lookup(rule, m)
            alerts.append(build_alert(m, case, inputs, coverage, registry, absence_lookup=absence_lookup))
    seen = {}
    for a in alerts:
        seen.setdefault(a["alert_id"], a)
    alerts = list(seen.values())
    for e in events:
        e.pop("_ioc_hits", None)
    upsert = store.upsert_alerts(case["case_id"], run_id, alerts)
    assessment = case_assessment(case, alerts, coverage, len(rejects), rule_stats)
    assessment.update(run_id=run_id, versions=versions, rule_stats=rule_stats)
    store.save_assessment(case["case_id"], run_id, assessment)
    stats = {"events": len(events), "alerts": len(alerts), **upsert, "rules_evaluated": sum(1 for s in rule_stats.values() if not s.get("not_evaluable")),
             "rules_not_evaluable": sum(1 for s in rule_stats.values() if s.get("not_evaluable"))}
    store.finish_run(run_id, stats)
    return {"run_id": run_id, "case_id": case["case_id"], "seq": seq, "stats": stats, "versions": versions}
