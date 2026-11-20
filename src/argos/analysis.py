"""Analysis run orchestration (deterministic, reproducible, case-scoped).

case -> active input revisions -> normalized events -> entities -> rules -> evaluator -> alerts +
case assessment -> ONE atomic commit (alerts, per-run snapshots, effective configuration, entities).
A failed or cancelled run is recorded as such and never replaces the last successful results.

Coverage semantics (v0.3): an observation *span* (first..last record) is not collection coverage.
History windows and absence statements only count as covered when (a) an analyst declared collection
coverage for that entity scope and interval at import, or (b) the same entity's own records from the
same vantage show collection was operating in that window. Otherwise ARGOS reports insufficient
baseline / "not observed in the supplied records".
"""
from __future__ import annotations

import bisect
import hashlib
import json
from collections import Counter, defaultdict

import yaml

from argos import ENGINE_VERSION, SCHEMA_VERSION, __version__
from argos.config import Settings
from argos.detect.context import IOCSet, Registry
from argos.detect.engine import evaluate_rule, key_value
from argos.detect.ops import Evaluator, derive
from argos.detect.rules import load_rules
from argos.entities.extract import build_entities
from argos.evidence.assess import build_alert, case_assessment, compute_coverage, iso_from
from argos.normalize.timeutil import now_iso
from argos.store import Store


class AnalysisError(ValueError):
    pass


class AnalysisCancelled(RuntimeError):
    pass


def _overrides(settings: Settings) -> tuple[dict, list[str]]:
    p = settings.config_dir / "rule_overrides.yaml"
    if not p.is_file():
        return {}, []
    data = yaml.safe_load(p.read_text("utf-8")) or {}
    disabled = data.get("_disabled") or []
    if not isinstance(disabled, list):
        raise AnalysisError("_disabled in rule_overrides.yaml must be a list of rule ids")
    return data, [str(x) for x in disabled]


def load_context(settings: Settings):
    rules, rules_hash, errors = load_rules(settings.rules_dir, settings.config_dir / "rule_overrides.yaml")
    _, disabled = _overrides(settings)
    registry = Registry.load(settings.config_dir / "authorized_automation.yaml")
    iocs = IOCSet.load(settings.rules_dir / "iocs")
    return rules, rules_hash, errors, registry, iocs, disabled


class CoverageContext:
    """Answers 'was collection evidently operating for this entity in [t0, t1)?' without guessing."""

    def __init__(self, events: list[dict], inputs: dict):
        self.declared = []
        input_vantages = defaultdict(set)
        for e in events:
            input_vantages[e["input_id"]].add(e["observation_vantage"])
        for iid, inp in inputs.items():
            if inp.get("coverage"):
                cov = json.loads(inp["coverage"])
                cov["vantages"] = sorted(input_vantages.get(iid, set()))
                cov["input_id"] = iid
                self.declared.append(cov)
        self.events = events
        self._index: dict = {}

    def _entity_index(self, fields: tuple, vantages: tuple):
        key = (fields, vantages)
        if key not in self._index:
            idx = defaultdict(list)
            for e in self.events:
                if e["observation_vantage"] not in vantages:
                    continue
                k = tuple(key_value(f, e.get(f)) for f in fields)
                if all(v is not None for v in k):
                    idx[k].append(e["event_epoch"])
            for v in idx.values():
                v.sort()
            self._index[key] = idx
        return self._index[key]

    def declared_cover(self, entity: dict, vantages, t0: float, t1: float):
        for c in self.declared:
            if not set(c["vantages"]) & set(vantages):
                continue
            if not (c["start_epoch"] <= t0 and t1 <= c["end_epoch"]):
                continue
            scope = c["scope"]
            if scope == "all":
                return c
            kind, _, val = scope.partition(":")
            field = {"tenant": "tenant_id", "host": "host", "app_id": "app_id"}[kind]
            ev_val = entity.get(field)
            if ev_val is not None and key_value(field, ev_val) == key_value(field, val):
                return c
        return None

    def entity_observed(self, fields: tuple, group_vals: tuple, vantages: tuple, t0: float, t1: float) -> int:
        epochs = self._entity_index(fields, vantages).get(group_vals, [])
        return bisect.bisect_left(epochs, t1) - bisect.bisect_left(epochs, t0)

    def window_status(self, rule, group: dict, t0: float, t1: float) -> str:
        fields = tuple(f for f in rule.group_by)
        vals = tuple(key_value(f, group[f]) for f in fields)
        if self.declared_cover(group, rule.observation_vantage, t0, t1):
            return "declared"
        if fields and self.entity_observed(fields, vals, tuple(rule.observation_vantage), t0, t1):
            return "entity_observed"
        return "gap"


def observation_gaps(events: list[dict], threshold_s: float = 6 * 3600) -> list[dict]:
    by = defaultdict(list)
    for e in events:
        by[(e["input_id"], e["observation_vantage"])].append(e["event_epoch"])
    out = []
    for (iid, v), ts in by.items():
        ts.sort()
        for a, b in zip(ts, ts[1:]):
            if b - a > threshold_s:
                out.append({"input_id": iid, "vantage": v, "from": iso_from(a), "to": iso_from(b), "hours": round((b - a) / 3600, 1)})
    return out[:200]


def source_diagnostics(events: list[dict], inputs: dict, rej_by_input: Counter) -> list[dict]:
    key_fields = ("tenant_id", "user", "host", "src_ip", "dst_ip", "process_guid", "session_id", "outcome")
    per = {iid: {"input_id": iid, "original_name": i["original_name"], "format": i["format"], "revision": i.get("revision", 1),
                 "status": i.get("status", "imported"), "trust": i["provenance_trust"], "events": 0, "vantages": Counter(),
                 "rejected": rej_by_input.get(iid, 0), "missing_fields": Counter(),
                 "declared_coverage": json.loads(i["coverage"]) if i.get("coverage") else None} for iid, i in inputs.items()}
    for e in events:
        d = per.get(e["input_id"])
        if d is None:
            continue
        d["events"] += 1
        d["vantages"][e["observation_vantage"]] += 1
        for f in key_fields:
            if e.get(f) in (None, ""):
                d["missing_fields"][f] += 1
    out = []
    for d in per.values():
        d["vantages"] = dict(d["vantages"])
        d["missing_fields"] = {k: v for k, v in d["missing_fields"].items() if d["events"] and v}
        out.append(d)
    return out


def _rule_status(st: dict, n_matches: int, abstained: int) -> str:
    if st.get("disabled"):
        return "disabled"
    if st.get("error"):
        return "processing_error"
    if st.get("not_evaluable"):
        return "vantage_absent"
    if st.get("selected", 0) == 0:
        return "evaluable_no_candidate_records"
    if st.get("selected", 0) == st.get("missing_required_telemetry", 0) + st.get("ungroupable", 0) and n_matches == 0:
        return "missing_required_telemetry"
    if abstained and abstained == n_matches:
        return "insufficient_history"
    return "matched" if n_matches else "evaluable_no_match"


def run_analysis(store: Store, settings: Settings, case_ref: str, progress=None, cancel=None) -> dict:
    case = store.get_case(case_ref)
    if not case:
        raise AnalysisError(f"unknown case {case_ref!r}")
    rules, rules_hash, rule_errors, registry, iocs, disabled = load_context(settings)
    if rule_errors:
        raise AnalysisError("rule validation failed: " + "; ".join(rule_errors))
    inputs = {i["input_id"]: i for i in store.list_inputs(case["case_id"])}
    manifest = sorted([{"input_id": i["input_id"], "sha256": i["sha256"], "format": i["format"], "parser_version": i["parser_version"],
                        "options": json.loads(i["options"]), "options_hash": i.get("options_hash"), "revision": i.get("revision", 1),
                        "provenance_trust": i["provenance_trust"], "coverage": json.loads(i["coverage"]) if i.get("coverage") else None}
                       for i in inputs.values()], key=lambda x: x["input_id"])
    manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()[:16]
    overrides_text = (settings.config_dir / "rule_overrides.yaml").read_text("utf-8") if (settings.config_dir / "rule_overrides.yaml").is_file() else None
    registry_text = (settings.config_dir / "authorized_automation.yaml").read_text("utf-8") if (settings.config_dir / "authorized_automation.yaml").is_file() else None
    versions = {"argos": __version__, "engine": ENGINE_VERSION, "schema": SCHEMA_VERSION,
                "parsers": sorted({i["parser_version"] for i in inputs.values()}), "rules_hash": rules_hash,
                "rules": sorted(f"{r.id}@{r.version}" for r in rules), "disabled_rules": sorted(disabled),
                "config_hash": settings.config_hash(), "registry_hash": registry.digest, "ioc_hash": iocs.digest,
                "manifest_hash": manifest_hash}
    seq = store.next_run_seq(case["case_id"])
    started = now_iso()
    run_id = "run-" + hashlib.sha256(f"{case['case_id']}|{seq}|{started}".encode()).hexdigest()[:16]
    store.add_run({"run_id": run_id, "case_id": case["case_id"], "seq": seq, "started_at": started,
                   "manifest": manifest, "versions": versions})

    def tick(frac: float, msg: str):
        if cancel is not None and cancel():
            raise AnalysisCancelled("analysis cancelled by the analyst")
        if progress is not None:
            progress(frac, msg)

    try:
        tick(0.02, "loading events")
        events = [derive(e) for e in store.iter_events(case["case_id"])]
        rejects = store.list_rejects(case["case_id"], limit=10_000_000)
        rej_by_input = Counter(r["input_id"] for r in rejects)
        coverage = compute_coverage(events, list(inputs.values()), rej_by_input)
        cov_ctx = CoverageContext(events, inputs)
        tick(0.1, "building entities")
        ents, rels, links = build_entities(case["case_id"], events)
        ev_fn = Evaluator(iocs)
        alerts, rule_stats = [], {}
        present_vantages = {v for v, c in coverage.items() if c.get("event_count")}

        def absence_lookup(rule, m):
            ac = rule.absence_check
            last = m.events[-1]
            end = last["event_epoch"] + ac.within_s
            join = {k: v for k, v in m.group.items() if ac.join_fields is None or k in ac.join_fields}
            same = [e for e in events if all(key_value(k, e.get(k)) == key_value(k, v) for k, v in join.items())]
            hits = [e for e in same if last["event_epoch"] < e["event_epoch"] <= end and ev_fn.match(ac.where, e)]
            base = {"label": ac.label, "window": f"{last['event_time']} + {ac.within_s}s", "join": join}
            if hits:
                return {**base, "status": "present", "event_ids": [e["event_id"] for e in hits[:20]]}
            if not coverage.get(ac.vantage, {}).get("event_count"):
                return {**base, "status": "not_assessable_telemetry_unavailable", "vantage": ac.vantage}
            decl = cov_ctx.declared_cover({**last, **join}, [ac.vantage], last["event_epoch"], end)
            if decl:
                return {**base, "status": "absent_within_declared_coverage",
                        "detail": f"no matching records; collection for scope '{decl['scope']}' {decl['start']}..{decl['end']} "
                                  f"was declared by the analyst (input {decl['input_id']}), not verified by ARGOS"}
            later = [e for e in same if e["observation_vantage"] == ac.vantage and e["event_epoch"] > last["event_epoch"]]
            if later:
                return {**base, "status": "not_observed_entity_records_continue",
                        "detail": f"no matching records in the supplied data; {len(later)} later record(s) of the same identity show "
                                  "collection for this identity continued, but completeness is not established"}
            return {**base, "status": "not_observed_in_supplied_records",
                    "detail": "no matching or later records for this identity in the supplied data; whether collection continued is unknown "
                              "(other identities' or hosts' records do not demonstrate coverage)"}

        def history_lookup(rule, m):
            sh = rule.source_history
            first = m.events[0]
            val = m.group.get(sh.field) or first.get(sh.field)
            keys = {k: key_value(k, first.get(k)) for k in sh.join_fields}
            prior = [e for e in events if first["event_epoch"] - sh.lookback_s <= e["event_epoch"] < first["event_epoch"]
                     and all(key_value(k, e.get(k)) == v for k, v in keys.items())]
            if not prior:
                return {"field": sh.field, "value": val, "status": "no_prior_history",
                        "detail": "no earlier records for this identity in the case; novelty of the source cannot be assessed"}
            known = [e for e in prior if key_value(sh.field, e.get(sh.field)) == key_value(sh.field, val) and ev_fn.match(sh.where, e)]
            if known:
                return {"field": sh.field, "value": val, "status": "known_source", "event_ids": [e["event_id"] for e in known[:10]],
                        "detail": f"this {sh.field} previously succeeded for the same identity ({len(known)} earlier record(s))"}
            return {"field": sh.field, "value": val, "status": "novel_source",
                    "detail": f"no earlier success from this {sh.field} among {len(prior)} prior records for the identity"}

        n = max(1, len(rules))
        for i, rule in enumerate(rules):
            tick(0.15 + 0.75 * i / n, f"rule {rule.id}")
            if rule.id in disabled:
                rule_stats[rule.id] = {"disabled": True, "status": "disabled"}
                continue
            if not (set(rule.observation_vantage) & present_vantages):
                rule_stats[rule.id] = {"not_evaluable": True, "reason": "required observation vantage not present in case", "status": "vantage_absent"}
                continue
            try:
                matches, st = evaluate_rule(rule, events, ev_fn, cov_ctx)
                made = []
                for m in matches:
                    if rule.source_history:
                        m.extra["_source_history"] = history_lookup(rule, m)
                    made.append(build_alert(m, case, inputs, coverage, registry, absence_lookup=absence_lookup))
            except AnalysisCancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - one broken rule must not hide the others; surfaced as processing_error
                rule_stats[rule.id] = {"error": f"{type(exc).__name__}: {exc}"[:300], "status": "processing_error"}
                continue
            alerts += made
            st["status"] = _rule_status(st, len(made), sum(a["abstained"] for a in made))
            st["alerts"] = len(made)
            rule_stats[rule.id] = st
        seen = {}
        for a in alerts:
            seen.setdefault(a["alert_id"], a)
        alerts = list(seen.values())
        for e in events:
            e.pop("_ioc_hits", None)
        tick(0.93, "assessing case")
        assessment = case_assessment(case, alerts, coverage, len(rejects), rule_stats)
        assessment.update(run_id=run_id, versions=versions, rule_stats=rule_stats,
                          diagnostics={"sources": source_diagnostics(events, inputs, rej_by_input),
                                       "observation_gaps": observation_gaps(events),
                                       "rule_status_counts": dict(Counter(s.get("status") for s in rule_stats.values()))})
        snapshot = {"rules": [r.model_dump(by_alias=True) for r in rules], "overrides": overrides_text, "registry": registry_text,
                    "iocs": [{k: v for k, v in it.items() if not k.startswith("_")} for its in iocs.items.values() for it in its],
                    "settings": settings.analysis_config()}
        stats = {"events": len(events), "alerts": len(alerts),
                 "rules_evaluated": sum(1 for s in rule_stats.values() if s.get("status") not in ("vantage_absent", "disabled", "processing_error")),
                 "rules_not_evaluable": sum(1 for s in rule_stats.values() if s.get("status") == "vantage_absent"),
                 "rules_disabled": sum(1 for s in rule_stats.values() if s.get("status") == "disabled"),
                 "rules_failed": sum(1 for s in rule_stats.values() if s.get("status") == "processing_error")}
        tick(0.96, "committing results")
        stats = store.commit_run(case["case_id"], run_id, alerts, assessment, snapshot, stats, entities=(ents, rels, links))
    except AnalysisCancelled as exc:
        store.fail_run(run_id, "cancelled", str(exc))
        raise
    except Exception as exc:
        store.fail_run(run_id, "failed", f"{type(exc).__name__}: {exc}")
        raise
    if progress is not None:
        progress(1.0, "done")
    return {"run_id": run_id, "case_id": case["case_id"], "seq": seq, "stats": stats, "versions": versions}
