"""Compare two analysis runs of the same case (F09 / feature B).

The comparison reads only each run's immutable snapshot (alerts, assessment, rules, settings,
input manifest). It reports what changed and attributes the change to the inputs that can be
proven to differ: data (input manifest), rules (per-rule definition hashes), configuration
(settings/overrides/registry/IOC hashes) and engine version. It never claims a single cause when
several inputs changed at once.
"""
from __future__ import annotations

import hashlib
import json

from argos.store import Store

DIMENSIONS = (("severity", lambda a: a["threat"]["severity"]), ("confidence", lambda a: a["confidence"]),
              ("automation", lambda a: a["automation"]["level"]), ("llm", lambda a: a["llm"]["level"]),
              ("framework", lambda a: a["framework"]["level"]), ("purpose", lambda a: a["purpose"]["hypothesis"]),
              ("disposition", lambda a: a.get("disposition")), ("event_count", lambda a: a.get("event_count")))


def _h(v) -> str:
    return hashlib.sha256(json.dumps(v, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _identity(a: dict) -> str:
    # stable across runs: rule + group keys + first observed time (alert ids are already derived from this)
    return a["alert_id"]


def _run_bundle(store: Store, run_id: str) -> dict:
    run = store.get_run(run_id)
    if not run:
        raise ValueError(f"unknown run {run_id!r}")
    if run["status"] != "succeeded":
        raise ValueError(f"run {run_id} has status {run['status']}")
    snap = store.run_snapshot(run_id)
    if snap is None:
        raise ValueError(f"run {run_id} predates run snapshots (legacy); it cannot be compared reliably")
    return {"run": run, "snap": snap, "alerts": {_identity(a): a for a in store.run_alerts(run_id)},
            "assessment": store.run_assessment(run_id) or {}}


def compare_runs(store: Store, run_a: str, run_b: str) -> dict:
    A, B = _run_bundle(store, run_a), _run_bundle(store, run_b)
    if A["run"]["case_id"] != B["run"]["case_id"]:
        raise ValueError("runs belong to different cases; comparison is case-scoped")
    ra = {r["id"]: _h(r) for r in A["snap"]["rules"]}
    rb = {r["id"]: _h(r) for r in B["snap"]["rules"]}
    rule_changes = {"added": sorted(set(rb) - set(ra)), "removed": sorted(set(ra) - set(rb)),
                    "modified": sorted(k for k in set(ra) & set(rb) if ra[k] != rb[k])}
    def _man(run):
        m = run["manifest"] or []
        return {i["input_id"]: i for i in (m.get("inputs", []) if isinstance(m, dict) else m)}
    ma, mb = _man(A["run"]), _man(B["run"])
    data_changes = {"added_inputs": sorted(set(mb) - set(ma)), "removed_inputs": sorted(set(ma) - set(mb)),
                    "changed_inputs": sorted(k for k in set(ma) & set(mb) if _h(ma[k]) != _h(mb[k])),
                    "provenance_trust_changed": sorted(k for k in set(ma) & set(mb)
                                                       if ma[k].get("provenance_trust") != mb[k].get("provenance_trust"))}
    cfg = {}
    for k in ("settings", "overrides", "registry", "iocs"):
        if _h(A["snap"].get(k)) != _h(B["snap"].get(k)):
            cfg[k] = {"a": _h(A["snap"].get(k)), "b": _h(B["snap"].get(k))}
    va, vb = A["run"]["versions"] or {}, B["run"]["versions"] or {}
    engine_change = {k: {"a": va.get(k), "b": vb.get(k)} for k in ("engine", "parsers", "argos") if va.get(k) != vb.get(k)}
    causes = [n for n, c in (("data", any(data_changes.values())), ("rules", any(rule_changes.values())),
                             ("configuration", bool(cfg)), ("engine", bool(engine_change))) if c]

    added, removed, changed = [], [], []
    for k in sorted(set(B["alerts"]) - set(A["alerts"])):
        a = B["alerts"][k]
        added.append({"alert_id": k, "rule_id": a["rule_id"], "what": a.get("what"),
                      "rule_changed": a["rule_id"] in rule_changes["added"] + rule_changes["modified"]})
    for k in sorted(set(A["alerts"]) - set(B["alerts"])):
        a = A["alerts"][k]
        removed.append({"alert_id": k, "rule_id": a["rule_id"], "what": a.get("what"),
                        "rule_changed": a["rule_id"] in rule_changes["removed"] + rule_changes["modified"]})
    for k in sorted(set(A["alerts"]) & set(B["alerts"])):
        a, b = A["alerts"][k], B["alerts"][k]
        diffs = {}
        for name, fn in DIMENSIONS:
            try:
                x, y = fn(a), fn(b)
            except (KeyError, TypeError):
                continue
            if x != y:
                diffs[name] = {"a": x, "b": y}
        if diffs:
            changed.append({"alert_id": k, "rule_id": a["rule_id"], "changes": diffs,
                            "rule_changed": a["rule_id"] in rule_changes["modified"]})
    aa, ab = A["assessment"], B["assessment"]
    case_level = {}
    for name, path in (("max_severity", ("threat", "max_severity")), ("automation", ("automation", "level")),
                       ("llm", ("llm", "level")), ("framework", ("framework", "level"))):
        x, y = aa, ab
        for p in path:
            x = (x or {}).get(p)
            y = (y or {}).get(p)
        if x != y:
            case_level[name] = {"a": x, "b": y}
    if not causes:
        attribution = "no recorded analysis input differs; any difference would indicate non-determinism and should be reported"
    elif len(causes) == 1:
        attribution = f"only {causes[0]} differ between the runs"
    else:
        attribution = "several inputs differ (" + ", ".join(causes) + "); differences cannot be attributed to one of them"
    return {"case_id": A["run"]["case_id"], "run_a": {"run_id": run_a, "seq": A["run"]["seq"], "started_at": A["run"]["started_at"]},
            "run_b": {"run_id": run_b, "seq": B["run"]["seq"], "started_at": B["run"]["started_at"]},
            "inputs_changed": {"data": data_changes, "rules": rule_changes, "configuration": cfg, "engine": engine_change},
            "attribution": attribution, "alerts": {"added": added, "removed": removed, "changed": changed},
            "case_level": case_level,
            "summary": {"added": len(added), "removed": len(removed), "changed": len(changed), "unchanged":
                        len(set(A["alerts"]) & set(B["alerts"])) - len(changed)}}
