"""Case export as JSON, self-contained HTML, and alert CSV."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from argos import ENGINE_VERSION, PARSER_VERSIONS, SCHEMA_VERSION, __version__
from argos.config import Settings
from argos.resources import templates_dir
from argos.detect.rules import load_rules
from argos.evidence.redact import csv_safe, redact, redact_obj
from argos.normalize.timeutil import now_iso
from argos.store import Store

TEMPLATES = templates_dir()


def jinja_env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "xml", "j2"], default=True))
    env.filters["redact"] = redact
    env.filters["tojson_pretty"] = lambda v: json.dumps(redact_obj(v), indent=2, sort_keys=True, default=str)
    return env


def build_case_export(store: Store, settings: Settings, case_ref: str, max_timeline: int = 5000, run_id: str | None = None) -> dict:
    """Export one analysis run (default: the latest successful run) from its immutable snapshot (F09).

    Alerts, assessment and rule definitions come from what that run stored, not from the current
    rule files or the mutable latest-alert table. Analyst workflow status is a live overlay and is
    reported separately with its as-of time.
    """
    case = store.get_case(case_ref)
    if not case:
        raise ValueError(f"unknown case {case_ref!r}")
    cid = case["case_id"]
    run = store.get_run(run_id) if run_id else store.latest_successful_run(cid)
    if run_id and (not run or run["case_id"] != cid):
        raise ValueError(f"run {run_id!r} not found in case {case['name']!r}")
    if run and run["status"] != "succeeded":
        raise ValueError(f"run {run['run_id']} has status {run['status']}; only succeeded runs can be exported")
    snapshot = store.run_snapshot(run["run_id"]) if run else None
    if run and snapshot is not None:
        alerts = [a | {"case_id": cid, "current": True} for a in store.run_alerts(run["run_id"])]
        assessment = store.run_assessment(run["run_id"])
        rule_defs = [r for r in snapshot["rules"] if r.get("id") in {a["rule_id"] for a in alerts}]
        rules_hash = (run.get("versions") or {}).get("rules_hash")
        basis = "immutable run snapshot"
    else:
        # legacy run (pre-v0.3) or no run: best effort from the latest-alert table and current rule files
        alerts = store.list_alerts(cid, include_stale=True)
        assessment = store.latest_assessment(cid)
        rules, rules_hash, _ = load_rules(settings.rules_dir, settings.config_dir / "rule_overrides.yaml")
        used = {a["rule_id"] for a in alerts}
        rule_defs = [r.model_dump(by_alias=True) for r in rules if r.id in used]
        basis = "legacy: no run snapshot available; alerts from latest-alert table and CURRENT rule files"
    ev_ids = sorted({i for a in alerts if a.get("current", True) for i in a["event_ids"]})
    timeline = store.get_events(ev_ids)[:max_timeline]
    for e in timeline:
        for k in ("uri_path", "process_name", "parent_name", "file_ext", "dst_is_private", "src_is_private",
                  "http_status_class", "domain", "proc_link", "remote"):
            e.pop(k, None)
    live = {a["alert_id"]: a.get("analyst_status", "new") for a in store.list_alerts(cid, include_stale=True)}
    export = {
        "export_format": "argos-case-export/2",
        "generated_at": now_iso(),
        "banner": "DEMO/SYNTHETIC DATA - not real activity" if case["synthetic"] else "Case data from supplied telemetry",
        "case": case,
        "run": {"run_id": run["run_id"], "seq": run["seq"], "started_at": run["started_at"], "finished_at": run.get("finished_at"),
                "status": run["status"], "basis": basis} if run else None,
        "versions": {"argos": __version__, "engine": ENGINE_VERSION, "schema": SCHEMA_VERSION, "parsers": PARSER_VERSIONS,
                     "rules_hash": rules_hash, "run_versions": run["versions"] if run else None},
        "configuration": (snapshot or {}).get("settings") or (settings.analysis_config() | {"config_hash": settings.config_hash()}),
        "inputs": store.list_inputs(cid, include_inactive=True),
        "runs": store.list_runs(cid),
        "assessment": assessment,
        "alerts": alerts,
        "analyst_status": {"as_of": now_iso(), "note": "live workflow overlay, not part of the run", "by_alert": live},
        "timeline": timeline,
        "notes": store.list_notes(cid),
        "data_quality": {"rejected_records": store.list_rejects(cid, limit=2000)},
        "rules": rule_defs,
        "limitations": [
            "Batch analysis of supplied files; not a real-time sensor or EDR.",
            "Heuristic evidence scores are not calibrated probabilities.",
            "Real-world detection accuracy NOT MEASURED; validation is synthetic only.",
            "SHA-256 values support local integrity checks; they are not a certified chain of custody.",
            "Secrets are redacted in this export; originals are retained locally.",
        ],
    }
    return redact_obj(export)


def render_html(export: dict) -> str:
    return jinja_env().get_template("report.html").render(x=export)


def alerts_csv(alerts: list[dict]) -> str:
    buf = io.StringIO()
    cols = ["alert_id", "case_id", "rule_id", "rule_version", "first_time", "last_time", "severity", "confidence", "disposition",
            "automation", "llm", "framework", "purpose", "what", "group", "event_count", "evidence_refs"]
    w = csv.writer(buf)
    w.writerow(cols)
    for a in alerts:
        row = [a["alert_id"], a.get("case_id"), a["rule_id"], a["rule_version"], a["first_time"], a["last_time"],
               a["threat"]["severity"], a["confidence"], a["disposition"], a["automation"]["level"], a["llm"]["level"],
               a["framework"]["level"], a["purpose"]["hypothesis"], a["what"],
               json.dumps(a["group"], sort_keys=True), a["event_count"], " ".join(a["evidence_refs"][:20])]
        w.writerow([csv_safe(redact(str(v))) for v in row])
    return buf.getvalue()


def write_report(store: Store, settings: Settings, case_ref: str, fmt: str, output: Path, run_id: str | None = None) -> Path:
    exp = build_case_export(store, settings, case_ref, run_id=run_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        output.write_text(json.dumps(exp, indent=2, sort_keys=True, default=str), encoding="utf-8")
    elif fmt == "html":
        output.write_text(render_html(exp), encoding="utf-8")
    elif fmt == "csv":
        output.write_text(alerts_csv([a for a in exp["alerts"] if a.get("current", True)]), encoding="utf-8")
    else:
        raise ValueError("format must be json, html or csv")
    return output
