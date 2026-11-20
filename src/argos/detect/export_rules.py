"""Export ARGOS rules to Sigma and Splunk SPL where a faithful translation exists.

Supported:
  * Sigma: rules with aggregate `each`, a single Sigma log source and predicates on fields
    that have a Sigma field mapping (process/file/network/DNS endpoint events, proxy HTTP).
  * SPL:   rules with aggregate `each`, and `threshold` rules without a median-timing
    condition (sliding event-time windows via `streamstats time_window=`).
Not exported (reported with the reason): `sequence` (ordered temporal correlation),
`baseline` (prior-history comparison), IOC lookups, timing medians, and fields without a
mapping. Output is syntax/structure checked here; it has NOT been executed in Splunk or a
Sigma backend.

SPL field names: the ARGOS normalized schema (e.g. data indexed from ARGOS JSON exports or
mapped with a Splunk field alias). See docs/RULE_EXPORTS.md.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import yaml

from argos.config import Settings
from argos.detect.rules import Predicate, load_rules

NS = uuid.UUID("6f1d3a52-0c55-4c8e-9a40-4f1f0f0e2a77")


class Unsupported(Exception):
    pass


# ----------------------------------------------------------------------------- Sigma
SIGMA_LOGSOURCE = {
    ("managed_endpoint", "process_start"): {"category": "process_creation"},
    ("managed_endpoint", "file_create"): {"category": "file_event"},
    ("managed_endpoint", "network_connection"): {"category": "network_connection"},
    ("managed_endpoint", "dns"): {"category": "dns_query"},
    ("victim_network", "http"): {"category": "proxy"},
    ("victim_network", "dns"): {"category": "dns"},
}
SIGMA_FIELDS = {
    "process_creation": {"process_image": "Image", "parent_image": "ParentImage", "process_command_line": "CommandLine",
                         "user": "User", "process_name": ("Image", "basename"), "parent_name": ("ParentImage", "basename")},
    "file_event": {"file_path": "TargetFilename", "process_image": "Image", "file_ext": ("TargetFilename", "suffix"),
                   "process_name": ("Image", "basename")},
    "network_connection": {"dst_ip": "DestinationIp", "dst_port": "DestinationPort", "src_ip": "SourceIp", "process_image": "Image"},
    "dns_query": {"dns_query": "QueryName", "domain": "QueryName", "process_image": "Image"},
    "proxy": {"http_uri": "c-uri", "http_host": "cs-host", "http_user_agent": "c-useragent", "http_status": "sc-status",
              "src_ip": "c-ip", "http_method": "cs-method"},
    "dns": {"dns_query": "query", "domain": "query"},
}
SIGMA_MOD = {"contains": "contains", "startswith": "startswith", "endswith": "endswith", "regex": "re", "cidr": "cidr",
             "gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte"}


def _preds(cond) -> list:
    if isinstance(cond, Predicate):
        return [cond]
    if cond.all is not None and all(isinstance(c, Predicate) for c in cond.all):
        return list(cond.all)
    raise Unsupported("condition shape (any/not/nested) not exported to Sigma")


def to_sigma(rule) -> dict:
    if rule.aggregate.type != "each":
        raise Unsupported(f"aggregate '{rule.aggregate.type}' (temporal/statistical correlation) not exported to Sigma")
    preds = _preds(rule.select)
    kinds = [p for p in preds if p.field == "event_kind"]
    if len(kinds) != 1 or kinds[0].op != "eq":
        raise Unsupported("needs exactly one event_kind == <kind> predicate to choose a Sigma log source")
    vant = rule.observation_vantage
    if len(vant) != 1 or (vant[0], kinds[0].value) not in SIGMA_LOGSOURCE:
        raise Unsupported(f"no Sigma log source for vantage {vant} / kind {kinds[0].value}")
    ls = SIGMA_LOGSOURCE[(vant[0], kinds[0].value)]
    fmap = SIGMA_FIELDS[ls["category"]]
    sel = {}
    for p in preds:
        if p.field == "event_kind":
            continue
        if p.field not in fmap:
            raise Unsupported(f"field '{p.field}' has no Sigma mapping for {ls['category']}")
        tgt = fmap[p.field]
        vals = p.value if isinstance(p.value, list) else [p.value]
        if isinstance(tgt, tuple):  # derived basename/suffix -> endswith on the full path
            field, how = tgt
            if p.op not in ("eq", "in"):
                raise Unsupported(f"operator {p.op} on derived field {p.field}")
            if how == "basename":
                sel[f"{field}|endswith"] = [f"\\{v}" for v in vals] + [f"/{v}" for v in vals]
            else:
                sel[f"{field}|endswith"] = list(vals)
            continue
        if p.op in ("eq", "in"):
            sel[tgt] = vals if len(vals) > 1 else vals[0]
        elif p.op in SIGMA_MOD:
            sel[f"{tgt}|{SIGMA_MOD[p.op]}"] = vals if len(vals) > 1 else vals[0]
        elif p.op == "exists":
            sel[f"{tgt}|exists"] = True
        else:
            raise Unsupported(f"operator {p.op} not exported to Sigma")
    return {
        "title": rule.title, "id": str(uuid.uuid5(NS, rule.id)), "status": "experimental" if rule.status == "experimental" else "test",
        "description": rule.description.strip() + f"\n(Exported from ARGOS {rule.id} v{rule.version}; not executed in a Sigma backend.)",
        "references": [s for s in rule.sources if s.startswith("http")] or None,
        "author": "ARGOS Defense rule export", "logsource": ls,
        "detection": {"selection": sel, "condition": "selection"},
        "falsepositives": rule.false_positives or ["unknown"],
        "level": {"informational": "informational", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}[rule.severity],
        "tags": [f"argos.{rule.family}", f"argos.rule.{rule.id.lower()}"],
    }


# ----------------------------------------------------------------------------- SPL
DERIVED_SPL = {
    "process_name": 'eval process_name=lower(replace(process_image, "^.*[\\\\\\\\/]", ""))',
    "parent_name": 'eval parent_name=lower(replace(parent_image, "^.*[\\\\\\\\/]", ""))',
    "file_ext": 'eval file_ext=lower(replace(file_path, "^.*(\\\\.[^.\\\\\\\\/]+)$", "\\1"))',
    "domain": 'eval domain=lower(coalesce(dns_query, http_host))',
    "uri_path": 'eval uri_path=mvindex(split(http_uri, "?"), 0)',
    "http_status_class": 'eval http_status_class=substr(tostring(http_status), 1, 1)."xx"',
    "remote": 'eval remote=coalesce(dst_ip, lower(coalesce(dns_query, http_host)), src_ip)',
}


def _q(v) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _rx(v: str) -> str:
    return re.escape(str(v).lower())


def _expr(cond, used: set) -> str:
    if not isinstance(cond, Predicate):
        if cond.all is not None:
            return "(" + " AND ".join(_expr(c, used) for c in cond.all) + ")"
        if cond.any is not None:
            return "(" + " OR ".join(_expr(c, used) for c in cond.any) + ")"
        return "NOT (" + _expr(cond.not_, used) + ")"
    p = cond
    f = p.field
    if f in ("dst_is_private", "src_is_private", "proc_link"):
        raise Unsupported(f"derived field {f} not exported")
    if f in DERIVED_SPL:
        used.add(f)
    vals = p.value if isinstance(p.value, list) else [p.value]
    lf = f"lower(tostring({f}))"
    if p.op == "eq":
        return f"{lf}={_q(str(p.value).lower())}" if not isinstance(p.value, (int, float)) else f"tonumber({f})={p.value}"
    if p.op == "ne":
        return f"({lf}!={_q(str(p.value).lower())} OR isnull({f}))"
    if p.op in ("in", "not_in"):
        e = f"in({lf}, {', '.join(_q(str(v).lower()) for v in vals)})"
        return e if p.op == "in" else f"(NOT {e} OR isnull({f}))"
    if p.op in ("contains", "not_contains"):
        e = "(" + " OR ".join(f"match({lf}, {_q(_rx(v))})" for v in vals) + ")"
        return e if p.op == "contains" else f"(NOT {e} OR isnull({f}))"
    if p.op == "startswith":
        return "(" + " OR ".join(f"match({lf}, {_q('^' + _rx(v))})" for v in vals) + ")"
    if p.op == "endswith":
        return "(" + " OR ".join(f"match({lf}, {_q(_rx(v) + '$')})" for v in vals) + ")"
    if p.op == "regex":
        return f"match(tostring({f}), {_q('(?i)' + p.value)})"
    if p.op in ("gt", "gte", "lt", "lte"):
        return f"tonumber({f}){ {'gt': '>', 'gte': '>=', 'lt': '<', 'lte': '<='}[p.op] }{float(p.value):g}"
    if p.op == "exists":
        return f"(isnotnull({f}) AND {f}!=\"\")"
    if p.op == "not_exists":
        return f"(isnull({f}) OR {f}=\"\")"
    if p.op in ("cidr", "not_cidr"):
        e = "(" + " OR ".join(f"cidrmatch({_q(c)}, {f})" for c in vals) + ")"
        return e if p.op == "cidr" else f"NOT {e}"
    raise Unsupported(f"operator {p.op} (e.g. IOC lookup) not exported to SPL")


def to_spl(rule) -> str:
    agg = rule.aggregate
    if agg.type not in ("each", "threshold"):
        raise Unsupported(f"aggregate '{agg.type}' (ordered sequence / history baseline) not exported to SPL")
    if agg.max_median_interarrival_s is not None:
        raise Unsupported("median inter-arrival condition has no faithful streamstats equivalent")
    used: set = set()
    where = _expr(rule.select, used)
    if agg.distinct_field in DERIVED_SPL:
        used.add(agg.distinct_field)
    req_fields = list(dict.fromkeys(f for f in rule.required_telemetry + rule.group_by if f != "event_time"))
    for f in req_fields:
        if f in DERIVED_SPL:
            used.add(f)
    req = " AND ".join(f"isnotnull({f})" for f in req_fields)
    ratio = _expr(agg.ratio_where, used) if agg.ratio_where is not None else None
    lines = [f"`comment(\"ARGOS {rule.id} v{rule.version}: {rule.title.replace(chr(34), '')} - exported, not executed in Splunk\")`",
             f'search observation_vantage IN ({", ".join(_q(v) for v in rule.observation_vantage)})']
    lines += [f"| {DERIVED_SPL[d]}" for d in sorted(used | {g for g in rule.group_by if g in DERIVED_SPL})]
    lines.append(f"| where {where}" + (f" AND {req}" if req else ""))
    by = " ".join(rule.group_by)
    if agg.type == "each":
        lines.append(f"| table _time {by} event_kind action outcome evidence_ref".replace("  ", " "))
        return "\n".join(lines)
    if ratio:
        lines.append(f"| eval argos_ratio_hit=if({ratio}, 1, 0)")
    stats = ["count as argos_count"]
    if agg.distinct_field:
        stats.append(f"dc({agg.distinct_field}) as argos_distinct")
    if ratio:
        stats.append("sum(argos_ratio_hit) as argos_ratio_hits")
    lines.append("| sort 0 _time")
    lines.append(f"| streamstats time_window={rule.window_s}s {', '.join(stats)}" + (f" by {by}" if by else ""))
    conds = [f"argos_count>={agg.min_count}"]
    if agg.distinct_field:
        conds.append(f"argos_distinct>={agg.min_distinct}")
    if ratio:
        conds.append(f"argos_ratio_hits/argos_count>={agg.min_ratio}")
    lines.append("| where " + " AND ".join(conds))
    lines.append(f"| stats min(_time) as first_time max(_time) as last_time max(argos_count) as events" + (f" by {by}" if by else ""))
    return "\n".join(lines)


def check_spl(text: str) -> list[str]:
    """Structural checks only (balanced quotes/parentheses/backticks, pipes); not a Splunk parser."""
    errs = []
    body = re.sub(r'\\.', "", text)
    if body.count('"') % 2:
        errs.append("unbalanced double quotes")
    depth = 0
    in_q = False
    for ch in body:
        if ch == '"':
            in_q = not in_q
        elif not in_q:
            depth += ch == "("
            depth -= ch == ")"
            if depth < 0:
                errs.append("unbalanced parentheses")
                break
    if depth > 0:
        errs.append("unbalanced parentheses")
    if body.count("`") % 2:
        errs.append("unbalanced backticks")
    if "||" in text.replace(" OR ", ""):
        errs.append("empty pipeline stage")
    return errs


def check_sigma(doc: dict) -> list[str]:
    errs = [f"missing {k}" for k in ("title", "id", "logsource", "detection", "level", "status") if k not in doc]
    det = doc.get("detection", {})
    if "condition" not in det or not any(k != "condition" for k in det):
        errs.append("detection needs a selection and a condition")
    yaml.safe_load(yaml.safe_dump(doc))
    return errs


def export_all(settings: Settings, out: Path, target: str = "all") -> dict:
    rules, rules_hash, errors = load_rules(settings.rules_dir, settings.config_dir / "rule_overrides.yaml")
    if errors:
        raise ValueError("; ".join(errors))
    out.mkdir(parents=True, exist_ok=True)
    report = {"rules_hash": rules_hash, "executed_in_splunk": False, "executed_in_sigma_backend": False, "rules": {}}
    for r in rules:
        entry = {}
        if target in ("sigma", "all"):
            try:
                doc = to_sigma(r)
                errs = check_sigma(doc)
                if errs:
                    raise Unsupported("; ".join(errs))
                (out / "sigma").mkdir(exist_ok=True)
                (out / "sigma" / f"{r.id}.yml").write_text(yaml.safe_dump({k: v for k, v in doc.items() if v is not None}, sort_keys=False, allow_unicode=True))
                entry["sigma"] = "exported"
            except Unsupported as exc:
                entry["sigma"] = f"unsupported: {exc}"
        if target in ("spl", "all"):
            try:
                spl = to_spl(r)
                errs = check_spl(spl)
                if errs:
                    raise Unsupported("structural check failed: " + "; ".join(errs))
                (out / "spl").mkdir(exist_ok=True)
                (out / "spl" / f"{r.id}.spl").write_text(spl + "\n")
                entry["spl"] = "exported"
            except Unsupported as exc:
                entry["spl"] = f"unsupported: {exc}"
        report["rules"][r.id] = entry
    report["summary"] = {k: {"exported": sum(1 for e in report["rules"].values() if e.get(k) == "exported"),
                             "unsupported": sum(1 for e in report["rules"].values() if str(e.get(k, "")).startswith("unsupported"))}
                         for k in ("sigma", "spl") if target in (k, "all")}
    (out / "export-report.json").write_text(json.dumps(report, indent=2))
    return report
