"""Rule evaluation: selection, grouping, event-time windows and aggregation.

Events are always processed in event-time order regardless of file order.
Baselines use only events strictly before the evaluated window.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict

from argos.detect.ops import Evaluator
from argos.detect.rules import Rule

MAX_EVIDENCE = 200


class Match:
    __slots__ = ("rule", "group", "events", "steps", "traces", "baseline", "extra")

    def __init__(self, rule, group, events, steps=None, traces=None, baseline=None):
        self.rule, self.group, self.events = rule, group, events
        self.steps = steps or {}
        self.traces = traces or {}
        self.baseline = baseline
        self.extra = {}


# Fields whose specification allows case-insensitive comparison (DNS names, account/UPN names,
# directory tenant ids, derived basenames). Every other identifier - session ids, tool call ids,
# process GUIDs, application ids, correlation ids - is opaque and compared exactly.
CASE_INSENSITIVE_FIELDS = {"user", "host", "http_host", "dns_query", "domain", "tenant_id", "process_name",
                           "parent_name", "file_ext", "remote"}


def key_value(field: str, v):
    if v is None or v == "":
        return None
    if isinstance(v, str) and field in CASE_INSENSITIVE_FIELDS:
        return v.lower()
    return v


def _group_key(rule: Rule, ev: dict):
    vals = []
    for f in rule.group_by:
        v = key_value(f, ev.get(f))
        if v is None:
            return None
        vals.append(v)
    return tuple(vals)


def evaluate_rule(rule: Rule, events: list[dict], ev_fn: Evaluator, cov_ctx=None) -> tuple[list[Match], dict]:
    stats = {"selected": 0, "missing_required_telemetry": 0, "ungroupable": 0, "groups": 0, "matches": 0}
    groups: dict[tuple, list] = defaultdict(list)
    first_trace: dict[str, list] = {}
    for ev in events:
        if ev["observation_vantage"] not in rule.observation_vantage:
            continue
        tr = []
        if not ev_fn.match(rule.select, ev, tr):
            continue
        if any(ev.get(f) in (None, "") for f in rule.required_telemetry):
            stats["missing_required_telemetry"] += 1
            continue
        stats["selected"] += 1
        k = _group_key(rule, ev)
        if k is None:
            stats["ungroupable"] += 1
            continue
        groups[k].append(ev)
        first_trace.setdefault(ev["event_id"], tr)
    stats["groups"] = len(groups)
    out: list[Match] = []
    agg = rule.aggregate
    for k, evs in groups.items():
        group = dict(zip(rule.group_by, k))
        if agg.type == "each":
            out += _each(rule, group, evs, first_trace)
        elif agg.type == "threshold":
            out += _threshold(rule, group, evs, ev_fn, first_trace)
        elif agg.type == "sequence":
            out += _sequence(rule, group, evs, ev_fn)
        elif agg.type == "baseline":
            out += _baseline(rule, group, evs, first_trace, cov_ctx)
    stats["matches"] = len(out)
    return out, stats


def _each(rule, group, evs, traces):
    out, cur = [], []
    for ev in evs:
        if cur and ev["event_epoch"] - cur[-1]["event_epoch"] > rule.window_s:
            out.append(Match(rule, group, cur, traces={"select": traces.get(cur[0]["event_id"], [])}))
            cur = []
        cur.append(ev)
    if cur:
        out.append(Match(rule, group, cur, traces={"select": traces.get(cur[0]["event_id"], [])}))
    return out


def _window_ok(agg, win, ratio_hits, distinct: Counter) -> bool:
    if len(win) < agg.min_count:
        return False
    if agg.distinct_field and len(distinct) < agg.min_distinct:
        return False
    if agg.ratio_where is not None and (ratio_hits / len(win)) < agg.min_ratio:
        return False
    if agg.max_median_interarrival_s is not None:
        gaps = [b["event_epoch"] - a["event_epoch"] for a, b in zip(win, win[1:])]
        if not gaps or statistics.median(gaps) > agg.max_median_interarrival_s:
            return False
    return True


def _threshold(rule, group, evs, ev_fn, traces):
    agg = rule.aggregate
    ratio_flags = [ev_fn.match(agg.ratio_where, e) if agg.ratio_where is not None else False for e in evs]
    episodes = []  # (l, r) index ranges
    left, ratio_hits = 0, 0
    distinct: Counter = Counter()
    for right, ev in enumerate(evs):
        ratio_hits += ratio_flags[right]
        if agg.distinct_field:
            distinct[ev.get(agg.distinct_field)] += 1
        while ev["event_epoch"] - evs[left]["event_epoch"] > rule.window_s:
            ratio_hits -= ratio_flags[left]
            if agg.distinct_field:
                dv = evs[left].get(agg.distinct_field)
                distinct[dv] -= 1
                if distinct[dv] <= 0:
                    del distinct[dv]
            left += 1
        if agg.distinct_field:
            distinct.pop(None, None)
        if _window_ok(agg, evs[left:right + 1], ratio_hits, distinct):
            if episodes and left <= episodes[-1][1] + 1:
                episodes[-1] = (episodes[-1][0], right)
            else:
                episodes.append((left, right))
    out = []
    for l, r in episodes:
        win = evs[l:r + 1]
        m = Match(rule, group, win, traces={"select": traces.get(win[0]["event_id"], [])})
        m.extra = {"count": len(win), "distinct": len({e.get(agg.distinct_field) for e in win}) if agg.distinct_field else None,
                   "ratio": (sum(ratio_flags[l:r + 1]) / len(win)) if agg.ratio_where is not None else None}
        out.append(m)
    return out


def _sequence(rule, group, evs, ev_fn):
    steps = rule.aggregate.steps
    flags, resets = [], []
    for ev in evs:
        row, rrow = [], []
        for st in steps:
            tr = []
            row.append(tr if ev_fn.match(st.where, ev, tr) else None)
            rrow.append(st.reset_where is not None and ev_fn.match(st.reset_where, ev))
        flags.append(row)
        resets.append(rrow)
    out, i, n = [], 0, len(evs)
    while i < n:
        if flags[i][0] is None:
            i += 1
            continue
        start_t = evs[i]["event_epoch"]
        step_events, step_traces, j, ok = {}, {}, i, True
        for si, st in enumerate(steps):
            got, distinct = [], set()
            allowed = None
            if st.same_as is not None:
                ref = step_events.get(st.same_as.step, [])
                allowed = {key_value(st.same_as.field, e.get(st.same_as.step_field)) for e in ref} - {None}
            while j < n and evs[j]["event_epoch"] - start_t <= rule.window_s:
                if resets[j][si] and flags[j][si] is None:
                    got, distinct = [], set()  # run interrupted
                    j += 1
                    continue
                if flags[j][si] is not None and allowed is not None and key_value(st.same_as.field, evs[j].get(st.same_as.field)) not in allowed:
                    j += 1  # e.g. executed tool differs from the requested tool: not part of this chain
                    continue
                if flags[j][si] is not None:
                    got.append(evs[j])
                    if st.distinct_field:
                        distinct.add(evs[j].get(st.distinct_field))
                    step_traces.setdefault(st.name, flags[j][si])
                j += 1
                if len(got) >= st.min_count and (not st.min_distinct or len(distinct) >= st.min_distinct):
                    # step satisfied; following steps must come strictly after (event time order)
                    break
            if len(got) < st.min_count or (st.min_distinct and len(distinct) < st.min_distinct):
                ok = False
                break
            step_events[st.name] = got
        if ok:
            allev = sorted({e["event_id"]: e for s in step_events.values() for e in s}.values(), key=lambda e: e["event_epoch"])
            out.append(Match(rule, group, allev, steps=step_events, traces=step_traces))
            i = j
        else:
            i += 1
    return out


def _baseline(rule, group, evs, traces, cov_ctx):
    """Compare the evaluated window with the entity's OWN prior windows - but only windows in which
    collection is evidenced (analyst-declared coverage, or other records of the same entity from the
    rule's vantage). Windows without such evidence are gaps, never zero-count history."""
    agg = rule.aggregate
    out = []
    for m in _threshold(rule, group, evs, Evaluator(), traces):
        start = m.events[0]["event_epoch"]
        w = rule.window_s
        hist_counts, kinds, gaps = [], Counter(), 0
        k = 1
        while k * w <= agg.history_lookback_s:
            ws, we = start - k * w, start - (k - 1) * w
            status = cov_ctx.window_status(rule, group, ws, we) if cov_ctx is not None else "gap"
            if status == "gap":
                gaps += 1
            else:
                kinds[status] += 1
                hist_counts.append(sum(1 for e in evs if ws <= e["event_epoch"] < we))
            k += 1
        info = {"reference": "observed_history", "history_windows": len(hist_counts), "window_s": w,
                "covered_window_basis": dict(kinds), "gap_windows_excluded": gaps,
                "min_history_windows": agg.min_history_windows, "factor": agg.factor,
                "current_count": len(m.events), "history_max": max(hist_counts) if hist_counts else None,
                "history_counts": hist_counts[:50], "uses_only_prior_events": True,
                "note": "windows count only when collection for this entity is evidenced (declared coverage or the entity's own records)"}
        if len(hist_counts) < agg.min_history_windows:
            info["status"] = "insufficient_baseline"
            m.baseline = info
            out.append(m)
        elif len(m.events) > agg.factor * max(max(hist_counts), 1):
            info["status"] = "exceeds_history"
            m.baseline = info
            out.append(m)
    return out
