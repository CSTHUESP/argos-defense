"""Entity extraction with explicit key strength.

Strong keys: tenant+identity, host+ProcessGuid, tenant/host+session id.
Weak keys: context-free usernames, host+pid. IP addresses are infrastructure
entities: sharing an IP never merges accounts or operators; such co-occurrence
is stored as an *inferred* relationship explicitly labelled as not identity.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from itertools import combinations


def _eid(case_id: str, etype: str, key: str) -> str:
    return "ent-" + hashlib.sha256(f"{case_id}|{etype}|{key}".encode()).hexdigest()[:20]


def entities_for_event(ev: dict) -> list[tuple[str, str, str, str, str]]:
    """Return (etype, key, strength, display, role) tuples for one event."""
    out = []
    tenant = ev.get("tenant_id")
    host = (ev.get("host") or "").lower() or None
    user = ev.get("user")
    if user:
        u = user.lower()
        if tenant:
            out.append(("account", f"{tenant}|{u}", "strong", f"{user} @ tenant {tenant}", "actor"))
        elif "\\" in u or "@" in u:
            scope = host if "\\" in u and host and u.split("\\")[0] in ("nt authority", host.split(".")[0]) else ""
            out.append(("account", f"{scope}|{u}", "strong", user, "actor"))
        else:
            out.append(("account", f"?|{u}", "weak", f"{user} (no tenant/domain context)", "actor"))
    if ev.get("app_id"):
        out.append(("service_principal", f"{tenant or '?'}|{ev['app_id']}", "strong" if tenant else "weak",
                    f"app {ev['app_id']}" + (f" @ {tenant}" if tenant else ""), "actor"))
    if tenant:
        out.append(("tenant", tenant, "strong", tenant, "context"))
    if host:
        out.append(("device", host, "strong", ev.get("host"), "location"))
    if ev.get("process_guid") and host:
        out.append(("process", f"{host}|{ev['process_guid']}", "strong",
                    f"{(ev.get('process_image') or '?').split(chr(92))[-1].split('/')[-1]} {ev['process_guid']}", "process"))
    elif ev.get("process_id") is not None and host:
        out.append(("process", f"{host}|pid:{ev['process_id']}", "weak", f"pid {ev['process_id']} on {host}", "process"))
    if ev.get("session_id"):
        scope = tenant or host or "?"
        out.append(("session", f"{scope}|{ev['session_id']}", "strong" if scope != "?" else "weak", ev["session_id"], "session"))
    for f, role in (("src_ip", "source_ip"), ("dst_ip", "destination_ip")):
        if ev.get(f):
            out.append(("ip_address", ev[f], "infrastructure", ev[f], role))
    dom = ev.get("dns_query") or ev.get("http_host")
    if dom:
        out.append(("domain", dom.lower().rstrip("."), "infrastructure", dom.lower().rstrip("."), "destination_domain"))
    if ev.get("resource"):
        out.append(("resource", ev["resource"], "strong", ev["resource"], "target"))
    return out


def build_entities(case_id: str, events: list[dict]):
    ents: dict[str, dict] = {}
    rels: dict[tuple, dict] = {}
    links = []
    ip_accounts: dict[str, set] = defaultdict(set)

    def rel(src, dst, name, basis, ev_id):
        k = (src, dst, name)
        r = rels.get(k)
        if r is None:
            rels[k] = {"src": src, "dst": dst, "rel": name, "basis": basis, "event_count": 1, "sample_event": ev_id}
        else:
            r["event_count"] += 1

    for ev in events:
        found = {}
        for etype, key, strength, display, role in entities_for_event(ev):
            eid = _eid(case_id, etype, key)
            e = ents.get(eid)
            if e is None:
                ents[eid] = e = {"entity_id": eid, "etype": etype, "ekey": key, "strength": strength, "display": display,
                                 "event_count": 0, "first_time": ev["event_time"], "last_time": ev["event_time"]}
            e["event_count"] += 1
            e["last_time"] = max(e["last_time"], ev["event_time"])
            e["first_time"] = min(e["first_time"], ev["event_time"])
            links.append((ev["event_id"], eid, role))
            found.setdefault(etype + ":" + role, eid)
        g = found.get
        actor = g("account:actor") or g("service_principal:actor")
        if actor and g("ip_address:source_ip"):
            rel(actor, g("ip_address:source_ip"), "observed_from_ip", "observed", ev["event_id"])
            ip_accounts[g("ip_address:source_ip")].add(actor)
        if actor and g("session:session"):
            rel(actor, g("session:session"), "has_session", "observed", ev["event_id"])
        if actor and g("resource:target"):
            rel(actor, g("resource:target"), f"acted_on:{ev.get('action') or 'unknown'}", "observed", ev["event_id"])
        if g("process:process") and g("device:location"):
            rel(g("process:process"), g("device:location"), "runs_on", "observed", ev["event_id"])
        if actor and g("device:location"):
            rel(actor, g("device:location"), "seen_on_device", "observed", ev["event_id"])
        if ev.get("parent_process_guid") and ev.get("host") and g("process:process"):
            pid = _eid(case_id, "process", f"{ev['host'].lower()}|{ev['parent_process_guid']}")
            if pid not in ents:
                ents[pid] = {"entity_id": pid, "etype": "process", "ekey": f"{ev['host'].lower()}|{ev['parent_process_guid']}",
                             "strength": "strong", "display": f"{(ev.get('parent_image') or '?').split(chr(92))[-1]} {ev['parent_process_guid']}",
                             "event_count": 0, "first_time": ev["event_time"], "last_time": ev["event_time"]}
            rel(g("process:process"), pid, "child_of", "observed", ev["event_id"])
        if g("ip_address:source_ip") and g("ip_address:destination_ip"):
            rel(g("ip_address:source_ip"), g("ip_address:destination_ip"), "connected_to", "observed", ev["event_id"])
        if (g("device:location") or g("ip_address:source_ip")) and g("domain:destination_domain"):
            rel(g("device:location") or g("ip_address:source_ip"), g("domain:destination_domain"), "contacted_domain", "observed", ev["event_id"])
    # Shared IP: inferred co-occurrence, explicitly NOT identity.
    for ip, accts in ip_accounts.items():
        for a, b in list(combinations(sorted(accts), 2))[:200]:
            rels[(a, b, "shares_source_ip_with")] = {"src": a, "dst": b, "rel": "shares_source_ip_with",
                                                    "basis": "inferred_cooccurrence_not_identity", "event_count": 0, "sample_event": None}
    return list(ents.values()), list(rels.values()), links
