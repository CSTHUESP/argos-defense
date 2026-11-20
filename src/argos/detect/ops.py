"""Restricted predicate evaluation over normalized events (no eval)."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache


@lru_cache(maxsize=512)
def _re(p: str):
    return re.compile(p, re.IGNORECASE)


@lru_cache(maxsize=512)
def _net(c: str):
    return ipaddress.ip_network(c, strict=False)


def _ip(v):
    try:
        return ipaddress.ip_address(v)
    except (ValueError, TypeError):
        return None


# "Internal" is an explicit list (RFC 1918, RFC 6598 CGNAT, loopback, link-local, ULA).
# Python's is_private also marks documentation ranges (RFC 5737) as private; ARGOS
# does not, so they behave like external addresses in synthetic data.
INTERNAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
                 "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"]


def is_private(ip: str | None):
    a = _ip(ip)
    if a is None:
        return None
    return any(a.version == _net(c).version and a in _net(c) for c in INTERNAL_NETS)


def derive(ev: dict) -> dict:
    """Add derived fields used by rules. Pure functions of the event."""
    uri = ev.get("http_uri")
    ev["uri_path"] = uri.split("?", 1)[0] if uri else None
    img = ev.get("process_image")
    ev["process_name"] = img.replace("\\", "/").rsplit("/", 1)[-1].lower() if img else None
    pimg = ev.get("parent_image")
    ev["parent_name"] = pimg.replace("\\", "/").rsplit("/", 1)[-1].lower() if pimg else None
    fp = ev.get("file_path")
    ev["file_ext"] = ("." + fp.rsplit(".", 1)[-1].lower()) if fp and "." in fp.replace("\\", "/").rsplit("/", 1)[-1] else None
    ev["dst_is_private"] = is_private(ev.get("dst_ip"))
    ev["src_is_private"] = is_private(ev.get("src_ip"))
    st = ev.get("http_status")
    ev["http_status_class"] = f"{st // 100}xx" if isinstance(st, int) else None
    d = ev.get("dns_query") or ev.get("http_host")
    ev["domain"] = d.lower().rstrip(".") if d else None
    ev["remote"] = ev.get("dst_ip") or ev["domain"] or ev.get("src_ip")
    # Opaque session ids are only meaningful inside the collection source and tenant that issued them.
    sid = ev.get("session_id")
    ev["session_key"] = f"{ev.get('source_type') or '?'}|{ev.get('tenant_id') or '-'}|{sid}" if sid else None
    ev["call_key"] = f"{ev['session_key']}|{ev['tool_call_id']}" if sid and ev.get("tool_call_id") else None
    # proc_link joins an agent/model audit record to the endpoint process it names
    ev["proc_link"] = ev.get("linked_process_guid") if ev.get("event_kind") in ("model_interaction", "tool_execution") else ev.get("process_guid")
    return ev


class Evaluator:
    def __init__(self, iocs=None):
        self.iocs = iocs

    def match(self, cond, ev: dict, trace: list | None = None) -> bool:
        if hasattr(cond, "op"):
            ok = self._pred(cond, ev)
            if ok and trace is not None:
                trace.append({"field": cond.field, "op": cond.op, "value": cond.value, "observed": ev.get(cond.field)})
            return ok
        if cond.all is not None:
            sub = [] if trace is not None else None
            ok = all(self.match(c, ev, sub) for c in cond.all)
            if ok and trace is not None:
                trace.extend(sub)
            return ok
        if cond.any is not None:
            for c in cond.any:
                sub = [] if trace is not None else None
                if self.match(c, ev, sub):
                    if trace is not None:
                        trace.extend(sub)
                    return True
            return False
        return not self.match(cond.not_, ev, None)

    def _pred(self, p, ev) -> bool:
        v = ev.get(p.field)
        op, x = p.op, p.value
        if op == "exists":
            return v is not None and v != ""
        if op == "not_exists":
            return v is None or v == ""
        if v is None:
            return op in ("ne", "not_in", "not_contains")
        if op == "eq":
            return str(v).lower() == str(x).lower() if isinstance(v, str) else v == x
        if op == "ne":
            return str(v).lower() != str(x).lower() if isinstance(v, str) else v != x
        if op in ("in", "not_in"):
            vals = {str(i).lower() for i in x}
            r = str(v).lower() in vals
            return r if op == "in" else not r
        sv = str(v).lower()
        if op == "contains":
            return any(str(i).lower() in sv for i in (x if isinstance(x, list) else [x]))
        if op == "not_contains":
            return not any(str(i).lower() in sv for i in (x if isinstance(x, list) else [x]))
        if op == "startswith":
            return any(sv.startswith(str(i).lower()) for i in (x if isinstance(x, list) else [x]))
        if op == "endswith":
            return any(sv.endswith(str(i).lower()) for i in (x if isinstance(x, list) else [x]))
        if op == "regex":
            return _re(x).search(str(v)[:4096]) is not None
        if op in ("gt", "gte", "lt", "lte"):
            try:
                a, b = float(v), float(x)
            except (TypeError, ValueError):
                return False
            return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
        if op in ("cidr", "not_cidr"):
            a = _ip(v)
            if a is None:
                return False
            inside = any(a.version == _net(c).version and a in _net(c) for c in x)
            return inside if op == "cidr" else not inside
        if op in ("ioc_valid", "ioc_any"):
            if self.iocs is None:
                return False
            hits = self.iocs.lookup(str(v), ev["event_epoch"])
            if op == "ioc_valid":
                hits = [h for h in hits if h["valid_at_event_time"]]
            if hits:
                ev.setdefault("_ioc_hits", []).extend(hits)
            return bool(hits)
        return False
