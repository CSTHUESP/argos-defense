"""Semantic fidelity of exported Sigma rules (feature D).

No Sigma backend or SIEM is available, so this test implements the subset of Sigma detection
semantics the exporter emits (field|modifier keys, AND across keys, OR within value lists,
case-insensitive string comparison, `exists`, `re`, `cidr`) and compares it, event by event, with
the NATIVE ARGOS predicate on the same records. Records are mapped to Sigma field names with the
exporter's own field table (Sysmon/ECS-like names). Divergences are either fixed or listed in
KNOWN_DIVERGENCES and documented in docs/RULE_EXPORTS.md. This is NOT backend execution.
"""
import ipaddress
import re

import pytest

from argos.detect.export_rules import SIGMA_FIELDS, SIGMA_LOGSOURCE, Unsupported, to_sigma
from argos.detect.ops import Evaluator, derive
from argos.detect.rules import load_rules
from conftest import RULES

PATHS = ["C:\\Windows\\System32\\cmd.exe", "C:\\WINDOWS\\SYSTEM32\\CMD.EXE", "/bin/bash", "/usr/bin/nmap", "C:\\Tools\\nmap.exe",
         "C:\\inetpub\\w3wp.exe", "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "/usr/sbin/nginx", "/opt/artex/bin/artex", "C:\\x\\ARTEX.exe",
         "C:\\Users\\a\\Downloads\\notcmd.exe.txt", "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", "/usr/bin/python3", "/usr/local/bin/node",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "/usr/bin/sqlmap", "C:\\Temp\\mimikatz.exe", "C:\\Temp\\Mimikatz.EXE"]
FILES = ["C:\\Users\\a\\_ca\\mitmproxy-ca-cert.pem", "/home/a/.artex/_ca/mitmproxy-ca-cert.pem", "/x/_CA/mitmproxy-ca-cert.pem", "C:\\Users\\a\\.mitmproxy\\mitmproxy-ca.pem", "/home/a/.mitmproxy/mitmproxy-ca-cert.pem", "/tmp/report.pdf", "C:\\x\\shell.aspx",
         "/var/www/html/up.php", "C:\\ProgramData\\artex\\artex.db", "/home/a/notes.txt"]


def corpus():
    out = []
    for i, img in enumerate(PATHS):
        for j, parent in enumerate(PATHS[::3]):
            out.append({"event_kind": "process_start", "observation_vantage": "managed_endpoint", "host": "h", "process_image": img,
                        "parent_image": parent, "process_command_line": f"{img} -x {i}", "user": "CORP\\a"})
    for f in FILES:
        for img in PATHS[:6]:
            out.append({"event_kind": "file_create", "observation_vantage": "managed_endpoint", "host": "h", "file_path": f, "process_image": img})
    return [derive(e) for e in out]


def to_sigma_record(ev, category):
    rec = {}
    for native, tgt in SIGMA_FIELDS[category].items():
        if isinstance(tgt, tuple):
            continue
        if ev.get(native) is not None:
            rec[tgt] = ev[native]
    return rec


def _cmp(mods, have, want):
    if have is None:
        return False
    if "re" in mods:
        return re.search(want, str(have), re.IGNORECASE if "i" in mods else 0) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(have) in ipaddress.ip_network(want, strict=False)
        except ValueError:
            return False
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        a, b = float(have), float(want)
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[[m for m in mods if m in ("gt", "gte", "lt", "lte")][0]]
    h, w = str(have).lower(), str(want).lower()
    if "contains" in mods:
        return w in h
    if "startswith" in mods:
        return h.startswith(w)
    if "endswith" in mods:
        return h.endswith(w)
    return h == w


def sigma_match(selection: dict, rec: dict) -> bool:
    for key, want in selection.items():
        field, *mods = key.split("|")
        if "exists" in mods:
            if (rec.get(field) is not None) != bool(want):
                return False
            continue
        vals = want if isinstance(want, list) else [want]
        if "all" in mods:
            if not all(_cmp(mods, rec.get(field), v) for v in vals):
                return False
        elif not any(_cmp(mods, rec.get(field), v) for v in vals):
            return False
    return True


# Native basename predicates also match a bare file name without any directory ("cmd.exe"),
# which Sigma's `|endswith: ['\\cmd.exe', '/cmd.exe']` does not. Sysmon Image/ParentImage values are
# always full paths, so the corpus uses full paths; the bare-name case is documented.
KNOWN_DIVERGENCES: dict = {}


def exported():
    rules, _, errors = load_rules(RULES)
    assert not errors
    out = []
    for r in rules:
        try:
            out.append((r, to_sigma(r)))
        except Unsupported:
            continue
    return out


@pytest.mark.parametrize("rule,doc", exported(), ids=lambda x: getattr(x, "id", ""))
def test_exported_sigma_agrees_with_native_select(rule, doc):
    ev_fn = Evaluator()
    cat = doc["logsource"]["category"]
    kind = [k for (v, k), ls in SIGMA_LOGSOURCE.items() if ls["category"] == cat][0]
    events = [e for e in corpus() if e["event_kind"] == kind]
    assert events
    native_hits = sigma_hits = 0
    disagreements = []
    for e in events:
        n = ev_fn.match(rule.select, e)
        s = sigma_match(doc["detection"]["selection"], to_sigma_record(e, cat))
        native_hits += n
        sigma_hits += s
        if n != s:
            disagreements.append((e.get("process_image") or e.get("file_path"), e.get("parent_image"), n, s))
    assert not disagreements, (rule.id, disagreements[:5])
    assert native_hits > 0, f"corpus has no positive case for {rule.id}; add one"
    assert native_hits < len(events), f"corpus has no negative case for {rule.id}"


def test_sequence_and_baseline_rules_are_rejected_not_approximated():
    rules, _, _ = load_rules(RULES)
    for r in rules:
        if r.aggregate.type in ("sequence", "baseline"):
            with pytest.raises(Unsupported):
                to_sigma(r)
