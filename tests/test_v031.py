"""Regression and preservation tests for the v0.3.1 corrective pass (R01-R09, docs/V031_REMEDIATION.md).
All data is SYNTHETIC. Negative tests fail on v0.3.0 where a defect existed; preservation tests check that
correct behaviour (positive chains, valid baselines, raw access, ...) still works."""
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

import pytest

from argos.analysis import run_analysis
from argos.synthetic import ts
from conftest import ROOT
from test_web_e2e import Client, Server

SENTINELS = ("SYNTH_LIST_SECRET", "SYNTH_NESTED_SECRET", "SYNTH_CSV_SECRET", "SYNTH_CASE_SECRET", "SYNTH_XML_SECRET", "SYNTH_SCALAR_SECRET")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# =============================================================== R01 redaction
def _r01_case(env, cl):
    st, _, body = cl.req("POST", "/api/cases", json.dumps({"name": "r01", "synthetic": True, "description": "api_key: SYNTH_CASE_SECRET"}),
                         {"Content-Type": "application/json"}, bearer=True)
    assert st == 201 and "SYNTH_CASE_SECRET" not in body
    c = env.store.get_case("r01")
    env.ingest(c, [
        {"event_time": ts(0), "event_kind": "dns", "dns_query": "list.example", "token": ["SYNTH_LIST_SECRET"]},
        {"event_time": ts(1), "event_kind": "dns", "dns_query": "nested.example", "credentials": {"value": "SYNTH_NESTED_SECRET"}},
        {"event_time": ts(2), "event_kind": "dns", "dns_query": "scalar.example", "password": "SYNTH_SCALAR_SECRET"},
    ], name="native.jsonl")
    p = env.tmp / "auth.csv"
    p.write_text('_time,user,src_ip,outcome,password,app\n'
                 f'{ts(5)},bob@x,192.0.2.1,failure,SYNTH_CSV_SECRET,"multi\nline, with comma"\n'
                 f'{ts(6)},carol@x,192.0.2.2,success,"SYNTH_CSV_SECRET,quoted",plain\n')
    r = env.ingest(c, p, fmt="splunk_csv", options={"profile": "auth"})
    assert r["accepted"] == 2
    return c, p


def test_r01_real_routes_and_exports_redact_list_nested_csv_and_case_metadata(env):
    token = "t-r01"
    with Server(env.settings, token) as srv:
        cl = Client(srv.port, token)
        c, csvp = _r01_case(env, cl)
        orig_hashes = {i["input_id"]: (i["sha256"], sha(i["stored_path"])) for i in env.store.list_inputs(c["case_id"])}
        st, _, body = cl.req("GET", "/api/cases", bearer=True)
        assert st == 200 and "SYNTH_CASE_SECRET" not in body
        st, _, body = cl.req("POST", f"/api/cases/{c['case_id']}/analyze", bearer=True)
        assert st == 200
        seen_csv = 0
        for ev in env.store.iter_events(c["case_id"]):
            st, _, body = cl.req("GET", f"/api/events/{ev['event_id']}", bearer=True)
            assert st == 200
            assert not [s for s in SENTINELS if s in body], body[:600]
            data = json.loads(body)
            o = data["original"]
            assert o["redacted"] is True and o["record_text"], o
            if o["format"] == "splunk_csv":
                seen_csv += 1
                assert o["redaction"].startswith("structured-csv")
                assert ("bob@x" in o["record_text"]) or ("carol@x" in o["record_text"])  # benign context kept
            # HTML page as well
            st, _, page = cl.req("GET", f"/events/{ev['event_id']}", bearer=True)
            assert st == 200 and not [s for s in SENTINELS if s in page]
            # explicit raw view remains available and labelled
            st, _, raw = cl.req("GET", f"/api/events/{ev['event_id']}?raw=1", bearer=True)
            rd = json.loads(raw)
            assert rd["redacted"] is False and rd["original"]["redaction"].startswith("none (explicit raw view)")
        assert seen_csv == 2
        st, _, raw = cl.req("GET", f"/events/{next(env.store.iter_events(c['case_id']))['event_id']}?raw=1", bearer=True)
        assert "RAW VIEW" in raw
        for fmt in ("json", "html", "csv"):
            st, _, body = cl.req("GET", f"/api/cases/{c['case_id']}/export?format={fmt}", bearer=True)
            assert st == 200 and not [s for s in SENTINELS if s in body], fmt
        # originals untouched
        for iid, (want, _) in orig_hashes.items():
            assert sha(env.store.get_input(iid)["stored_path"]) == want


def test_r01_unparseable_record_is_withheld_not_labelled_redacted(env):
    from argos.evidence.original import redact_record
    text, basis = redact_record("csv_record", "splunk_csv", 'a,b\n"unterminated, SYNTH_CSV_SECRET\n')
    assert text is None or "SYNTH_CSV_SECRET" not in text
    t2, b2 = redact_record("jsonl_line", "native_jsonl", "not json password SYNTH_SCALAR_SECRET")
    assert t2 is None and b2.startswith("unavailable")


def test_r01_redact_obj_policy_keeps_structure_and_context():
    from argos.evidence.redact import redact_obj
    out = redact_obj({"token": ["SYNTH_LIST_SECRET", None], "credentials": {"value": "SYNTH_NESTED_SECRET", "rotated": True},
                      "user": "bob@corp.example", "dns_query": "ok.example", "api_key": None})
    assert out["token"] == ["[REDACTED]", None] and out["credentials"] == {"value": "[REDACTED]", "rotated": True}
    assert out["user"] == "bob@corp.example" and out["dns_query"] == "ok.example" and out["api_key"] is None


def test_r01_xml_data_name_redaction():
    from argos.evidence.original import redact_record
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="Image">C:\\x\\cmd.exe</Data>'
           '<Data Name="Password">SYNTH_XML_SECRET</Data><Data Name="CommandLine">net use /p:SYNTH_XML_SECRET</Data></EventData></Event>')
    t, b = redact_record("xml_element", "sysmon_xml", xml)
    assert t and "SYNTH_XML_SECRET" not in t and "cmd.exe" in t and b.startswith("structured-xml")


# =============================================================== R02 backup completeness
def _backup_case(env):
    c = env.run("bk", [{"event_time": ts(i), "event_kind": "authentication", "tenant_id": "t", "user": f"u{i}@x",
                        "src_ip": "192.0.2.5", "outcome": "failure"} for i in range(12)])
    env.store.add_note(c["case_id"], "note survives")
    return c


def test_r02_healthy_backup_complete_and_restored_references_rebased(env, tmp_path):
    from argos.backup import create_backup, restore_backup, verify_backup
    from argos.config import Settings
    from argos.evidence.original import original_record
    from argos.reporting.export import build_case_export
    from argos.store import Store
    c = _backup_case(env)
    res = create_backup(env.settings, tmp_path / "ok.zip")
    assert res["evidence_completeness"] == "complete" and res["database_consistency"] == "ok"
    v = verify_backup(Path(res["backup"]))
    assert v["evidence_completeness"] == "complete" and v["expected_originals"] == v["archived_originals"] >= 1
    s2 = Settings()
    s2.home = tmp_path / "elsewhere ñ" / "home"
    out = restore_backup(Path(res["backup"]), s2)
    assert out["evidence_completeness"] == "complete" and out["missing_originals"] == []
    st = Store(s2.db_path)
    try:
        for i in st.list_inputs(c["case_id"], include_inactive=True):
            assert Path(i["stored_path"]).resolve().is_relative_to(s2.home.resolve())
            assert sha(i["stored_path"]) == i["sha256"]
            assert str(env.settings.home) not in i["stored_path"]
        ev = next(st.iter_events(c["case_id"]))
        assert original_record(st.get_input(ev["input_id"]), ev)["status"] == "located"
        r = run_analysis(st, s2, c["case_id"])
        assert st.get_run(r["run_id"])["status"] == "succeeded"
        assert build_case_export(st, s2, c["case_id"])["run"]["run_id"] == r["run_id"]
    finally:
        st.close()


def test_r02_missing_original_fails_complete_backup_or_marks_incomplete(env, tmp_path):
    from argos.backup import BackupError, create_backup, restore_backup, verify_backup
    from argos.config import Settings
    from argos.store import Store
    c = _backup_case(env)
    sp = Path(env.store.list_inputs(c["case_id"])[0]["stored_path"])
    os.chmod(sp, 0o600)
    sp.unlink()
    with pytest.raises(BackupError, match="missing"):
        create_backup(env.settings, tmp_path / "x.zip")
    assert not (tmp_path / "x.zip").exists()
    res = create_backup(env.settings, tmp_path / "inc.zip", allow_incomplete=True)
    assert res["evidence_completeness"] == "incomplete" and res["missing_originals"]
    v = verify_backup(Path(res["backup"]))
    assert v["evidence_completeness"] == "incomplete"
    with pytest.raises(BackupError, match="incomplete"):
        verify_backup(Path(res["backup"]), require_complete=True)
    s2 = Settings()
    s2.home = tmp_path / "r2"
    out = restore_backup(Path(res["backup"]), s2)
    assert out["evidence_completeness"] == "incomplete" and len(out["missing_originals"]) == 1
    st = Store(s2.db_path)
    try:
        for i in st.list_inputs(c["case_id"], include_inactive=True):
            assert str(env.settings.home) not in i["stored_path"]  # never left pointing at the old installation
    finally:
        st.close()


def test_r02_hash_mismatch_is_not_complete(env, tmp_path):
    from argos.backup import BackupError, create_backup
    c = _backup_case(env)
    sp = Path(env.store.list_inputs(c["case_id"])[0]["stored_path"])
    os.chmod(sp, 0o600)
    sp.write_bytes(sp.read_bytes() + b"\n")
    with pytest.raises(BackupError, match="hash"):
        create_backup(env.settings, tmp_path / "m.zip")


def test_r02_tampered_archive_member_detected_against_db_inventory(env, tmp_path):
    import zipfile
    from argos.backup import BackupError, create_backup, verify_backup
    _backup_case(env)
    res = create_backup(env.settings, tmp_path / "ok.zip")
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(res["backup"]) as zin, zipfile.ZipFile(bad, "w") as zout:
        man = json.loads(zin.read("manifest.json"))
        for n in zin.namelist():
            if n.startswith("cases/"):
                data = zin.read(n) + b"x"
                for f in man["files"]:
                    if f["name"] == n:
                        f["sha256"], f["size"] = hashlib.sha256(data).hexdigest(), len(data)
                zout.writestr(n, data)
            elif n != "manifest.json":
                zout.writestr(n, zin.read(n))
        zout.writestr("manifest.json", json.dumps(man))
    with pytest.raises(BackupError, match="database inventory"):
        verify_backup(bad)


# =============================================================== R03 watcher identity
def _line(i, q):
    return json.dumps({"event_time": ts(i), "event_kind": "dns", "dns_query": q}) + "\n"


def _queries(env, c):
    return sorted(e["dns_query"] for e in env.store.iter_events(c["case_id"]))


def test_r03_same_first_line_same_length_files_both_delivered(env, tmp_path):
    from argos.watch import add_source, poll_once
    d = tmp_path / "SYNTHETIC-watch"
    d.mkdir()
    (d / "a.jsonl").write_text(_line(0, "shared.example") + _line(1, "only-in-a.example"))
    (d / "b.jsonl").write_text(_line(0, "shared.example") + _line(1, "only-in-b.example"))
    assert (d / "a.jsonl").stat().st_size == (d / "b.jsonl").stat().st_size
    c = env.case("r03")
    src = add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    s = poll_once(env.store, env.settings, src)
    q = _queries(env, c)
    assert "only-in-a.example" in q and "only-in-b.example" in q, (q, s)
    assert q.count("shared.example") == 2  # distinct files -> distinct events (not content-deduplicated)


def test_r03_restart_append_truncate_trailing_and_failed_import(env, tmp_path, monkeypatch):
    import argos.watch as W
    from argos.store import Store
    d = tmp_path / "w"
    d.mkdir()
    f = d / "app.jsonl"
    c = env.case("r03b")
    src = W.add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    f.write_text(_line(0, "e0.example") + _line(1, "e1.example")[:15])
    W.poll_once(env.store, env.settings, src)
    assert _queries(env, c) == ["e0.example"]
    with open(f, "a") as fh:
        fh.write(_line(1, "e1.example")[15:])
    # failed import: nothing consumed
    real = W.ingest_file

    def boom(*a, **k):
        raise OSError("simulated disk failure")
    monkeypatch.setattr(W, "ingest_file", boom)
    s = W.poll_once(env.store, env.settings, src)
    assert s["errors"] and _queries(env, c) == ["e0.example"]
    monkeypatch.setattr(W, "ingest_file", real)
    st2 = Store(env.settings.db_path)  # restart
    W.poll_once(st2, env.settings, src)
    st2.close()
    assert _queries(env, c) == ["e0.example", "e1.example"]
    # copy-truncate rotation: content copied away, original truncated and rewritten with new events
    (d / "app.1.jsonl.gz.done").write_bytes(f.read_bytes())  # not matching the pattern
    with open(f, "w") as fh:
        fh.write(_line(10, "after-truncate.example"))
    s = W.poll_once(env.store, env.settings, src)
    assert "after-truncate.example" in _queries(env, c) and s["rotations"] >= 1
    # rename rotation + new file: old generation keeps its checkpoint (no duplicates), new file read fully
    f.rename(d / "app.2.jsonl")
    (d / "app.jsonl").write_text(_line(20, "new-file.example"))
    W.poll_once(env.store, env.settings, src)
    q = _queries(env, c)
    assert q.count("after-truncate.example") == 1 and "new-file.example" in q and q.count("e0.example") == 1


def test_r03_rejected_segment_does_not_advance(env, tmp_path, monkeypatch):
    import argos.watch as W
    d = tmp_path / "w3"
    d.mkdir()
    (d / "x.jsonl").write_text(_line(0, "a.example"))
    c = env.case("r03c")
    src = W.add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    real = W.ingest_file
    monkeypatch.setattr(W, "ingest_file", lambda *a, **k: {"status": "rejected", "error": "simulated", "accepted": 0, "rejected": 1})
    s = W.poll_once(env.store, env.settings, src)
    assert s["errors"]
    monkeypatch.setattr(W, "ingest_file", real)
    W.poll_once(env.store, env.settings, src)
    assert _queries(env, c) == ["a.example"]


# =============================================================== R04 correlation keys
M = {"event_kind": "model_interaction", "model_tool_name": "bash", "tenant_id": "t", "source_type": "gw", "host": "h1"}
X = {"event_kind": "tool_execution", "tool_name": "bash", "tenant_id": "t", "source_type": "gw", "host": "h2"}


def _chain_case(env, name, m, x, files=1, collector=None):
    c = env.case(name)
    m = {"event_time": ts(0), **M, **m}
    x = {"event_time": ts(5), **X, **x}
    m = {k: v for k, v in m.items() if v is not None}
    x = {k: v for k, v in x.items() if v is not None}
    opts = {"collector_id": collector} if collector else {}
    if files == 1:
        env.ingest(c, [m, x], options=opts)
    else:
        env.ingest(c, [m], name=f"{name}-a.jsonl", options=opts)
        env.ingest(c, [x], name=f"{name}-b.jsonl", options=opts)
    env.analyze(c)
    return c


@pytest.mark.parametrize("name,m,x,files,collector,expect", [
    ("delimiter-collision", {"session_id": "session|part", "tool_call_id": "call"}, {"session_id": "session", "tool_call_id": "part|call"}, 1, None, False),
    # "" and "-" are normalized to "absent" at ingestion (documented log-placeholder rule): no id -> no link
    ("empty-session-ids", {"session_id": "", "tool_call_id": "c"}, {"session_id": "", "tool_call_id": "c"}, 1, None, False),
    ("placeholder-session-ids", {"session_id": "-", "tool_call_id": "c"}, {"session_id": "-", "tool_call_id": "c"}, 1, None, False),
    ("empty-call-ids", {"session_id": "s", "tool_call_id": ""}, {"session_id": "s", "tool_call_id": ""}, 1, None, False),
    ("tenant-present-vs-absent", {"session_id": "s", "tool_call_id": "c", "tenant_id": "t"}, {"session_id": "s", "tool_call_id": "c", "tenant_id": None}, 1, None, False),
    ("case-difference", {"session_id": "S", "tool_call_id": "c"}, {"session_id": "s", "tool_call_id": "c"}, 1, None, False),
    ("independent-collectors", {"session_id": "s1", "tool_call_id": "c1", "tenant_id": None, "source_type": None},
     {"session_id": "s1", "tool_call_id": "c1", "tenant_id": None, "source_type": None}, 2, None, False),
    ("mismatched-tool", {"session_id": "s", "tool_call_id": "c"}, {"session_id": "s", "tool_call_id": "c", "tool_name": "send_email"}, 1, None, False),
    ("valid-same-source", {"session_id": "s", "tool_call_id": "c"}, {"session_id": "s", "tool_call_id": "c"}, 1, None, True),
    ("valid-distributed-declared-collector", {"session_id": "s", "tool_call_id": "c"}, {"session_id": "s", "tool_call_id": "c", "host": "worker-9"}, 2,
     "gateway-prod-1", True),
])
def test_r04_correlation_keys(env, name, m, x, files, collector, expect):
    c = _chain_case(env, f"r04-{name}", m, x, files, collector)
    got = env.alerts(c, "ARG-LLM-002")
    assert bool(got) is expect, (name, [g["group"] for g in got])
    if not expect:
        assert all(a["llm"]["level"] != "directly_observed" for a in env.alerts(c))


def test_r04_key_encoding_is_unambiguous():
    from argos.detect.ops import derive
    a = derive({"session_id": "session|part", "tool_call_id": "call", "input_id": "i", "tenant_id": "t"})
    b = derive({"session_id": "session", "tool_call_id": "part|call", "input_id": "i", "tenant_id": "t"})
    assert a["call_key"] != b["call_key"]
    e1 = derive({"session_id": "s", "input_id": "i", "tenant_id": ""})
    e2 = derive({"session_id": "s", "input_id": "i"})
    e3 = derive({"session_id": "s", "input_id": "i", "tenant_id": "-"})
    assert len({e1["session_key"], e2["session_key"], e3["session_key"]}) == 3
    assert derive({"session_id": "s"})["session_key"] is None  # no namespace -> abstain


def test_r04_collector_id_cannot_be_self_declared_by_records(env):
    c = env.case("r04-self")
    env.ingest(c, [{"event_time": ts(0), "event_kind": "dns", "dns_query": "a", "collector_id": "forged"}])
    ev = next(env.store.iter_events(c["case_id"]))
    assert ev.get("collector_id") is None


# =============================================================== R05 coverage before zeros
SP = {"tenant_id": "t", "app_id": "app-x", "account_type": "service_principal", "source_type": "idp"}


def _reads(start_h, n, app="app-x"):
    return [{"event_time": ts(start_h * 3600 + i * 20), "event_kind": "cloud_operation", "action": "secret_read",
             "resource": f"kv{i % 3}", "outcome": "success", **dict(SP, app_id=app)} for i in range(n)]


def _sp002(env, c):
    return env.alerts(c, "ARG-SP-002")


def test_r05_auth_history_does_not_create_secret_read_zero_baseline(env):
    c = env.case("r05a")
    env.ingest(c, [{"event_time": ts(h * 3600), "event_kind": "authentication", "outcome": "success", **SP} for h in range(30)],
               name="signins.jsonl", coverage={"start": ts(-3600), "end": ts(31 * 3600), "scope": "app_id:app-x"})
    env.ingest(c, _reads(30, 25), name="audit.jsonl")
    env.analyze(c)
    for a in _sp002(env, c):
        assert a["abstained"] or a["baseline"]["status"] == "insufficient_baseline", a["baseline"]
        assert a["baseline"].get("covered_zero_windows", 0) == 0


def test_r05_complete_relevant_history_supports_zero(env):
    c = env.case("r05b")
    hist = [{"event_time": ts(h * 3600 + 60), "event_kind": "cloud_operation", "action": "list_keys", "outcome": "success", **SP} for h in range(30)]
    env.ingest(c, hist + _reads(30, 25), name="audit.jsonl",
               coverage={"start": ts(-3600), "end": ts(32 * 3600), "scope": "app_id:app-x", "event_kinds": ["cloud_operation"],
                         "note": "SYNTHETIC complete audit export"})
    env.analyze(c)
    al = _sp002(env, c)
    assert al and not al[0]["abstained"] and al[0]["baseline"]["status"] == "exceeds_history"
    assert al[0]["baseline"]["covered_zero_windows"] >= 24
    assert "declared" in json.dumps(al[0]["baseline"]["covered_window_basis"])


@pytest.mark.parametrize("variant", ["other-entity-scope", "gap", "absent-family"])
def test_r05_other_entity_gap_and_absent_family_do_not_count(env, variant):
    c = env.case(f"r05-{variant}")
    hist = [{"event_time": ts(h * 3600 + 60), "event_kind": "cloud_operation", "action": "list_keys", "outcome": "success", **SP} for h in range(30)]
    cov = {"start": ts(-3600), "end": ts(32 * 3600), "scope": "app_id:app-x", "event_kinds": ["cloud_operation"]}
    if variant == "other-entity-scope":
        cov["scope"] = "app_id:other-app"
    elif variant == "gap":
        cov["start"] = ts(29 * 3600)  # covered only right before the burst
    else:
        cov["event_kinds"] = ["authentication"]
    env.ingest(c, hist + _reads(30, 25), name="audit.jsonl", coverage=cov)
    env.analyze(c)
    for a in _sp002(env, c):
        assert a["abstained"] or a["baseline"]["status"] == "insufficient_baseline", (variant, a["baseline"])


def test_r05_action_based_detection_still_works_without_baseline(env):
    c = env.run("r05-sp001", [dict(event_time=ts(0), event_kind="authentication", outcome="success", **SP),
                              dict(event_time=ts(60), event_kind="cloud_operation", action="credential_add", outcome="success", **SP)])
    assert env.alerts(c, "ARG-SP-001")


def test_r05_legacy_coverage_without_kinds_is_limited_to_kinds_present(env):
    from argos.analysis import CoverageContext
    c = env.case("r05-legacy")
    env.ingest(c, [{"event_time": ts(h * 3600), "event_kind": "authentication", "outcome": "success", **SP} for h in range(3)],
               coverage={"start": ts(-3600), "end": ts(4 * 3600), "scope": "all"})
    inp = env.store.list_inputs(c["case_id"])[0]
    cov = json.loads(inp["coverage"])
    assert cov.get("event_kinds") in (None, [])  # declaration did not name kinds
    events = list(env.store.iter_events(c["case_id"]))
    ctx = CoverageContext(events, {inp["input_id"]: inp})
    v = [events[0]["observation_vantage"]]
    t0, t1 = ts_epoch(ts(3600)), ts_epoch(ts(7200))
    assert ctx.declared_cover({"app_id": "app-x", "tenant_id": "t"}, v, t0, t1, {"cloud_operation"}) is None
    assert ctx.declared_cover({"app_id": "app-x", "tenant_id": "t"}, v, t0, t1, {"authentication"}) is not None
    assert ctx.declared_cover({"app_id": "app-x", "tenant_id": "t"}, v, t0, t1, None) is None


def ts_epoch(s):
    from argos.normalize.timeutil import parse_timestamp
    return parse_timestamp(s)[0].timestamp()


# =============================================================== R07 explainer test that must invoke the provider
class RecordingProvider:
    name = "recording-fake"

    def __init__(self, response_fn):
        self.calls = []
        self.response_fn = response_fn

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        return self.response_fn(prompt)


def _explainer_payload(env, bypass_redaction=False, monkeypatch=None):
    from argos.llm import explain as ex
    c = env.run("r07", [{"event_time": ts(i * 30), "event_kind": "authentication", "tenant_id": "t", "user": "bob@x",
                         "outcome": "failure", "src_ip": "192.0.2.10"} for i in range(6)]
                + [{"event_time": ts(300), "event_kind": "authentication", "tenant_id": "t", "user": "bob@x", "outcome": "success",
                    "src_ip": "192.0.2.10"}])
    a = env.alerts(c, "ARG-AUTH-003")[0]
    a = dict(a)
    # sentinel secrets inside fields that the supported explainer path sends to the provider
    a["why"] = a["why"] + ' Authorization: Bearer SYNTH_SCALAR_SECRET'
    a["missing_visibility"] = list(a["missing_visibility"]) + [{"token": ["SYNTH_LIST_SECRET"]}]
    a["resolving_data"] = list(a["resolving_data"]) + [{"credentials": {"value": "SYNTH_NESTED_SECRET"}}]
    if bypass_redaction:
        monkeypatch.setattr(ex, "redact_obj", lambda x: x)
    prov = RecordingProvider(lambda p: json.dumps({"summary": "Review the sign-in sequence.",
                                                   "suggested_checks": [{"check": "Check MFA logs", "evidence_refs": a["evidence_refs"][:1]}],
                                                   "cited_evidence_refs": a["evidence_refs"][:1]}))
    res = ex.explain(a, prov)
    return a, prov, res


def _payload_leaks(prov):
    assert len(prov.calls) == 1, "provider was not invoked exactly once"
    return [s for s in SENTINELS if s in prov.calls[0]]


def test_r07_explainer_invokes_provider_with_redacted_payload(env):
    a, prov, res = _explainer_payload(env)
    assert _payload_leaks(prov) == []
    p = prov.calls[0]
    assert "ARG-AUTH-003" in p and a["evidence_refs"][0] in p and "bob@x" in p  # useful context kept
    assert res["provider"] == "recording-fake" and res["explanation"]["cited_evidence_refs"]


def test_r07_check_fails_when_redaction_is_bypassed(env, monkeypatch):
    a, prov, _ = _explainer_payload(env, bypass_redaction=True, monkeypatch=monkeypatch)
    assert _payload_leaks(prov), "the leak check must detect a bypassed redaction"


def test_r07_check_fails_when_provider_is_never_called():
    prov = RecordingProvider(lambda p: "")
    with pytest.raises(AssertionError, match="not invoked"):
        _payload_leaks(prov)


def test_r07_explainer_rejects_invented_references_explicitly(env):
    from argos.llm import explain as ex
    c = env.run("r07b", [{"event_time": ts(0), "event_kind": "dns", "dns_query": "api.openai.com", "src_ip": "192.0.2.4"}])
    a = env.alerts(c)[0]
    prov = RecordingProvider(lambda p: json.dumps({"summary": "x", "suggested_checks": [], "cited_evidence_refs": ["ev:invented:1"]}))
    with pytest.raises(ex.LLMRejected, match="non-existent"):
        ex.explain(a, prov)
    assert len(prov.calls) == 1


# =============================================================== R08 global admission
def test_r08_global_admission_queue_cancel_and_reject(env, monkeypatch):
    import argos.analysis as AN
    from argos.jobs import JobRunner, QueueFull
    cases = [env.run(f"r08-{i}", [{"event_time": ts(j), "event_kind": "dns", "dns_query": f"q{j}.example"} for j in range(5)]) for i in range(5)]
    before = {c["case_id"]: env.store.latest_successful_run(c["case_id"])["run_id"] for c in cases}
    gate = threading.Event()
    active, peak = [0], [0]
    lock = threading.Lock()
    orig = AN.case_assessment

    def slow(*a, **k):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            gate.wait(15)
            return orig(*a, **k)
        finally:
            with lock:
                active[0] -= 1
    monkeypatch.setattr(AN, "case_assessment", slow)
    env.settings.max_concurrent_jobs = 1
    env.settings.max_queued_jobs = 2
    jr = JobRunner(env.settings)
    j0 = jr.submit_analysis(env.store, cases[0]["case_id"])
    j1 = jr.submit_analysis(env.store, cases[1]["case_id"])
    j2 = jr.submit_analysis(env.store, cases[2]["case_id"])
    with pytest.raises(QueueFull):
        jr.submit_analysis(env.store, cases[3]["case_id"])
    time.sleep(0.5)
    assert env.store.get_job(j0)["status"] == "running"
    assert env.store.get_job(j1)["status"] == "queued" and env.store.get_job(j2)["status"] == "queued"
    assert JobRunner.cancel(env.store, j2)
    gate.set()
    for j in (j0, j1, j2):
        assert jr.wait(j, 30)
    assert peak[0] == 1
    assert env.store.get_job(j0)["status"] == "succeeded" and env.store.get_job(j1)["status"] == "succeeded"
    assert env.store.get_job(j2)["status"] == "cancelled"
    assert env.store.latest_successful_run(cases[2]["case_id"])["run_id"] == before[cases[2]["case_id"]]
    # a failed job releases its slot and preserves the previous result
    monkeypatch.setattr(AN, "case_assessment", lambda *a, **k: 1 / 0)
    jf = jr.submit_analysis(env.store, cases[4]["case_id"])
    assert jr.wait(jf, 30) and env.store.get_job(jf)["status"] == "failed"
    assert env.store.latest_successful_run(cases[4]["case_id"])["run_id"] == before[cases[4]["case_id"]]
    monkeypatch.setattr(AN, "case_assessment", orig)
    jok = jr.submit_analysis(env.store, cases[3]["case_id"])
    assert jr.wait(jok, 30) and env.store.get_job(jok)["status"] == "succeeded"


def test_r08_data_dir_lock_enforces_single_server_process(env):
    from argos.jobs import DataDirLock, DataDirBusy
    l1 = DataDirLock(env.settings.home)
    l1.acquire()
    try:
        with pytest.raises(DataDirBusy):
            DataDirLock(env.settings.home).acquire()
        from argos.cli import main
        rc = main(["--data-dir", str(env.settings.home), "analyze", "--case", "nonexistent", "--quiet"])
        assert rc == 5
    finally:
        l1.release()
    DataDirLock(env.settings.home).acquire().release()


# =============================================================== R09 private-repo git auth in preflight
def test_r09_preflight_git_reads_authenticate_without_token_in_argv(monkeypatch):
    import sys
    sys.path.insert(0, str(ROOT / "packaging"))
    import release_preflight as P
    monkeypatch.setenv("GH_TOKEN", "SYNTH_TOKEN_VALUE")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")  # a pre-existing runner entry must be preserved
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "http.sslCAInfo")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/etc/ssl/runner.pem")
    env = P.git_env()
    assert env["GIT_CONFIG_KEY_0"] == "http.sslCAInfo" and env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    keys = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    hdr = keys["http.https://github.com/.extraheader"]
    import base64
    assert base64.b64decode(hdr.split()[-1]).decode() == "x-access-token:SYNTH_TOKEN_VALUE"
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["env"] = cmd, kw.get("env")

        class R:
            returncode, stdout, stderr = 0, "", ""
        return R()
    monkeypatch.setattr(P.subprocess, "run", fake_run)
    P.git("ls-remote", "origin")
    assert "SYNTH_TOKEN_VALUE" not in " ".join(seen["cmd"]) and seen["env"]["GIT_CONFIG_COUNT"] == env["GIT_CONFIG_COUNT"]
    monkeypatch.delenv("GH_TOKEN")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    e2 = P.git_env()
    assert not [k for k, v in e2.items() if k.startswith("GIT_CONFIG_VALUE_") and "AUTHORIZATION" in v]


def test_r09_release_jobs_running_preflight_provide_token():
    import yaml
    wf = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    for name, job in wf["jobs"].items():
        for stp in job.get("steps", []):
            if "release_preflight.py" in str(stp.get("run", "")):
                env = {**job.get("env", {}), **stp.get("env", {})}
                assert env.get("GH_TOKEN") == "${{ github.token }}", name
    text = (ROOT / ".github/workflows/release.yml").read_text()
    assert "x-access-token" not in text and "extraheader" not in text  # no token handling inlined in shell commands
