"""Regression tests for audit findings F01-F10 (see docs/AUDIT_REMEDIATION.md).

Important cases go through the file adapters -> normalization -> correlation -> assessment/export path:
fixtures are written as files and imported with ingest_file, never injected as normalized dicts.
All data is SYNTHETIC.
"""
import csv
import io
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from argos.analysis import run_analysis
from argos.reporting.export import alerts_csv, build_case_export, render_html
from argos.store import SCHEMA, Store
from argos.synthetic import ts
from conftest import ROOT

SECRETS = ("SYNTHETIC_SECRET_123", "SYNTH_APIKEY_456", "SYNTH_TOKEN_789", "SYNTH_URLPASS_1", "SYNTH_QUERY_2", "SYNTH_ARG_3")


def jl(env, name, rows):
    return env.write(name, rows)


def llm_levels(env, c):
    return {a["rule_id"]: a["llm"]["level"] for a in env.alerts(c)}


# ------------------------------------------------------------------ F01
def test_f01_generic_automation_without_model_record_is_llm_unknown(env):
    rows = [{"event_time": ts(0), "event_kind": "tool_execution", "host": "h1", "linked_process_guid": "{G}", "session_id": "s1", "tool_name": "bash"},
            {"event_time": ts(2), "event_kind": "process_start", "host": "h1", "process_guid": "{G}", "process_image": "/bin/sh"}]
    c = env.run("f01", rows)
    lv = llm_levels(env, c)
    assert "ARG-AUTO-003" in lv and lv["ARG-AUTO-003"] == "unknown"
    assert "directly_observed" not in lv.values()
    a = env.alerts(c, "ARG-AUTO-003")[0]
    assert a["automation"]["level"] == "observed_automation"
    assert env.assessment(c)["llm"]["level"] != "directly_observed"


def test_f01_model_request_with_process_link_still_directly_observed(env):
    rows = [{"event_time": ts(0), "event_kind": "model_interaction", "host": "h1", "linked_process_guid": "{G}", "session_id": "s1", "model_tool_name": "bash"},
            {"event_time": ts(2), "event_kind": "process_start", "host": "h1", "process_guid": "{G}", "process_image": "/bin/sh"}]
    c = env.run("f01pos", rows)
    a = env.alerts(c, "ARG-LLM-003")[0]
    assert a["llm"]["level"] == "directly_observed"
    assert any("unverified provenance" in x for x in a["llm"]["limitations"])


# ------------------------------------------------------------------ F02
def _chain(model, execu):
    base = {"event_kind": "model_interaction", "session_id": "session-1", "model_tool_name": "read_file", "tool_call_id": "call-1",
            "tenant_id": "A", "host": "hA", "source_type": "agent_audit"}
    m = dict(base) | {"event_time": ts(0)} | model
    x = {"event_time": ts(5), "event_kind": "tool_execution", "session_id": "session-1", "tool_name": "read_file", "tool_call_id": "call-1",
         "tenant_id": "A", "host": "hA", "source_type": "agent_audit"} | execu
    return [m, x]


@pytest.mark.parametrize("case,execu,expect", [
    ("other-tenant", {"tenant_id": "B", "host": "hB"}, False),
    ("other-source", {"source_type": "other_collector"}, False),
    ("different-tool", {"tool_name": "send_email"}, False),
    ("mismatched-call", {"tool_call_id": "call-2"}, False),
    ("case-collision-call", {"tool_call_id": "CALL-1"}, False),
    ("case-collision-session", {"session_id": "Session-1"}, False),
    ("missing-call-id", {"tool_call_id": None}, False),
    ("same-process-valid", {}, True),
    ("distributed-explicit-link", {"host": "executor-7"}, True),
])
def test_f02_no_false_model_execution_chain(env, case, execu, expect):
    rows = _chain({}, execu)
    rows = [{k: v for k, v in r.items() if v is not None} for r in rows]
    c = env.run(f"f02-{case}", rows)
    got = env.alerts(c, "ARG-LLM-002")
    assert bool(got) is expect, (case, [g["group"] for g in got])
    if expect:
        assert got[0]["llm"]["level"] == "directly_observed"
    else:
        assert all(a["llm"]["level"] != "directly_observed" for a in env.alerts(c))


def test_f02_missing_call_id_reported_only_as_possible(env):
    rows = [{"event_time": ts(0), "event_kind": "model_interaction", "session_id": "s", "model_tool_name": "bash", "host": "h", "tenant_id": "t"},
            {"event_time": ts(3), "event_kind": "tool_execution", "session_id": "s", "tool_name": "bash", "host": "h", "tenant_id": "t"}]
    c = env.run("f02-possible", rows)
    lv = llm_levels(env, c)
    assert "ARG-LLM-002" not in lv
    assert lv.get("ARG-LLM-005") == "possible"


# ------------------------------------------------------------------ F03
@pytest.mark.parametrize("outcome,expect_outcome,expect_stage", [
    ("success", "success", "observed_success"),
    ("failure", "failure", "attempt"),
    (None, "unknown", "outcome_unknown"),
])
def test_f03_terminal_outcome_from_credential_change(env, outcome, expect_outcome, expect_stage):
    sp = dict(tenant_id="t", app_id="app-1", account_type="service_principal", source_type="entra")
    change = dict(event_time=ts(60), event_kind="cloud_operation", action="credential_add", **sp)
    if outcome:
        change["outcome"] = outcome
    rows = [dict(event_time=ts(0), event_kind="authentication", outcome="success", **sp), change]
    c = env.run(f"f03-{expect_outcome}", rows)
    a = env.alerts(c, "ARG-SP-001")[0]
    ao = a["purpose"]["action_outcome"]
    assert ao["outcome"] == expect_outcome and ao["terminal_step"] == "privilege_or_credential_change"
    assert a["purpose"]["stage"] == expect_stage
    assert f"Terminal action outcome: {expect_outcome}" in a["why"]
    if expect_outcome != "success":
        assert "completed" not in a["what"].lower()
    assert a["threat"]["severity"] in ("high", "critical", "medium")  # a failed unauthorized change stays serious
    html = render_html(build_case_export(env.store, env.settings, c["case_id"]))
    assert expect_outcome in html


# ------------------------------------------------------------------ F04
def test_f04_other_tenant_history_is_not_baseline(env):
    rows = [{"event_time": ts(0), "event_kind": "cloud_operation", "tenant_id": "X", "app_id": "other", "action": "signin_noise"}]
    rows += [{"event_time": ts(40 * 3600 + i * 10), "event_kind": "cloud_operation", "tenant_id": "Y", "app_id": "new",
              "action": "secret_read", "resource": "kv"} for i in range(30)]
    c = env.run("f04", rows)
    for a in env.alerts(c, "ARG-SP-002"):
        assert a["abstained"] or (a["baseline"] or {}).get("status") == "insufficient_baseline"


def test_f04_declared_coverage_enables_absence_but_gaps_and_other_hosts_do_not(env):
    fails = [{"event_time": ts(i * 30), "event_kind": "authentication", "tenant_id": "t", "user": "bob@x", "outcome": "failure",
              "src_ip": "192.0.2.10", "source_type": "idp"} for i in range(6)]
    succ = [{"event_time": ts(300), "event_kind": "authentication", "tenant_id": "t", "user": "bob@x", "outcome": "success",
             "src_ip": "192.0.2.10", "source_type": "idp"}]
    later_other = [{"event_time": ts(20000), "event_kind": "authentication", "tenant_id": "t", "user": "zed@x", "outcome": "success",
                    "src_ip": "192.0.2.11", "source_type": "idp"}]
    # (a) a later record of a different user is not coverage for bob
    c = env.run("f04-a", fails + succ + later_other)
    st = env.alerts(c, "ARG-AUTH-003")[0]["absence_checks"][0]["status"]
    assert st in ("not_observed_in_supplied_records", "not_observed_entity_records_continue")
    assert st != "absent_within_declared_coverage"
    # (b) declared coverage for a different tenant does not count
    c = env.run("f04-b", fails + succ, coverage={"start": ts(-3600), "end": ts(30000), "scope": "tenant:other"})
    assert env.alerts(c, "ARG-AUTH-003")[0]["absence_checks"][0]["status"] != "absent_within_declared_coverage"
    # (c) declared coverage ending before the follow-up window -> not demonstrated
    c = env.run("f04-c", fails + succ, coverage={"start": ts(-3600), "end": ts(400), "scope": "tenant:t"})
    assert env.alerts(c, "ARG-AUTH-003")[0]["absence_checks"][0]["status"] != "absent_within_declared_coverage"
    # (d) matching declared coverage -> absence within declared coverage, labelled as declared
    c = env.run("f04-d", fails + succ, coverage={"start": ts(-3600), "end": ts(30000), "scope": "tenant:t", "note": "SYNTHETIC export"})
    chk = env.alerts(c, "ARG-AUTH-003")[0]["absence_checks"][0]
    assert chk["status"] == "absent_within_declared_coverage"
    src = env.assessment(c)["diagnostics"]["sources"][0]
    assert src["declared_coverage"]["basis"].startswith("analyst-declared")


def test_f04_coverage_cannot_come_from_inside_the_file(env):
    rows = [{"event_time": ts(0), "event_kind": "dns", "dns_query": "a.example", "coverage": {"start": ts(-9999), "end": ts(9999)}}]
    c = env.run("f04-self", rows)
    assert env.store.list_inputs(c["case_id"])[0]["coverage"] is None


# ------------------------------------------------------------------ F05
def _secret_rows():
    msg = ('{"password":"SYNTHETIC_SECRET_123","nested":{"api_key":"SYNTH_APIKEY_456"}} Authorization: "Bearer SYNTH_TOKEN_789" '
           'url=https://admin:SYNTH_URLPASS_1@db.example/x?token=SYNTH_QUERY_2 cmd=mysql -u root --password SYNTH_ARG_3')
    rows = [{"event_time": ts(i), "event_kind": "authentication", "tenant_id": "t", "user": f"u{i}@x", "src_ip": "192.0.2.50",
             "outcome": "failure", "message": msg, "headers": {"Authorization": "Bearer SYNTH_TOKEN_789"}} for i in range(12)]
    return rows


def test_f05_exports_api_and_html_redact_structured_secrets(env):
    rows = _secret_rows()
    p = env.write("sec.jsonl", rows)
    with open(p, "a") as fh:  # a rejected record carrying secrets
        fh.write('{"event_kind":"dns","password":"SYNTHETIC_SECRET_123","dns_query":"x"}\n')
    c = env.case("f05")
    env.ingest(c, p)
    env.analyze(c)
    env.store.add_note(c["case_id"], 'creds {"password":"SYNTHETIC_SECRET_123"} api_key=SYNTH_APIKEY_456')
    exp = build_case_export(env.store, env.settings, c["case_id"])
    texts = {"json": json.dumps(exp), "html": render_html(exp), "csv": alerts_csv(exp["alerts"])}
    for kind, t in texts.items():
        leaks = [s for s in SECRETS if s in t]
        assert not leaks, (kind, leaks)
    assert "[REDACTED]" in texts["json"]
    # rejected excerpt stored redacted
    rej = env.store.list_rejects(c["case_id"])
    assert rej and all("SYNTHETIC_SECRET_123" not in (r["excerpt"] or "") for r in rej)
    # originals are preserved byte-for-byte
    orig = Path(env.store.list_inputs(c["case_id"])[0]["stored_path"]).read_text()
    assert "SYNTHETIC_SECRET_123" in orig


def test_f05_original_record_view_redacts_unless_raw(env):
    from argos.evidence.original import original_record
    c = env.run("f05b", _secret_rows())
    ev = next(env.store.iter_events(c["case_id"]))
    inp = env.store.get_input(ev["input_id"])
    red = original_record(inp, ev)
    assert red["redacted"] and not any(s in red["record_text"] for s in SECRETS)
    raw = original_record(inp, ev, raw=True)
    assert not raw["redacted"] and "SYNTHETIC_SECRET_123" in raw["record_text"]


def test_f05_llm_input_is_redacted(env):
    from argos.llm import explain as ex
    c = env.run("f05c", _secret_rows())
    a = env.alerts(c)[0]
    seen = {}

    class P:
        name = "fake"

        def generate(self, prompt, **kw):
            seen["prompt"] = prompt
            return json.dumps({"summary": "x", "evidence_refs": [], "caveats": []})
    try:
        ex.explain(a, env.store.get_events(a["event_ids"]), P())
    except Exception:  # noqa: BLE001 - only the prompt matters here
        pass
    if "prompt" in seen:
        assert not any(s in seen["prompt"] for s in SECRETS)


def test_f05_csv_formula_and_xss_protection_preserved():
    from argos.evidence.redact import csv_safe
    assert csv_safe("=HYPERLINK(1)").startswith("'")
    from argos.reporting.export import jinja_env
    t = jinja_env().from_string("{{ v }}").render(v="<script>alert(1)</script>")
    assert "<script>" not in t


# ------------------------------------------------------------------ F06
def _unclean_db(path: Path, n: int):
    code = f"""
import sqlite3,os,sys
sys.path.insert(0,{str(ROOT / 'src')!r})
from argos.store import SCHEMA
c=sqlite3.connect({str(path)!r}); c.executescript(SCHEMA); c.execute("PRAGMA journal_mode=WAL")
for i in range({n}):
    c.execute("INSERT INTO cases VALUES(?,?,0,'','open','2026-11-01T00:00:00Z')", (f"case-{{i}}", f"c{{i}}")); c.commit()
c.execute("INSERT INTO notes(case_id,alert_id,author,text,created_at) VALUES('case-0',NULL,'a','n1','x')"); c.commit()
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", code], check=True)


def test_f06_migration_backup_includes_committed_wal_after_unclean_exit(tmp_path):
    db = tmp_path / "argos.sqlite3"
    _unclean_db(db, 3)
    assert (tmp_path / "argos.sqlite3-wal").exists()
    st = Store(db)
    assert st.schema_version() == 3
    live = st.conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    st.close()
    bk = next(tmp_path.glob("argos.v*-backup.sqlite3"))
    b = sqlite3.connect(bk)
    assert b.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert b.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == live == 3
    assert b.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 1
    b.close()
    assert stat.S_IMODE(bk.stat().st_mode) & 0o077 == 0
    # idempotent restart: no second migration, data intact
    st = Store(db)
    assert st.schema_version() == 3 and st.conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 3
    st.close()


def test_f06_failed_migration_rolls_back_and_keeps_backup(tmp_path, monkeypatch):
    import argos.store as S
    db = tmp_path / "argos.sqlite3"
    _unclean_db(db, 2)

    def boom(self, c):
        c.execute("CREATE TABLE half_done(x)")
        raise RuntimeError("simulated failure mid-migration")
    monkeypatch.setattr(S.Store, "_migrate_2_to_3", boom)
    with pytest.raises(S.MigrationError):
        Store(db)
    monkeypatch.undo()
    c = sqlite3.connect(db)
    names = {r[0] for r in c.execute("SELECT name FROM sqlite_master")}
    assert "half_done" not in names and c.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 2
    c.close()
    assert next(tmp_path.glob("argos.v*-backup.sqlite3"))
    st = Store(db)  # retry succeeds
    assert st.schema_version() == 3
    st.close()


# ------------------------------------------------------------------ F07
@pytest.mark.skipif(os.name == "nt", reason="POSIX modes; Windows ACLs are covered by the native Windows smoke test")
def test_f07_private_permissions_under_permissive_umask(env, tmp_path):
    from argos.backup import create_backup
    from argos.config import permission_findings
    old = os.umask(0o022)
    try:
        c = env.case("f07")
        env.ingest(c, [{"event_time": ts(0), "event_kind": "dns", "dns_query": "a"}])
        env.analyze(c)
        bk = create_backup(env.settings)["backup"]
    finally:
        os.umask(old)
    paths = [env.settings.home, env.settings.cases_dir, env.settings.db_path, Path(env.store.list_inputs(c["case_id"])[0]["stored_path"]),
             Path(bk), env.settings.backups_dir]
    for p in paths:
        assert stat.S_IMODE(p.stat().st_mode) & 0o077 == 0, (p, oct(p.stat().st_mode))
    assert stat.S_IMODE(Path(env.store.list_inputs(c["case_id"])[0]["stored_path"]).stat().st_mode) == 0o400
    assert permission_findings(env.settings.home) == []
    os.chmod(env.settings.cases_dir, 0o755)
    f = permission_findings(env.settings.home)
    assert f and "chmod 700" in f[0]


# ------------------------------------------------------------------ F08
def test_f08_pretty_json_array_record_navigation(env):
    from argos.evidence.original import original_record
    c = env.case("f08a")
    p = env.tmp / "arr.json"
    p.write_text(json.dumps([{"event_time": ts(0), "event_kind": "dns", "dns_query": "first.example"},
                             {"event_time": ts(1), "event_kind": "dns", "dns_query": "zweite-ü.example"}], indent=2, ensure_ascii=False),
                 encoding="utf-8")
    env.ingest(c, p)
    evs = sorted(env.store.iter_events(c["case_id"]), key=lambda e: e["record_no"])
    r0 = original_record(env.store.get_input(evs[0]["input_id"]), evs[0])
    r1 = original_record(env.store.get_input(evs[1]["input_id"]), evs[1])
    assert r0["status"] == "located" and "first.example" in r0["record_text"] and r0["record_text"].strip() != "["
    assert "zweite-ü.example" in r1["record_text"] and "first.example" not in r1["record_text"]
    assert evs[1]["source_locator"]["pointer"] == "/1"


def test_f08_multiline_csv_record_navigation(env):
    from argos.evidence.original import original_record
    c = env.case("f08b")
    p = env.tmp / "auth.csv"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["_time", "user", "src", "action", "app"])
    w.writerow([ts(0), "anna@x", "192.0.2.1", "failure", "line one\nline two"])
    w.writerow([ts(5), "bob@x", "192.0.2.2", "success", "single"])
    p.write_text(buf.getvalue(), encoding="utf-8")
    r = env.ingest(c, p, fmt="splunk_csv", options={"profile": "auth"})
    assert r["accepted"] == 2, r
    evs = {e["user"]: e for e in env.store.iter_events(c["case_id"])}
    o = original_record(env.store.get_input(evs["bob@x"]["input_id"]), evs["bob@x"])
    assert "bob@x" in o["record_text"] and "anna@x" not in o["record_text"] and o["record_text"].startswith("_time")
    o = original_record(env.store.get_input(evs["anna@x"]["input_id"]), evs["anna@x"])
    assert "line one" in o["record_text"] and "line two" in o["record_text"] and "bob@x" not in o["record_text"]


def test_f08_xml_element_navigation_and_integrity_mismatch(env):
    from argos.evidence.original import original_record
    xml = (ROOT / "fixtures" / "demo" / "endpoint_sysmon.xml")
    c = env.case("f08c")
    env.ingest(c, xml, fmt="sysmon_xml")
    ev = sorted(env.store.iter_events(c["case_id"]), key=lambda e: e["record_no"])[1]
    inp = env.store.get_input(ev["input_id"])
    o = original_record(inp, ev)
    assert o["status"] == "located" and o["record_text"].count("<") > 3 and "EventData" in o["record_text"]
    # tamper with the retained copy -> integrity mismatch, no excerpt
    sp = Path(inp["stored_path"])
    os.chmod(sp, 0o600)
    sp.write_bytes(sp.read_bytes() + b" ")
    o = original_record(inp, ev)
    assert o["status"] == "integrity_mismatch" and o["record_text"] is None


def test_f08_legacy_event_without_locator_is_labelled(env):
    from argos.evidence.original import original_record
    c = env.run("f08d", [{"event_time": ts(0), "event_kind": "dns", "dns_query": "a"}])
    ev = next(env.store.iter_events(c["case_id"]))
    ev.pop("source_locator")
    o = original_record(env.store.get_input(ev["input_id"]), ev)
    assert o["status"] == "legacy_record_number" and "a" in o["record_text"]


# ------------------------------------------------------------------ F09
def test_f09_runs_keep_their_own_alert_payloads_and_reports(env):
    rows = [{"event_time": ts(i * 10), "event_kind": "authentication", "tenant_id": "t", "user": f"u{i}@x", "src_ip": "192.0.2.50",
             "outcome": "failure"} for i in range(12)]
    c = env.run("f09", rows)
    run1 = env.store.latest_successful_run(c["case_id"])
    a1 = {a["alert_id"]: a for a in env.store.run_alerts(run1["run_id"])}
    # change a rule override between runs -> different payload in run 2
    (env.settings.config_dir / "rule_overrides.yaml").write_text("ARG-AUTH-001:\n  base_confidence: low\n")
    env.analyze(c)
    run2 = env.store.latest_successful_run(c["case_id"])
    assert run2["run_id"] != run1["run_id"]
    a1_again = {a["alert_id"]: a for a in env.store.run_alerts(run1["run_id"])}
    assert a1_again == a1  # immutable
    exp1 = build_case_export(env.store, env.settings, c["case_id"], run_id=run1["run_id"])
    assert exp1["run"]["run_id"] == run1["run_id"] and exp1["run"]["basis"] == "immutable run snapshot"
    from argos.reporting.compare import compare_runs
    cmp_ = compare_runs(env.store, run1["run_id"], run2["run_id"])
    assert "configuration" in cmp_["attribution"] or "overrides" in cmp_["inputs_changed"]["configuration"]


def test_f09_failed_or_cancelled_run_keeps_previous_success(env, monkeypatch):
    from argos.analysis import AnalysisCancelled
    c = env.run("f09b", [{"event_time": ts(i), "event_kind": "authentication", "tenant_id": "t", "user": f"u{i}@x",
                          "src_ip": "192.0.2.5", "outcome": "failure"} for i in range(12)])
    before = env.store.latest_successful_run(c["case_id"])
    n_alerts = len(env.alerts(c))
    with pytest.raises(AnalysisCancelled):
        run_analysis(env.store, env.settings, c["case_id"], cancel=lambda: True)
    import argos.analysis as A
    monkeypatch.setattr(A, "case_assessment", lambda *a, **k: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        run_analysis(env.store, env.settings, c["case_id"])
    assert env.store.latest_successful_run(c["case_id"])["run_id"] == before["run_id"]
    assert len(env.alerts(c)) == n_alerts
    statuses = [r["status"] for r in env.store.list_runs(c["case_id"])]
    assert statuses == ["succeeded", "cancelled", "failed"]


def test_f09_legacy_runs_are_labelled_not_invented(tmp_path):
    db = tmp_path / "argos.sqlite3"
    c = sqlite3.connect(db)
    c.executescript(SCHEMA)
    c.execute("INSERT INTO cases VALUES('case-x','old',0,'','open','2026-11-01T00:00:00Z')")
    c.execute("INSERT INTO runs(run_id,case_id,seq,started_at,finished_at,manifest,versions,stats) VALUES('run-old','case-x',1,'t','t','[]','{}','{}')")
    c.commit()
    c.close()
    st = Store(db)
    r = st.get_run("run-old")
    assert r["snapshot_available"] == 0 and st.run_alerts("run-old") == [] and st.run_snapshot("run-old") is None
    st.close()


# ------------------------------------------------------------------ F10
def test_f10_reprocess_timezone_and_mapping_revisions(env):
    c = env.case("f10")
    p = env.write("naive.jsonl", [{"event_time": "2026-11-03 10:00:00", "event_kind": "dns", "dns_query": f"q{i}.example"} for i in range(5)])
    r1 = env.ingest(c, p)
    assert r1["status"] == "rejected" or r1["accepted"] == 0
    r_same = env.ingest(c, p, options={"assume_tz": "UTC"})
    assert r_same["status"] in ("imported", "different_options_require_reprocess")
    if r_same["status"] == "different_options_require_reprocess":
        r_same = ingest_reprocess(env, c, p, {"assume_tz": "UTC"})
    assert r_same["accepted"] == 5
    env.analyze(c)
    run_a = env.store.latest_successful_run(c["case_id"])
    assert env.store.count_events(c["case_id"]) == 5
    # identical options again: idempotent
    assert env.ingest(c, p, options={"assume_tz": "UTC"})["status"] == "already_imported"
    # different correction (another zone) needs explicit reprocess
    r3 = env.ingest(c, p, options={"assume_tz": "+02:00"})
    assert r3["status"] == "different_options_require_reprocess"
    r4 = ingest_reprocess(env, c, p, {"assume_tz": "+02:00"})
    assert r4["status"] == "reprocessed" and r4["accepted"] == 5
    assert env.store.count_events(c["case_id"]) == 5  # no double counting
    env.store.add_note(c["case_id"], "kept across revisions")
    env.analyze(c)
    run_b = env.store.latest_successful_run(c["case_id"])
    from argos.reporting.compare import compare_runs
    cmp_ = compare_runs(env.store, run_a["run_id"], run_b["run_id"])
    assert cmp_["inputs_changed"]["data"]["added_inputs"] or cmp_["inputs_changed"]["data"]["removed_inputs"]
    # historical run keeps its manifest (old revision)
    assert {i["input_id"] for i in run_a["manifest"]} != {i["input_id"] for i in run_b["manifest"]}
    revs = env.store.list_inputs(c["case_id"], include_inactive=True)
    assert len(revs) >= 3 and sum(1 for r in revs if r["active"]) == 1
    assert env.store.list_notes(c["case_id"])[0]["text"] == "kept across revisions"
    # activate the previous revision explicitly
    prev = [r for r in revs if r["options_hash"] == r_same["options_hash"]][0]
    env.store.activate_revision(prev["input_id"])
    assert env.store.count_events(c["case_id"]) == 5


def ingest_reprocess(env, c, p, options):
    from argos.ingest.pipeline import ingest_file
    return ingest_file(env.store, env.settings, c, p, "native_jsonl", options, reprocess=True)


def test_f10_failed_reprocess_keeps_usable_revision(env):
    from argos.ingest.pipeline import ingest_file
    c = env.case("f10b")
    p = env.tmp / "auth.csv"
    p.write_text("_time,user,src_ip,outcome\n" + "".join(f"{ts(i)},u{i}@x,192.0.2.1,failure\n" for i in range(3)))
    assert env.ingest(c, p, fmt="splunk_csv", options={"profile": "auth"})["accepted"] == 3
    m = env.tmp / "wrong.yaml"
    m.write_text("time: no_such_column\nfields: {user: user}\nconstants: {event_kind: authentication, observation_vantage: identity_cloud}\n")
    bad = ingest_file(env.store, env.settings, c, p, "splunk_csv", {"mapping": str(m)}, reprocess=True)
    assert bad["status"] == "reprocess_failed_previous_kept" and bad["accepted"] == 0 and bad["rejected"] == 3
    assert env.store.count_events(c["case_id"]) == 3
    active = [i for i in env.store.list_inputs(c["case_id"], include_inactive=True) if i["active"]]
    assert len(active) == 1 and active[0]["records_accepted"] == 3
    # invalid option fails before anything changes
    with pytest.raises(Exception):
        ingest_file(env.store, env.settings, c, p, "splunk_csv", {"profile": "auth", "assume_tz": "Mars/Olympus"}, reprocess=True)
    assert env.store.count_events(c["case_id"]) == 3


# ------------------------------------------------------------------ backup / restore
def test_backup_restore_roundtrip_with_relationships(env, tmp_path):
    from argos.backup import BackupError, create_backup, restore_backup, verify_backup
    from argos.config import Settings
    c = env.run("bk", [{"event_time": ts(i), "event_kind": "authentication", "tenant_id": "t", "user": f"u{i}@x",
                        "src_ip": "192.0.2.5", "outcome": "failure"} for i in range(12)])
    env.store.add_note(c["case_id"], "note survives")
    a = env.alerts(c)[0]
    env.store.set_alert_status(a["alert_id"], "triaged", "SYNTHETIC rationale")
    res = create_backup(env.settings, tmp_path / "b.zip")
    verify_backup(Path(res["backup"]))
    s2 = Settings()
    s2.home = tmp_path / "restored home ñ"
    out = restore_backup(Path(res["backup"]), s2)
    assert out["table_counts"]["events"] == env.store.count_events(c["case_id"])
    st2 = Store(s2.db_path)
    try:
        c2 = st2.get_case("bk")
        assert c2["case_id"] == c["case_id"]
        assert st2.list_notes(c2["case_id"])[0]["text"] == "note survives"
        assert st2.get_alert(a["alert_id"])["status_history"][0]["rationale"] == "SYNTHETIC rationale"
        inp = st2.list_inputs(c2["case_id"])[0]
        assert Path(inp["stored_path"]).is_relative_to(s2.home)
        from argos.evidence.original import original_record
        ev = next(st2.iter_events(c2["case_id"]))
        assert original_record(inp, ev)["status"] == "located"
        assert len(st2.run_alerts(st2.latest_successful_run(c2["case_id"])["run_id"])) == len(env.alerts(c))
    finally:
        st2.close()
    # refuses a non-empty target and a tampered archive
    with pytest.raises(BackupError):
        restore_backup(Path(res["backup"]), s2)
    import zipfile
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(res["backup"]) as zin, zipfile.ZipFile(bad, "w") as zout:
        for n in zin.namelist():
            data = zin.read(n)
            zout.writestr(n, data + b"x" if n.startswith("db/") else data)
    with pytest.raises(BackupError):
        verify_backup(bad)
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("manifest.json", json.dumps({"format": "argos-backup/1", "files": []}))
        z.writestr("../escape.txt", "x")
    with pytest.raises(BackupError):
        verify_backup(evil)


# ------------------------------------------------------------------ jobs (feature C)
def test_job_cancel_preserves_previous_and_restart_recovery(env):
    from argos.jobs import CaseBusy, JobRunner
    c = env.run("jobs", [{"event_time": ts(i), "event_kind": "dns", "dns_query": f"q{i}.example"} for i in range(50)])
    before = env.store.latest_successful_run(c["case_id"])["run_id"]
    jr = JobRunner(env.settings)
    import argos.analysis as A
    gate = threading.Event()
    orig = A.case_assessment

    def slow(*a, **k):
        gate.wait(5)
        return orig(*a, **k)
    A.case_assessment = slow
    try:
        jid = jr.submit_analysis(env.store, c["case_id"])
        time.sleep(0.2)
        with pytest.raises(CaseBusy):
            jr.submit_analysis(env.store, c["case_id"])
        assert JobRunner.cancel(env.store, jid)
        gate.set()
        assert jr.wait(jid, 20)
    finally:
        A.case_assessment = orig
    j = env.store.get_job(jid)
    assert j["status"] in ("cancelled", "succeeded")  # cancel is checked between stages
    if j["status"] == "cancelled":
        assert env.store.latest_successful_run(c["case_id"])["run_id"] == before
    # restart recovery
    jid2 = env.store.create_job(c["case_id"], "analyze")
    env.store.update_job(jid2, status="running")
    assert env.store.recover_interrupted_jobs() >= 1
    assert env.store.get_job(jid2)["status"] == "interrupted"


# ------------------------------------------------------------------ watcher (feature E)
def test_watch_partial_writes_rotation_duplicates_and_restart(env, tmp_path):
    from argos.watch import add_source, list_sources, poll_once
    d = tmp_path / "SYNTHETIC-watch"
    d.mkdir()
    c = env.case("watch")
    f = d / "app.jsonl"
    line = lambda i: json.dumps({"event_time": ts(i), "event_kind": "dns", "dns_query": f"q{i}.example"}) + "\n"  # noqa: E731
    f.write_text(line(0) + line(1) + line(2)[:20])  # partial third line
    src = add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    before = f.read_bytes()
    s = poll_once(env.store, env.settings, src)
    assert s["accepted"] == 2 and s["waiting_partial"] >= 1
    assert f.read_bytes() == before  # read-only
    with open(f, "a") as fh:
        fh.write(line(2)[20:] + line(3) + "{not json}\n")
    s = poll_once(env.store, env.settings, src)
    assert s["accepted"] == 2 and s["rejected"] == 1
    # restart: new Store, nothing re-imported
    st2 = Store(env.settings.db_path)
    s = poll_once(st2, env.settings, src)
    st2.close()
    assert s["segments_imported"] == 0
    assert env.store.count_events(c["case_id"]) == 4
    # rotation: rename and start a new file
    f.rename(d / "app.1.jsonl")
    (d / "app.jsonl").write_text(line(10))
    s = poll_once(env.store, env.settings, src)
    assert s["accepted"] == 1 and env.store.count_events(c["case_id"]) == 5
    # duplicate delivery of identical content under another name is not double counted
    (d / "copy.jsonl").write_text(line(10))
    poll_once(env.store, env.settings, src)
    assert env.store.count_events(c["case_id"]) == 5
    info = list_sources(env.store, c["case_id"])[0]
    assert info["last_event_time"] and info["last_poll"] and len(info["files"]) >= 2
    # invalid format for watching
    from argos.watch import WatchError
    with pytest.raises(WatchError):
        add_source(env.store, c, d, "*.xml", "sysmon_xml")


def test_watch_backpressure(env, tmp_path):
    from argos.watch import add_source, poll_once
    d = tmp_path / "w2"
    d.mkdir()
    c = env.case("watch2")
    (d / "big.jsonl").write_text("".join(json.dumps({"event_time": ts(i), "event_kind": "dns", "dns_query": f"q{i}"}) + "\n" for i in range(400)))
    src = add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    s = poll_once(env.store, env.settings, src, max_chunk_bytes=4096, max_cycle_bytes=8192)
    assert s["backpressure"] and env.store.count_events(c["case_id"]) < 400
    for _ in range(40):
        if not poll_once(env.store, env.settings, src, max_chunk_bytes=4096, max_cycle_bytes=8192)["backpressure"]:
            break
    assert env.store.count_events(c["case_id"]) == 400
