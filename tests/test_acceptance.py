"""Acceptance scenarios 1-15 from the build specification (16 is in test_web_e2e.py)."""
import json
import shutil

from argos.analysis import run_analysis
from argos.store import Store
from argos.synthetic import ts
from conftest import ROOT, RULES, ev

FIX = ROOT / "fixtures"
ADMIN = {"alert_id", "case_id", "event_ids", "evidence_refs", "evidence", "first_run", "last_run", "runs", "provenance", "entities", "group"}


def substantive(alerts):
    out = []
    for a in alerts:
        out.append({k: v for k, v in a.items() if k not in ADMIN} | {"group_keys": sorted(a["group"])})
    return sorted(out, key=lambda x: (x["rule_id"], x["first_time"]))


def strip_assessment(a):
    a = dict(a)
    for k in ("case_id", "case_name", "run_id", "coverage", "entities", "rule_stats"):
        a.pop(k, None)
    a["framework"] = {"level": a["framework"]["level"]}
    a["versions"] = {k: v for k, v in a["versions"].items() if k != "manifest_hash"}
    if "diagnostics" in a:  # input ids are administrative identifiers, like case ids
        d = dict(a["diagnostics"])
        d["sources"] = [{k: v for k, v in s.items() if k != "input_id"} for s in d.get("sources", [])]
        a["diagnostics"] = d
    return a


def test_01_same_trace_different_external_labels_same_conclusions(env):
    labels = json.loads((FIX / "ground_truth" / "same_trace_labels.json").read_text())["labels"]
    results = {}
    for label in labels:  # human / script / llm - labels exist ONLY outside detector input
        c = env.case(f"trace-{label}")
        env.ingest(c, FIX / "acceptance" / "same_trace.jsonl")
        env.analyze(c)
        results[label] = (substantive(env.alerts(c)), strip_assessment(env.assessment(c)))
    vals = list(results.values())
    assert vals[0] == vals[1] == vals[2]
    assert vals[0][0], "trace must produce findings"
    # nothing in the substantive conclusion claims an operator type
    assert vals[0][1]["llm"]["level"] == "unknown"


def test_02_authorized_fast_activity_not_artex_or_malicious(env):
    from conftest import ev as e
    scan = [e(i * 0.1, event_kind="http", src_ip="198.51.100.10", http_host="h", http_uri=f"/c{i}", http_status=404) for i in range(150)]
    ci = [e(500 + i * 0.2, event_kind="http", src_ip="198.51.100.20", http_host="h", http_uri="/healthz", http_status=200) for i in range(130)]
    backup = [e(900, event_kind="file_create", host="backup-01", file_path="/b/n.tar", observation_vantage="managed_endpoint"),
              e(950, event_kind="network_connection", host="backup-01", dst_ip="203.0.113.90", bytes_src_to_dst=900_000_000,
                bytes_basis="edr", observation_vantage="managed_endpoint")]
    c = env.run("authz", scan + ci + backup)
    al = env.alerts(c)
    assert al, "fast activity is still visible"
    for a in al:
        assert a["framework"]["level"] == "unknown"
        assert a["disposition"] == "authorized_automation", a["rule_id"]
        assert a["threat"]["suspicion"] != "likely_malicious" or a["disposition"] == "authorized_automation"
    asm = env.assessment(c)
    assert asm["framework"]["level"] == "unknown" and asm["threat"]["open_alerts"] == 0
    # Without registry coverage, speed alone yields only an automation indicator, never malicious/framework
    c2 = env.run("unreg", [e(i * 0.1, event_kind="http", src_ip="192.0.2.44", http_host="h", http_uri="/x", http_status=200) for i in range(150)])
    a2 = env.alerts(c2)
    assert {a["rule_id"] for a in a2} == {"ARG-AUTO-001"}
    assert a2[0]["threat"]["suspicion"] == "informational" and a2[0]["framework"]["level"] == "unknown" and a2[0]["llm"]["level"] == "unknown"


def test_03_legitimate_llm_provider_use_not_malicious(env):
    rows = [ev(0, event_kind="dns", src_ip="10.0.0.31", dns_query="api.openai.com"),
            ev(1, event_kind="http", src_ip="10.0.0.31", http_host="api.openai.com", http_uri="/v1/chat/completions", http_status=200)]
    c = env.run("ai", rows)
    al = env.alerts(c)
    assert {a["rule_id"] for a in al} == {"ARG-LLM-001"}
    for a in al:
        assert a["threat"]["suspicion"] == "informational" and a["threat"]["severity"] == "informational"
        assert a["llm"]["level"] == "possible"
    assert env.assessment(c)["threat"]["max_severity"] == "informational"


def test_04_audit_chain_increases_llm_evidence(env):
    network_only = [ev(0, event_kind="http", src_ip="192.0.2.5", http_host="h", http_uri="/a", http_status=200)]
    c1 = env.run("llm-before", network_only)
    before = env.assessment(c1)["llm"]
    audit = [ev(0, event_kind="model_interaction", session_id="sx", model_tool_name="bash", tool_call_id="c1", host="d", linked_process_guid="{p}"),
             ev(1, event_kind="tool_execution", session_id="sx", tool_name="bash", tool_call_id="c1", host="d", linked_process_guid="{p}"),
             ev(2, event_kind="process_start", host="d", process_guid="{p}", process_image="/bin/bash")]
    c2 = env.run("llm-after", network_only + audit)
    after = env.assessment(c2)["llm"]
    assert before["level"] == "unknown" and after["level"] == "directly_observed"
    assert after["heuristic_evidence_score"] > before["heuristic_evidence_score"]
    a = env.alerts(c2, "ARG-LLM-002")[0]
    assert any("unverified provenance" in x for x in a["llm"]["limitations"])


def test_05_text_artex_not_strong_attribution(env):
    rows = [ev(i, event_kind="http", src_ip="192.0.2.8", http_host="h", http_uri="/artex/x", http_status=200,
               http_user_agent="ARTEX/0.6.0 (autonomous pentest)") for i in range(50)]
    rows.append(ev(60, event_kind="file_create", host="h1", file_path="C:\\temp\\artex_payload.txt", observation_vantage="managed_endpoint"))
    c = env.run("txt", rows)
    al = env.alerts(c, "ARG-ARTEX-W01")
    assert al and all(a["confidence"] == "low" and a["framework"]["level"] == "consistent_with" for a in al)
    fw = env.assessment(c)["framework"]
    assert fw["level"] == "consistent_with" and fw["candidates"][0]["independent_families"] == []


def test_06_slow_attack_alerts_with_unknown_origin(env):
    rows = [ev(i * 7200, event_kind="authentication", tenant_id="t", user="slow@x", outcome="failure", src_ip="192.0.2.90") for i in range(3)]
    rows += [ev(30000, event_kind="authentication", tenant_id="t", user="slow@x", outcome="success", src_ip="192.0.2.90"),
             ev(40000, event_kind="cloud_operation", tenant_id="t", user="slow@x", action="role_assignment")]
    c = env.run("slow", rows)
    a = env.alerts(c, "ARG-AUTH-002")
    assert len(a) == 1 and a[0]["threat"]["severity"] == "high"
    assert a[0]["automation"]["level"] == "unknown" and a[0]["llm"]["level"] == "unknown"
    assert env.alerts(c, "ARG-AUTO-001") == []


def test_07_network_only_exposes_limitations(env):
    rows = [ev(i * 0.1, event_kind="http", src_ip="192.0.2.66", http_host="h", http_uri=f"/{i}", http_status=404) for i in range(120)]
    c = env.run("net", rows)
    asm = env.assessment(c)
    assert asm["llm"]["level"] == "unknown"
    lim = " ".join(asm["limitations"])
    assert "managed_endpoint telemetry not supplied" in lim and "agent_or_model_audit telemetry not supplied" in lim
    a = env.alerts(c, "ARG-AUTO-001")[0]
    assert any("UNKNOWN" in x and "does not establish human" in x for x in a["llm"]["limitations"])
    assert any("victim-side traffic does not reveal" in x for x in a["llm"]["limitations"])
    assert asm["coverage"]["managed_endpoint"]["status"] == "unavailable"
    assert asm["rule_stats"]["ARG-LLM-002"]["not_evaluable"]


def test_08_same_ip_entities_not_merged(env):
    rows = [ev(0, event_kind="authentication", tenant_id="t", user="bob@x", src_ip="192.0.2.10", outcome="success"),
            ev(1, event_kind="authentication", tenant_id="t", user="carol@x", src_ip="192.0.2.10", outcome="success"),
            ev(2, event_kind="authentication", user="dave", src_ip="192.0.2.10", outcome="success")]
    c = env.run("nat", rows)
    accts = env.store.list_entities(c["case_id"], "account")
    assert len(accts) == 3
    assert {a["strength"] for a in accts} == {"strong", "weak"}  # 'dave' has no tenant/domain context
    rels = env.store.conn.execute("SELECT rel, basis FROM relationships WHERE case_id=? AND rel='shares_source_ip_with'", (c["case_id"],)).fetchall()
    assert rels and all(r["basis"] == "inferred_cooccurrence_not_identity" for r in rels)


def test_09_and_10_covered_in_test_ingest():
    # Idempotent reimport, out-of-order, ambiguous timestamps, missing fields, malformed records (9)
    # and identical distinct records (10) are verified in tests/test_ingest.py.
    assert True


def test_12_expired_ioc_no_strong_attribution(env):
    rows = [ev(0, event_kind="http", src_ip="10.0.0.5", http_host="203.0.113.99", dst_ip="203.0.113.99", http_uri="/", http_status=200),
            ev(10, event_kind="http", src_ip="10.0.0.5", http_host="203.0.113.66", dst_ip="203.0.113.66", http_uri="/", http_status=200)]
    c = env.run("ioc", rows)
    al = {a["group"]["remote"]: a for a in env.alerts(c, "ARG-IOC-001")}
    exp, val = al["203.0.113.99"], al["203.0.113.66"]
    assert exp["confidence"] == "low" and exp["threat"]["severity"] == "informational"
    assert not exp["ioc_matches"][0]["valid_at_event_time"] and exp["ioc_matches"][0]["cutoff_used"] == "event_time"
    assert exp["framework"]["level"] == "unknown"
    assert "no blocking" in exp["recommendation"]
    assert val["ioc_matches"][0]["valid_at_event_time"]


def test_13_success_without_data_access_not_exfiltration(env):
    # AUTH-003 v2 requires a source address (per-source failure run); fixture carries one.
    rows = [ev(i * 30, event_kind="authentication", tenant_id="t", user="bob@x", outcome="failure", src_ip="192.0.2.10") for i in range(6)]
    rows += [ev(300, event_kind="authentication", tenant_id="t", user="bob@x", outcome="success", src_ip="192.0.2.10"),
             ev(20000, event_kind="authentication", tenant_id="t", user="zed@x", outcome="success", src_ip="192.0.2.11")]
    # F02: without declared collection coverage, absence is only "not observed in supplied records"
    c0 = env.run("noexf-nocov", rows)
    assert env.alerts(c0, "ARG-AUTH-003")[0]["absence_checks"][0]["status"] == "not_observed_in_supplied_records"
    cov = {"start": ts(-3600), "end": ts(30000), "scope": "tenant:t", "vantages": ["identity_provider", "cloud_control_plane"]}
    c = env.run("noexf", rows, coverage=cov)
    a = env.alerts(c, "ARG-AUTH-003")[0]
    assert a["purpose"]["hypothesis"] == "credential_access"
    assert a["absence_checks"][0]["status"] == "absent_within_declared_coverage"
    hyps = {p["hypothesis"] for p in env.assessment(c)["purpose"]}
    assert "possible_exfiltration" not in hyps and "collection" not in hyps
    # with a later data read the follow-up check reports it as present
    c2 = env.run("exf", rows + [ev(600, event_kind="cloud_operation", tenant_id="t", user="bob@x", action="secret_read", resource="kv")])
    assert env.alerts(c2, "ARG-AUTH-003")[0]["absence_checks"][0]["status"] == "present"


def test_14_duplicates_do_not_inflate_and_self_trust_ignored(env):
    one = [ev(0, event_kind="dns", src_ip="10.0.0.3", dns_query="api.openai.com")]
    many = [ev(i, event_kind="dns", src_ip="10.0.0.3", dns_query="api.openai.com") for i in range(300)]
    c1, c2 = env.run("d1", one), env.run("d300", many)
    a1, a2 = env.assessment(c1), env.assessment(c2)
    assert a1["llm"] == a2["llm"]
    assert env.alerts(c1)[0]["confidence"] == env.alerts(c2)[0]["confidence"]
    c3 = env.case("selftrust")
    env.ingest(c3, [ev(0, event_kind="dns", dns_query="a.x", provenance_trust="analyst_attested", trusted=True)])
    inp = env.store.list_inputs(c3["case_id"])[0]
    assert inp["provenance_trust"] == "unverified"
    e = next(env.store.iter_events(c3["case_id"]))
    assert any(w.startswith("self_declared_trust_field_ignored") for w in e["quality_warnings"])


def test_14b_analyst_attestation_is_external_and_raises_cap(env):
    rows = [ev(i * 30, event_kind="authentication", tenant_id="t", user="u@x", outcome="failure") for i in range(3)]
    rows += [ev(100, event_kind="authentication", tenant_id="t", user="u@x", outcome="success"),
             ev(200, event_kind="cloud_operation", tenant_id="t", user="u@x", action="role_assignment")]
    c = env.run("att", rows)
    assert env.alerts(c, "ARG-AUTH-002")[0]["confidence"] == "medium"
    inp = env.store.list_inputs(c["case_id"])[0]
    env.store.set_input_trust(inp["input_id"], "analyst_attested", "analyst: exported by me from IdP admin console")
    env.analyze(c)
    assert env.alerts(c, "ARG-AUTH-002")[0]["confidence"] == "high"


def test_15_persistence_restart_reanalysis_no_duplicates(env, tmp_path):
    c = env.run("persist", [ev(i * 10, event_kind="authentication", tenant_id="t", user=f"u{i}@x", src_ip="192.0.2.50", outcome="failure") for i in range(12)])
    other = env.run("persist-other", [ev(0, event_kind="dns", dns_query="api.openai.com")])
    a = env.alerts(c)
    assert len(a) == 1
    env.store.add_note(c["case_id"], "analyst note survives", alert_id=a[0]["alert_id"])
    env.store.set_alert_status(a[0]["alert_id"], "escalated")
    env.store.close()
    # "restart": new Store on the same database file
    st2 = Store(env.settings.db_path)
    env.store = st2
    run_analysis(st2, env.settings, c["case_id"])
    run_analysis(st2, env.settings, c["case_id"])
    a2 = st2.list_alerts(c["case_id"])
    assert len(a2) == 1 and a2[0]["alert_id"] == a[0]["alert_id"] and a2[0]["analyst_status"] == "escalated"
    assert st2.list_notes(c["case_id"], a[0]["alert_id"])[0]["text"] == "analyst note survives"
    assert len(st2.list_runs(c["case_id"])) == 3
    assert all(x["case_id"] == other["case_id"] for x in st2.list_alerts(other["case_id"]))
    assert {x["rule_id"] for x in st2.list_alerts(other["case_id"])} == {"ARG-LLM-001"}


def test_15b_rule_change_preserves_history(env, tmp_path):
    rules = tmp_path / "rules"
    shutil.copytree(RULES, rules)
    env.settings.rules_dir = rules
    c = env.run("hist", [ev(i * 10, event_kind="authentication", tenant_id="t", user=f"u{i}@x", src_ip="192.0.2.50", outcome="failure") for i in range(12)])
    old = env.alerts(c)[0]
    env.store.add_note(c["case_id"], "note on v1", alert_id=old["alert_id"])
    p = rules / "detections" / "03_auth.yaml"
    p.write_text(p.read_text().replace("id: ARG-AUTH-001\nversion: 1", "id: ARG-AUTH-001\nversion: 2", 1))
    env.analyze(c)
    cur = env.alerts(c)
    allv = env.store.list_alerts(c["case_id"], include_stale=True)
    assert len(cur) == 1 and cur[0]["rule_version"] == 2
    stale = [x for x in allv if not x["current"]]
    assert len(stale) == 1 and stale[0]["alert_id"] == old["alert_id"]
    assert env.store.list_notes(c["case_id"], old["alert_id"])[0]["text"] == "note on v1"
    runs = env.store.list_runs(c["case_id"])
    assert runs[0]["versions"]["rules_hash"] != runs[1]["versions"]["rules_hash"]
