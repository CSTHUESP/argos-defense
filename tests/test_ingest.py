"""Adapters, normalization, idempotency, timestamps, data quality (acceptance 9, 10)."""
import json

import pytest

from argos.ingest.pipeline import ImportError_, safe_original_name
from argos.normalize.mappers import MappingError
from conftest import ev


def test_native_minimum_schema_and_nulls(env):
    c = env.case("n1")
    r = env.ingest(c, [ev(0, event_kind="authentication", user="a@x", tenant_id="t1", outcome="failure")])
    assert r["status"] == "imported" and r["accepted"] == 1
    e = next(env.store.iter_events(c["case_id"]))
    for k in ("schema_version", "event_id", "event_time", "original_timestamp", "ingested_at", "source_type",
              "observation_vantage", "event_kind", "evidence_ref", "quality_warnings"):
        assert e[k] is not None
    assert e["observation_vantage"] == "identity_cloud"  # defaulted from kind, flagged
    assert "vantage_defaulted_from_event_kind" in e["quality_warnings"]
    # unavailable fields are null, never fabricated
    assert e["src_ip"] is None and e["host"] is None and e["process_guid"] is None and e["bytes_src_to_dst"] is None


def test_idempotent_reimport(env):
    c = env.case("idem")
    p = env.write("a.jsonl", [ev(i, event_kind="dns", dns_query=f"h{i}.x", src_ip="10.0.0.1") for i in range(5)])
    r1 = env.ingest(c, p)
    r2 = env.ingest(c, p)
    assert r1["new_events"] == 5 and r2["status"] == "already_imported" and r2["new_events"] == 0
    assert env.store.count_events(c["case_id"]) == 5


def test_identical_distinct_records_are_kept(env):
    c = env.case("dupes")
    row = ev(10, event_kind="http", src_ip="10.0.0.1", http_uri="/a", http_status=200)
    r = env.ingest(c, [row, row, row])
    assert r["accepted"] == 3
    assert env.store.count_events(c["case_id"]) == 3


def test_out_of_order_events_processed_in_event_time(env):
    S = "192.0.2.4"  # AUTH-003 v2 groups per source address
    rows = [ev(3, event_kind="authentication", tenant_id="t", user="u@x", outcome="success", src_ip=S),
            ev(0, event_kind="authentication", tenant_id="t", user="u@x", outcome="failure", src_ip=S),
            ev(1, event_kind="authentication", tenant_id="t", user="u@x", outcome="failure", src_ip=S),
            ev(2, event_kind="authentication", tenant_id="t", user="u@x", outcome="failure", src_ip=S),
            ev(0.5, event_kind="authentication", tenant_id="t", user="u@x", outcome="failure", src_ip=S),
            ev(1.5, event_kind="authentication", tenant_id="t", user="u@x", outcome="failure", src_ip=S)]
    c = env.run("ooo", rows)
    times = [e["event_epoch"] for e in env.store.iter_events(c["case_id"])]
    assert times == sorted(times)
    assert len(env.alerts(c, "ARG-AUTH-003")) == 1  # 5 failures then success despite shuffled file order


def test_ambiguous_timestamp_rejected_without_option_and_accepted_with_it(env):
    c = env.case("tz1")
    rows = [{"event_time": "2026-11-03 10:00:00", "event_kind": "dns", "dns_query": "a.x"}]
    r = env.ingest(c, rows, name="tz.jsonl")
    assert r["accepted"] == 0 and r["rejected"] == 1
    assert "ambiguous" in env.store.list_rejects(c["case_id"])[0]["reason"]
    c2 = env.case("tz2")
    r = env.ingest(c2, env.tmp / "tz.jsonl", options={"assume_tz": "Europe/Budapest"})
    assert r["accepted"] == 1
    e = next(env.store.iter_events(c2["case_id"]))
    assert e["event_time"] == "2026-11-03T09:00:00.000000Z"  # CET = UTC+1 in November
    assert e["original_timestamp"] == "2026-11-03 10:00:00" and e["timestamp_note"] == "zone_assumed:Europe/Budapest"


def test_malformed_records_are_reported_not_dropped(env):
    c = env.case("bad")
    p = env.write("bad.jsonl", '{"event_time":"2026-11-03T10:00:00Z","event_kind":"dns","dns_query":"a"}\n{not json\n[1,2]\n'
                  '{"event_time":"2026-11-03T10:00:00Z","event_kind":"teleport"}\n{"event_kind":"dns"}\n')
    r = env.ingest(c, p)
    assert r["accepted"] == 1 and r["rejected"] == 4 and r["total"] == 5
    reasons = " | ".join(x["reason"] for x in env.store.list_rejects(c["case_id"]))
    assert "malformed JSON" in reasons and "not a JSON object" in reasons and "event_kind" in reasons and "missing timestamp" in reasons


def test_splunk_json_result_wrapper_and_proxy_profile(env):
    c = env.case("sj")
    rows = [{"preview": False, "result": {"_time": "2026-11-03T10:00:00.000+00:00", "c_ip": "192.0.2.5", "cs_host": "h.example",
                                          "cs_method": "GET", "cs_uri": "/x", "sc_status": "404", "cs_bytes": "100", "sc_bytes": "2000"}}]
    r = env.ingest(c, rows, fmt="splunk_json", options={"profile": "proxy"})
    assert r["accepted"] == 1
    e = next(env.store.iter_events(c["case_id"]))
    assert e["src_ip"] == "192.0.2.5" and e["http_status"] == 404 and e["bytes_src_to_dst"] == 100 and e["bytes_dst_to_src"] == 2000
    assert "cs_bytes=client_to_server" in e["bytes_basis"]
    assert e["observation_vantage"] == "victim_network"


def test_splunk_csv_requires_explicit_mapping(env):
    c = env.case("sc")
    p = env.write("p.csv", "_time,c_ip\n2026-11-03T10:00:00Z,192.0.2.1\n")
    with pytest.raises(MappingError):
        env.ingest(c, p, fmt="splunk_csv")
    m = env.write("map.yaml", "time: _time\nfields:\n  src_ip: c_ip\n  bytes_src_to_dst: c_ip\nconstants: {event_kind: http}\n")
    with pytest.raises(MappingError, match="bytes_basis"):
        env.ingest(c, p, fmt="splunk_csv", options={"mapping": str(m)})
    m2 = env.write("map2.yaml", "time: _time\nfields:\n  src_ip: c_ip\nconstants: {event_kind: http, observation_vantage: victim_network}\n")
    r = env.ingest(c, p, fmt="splunk_csv", options={"mapping": str(m2)})
    assert r["accepted"] == 1


def test_sysmon_xml_supported_ids_and_reject_others(env):
    from argos.synthetic import sysmon_events, sysmon_xml
    c = env.case("sy")
    p = env.write("s.xml", sysmon_xml(sysmon_events()))
    r = env.ingest(c, p, fmt="sysmon_xml")
    assert r["accepted"] == 8 and r["rejected"] == 1
    kinds = {e["event_kind"] for e in env.store.iter_events(c["case_id"])}
    assert kinds == {"process_start", "network_connection", "file_create", "dns"}
    assert "unsupported Sysmon EventID" in env.store.list_rejects(c["case_id"])[0]["reason"]


def test_sysmon_xxe_and_doctype_rejected(env):
    c = env.case("xxe")
    p = env.write("x.xml", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><Events><Event>&x;</Event></Events>')
    r = env.ingest(c, p, fmt="sysmon_xml")
    assert r["status"] == "rejected" and "not accepted" in r["error"]
    assert env.store.count_events(c["case_id"]) == 0


def test_zeek_logs_preserve_uid(env):
    c = env.case("zk")
    conn = [{"ts": 1793700000.5, "uid": "CabC1", "id.orig_h": "10.0.0.1", "id.orig_p": 5000, "id.resp_h": "192.0.2.9", "id.resp_p": 443,
             "proto": "tcp", "conn_state": "SF", "orig_bytes": 10, "resp_bytes": 99}]
    env.ingest(c, conn, fmt="zeek_jsonl", options={"zeek_log": "conn"})
    http = [{"ts": 1793700001, "uid": "CabC1", "id.orig_h": "10.0.0.1", "id.orig_p": 5000, "id.resp_h": "192.0.2.9", "id.resp_p": 80,
             "method": "GET", "host": "h", "uri": "/", "status_code": 200}]
    env.ingest(c, http, fmt="zeek_jsonl")  # auto-detected
    dns = [{"ts": 1793700002, "uid": "Cd1", "id.orig_h": "10.0.0.1", "id.orig_p": 5353, "id.resp_h": "10.0.0.2", "id.resp_p": 53,
            "query": "a.example", "rcode_name": "NOERROR"}]
    env.ingest(c, dns, fmt="zeek_jsonl")
    evs = list(env.store.iter_events(c["case_id"]))
    assert [e["event_kind"] for e in evs] == ["network_connection", "http", "dns"]
    assert evs[0]["zeek_uid"] == "CabC1" and evs[1]["zeek_uid"] == "CabC1"
    assert evs[0]["bytes_src_to_dst"] == 10 and "originator->responder" in evs[0]["bytes_basis"]


def test_hostile_filenames_rejected():
    for bad in ["../../etc/passwd.jsonl", "a/b.jsonl", "..\\x.jsonl", "evil.exe", "", "x\x00.jsonl"]:
        with pytest.raises(ImportError_):
            safe_original_name(bad)
    assert safe_original_name("proxy export (1).csv") == "proxy export (1).csv"
    assert safe_original_name("sysmon export é.xml") == "sysmon export é.xml"  # non-ASCII names are fine
    assert safe_original_name("Prüfung 测试.jsonl") == "Prüfung 测试.jsonl"
    for bad in ["a\nb.jsonl", "a\tb.jsonl", "é/../x.jsonl", "..é.jsonl"]:
        with pytest.raises(ImportError_):
            safe_original_name(bad)


def test_size_limit_enforced(env):
    env.settings.max_file_bytes = 100
    c = env.case("big")
    with pytest.raises(ImportError_, match="limit"):
        env.ingest(c, [ev(i, event_kind="dns", dns_query="x" * 50) for i in range(10)])


def test_record_size_limit(env):
    env.settings.max_record_bytes = 200
    c = env.case("rec")
    r = env.ingest(c, [ev(0, event_kind="dns", dns_query="a"), ev(1, event_kind="dns", dns_query="b" * 500)])
    assert r["accepted"] == 1 and r["rejected"] == 1


def test_case_boundaries_same_file_two_cases(env):
    a, b = env.case("ca"), env.case("cb")
    p = env.write("same.jsonl", [ev(0, event_kind="dns", dns_query="a.x")])
    env.ingest(a, p)
    env.ingest(b, p)
    ea = next(env.store.iter_events(a["case_id"]))
    eb = next(env.store.iter_events(b["case_id"]))
    assert ea["event_id"] != eb["event_id"] and ea["case_id"] != eb["case_id"]


def test_synthetic_and_real_not_mixed(env):
    env.case("mix", synthetic=True)
    with pytest.raises(ValueError, match="never mixed"):
        env.store.create_case("mix", synthetic=False)


def test_original_copy_retained_and_hash(env, tmp_path):
    import hashlib
    c = env.case("orig")
    p = env.write("o.jsonl", [ev(0, event_kind="dns", dns_query="a")])
    r = env.ingest(c, p)
    assert r["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()
    inp = env.store.list_inputs(c["case_id"])[0]
    assert open(inp["stored_path"], "rb").read() == p.read_bytes()
    assert inp["provenance_trust"] == "unverified" and json.loads(inp["options"]) == {}


def test_outcome_synonyms_normalized_conservatively(env):
    c = env.case("outc")
    env.ingest(c, [ev(0, event_kind="authentication", outcome="Failed"), ev(1, event_kind="authentication", outcome="SUCCEEDED"),
                   ev(2, event_kind="authentication", outcome="50126")])
    evs = list(env.store.iter_events(c["case_id"]))
    assert [e["outcome"] for e in evs] == ["failure", "success", "unknown"]
    assert any(w.startswith("outcome_normalized") for w in evs[0]["quality_warnings"])
    assert any(w.startswith("outcome_unrecognized") for w in evs[2]["quality_warnings"])
