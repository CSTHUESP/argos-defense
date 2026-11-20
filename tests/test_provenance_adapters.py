"""EP-002 / vantage provenance through the real adapters: adapter -> normalization -> correlation."""
from argos.synthetic import sysmon_xml
from conftest import ev


def sysmon_chain(host="web-9", parent="C:\\Windows\\System32\\inetsrv\\w3wp.exe", dst="203.0.113.5"):
    t = "2026-11-03 10:00:0{}.000"
    return sysmon_xml([
        {"id": 1, "host": host, "data": {"UtcTime": t.format(0), "ProcessGuid": "{E-1}", "ProcessId": "10", "Image": "C:\\Windows\\System32\\cmd.exe",
                                         "CommandLine": "cmd.exe /c whoami", "ParentProcessGuid": "{E-0}", "ParentProcessId": "9", "ParentImage": parent}},
        {"id": 3, "host": host, "data": {"UtcTime": t.format(5), "ProcessGuid": "{E-1}", "ProcessId": "10", "Image": "C:\\Windows\\System32\\cmd.exe",
                                         "Protocol": "tcp", "Initiated": "true", "SourceIp": "10.0.0.9", "SourcePort": "5555",
                                         "DestinationIp": dst, "DestinationPort": "443"}},
    ])


def test_sysmon_connection_keeps_endpoint_vantage_and_correlates(env):
    c = env.case("sysm")
    r = env.ingest(c, env.write("chain.xml", sysmon_chain()), fmt="sysmon_xml")
    assert r["accepted"] == 2
    evs = list(env.store.iter_events(c["case_id"]))
    assert {e["observation_vantage"] for e in evs} == {"managed_endpoint"}
    assert all("vantage_defaulted" not in " ".join(e["quality_warnings"]) for e in evs)
    env.analyze(c)
    a = env.alerts(c, "ARG-EP-002")
    assert len(a) == 1 and {x["step"] for x in a[0]["evidence"]} == {"shell_start", "external_connection"}
    assert env.alerts(c, "ARG-EP-001")


def test_sysmon_internal_destination_no_ep002(env):
    c = env.case("sysm2")
    env.ingest(c, env.write("chain2.xml", sysmon_chain(dst="10.1.2.3")), fmt="sysmon_xml")
    env.analyze(c)
    assert env.alerts(c, "ARG-EP-002") == []


def test_zeek_connection_is_victim_network_and_cannot_satisfy_endpoint_rule(env):
    c = env.case("zk")
    conn = [{"ts": 1793700000.0, "uid": "C1", "id.orig_h": "10.0.0.9", "id.orig_p": 5555, "id.resp_h": "203.0.113.5", "id.resp_p": 443,
             "proto": "tcp", "conn_state": "SF", "observation_vantage": "managed_endpoint", "process_guid": "{E-1}"}]
    env.ingest(c, env.write("chain.xml", sysmon_chain()).with_name("chain.xml"), fmt="sysmon_xml")
    env.ingest(c, conn, fmt="zeek_jsonl", options={"zeek_log": "conn"})
    z = [e for e in env.store.iter_events(c["case_id"]) if e["source_format"] == "zeek_jsonl"][0]
    assert z["observation_vantage"] == "victim_network" and z["process_guid"] is None  # fields in the record cannot claim endpoint visibility
    env.analyze(c)
    a = env.alerts(c, "ARG-EP-002")[0]
    assert all(x["input_id"] != z["input_id"] for x in a["evidence"])


def test_native_network_without_vantage_defaults_conservatively(env):
    c = env.case("nat1")
    env.ingest(c, [ev(0, event_kind="network_connection", src_ip="10.0.0.1", dst_ip="203.0.113.5", dst_port=443)])
    e = next(env.store.iter_events(c["case_id"]))
    assert e["observation_vantage"] == "victim_network"
    assert "vantage_defaulted_conservatively:victim_network" in e["quality_warnings"]


def test_native_network_with_process_fields_but_no_vantage_is_rejected(env):
    c = env.case("nat2")
    r = env.ingest(c, [ev(0, event_kind="network_connection", host="w1", process_guid="{c}", dst_ip="203.0.113.5")])
    assert r["accepted"] == 0 and r["rejected"] == 1
    assert "ambiguous observation_vantage" in env.store.list_rejects(c["case_id"])[0]["reason"]


def test_victim_network_records_never_satisfy_endpoint_rules(env):
    # same shell + connection shape but declared from a network sensor: EP-002 needs managed_endpoint
    rows = [ev(0, event_kind="process_start", host="w1", process_guid="{c}", process_image="C:\\Windows\\System32\\cmd.exe",
               parent_image="C:\\Windows\\System32\\inetsrv\\w3wp.exe", parent_process_guid="{p}"),
            ev(5, event_kind="network_connection", host="w1", process_guid="{c}", dst_ip="203.0.113.5", observation_vantage="victim_network")]
    c = env.run("vn", rows)
    assert env.alerts(c, "ARG-EP-002") == []
