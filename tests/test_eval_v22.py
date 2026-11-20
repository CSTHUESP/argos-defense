"""FU5: the eval-v2.2 attribution scorer identifies ground-truth chains by EXACT fixture records.

A prediction that pairs a chain's model request with an execution from another collector/session that merely
reuses the same call string (or the same process GUID) is an overclaim and does not mark the real chain detected.
The v2.1 scorer accepted that mismatch; the regression test documents it.
"""
import importlib.util

from conftest import ROOT


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


E = _load("eval_v22")
E21 = _load("eval_v21")

U = "u0001"
LABELS = {U: {"scenario": "N6_valid_chain_plus_reused_call_and_guid_in_other_collector", "threat": "benign",
              "origin": "llm_agent", "framework": None,
              "chains": [{"chain_id": f"{U}:chain0", "model": "events.jsonl:10",
                          "executions": ["events.jsonl:11", "events.jsonl:12"]}]}}
CALL, GUID = f"call-{U}", f"{{{U}-p0}}"
EV = {
    # collector A, session A: the real chain
    "m": {"_src": "events.jsonl:10", "event_kind": "model_interaction", "tool_call_id": CALL, "session_id": f"sessA-{U}", "host": f"{U}-host"},
    "x": {"_src": "events.jsonl:11", "event_kind": "tool_execution", "tool_call_id": CALL, "session_id": f"sessA-{U}", "host": f"{U}-host"},
    "p": {"_src": "events.jsonl:12", "event_kind": "process_start", "process_guid": GUID, "host": f"{U}-host"},
    # collector B, session B, another host: SAME call string and SAME process GUID, unrelated
    "xb": {"_src": "collector_b.jsonl:3", "event_kind": "tool_execution", "tool_call_id": CALL, "session_id": f"sessB-{U}", "host": f"{U}-otherhost"},
    "pb": {"_src": "collector_b.jsonl:4", "event_kind": "process_start", "process_guid": GUID, "host": f"{U}-otherhost"},
}


def alert(aid, ids, llm="directly_observed"):
    return {"alert_id": aid, "rule_id": "ARG-LLM-002", "event_ids": ids, "llm": {"level": llm}, "framework": {"level": "unknown"}}


def test_valid_chain_detected_without_overclaim():
    for ids in (["m", "x"], ["m", "p"], ["m", "x", "p"]):
        r = E.score([alert("a", ids)], EV, LABELS)
        assert r["llm_overclaims"] == [] and r["labelled_chains_directly_observed"] == 1, ids


def test_same_call_other_collector_session_is_overclaim_and_not_detection():
    r = E.score([alert("bad", ["m", "xb"])], EV, LABELS)
    assert len(r["llm_overclaims"]) == 1 and r["llm_overclaims"][0]["supported_max"] == "possible"
    assert r["labelled_chains_directly_observed"] == 0 and r["labelled_chains_missed"] == [f"{U}:chain0"]


def test_reused_process_guid_other_host_is_overclaim_and_not_detection():
    r = E.score([alert("bad", ["m", "pb"])], EV, LABELS)
    assert len(r["llm_overclaims"]) == 1 and r["labelled_chains_directly_observed"] == 0


def test_bad_alert_does_not_borrow_detection_from_a_good_alert_and_vice_versa():
    r = E.score([alert("bad", ["m", "xb"]), alert("ok", ["m", "x"])], EV, LABELS)
    assert [o["alert"] for o in r["llm_overclaims"]] == ["bad"] and r["labelled_chains_directly_observed"] == 1


def test_execution_without_model_and_possible_level_are_not_overclaims():
    r = E.score([alert("a", ["x", "p"], llm="possible"), alert("b", ["m"], llm="possible")], EV, LABELS)
    assert len(r["llm_overclaims"]) == 1 and r["llm_overclaims"][0]["alert"] == "a"  # no model record -> max unknown
    assert r["labelled_chains_directly_observed"] == 0


def test_v21_scorer_accepted_the_mismatch_regression_evidence():
    """Documents defect FU5: the v2.1 scorer (call-string/GUID keyed) accepted the cross-collector pairing."""
    lab21 = {U: dict(LABELS[U], chains=[{"call": CALL, "process": GUID}])}
    ev21 = {k: {kk: vv for kk, vv in v.items() if kk != "_src"} for k, v in EV.items()}
    r = E21.score([alert("bad", ["m", "xb"])], ev21, lab21)
    assert r["llm_overclaims"] == [] and r["labelled_chains_directly_observed"] == 1


def test_frozen_v22_labels_reference_exact_records():
    import json
    for name in ("dev", "reserved"):
        d = ROOT / "fixtures" / "eval_v2_2" / name
        files = {fn: (d / fn).read_text().splitlines() for fn in ("events.jsonl", "collector_b.jsonl")}
        units = json.loads((d / "labels.json").read_text())["units"]
        n6 = [u for u, l in units.items() if l["scenario"].startswith("N6_")]
        assert n6
        for u, lab in units.items():
            for c in lab["chains"]:
                fn, ln = c["model"].split(":")
                assert json.loads(files[fn][int(ln) - 1])["event_kind"] == "model_interaction"
                for x in c["executions"]:
                    fn, ln = x.split(":")
                    assert json.loads(files[fn][int(ln) - 1])["event_kind"] in ("tool_execution", "process_start")
