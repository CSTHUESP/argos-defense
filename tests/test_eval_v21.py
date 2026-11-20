"""R06: the attribution scorer is independent of the production correlator and counts injected wrong
predictions as errors; valid chains are scored correctly; unrelated activity in a mixed unit does not
inherit a valid chain's attribution."""
import importlib.util

import pytest

from conftest import ROOT

spec = importlib.util.spec_from_file_location("eval_v21", ROOT / "scripts" / "eval_v21.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

LABELS = {
    "u0001": {"scenario": "N5_mixed_valid_chain_and_unrelated_execution", "threat": "benign", "origin": "llm_agent",
              "chains": [{"call": "call-u0001-ok", "process": "{u0001-p-ok}"}], "framework": None},
    "u0002": {"scenario": "N1_tool_only_automation", "threat": "benign", "origin": "llm_agent", "chains": [], "framework": None},
    "u0003": {"scenario": "N2_model_only", "threat": "benign", "origin": "llm_agent", "chains": [], "framework": None},
}
EV = {
    "m1": {"event_kind": "model_interaction", "tool_call_id": "call-u0001-ok", "session_id": "sess-u0001", "host": "u0001-host"},
    "x1": {"event_kind": "tool_execution", "tool_call_id": "call-u0001-ok", "session_id": "sess-u0001", "host": "u0001-host"},
    "p1": {"event_kind": "process_start", "process_guid": "{u0001-p-ok}", "host": "u0001-host"},
    "x2": {"event_kind": "tool_execution", "tool_call_id": "job-u0001", "session_id": "cron-u0001", "host": "u0001-host"},
    "p2": {"event_kind": "process_start", "process_guid": "{u0001-p-other}", "host": "u0001-host"},
    "t3": {"event_kind": "tool_execution", "tool_call_id": "call-u0002-0", "session_id": "sess-u0002", "host": "u0002-host"},
    "q3": {"event_kind": "process_start", "process_guid": "{u0002-p0}", "host": "u0002-host"},
    "m4": {"event_kind": "model_interaction", "tool_call_id": "call-u0003-0", "session_id": "sess-u0003", "host": "u0003-host"},
}


def alert(aid, rule, ids, llm="unknown", fw="unknown", **extra):
    return {"alert_id": aid, "rule_id": rule, "event_ids": ids, "llm": {"level": llm}, "framework": {"level": fw}, **extra}


def test_valid_chain_is_scored_correct():
    r = E.score([alert("a1", "ARG-LLM-002", ["m1", "x1"], "directly_observed")], EV, LABELS)
    assert r["llm_overclaims"] == [] and r["labelled_chains_directly_observed"] == 1


def test_unrelated_execution_in_mixed_unit_does_not_inherit_attribution():
    r = E.score([alert("a2", "ARG-AUTO-003", ["x2", "p2"], "directly_observed")], EV, LABELS)
    assert len(r["llm_overclaims"]) == 1 and r["llm_overclaims"][0]["supported_max"] == "unknown"


@pytest.mark.parametrize("ids,llm,expected_max", [
    (["t3", "q3"], "directly_observed", "unknown"),      # tool-only automation
    (["t3", "q3"], "possible", "unknown"),               # even "possible" is unsupported without model evidence
    (["m4"], "directly_observed", "possible"),           # model-only
    (["m1", "x2"], "directly_observed", "possible"),     # model record + execution of another call (mismatch)
])
def test_injected_wrong_llm_predictions_are_errors(ids, llm, expected_max):
    r = E.score([alert("w", "ARG-X", ids, llm)], EV, LABELS)
    assert len(r["llm_overclaims"]) == 1 and r["llm_overclaims"][0]["supported_max"] == expected_max


def test_injected_framework_responsibility_and_identity_are_errors():
    r = E.score([alert("f", "ARG-ARTEX-X01", ["p2"], fw="corroborated_presence", person="J. Doe")], EV, LABELS,
                {"attribution": {"threat_group": "APT-SYNTH", "person": "not assessed (out of scope)"}})
    assert len(r["framework_errors"]) == 1
    assert {e["field"] for e in r["identity_errors"]} == {"person", "case.attribution.threat_group"}


def test_missed_chain_reported_when_valid_chain_not_directly_observed():
    r = E.score([alert("a1", "ARG-LLM-005", ["m1", "x1"], "possible")], EV, LABELS)
    assert r["llm_overclaims"] == [] and r["labelled_chains_directly_observed"] == 0 and r["labelled_chains_missed"]


def test_scorer_does_not_use_production_correlator():
    src = (ROOT / "scripts" / "eval_v21.py").read_text()
    body = src[src.index("def allowed_llm"):src.index("def evaluate")]
    assert "derive" not in body and "session_key" not in body and "call_key" not in body
