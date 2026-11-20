"""Positive and negative tests per rule family, plus rule-schema safety."""
import pytest
import yaml
from pydantic import ValidationError

from argos.detect.rules import Rule, load_rules
from conftest import RULES, ev

TEN = "tenant-x"


def http_burst(src, n, step=0.1, start=0, status=200, path=lambda i: f"/p{i}"):
    return [ev(start + i * step, event_kind="http", src_ip=src, http_host="h.example", http_uri=path(i), http_status=status) for i in range(n)]


# ---------- family 1: bursts
def test_auto001_positive_and_slow_negative(env):
    c = env.run("a1", http_burst("192.0.2.1", 120))
    al = env.alerts(c, "ARG-AUTO-001")
    assert len(al) == 1 and al[0]["automation"]["level"] == "consistent_with_automation"
    assert al[0]["llm"]["level"] == "unknown" and al[0]["framework"]["level"] == "unknown"
    assert al[0]["threat"]["suspicion"] == "informational"
    c2 = env.run("a1n", http_burst("192.0.2.1", 120, step=5))  # same count, slow
    assert env.alerts(c2, "ARG-AUTO-001") == []


def test_auto002_process_burst(env):
    rows = [ev(i * 0.2, event_kind="process_start", host="h1", process_guid=f"{{g{i}}}", parent_process_guid="{p}",
               process_image="/bin/sh", parent_image="/usr/bin/make") for i in range(25)]
    c = env.run("a2", rows)
    assert len(env.alerts(c, "ARG-AUTO-002")) == 1
    c2 = env.run("a2n", rows[:10])
    assert env.alerts(c2, "ARG-AUTO-002") == []


# ---------- family 2: enumeration / adaptation
def test_enum001_and_002(env):
    rows = http_burst("192.0.2.9", 45, step=2, status=404) + [ev(200, event_kind="http", src_ip="192.0.2.9", http_host="h.example", http_uri="/ok", http_status=200)]
    c = env.run("e1", rows)
    assert len(env.alerts(c, "ARG-ENUM-001")) == 1
    a2 = env.alerts(c, "ARG-ENUM-002")
    assert len(a2) == 1 and set(a2[0]["matched_predicates"]) == {"failures", "success"}
    neg = http_burst("192.0.2.9", 45, step=2, status=200)  # many paths but successful -> not enumeration
    c2 = env.run("e1n", neg)
    assert env.alerts(c2, "ARG-ENUM-001") == [] and env.alerts(c2, "ARG-ENUM-002") == []


def test_enum003_port_sweep(env):
    rows = [ev(i, event_kind="network_connection", src_ip="192.0.2.7", dst_ip="10.0.0.5", dst_port=1000 + i) for i in range(25)]
    c = env.run("e3", rows)
    assert len(env.alerts(c, "ARG-ENUM-003")) == 1
    rows_n = [ev(i, event_kind="network_connection", src_ip="192.0.2.7", dst_ip="10.0.0.5", dst_port=443) for i in range(25)]
    assert env.alerts(env.run("e3n", rows_n), "ARG-ENUM-003") == []


# ---------- family 3: authentication
def test_auth001_spray_and_negative(env):
    rows = [ev(i * 10, event_kind="authentication", tenant_id=TEN, user=f"u{i}@x", src_ip="192.0.2.50", outcome="failure") for i in range(12)]
    c = env.run("s1", rows)
    assert len(env.alerts(c, "ARG-AUTH-001")) == 1
    rows_n = [ev(i * 10, event_kind="authentication", tenant_id=TEN, user="same@x", src_ip="192.0.2.50", outcome="failure") for i in range(12)]
    assert env.alerts(env.run("s1n", rows_n), "ARG-AUTH-001") == []


def chain(user="alice@x", spacing=60):
    rows = [ev(i * spacing, event_kind="authentication", tenant_id=TEN, user=user, outcome="failure", src_ip="192.0.2.51") for i in range(3)]
    rows.append(ev(3 * spacing + 10, event_kind="authentication", tenant_id=TEN, user=user, outcome="success", src_ip="192.0.2.51"))
    rows.append(ev(3 * spacing + 100, event_kind="cloud_operation", tenant_id=TEN, user=user, action="role_assignment", outcome="success"))
    return rows


def test_auth002_chain_keeps_outcomes_separate(env):
    c = env.run("ch", chain())
    a = env.alerts(c, "ARG-AUTH-002")
    assert len(a) == 1
    steps = {e["step"] for e in a[0]["evidence"]}
    assert steps == {"failed_signins", "successful_signin", "sensitive_action"}
    # different user for the sensitive action -> no chain (correlation by identity)
    rows = chain()
    rows[-1]["user"] = "mallory@x"
    assert env.alerts(env.run("chn", rows), "ARG-AUTH-002") == []


# ---------- family 4: service principals
def test_sp001_and_sp002_baseline(env):
    sp = dict(tenant_id=TEN, app_id="app-1", account_type="service_principal")
    rows = [ev(0, event_kind="authentication", outcome="success", **sp), ev(100, event_kind="cloud_operation", action="credential_add", **sp)]
    c = env.run("sp", rows)
    assert len(env.alerts(c, "ARG-SP-001")) == 1
    rows_n = [ev(0, event_kind="authentication", outcome="success", **sp), ev(100, event_kind="cloud_operation", action="secret_read", resource="kv1", **sp)]
    assert env.alerts(env.run("spn", rows_n), "ARG-SP-001") == []


def test_sp002_insufficient_baseline_abstains(env):
    sp = dict(tenant_id=TEN, app_id="app-2")
    rows = [ev(i * 10, event_kind="cloud_operation", action="secret_read", resource="kv1", **sp) for i in range(30)]
    c = env.run("bl1", rows)
    a = env.alerts(c, "ARG-SP-002")
    assert len(a) == 1 and a[0]["abstained"] and a[0]["confidence"] == "insufficient_evidence"
    assert a[0]["baseline"]["status"] == "insufficient_baseline"


def test_sp002_history_used_only_from_prior_events(env):
    sp = dict(tenant_id=TEN, app_id="app-3")
    hist = [ev(h * 3600 + 60, event_kind="cloud_operation", action="secret_read", resource="kv1", **sp) for h in range(30)]  # 1/hour for 30h
    spike = [ev(30 * 3600 + 100 + i * 5, event_kind="cloud_operation", action="secret_read", resource="kv1", **sp) for i in range(40)]
    c = env.run("bl2", hist + spike)
    a = [x for x in env.alerts(c, "ARG-SP-002") if not x["abstained"]]
    assert len(a) == 1 and a[0]["baseline"]["status"] == "exceeds_history" and a[0]["baseline"]["uses_only_prior_events"]
    # same volume every hour -> no exceedance
    flat = [ev(h * 3600 + 100 + i * 5, event_kind="cloud_operation", action="secret_read", resource="kv1", **sp) for h in range(31) for i in range(40)]
    c2 = env.run("bl3", flat)
    assert [x for x in env.alerts(c2, "ARG-SP-002") if not x["abstained"]] == []


# ---------- family 5: endpoint
def test_ep_rules(env):
    rows = [ev(0, event_kind="process_start", host="w1", process_guid="{c}", parent_process_guid="{p}", process_image="C:\\Windows\\System32\\cmd.exe",
               parent_image="C:\\Windows\\System32\\inetsrv\\w3wp.exe"),
            ev(5, event_kind="network_connection", host="w1", process_guid="{c}", dst_ip="203.0.113.5", dst_port=443, observation_vantage="managed_endpoint")]
    c = env.run("ep", rows)
    assert len(env.alerts(c, "ARG-EP-001")) == 1 and len(env.alerts(c, "ARG-EP-002")) == 1
    rows_n = [ev(0, event_kind="process_start", host="w1", process_guid="{c}", parent_process_guid="{p}", process_image="C:\\Windows\\System32\\cmd.exe",
                 parent_image="C:\\Windows\\explorer.exe"),
              ev(5, event_kind="network_connection", host="w1", process_guid="{c}", dst_ip="10.1.1.1", dst_port=443, observation_vantage="managed_endpoint")]
    c2 = env.run("epn", rows_n)
    assert env.alerts(c2, "ARG-EP-001") == [] and env.alerts(c2, "ARG-EP-002") == []


# ---------- family 6: model linkage
def test_llm_rules(env):
    audit = [ev(0, event_kind="model_interaction", session_id="s1", model_tool_name="bash", host="d1", linked_process_guid="{x}"),
             ev(2, event_kind="tool_execution", session_id="s1", host="d1", linked_process_guid="{x}")]
    proc = [ev(3, event_kind="process_start", host="d1", process_guid="{x}", process_image="/bin/bash")]
    c = env.run("llm", audit + proc)
    assert env.alerts(c, "ARG-LLM-002")[0]["llm"]["level"] == "directly_observed"
    assert len(env.alerts(c, "ARG-LLM-003")) == 1
    # model interaction without a tool call / without execution -> no linkage
    c2 = env.run("llmn", [ev(0, event_kind="model_interaction", session_id="s1", host="d1"),
                           ev(3, event_kind="process_start", host="d1", process_guid="{y}", process_image="/bin/bash")])
    assert env.alerts(c2, "ARG-LLM-002") == [] and env.alerts(c2, "ARG-LLM-003") == []


# ---------- family 7: ARTEX candidates
def test_artex_candidates_experimental_and_bounded(env):
    rows = [ev(0, event_kind="process_start", host="h7", process_guid="{a}", process_image="/opt/artex/artex"),
            ev(1, event_kind="process_start", host="h7", process_guid="{b}", parent_process_guid="{a}", process_image="/bin/bash", parent_image="/opt/artex/artex")]
    c = env.run("ax", rows)
    for rid in ("ARG-ARTEX-X01", "ARG-ARTEX-X02"):
        a = env.alerts(c, rid)[0]
        assert a["rule_status"] == "experimental" and a["confidence"] == "low" and a["framework"]["level"] == "consistent_with"
    # same independence family twice -> still not corroborated
    assert env.assessment(c)["framework"]["level"] == "consistent_with"
    c2 = env.run("axn", [ev(0, event_kind="process_start", host="h7", process_guid="{a}", process_image="/usr/bin/artemis")])
    assert env.alerts(c2, "ARG-ARTEX-X01") == []


def test_artex_corroboration_needs_two_independent_families_same_host(env):
    proc = ev(0, event_kind="process_start", host="h8", process_guid="{a}", process_image="/opt/artex/artex")
    gw = ev(5, event_kind="model_interaction", host="h8", session_id="exp3-worker-i7")
    c = env.run("axc", [proc, gw])
    fw = env.assessment(c)["framework"]
    assert fw["level"] == "corroborated_presence"
    cand = fw["candidates"][0]
    assert cand["responsibility_for_activity"].startswith("not established") and cand["execution"].startswith("not established")
    assert "no validated victim-side fingerprint" in cand["victim_side_fingerprint"]
    # different hosts -> no corroboration
    gw2 = dict(gw, host="other")
    assert env.assessment(env.run("axc2", [proc, gw2]))["framework"]["level"] == "consistent_with"


def test_artex_mitmproxy_ca_filename_never_corroborates(env):
    # v2 review: '_ca/mitmproxy-ca-cert.pem' is mitmproxy's standard name -> weak; same-artifact strings
    # (binary name + child-of-binary) are one family, so these three together are still only consistent_with.
    rows = [ev(0, event_kind="process_start", host="h9", process_guid="{a}", process_image="/opt/artex/artex"),
            ev(1, event_kind="process_start", host="h9", process_guid="{b}", parent_process_guid="{a}", process_image="/bin/sh", parent_image="/opt/artex/artex"),
            ev(5, event_kind="file_create", host="h9", file_path="/srv/t/_ca/mitmproxy-ca-cert.pem")]
    fw = env.assessment(env.run("axw", rows))["framework"]
    assert fw["level"] == "consistent_with" and fw["candidates"][0]["independent_families"] == ["controller_process"]


# ---------- family 8: collection / exfil / persistence
def test_coll_and_persistence(env):
    rows = [ev(0, event_kind="file_create", host="f1", file_path="D:\\x\\dump.zip", outcome="success"),
            ev(60, event_kind="network_connection", host="f1", dst_ip="203.0.113.8", bytes_src_to_dst=60_000_000, bytes_basis="edr: sent"),
            ev(100, event_kind="process_start", host="f1", process_guid="{s}", process_image="C:\\Windows\\System32\\schtasks.exe",
               process_command_line="schtasks /create /tn x /tr c:\\x.exe", outcome="failure")]
    c = env.run("co", rows)
    a = env.alerts(c, "ARG-COLL-001")[0]
    assert a["purpose"]["hypothesis"] == "possible_exfiltration" and "NOT established" in a["why"]
    p = env.alerts(c, "ARG-PERS-001")[0]
    assert p["purpose"]["stage"] == "attempt"  # outcome failure -> attempt, not success
    rows_n = [rows[0], ev(60, event_kind="network_connection", host="f1", dst_ip="203.0.113.8", bytes_src_to_dst=1000, bytes_basis="edr: sent")]
    assert env.alerts(env.run("con", rows_n), "ARG-COLL-001") == []


def test_coll002_multivault(env):
    sp = dict(tenant_id=TEN, app_id="a9")
    rows = [ev(i * 30, event_kind="cloud_operation", action="secret_read", resource=f"kv{i}", **sp) for i in range(3)]
    assert len(env.alerts(env.run("mv", rows), "ARG-COLL-002")) == 1
    rows_n = [ev(i * 30, event_kind="cloud_operation", action="secret_read", resource="kv0", **sp) for i in range(3)]
    assert env.alerts(env.run("mvn", rows_n), "ARG-COLL-002") == []


# ---------- registry
def test_registry_partial_scope_not_suppressed(env):
    rows = http_burst("198.51.100.10", 110) + http_burst("192.0.2.200", 0)
    c = env.run("rg", rows)
    a = env.alerts(c, "ARG-AUTO-001")[0]
    assert a["disposition"] == "authorized_automation"
    # same burst but some events from an unregistered source grouped together is impossible (grouped by src);
    # registry entry expired -> not suppressed
    late = http_burst("198.51.100.10", 110, start=(2027 - 2026) * 365 * 86400)
    c2 = env.run("rg2", late)
    assert env.alerts(c2, "ARG-AUTO-001")[0]["disposition"] == "open"


def test_registry_never_hides_credential_changes(env):
    sp = dict(tenant_id=TEN, app_id="app-ci", account_type="service_principal", src_ip="198.51.100.20")
    rows = [ev(0, event_kind="authentication", outcome="success", **sp), ev(100, event_kind="cloud_operation", action="credential_add", **sp)]
    a = env.alerts(env.run("rgc", rows), "ARG-SP-001")[0]
    assert a["disposition"] == "open"


# ---------- schema safety
def test_rules_all_valid_and_complete():
    rules, h, errors = load_rules(RULES)
    assert not errors and len(rules) >= 20
    fams = {r.family for r in rules}
    assert {"automation_burst", "enumeration_adaptation", "auth_sequence", "service_principal_abuse", "endpoint_process",
            "model_tool_linkage", "framework_candidate", "collection_exfil_persistence"} <= fams
    for r in rules:
        assert r.sources and r.false_positives is not None and r.alternatives and r.validation_status
        if r.family == "framework_candidate" and r.id != "ARG-ARTEX-W01":
            assert r.fingerprint and r.status == "experimental"


def base_rule(**over):
    d = yaml.safe_load((RULES / "detections/01_automation.yaml").read_text().split("---")[0])
    d.update(over)
    return d


@pytest.mark.parametrize("bad", [
    {"select": {"field": "event_kind", "op": "eval", "value": "__import__('os')"}},
    {"select": {"field": "__class__", "op": "eq", "value": 1}},
    {"select": {"field": "event_kind", "op": "regex", "value": "a" * 500}},
    {"python": "print(1)"},
    {"aggregate": {"type": "shell", "min_count": 1}},
])
def test_rule_schema_rejects_code_and_unknowns(bad):
    with pytest.raises(ValidationError):
        Rule.model_validate(base_rule(**bad))


def test_unsafe_yaml_tags_rejected(tmp_path):
    d = tmp_path / "detections"
    d.mkdir()
    (d / "x.yaml").write_text("id: !!python/object/apply:os.system ['echo pwned']\n")
    rules, h, errors = load_rules(tmp_path)
    assert rules == [] and errors and "YAML error" in errors[0]


# ---------- AUTH-003 v2 (per-source uninterrupted failure run)
def _a(sec, user, outcome, src, tenant=TEN):
    return ev(sec, event_kind="authentication", tenant_id=tenant, user=user, outcome=outcome, src_ip=src)


def test_auth003_v2_interleaved_successes_reset_the_run(env):
    seq = "FFSFFSFFFS"  # never 5 failures in a row
    rows = [_a(i * 60, "u@x", "failure" if ch == "F" else "success", "192.0.2.20") for i, ch in enumerate(seq)]
    assert env.alerts(env.run("v2a", rows), "ARG-AUTH-003") == []


def test_auth003_v2_failures_spread_over_sources_not_combined(env):
    rows = [_a(i * 60, "u@x", "failure", f"192.0.2.{30 + i}") for i in range(6)] + [_a(600, "u@x", "success", "192.0.2.99")]
    assert env.alerts(env.run("v2b", rows), "ARG-AUTH-003") == []


def test_auth003_v2_attack_with_interleaved_legit_user_still_detected(env):
    rows = []
    for i in range(6):
        rows.append(_a(i * 600, "victim@x", "failure", "203.0.113.40"))
        rows.append(_a(i * 600 + 30, "victim@x", "success", "192.0.2.50"))  # real user from home
    rows.append(_a(4000, "victim@x", "success", "203.0.113.40"))
    a = env.alerts(env.run("v2c", rows), "ARG-AUTH-003")
    assert len(a) == 1 and a[0]["group"]["src_ip"] == "203.0.113.40"


def test_auth003_v2_slow_guessing_detected(env):
    rows = [_a(i * 7200, "slow@x", "failure", "203.0.113.41") for i in range(6)] + [_a(6 * 7200, "slow@x", "success", "203.0.113.41")]
    a = env.alerts(env.run("v2d", rows), "ARG-AUTH-003")
    assert len(a) == 1 and a[0]["automation"]["level"] == "unknown"


def test_auth003_v2_tenant_boundary(env):
    rows = [_a(i * 60, "same@x", "failure", "192.0.2.60", tenant="tA") for i in range(6)] + [_a(600, "same@x", "success", "192.0.2.60", tenant="tB")]
    assert env.alerts(env.run("v2e", rows), "ARG-AUTH-003") == []


def test_auth003_v2_without_source_address_is_not_evaluated(env):
    rows = [ev(i * 60, event_kind="authentication", tenant_id=TEN, user="u@x", outcome="failure") for i in range(6)]
    rows.append(ev(600, event_kind="authentication", tenant_id=TEN, user="u@x", outcome="success"))
    c = env.run("v2f", rows)
    assert env.alerts(c, "ARG-AUTH-003") == []
    assert env.assessment(c)["rule_stats"]["ARG-AUTH-003"]["missing_required_telemetry"] == 7  # visible, not silent
    assert any("ARG-AUTH-003: 7 candidate records lacked" in x for x in env.assessment(c)["limitations"])


# ---------- Sigma / SPL export (syntax/structure only; never executed in Splunk or a Sigma backend)
def test_rule_exports_faithful_or_explicitly_unsupported(env, tmp_path):
    import json as _j

    import yaml as _y
    from argos.detect.export_rules import DERIVED_SPL, check_spl, export_all
    rep = export_all(env.settings, tmp_path / "x")
    assert rep["executed_in_splunk"] is False
    for rid, e in rep["rules"].items():
        for k in ("sigma", "spl"):
            assert e[k] == "exported" or e[k].startswith("unsupported: "), (rid, k)
    # temporal correlations are never approximated
    for rid in ("ARG-AUTH-002", "ARG-AUTH-003", "ARG-EP-002", "ARG-SP-002", "ARG-COLL-001"):
        assert "unsupported" in rep["rules"][rid]["spl"] and "unsupported" in rep["rules"][rid]["sigma"]
    sig = _y.safe_load((tmp_path / "x/sigma/ARG-EP-001.yml").read_text())
    assert sig["logsource"]["category"] == "process_creation" and "Image|endswith" in sig["detection"]["selection"]
    for f in (tmp_path / "x/spl").glob("*.spl"):
        text = f.read_text()
        assert not check_spl(text), f.name
        for d in DERIVED_SPL:  # every derived field used is defined first
            if f"({d})" in text or f" {d} " in text.split("| where", 1)[-1] or f"dc({d})" in text:
                assert f"eval {d}=" in text, (f.name, d)
    assert _j.loads((tmp_path / "x/export-report.json").read_text())["summary"]["spl"]["exported"] >= 10
