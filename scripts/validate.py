"""Scenario validation against SYNTHETIC ground truth (fixtures/ground_truth/demo.json).

The detector never reads the ground truth. This script maps observed alerts to
scenarios, checks scenario expectations, and lists unexpected alerts (potential
false positives) and abstentions. Results validate only the prototype's synthetic
scenarios; real-world detection accuracy remains NOT MEASURED.
"""
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from argos.analysis import run_analysis  # noqa: E402
from argos.config import Settings  # noqa: E402
from argos.ingest.pipeline import ingest_file  # noqa: E402
from argos.store import Store  # noqa: E402
from argos.synthetic import generate_bulk  # noqa: E402


def g(a, k):
    return str(a["group"].get(k, ""))


SCENARIOS = {
    "authorized_scanner_198.51.100.10": (lambda a: g(a, "src_ip") == "198.51.100.10",
                                         lambda al, asm: al and all(a["disposition"] == "authorized_automation" and a["framework"]["level"] == "unknown" for a in al)),
    "ci_healthchecks_198.51.100.20": (lambda a: g(a, "src_ip") == "198.51.100.20",
                                      lambda al, asm: al and all(a["disposition"] == "authorized_automation" for a in al)),
    "web_enumeration_203.0.113.50": (lambda a: a["rule_id"].startswith("ARG-ENUM") and g(a, "src_ip") == "203.0.113.50",
                                     lambda al, asm: {"ARG-ENUM-001", "ARG-ENUM-003"} <= {a["rule_id"] for a in al} and all(a["llm"]["level"] == "unknown" for a in al)),
    "password_spray_203.0.113.50": (lambda a: a["rule_id"] == "ARG-AUTH-001",
                                    lambda al, asm: len(al) == 1 and al[0]["purpose"]["hypothesis"] == "credential_access"),
    "alice_slow_takeover": (lambda a: "alice@" in g(a, "user"),
                            lambda al, asm: any(a["rule_id"] == "ARG-AUTH-002" and a["threat"]["severity"] == "high" and a["automation"]["level"] == "unknown" for a in al)),
    "bob_fail_then_success_no_access": (lambda a: "bob@" in g(a, "user"),
                                        lambda al, asm: any(a["rule_id"] == "ARG-AUTH-003" and a["absence_checks"][0]["status"].startswith("absent") for a in al)
                                        and not any(a["purpose"]["hypothesis"] in ("possible_exfiltration", "collection") for a in al)),
    "sp_app-1111_credential_add_and_vault_reads": (lambda a: g(a, "app_id") == "app-1111-demo",
                                                   lambda al, asm: {"ARG-SP-001", "ARG-COLL-002"} <= {a["rule_id"] for a in al}),
    "web01_webshell": (lambda a: "web-01" in g(a, "host"),
                       lambda al, asm: {"ARG-EP-001", "ARG-EP-002", "ARG-PERS-001"} <= {a["rule_id"] for a in al}),
    "dev-ws-07_artex_agent": (lambda a: "dev-ws-07" in g(a, "host") or g(a, "session_id") == "exp12-worker-i3"
                              or "\"exp12-worker-i3\"" in g(a, "call_key") or g(a, "domain") == "api.deepseek.com",
                              lambda al, asm: asm["framework"]["level"] == "corroborated_presence"
                              and any(a["llm"]["level"] == "directly_observed" for a in al)
                              and asm["automation"]["level"] == "mixed"),
    "fileserver-02_archive_upload": (lambda a: "fileserver-02" in g(a, "host"),
                                     lambda al, asm: any(a["purpose"]["hypothesis"] == "possible_exfiltration" and a["disposition"] == "open" for a in al)),
    "backup-01_nightly": (lambda a: g(a, "host") == "backup-01",
                          lambda al, asm: al and all(a["disposition"] == "authorized_automation" for a in al)),
    "developer_openai_dns": (lambda a: g(a, "domain") == "api.openai.com",
                             lambda al, asm: len(al) == 1 and al[0]["threat"]["severity"] == "informational" and al[0]["llm"]["level"] == "possible"),
    "artex_text_in_user_agent": (lambda a: a["rule_id"] == "ARG-ARTEX-W01",
                                 lambda al, asm: al and all(a["confidence"] == "low" for a in al)),
    "_synthetic_ioc_contacts (not in ground truth list)": (lambda a: a["rule_id"] == "ARG-IOC-001",
                                                           lambda al, asm: len(al) == 2),
}


def main():
    tmp = Path(tempfile.mkdtemp(prefix="argos-validate-"))
    s = Settings()
    s.home = tmp
    s.ensure()
    st = Store(s.db_path)
    gt = json.loads((ROOT / "fixtures" / "ground_truth" / "demo.json").read_text())
    case = st.create_case("validation-demo", True)
    for f in json.loads((ROOT / "fixtures" / "demo" / "import_manifest.json").read_text()):
        ingest_file(st, s, case, ROOT / "fixtures" / "demo" / f["file"], f["format"], f["options"], coverage=f.get("coverage"))
    run_analysis(st, s, case["case_id"])
    alerts = st.list_alerts(case["case_id"])
    asm = st.latest_assessment(case["case_id"])
    results, used = {}, set()
    for name, (sel, check) in SCENARIOS.items():
        al = [a for a in alerts if sel(a)]
        used |= {a["alert_id"] for a in al}
        ok = bool(check(al, asm))
        results[name] = {"pass": ok, "ground_truth": gt["scenarios"].get(name, {}).get("truth", "n/a"),
                         "alerts": sorted(f"{a['rule_id']}[{a['threat']['severity']}/{a['confidence']}/{a['disposition']}]" for a in al)}
    unexpected = [f"{a['rule_id']} {a['group']}" for a in alerts if a["alert_id"] not in used]
    # entity separation check (carol vs bob behind the same IP)
    accts = {e["ekey"] for e in st.list_entities(case["case_id"], "account")}
    results["carol_shares_ip_with_bob"] = {"pass": any("carol@" in k for k in accts) and any("bob@" in k for k in accts),
                                          "ground_truth": "distinct_identity", "alerts": []}
    # background noise: random bulk data
    bulk = tmp / "bulk.jsonl"
    generate_bulk(bulk, 12000)
    bc = st.create_case("validation-bulk-noise", True)
    ingest_file(st, s, bc, bulk, "native_jsonl", {})
    run_analysis(st, s, bc["case_id"])
    noise = Counter(a["rule_id"] for a in st.list_alerts(bc["case_id"]))
    out = {"generated_with": "scripts/validate.py", "scenario_results": results,
           "scenarios_passed": sum(r["pass"] for r in results.values()), "scenarios_total": len(results),
           "unexpected_alerts_in_demo": unexpected,
           "abstentions_in_demo": [a["rule_id"] for a in alerts if a["abstained"]],
           "alerts_on_random_background_noise_12k": dict(noise),
           "case_assessment_demo": {k: asm[k]["level"] for k in ("automation", "llm", "framework")},
           "real_world_accuracy": "NOT MEASURED (no independent labelled corpus)"}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "validation_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    return 0 if out["scenarios_passed"] == out["scenarios_total"] else 1


if __name__ == "__main__":
    sys.exit(main())
