"""Labeled evaluation of the failures-then-success authentication rule (ARG-AUTH-003).

Generates SYNTHETIC identity/session sequences for benign and malicious scenarios into
two independent sets (tuning, held-out) with different seeds and parameter ranges.
Labels go to fixtures/ground_truth/ and are only read here, never by the detector.
Unit of evaluation: one identity sequence (tenant+account instance), not raw events.

Usage: python scripts/auth_eval.py [--write-fixtures] [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argos.analysis import run_analysis  # noqa: E402
from argos.config import Settings  # noqa: E402
from argos.ingest.pipeline import ingest_file  # noqa: E402
from argos.store import Store  # noqa: E402
from argos.resources import rules_dir  # noqa: E402

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)

# ARG-AUTH-003 version 1 (as shipped in v0.1.0), kept verbatim in behaviour for comparison.
V1_RULE = """
id: ARG-AUTH-003
version: 1
title: Failed sign-ins followed by a successful sign-in (v1, comparison only)
description: v1 for evaluation comparison
family: auth_sequence
status: test
validation_status: comparison
observation_vantage: [identity_cloud]
required_telemetry: [event_time, tenant_id, user, outcome]
select: {field: event_kind, op: eq, value: authentication}
group_by: [tenant_id, user]
window_s: 86400
aggregate:
  type: sequence
  steps:
    - {name: failed_signins, where: {field: outcome, op: eq, value: failure}, min_count: 5}
    - {name: successful_signin, where: {field: outcome, op: eq, value: success}}
reference: {type: explicit_threshold, description: v1}
severity: medium
base_confidence: medium
contributes:
  threat: {activity: v1, suspicion: suspicious}
  purpose: {observed_action: v1, hypothesis: credential_access, stage: observed_success}
evidence_family: auth_fail_then_success
required_evidence: v1
explanation: v1
alternatives: [v1]
false_positives: [v1]
sources: [v1]
"""

LABEL = {"B1_typo_then_success": "benign", "B2_many_typos_own_device": "benign", "B3_intermittent_multi_device": "benign",
         "B4_stale_password_device": "benign", "B5_shared_nat_users": "benign", "B6_cross_tenant_same_username": "benign",
         "M1_fast_guessing": "malicious", "M2_slow_guessing": "malicious", "M3_guessing_with_interleaved_legit_user": "malicious",
         "M4_rotating_source_per_attempt": "malicious"}

PARAMS = {
    # tuning and held-out differ in seed, counts, spacing, failure probability and address pools
    "tuning": {"seed": 1, "n": 20, "typo_k": (1, 3), "heavy_k": (5, 7), "p_fail": 0.35, "devices": 3, "stale_k": (4, 10),
               "stale_update_p": 0.0, "fast_k": (6, 12), "slow_gap_h": (1, 3), "m3_k": (5, 8), "net": "192.0.2", "atk": "203.0.113"},
    "heldout": {"seed": 2, "n": 30, "typo_k": (1, 4), "heavy_k": (5, 9), "p_fail": 0.45, "devices": 4, "stale_k": (5, 12),
                "stale_update_p": 0.5, "fast_k": (5, 15), "slow_gap_h": (0.5, 3.5), "m3_k": (5, 10), "net": "198.51.100", "atk": "203.0.113"},
}


def ts(sec: float) -> str:
    return (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def auth(sec, tenant, user, outcome, src):
    return {"event_time": ts(sec), "event_kind": "authentication", "observation_vantage": "identity_cloud", "action": "signin",
            "tenant_id": tenant, "user": user, "outcome": outcome, "src_ip": src, "source_type": "synthetic_auth_eval"}


def generate(set_name: str):
    p = PARAMS[set_name]
    rng = random.Random(p["seed"])
    rows, labels = [], {}
    slot = 0

    def ip(prefix):
        return f"{prefix}.{rng.randint(1, 254)}"

    def nxt():
        nonlocal slot
        slot += 1
        return slot * 2 * 86400  # each instance gets its own 2-day slot

    for scen in LABEL:
        for i in range(p["n"]):
            base = nxt()
            user = f"{scen.split('_')[0].lower()}-{set_name}-{i}@eval.example"
            tenant = "tenant-eval"
            key = f"{tenant}|{user}"
            home = ip(p["net"])
            if scen == "B1_typo_then_success":
                k = rng.randint(*p["typo_k"])
                t = base
                for _ in range(k):
                    rows.append(auth(t, tenant, user, "failure", home)); t += rng.uniform(5, 30)
                rows.append(auth(t, tenant, user, "success", home))
            elif scen == "B2_many_typos_own_device":
                k = rng.randint(*p["heavy_k"])
                t = base
                rows.append(auth(base - 86400 * 0.5, tenant, user, "success", home))  # prior history from same device
                for _ in range(k):
                    rows.append(auth(t, tenant, user, "failure", home)); t += rng.uniform(5, 40)
                rows.append(auth(t, tenant, user, "success", home))
            elif scen == "B3_intermittent_multi_device":
                devs = [ip(p["net"]) for _ in range(p["devices"])]
                for _ in range(rng.randint(8, 20)):
                    rows.append(auth(base + rng.uniform(0, 86400), tenant, user, "failure" if rng.random() < p["p_fail"] else "success", rng.choice(devs)))
            elif scen == "B4_stale_password_device":
                dev = ip(p["net"])
                t = base
                k = rng.randint(*p["stale_k"])
                for j in range(k):
                    rows.append(auth(t, tenant, user, "failure", dev))
                    rows.append(auth(t + 60, tenant, user, "success", home))  # user works normally from browser
                    t += rng.uniform(1800, 3600)
                if rng.random() < p["stale_update_p"]:
                    rows.append(auth(t, tenant, user, "success", dev))  # user finally updates saved password
            elif scen == "B5_shared_nat_users":
                nat = f"{p['net']}.1"
                for _ in range(rng.randint(1, 2)):
                    rows.append(auth(base + rng.uniform(0, 600), tenant, user, "failure", nat))
                rows.append(auth(base + 900, tenant, user, "success", nat))
            elif scen == "B6_cross_tenant_same_username":
                for j in range(6):
                    rows.append(auth(base + j * 30, "tenant-other", user, "failure", home))
                rows.append(auth(base + 400, tenant, user, "success", home))
            elif scen == "M1_fast_guessing":
                atk = ip(p["atk"])
                t = base
                for _ in range(rng.randint(*p["fast_k"])):
                    rows.append(auth(t, tenant, user, "failure", atk)); t += rng.uniform(2, 20)
                rows.append(auth(t + 5, tenant, user, "success", atk))
            elif scen == "M2_slow_guessing":
                atk = ip(p["atk"])
                t = base
                for _ in range(rng.randint(5, 6)):
                    rows.append(auth(t, tenant, user, "failure", atk)); t += rng.uniform(*p["slow_gap_h"]) * 3600
                rows.append(auth(t, tenant, user, "success", atk))
            elif scen == "M3_guessing_with_interleaved_legit_user":
                atk = ip(p["atk"])
                t = base
                for _ in range(rng.randint(*p["m3_k"])):
                    rows.append(auth(t, tenant, user, "failure", atk))
                    if rng.random() < 0.7:
                        rows.append(auth(t + 20, tenant, user, "success", home))
                    t += rng.uniform(60, 1800)
                rows.append(auth(t, tenant, user, "success", atk))
            elif scen == "M4_rotating_source_per_attempt":
                t = base
                for _ in range(rng.randint(6, 10)):
                    rows.append(auth(t, tenant, user, "failure", ip(p["atk"]))); t += rng.uniform(10, 300)
                rows.append(auth(t, tenant, user, "success", ip(p["atk"])))
            labels[key] = {"scenario": scen, "label": LABEL[scen]}
            if scen == "B6_cross_tenant_same_username":
                labels[f"tenant-other|{user}"] = {"scenario": scen, "label": "benign"}
    rng.shuffle(rows)
    return rows, labels


def write_fixtures():
    out = ROOT / "fixtures" / "auth_eval"
    out.mkdir(parents=True, exist_ok=True)
    gt = ROOT / "fixtures" / "ground_truth"
    for name in PARAMS:
        rows, labels = generate(name)
        with open(out / f"{name}.jsonl", "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        (gt / f"auth_eval_{name}.json").write_text(json.dumps({"_note": "SYNTHETIC labels; never imported", "labels": labels}, indent=1, sort_keys=True))


def evaluate(set_name: str, rule_version: str) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="argos-autheval-"))
    rdir = tmp / "rules"
    shutil.copytree(rules_dir(), rdir)
    if rule_version == "v1":
        p = rdir / "detections" / "03_auth.yaml"
        text = p.read_text()
        p.write_text(text[: text.index("id: ARG-AUTH-003")] + V1_RULE.lstrip())  # v1 alone (AUTH-004 did not exist)
    s = Settings()
    s.home, s.rules_dir = tmp / "home", rdir
    s.ensure()
    st = Store(s.db_path)
    case = st.create_case(f"auth-eval-{set_name}", True)
    ingest_file(st, s, case, ROOT / "fixtures" / "auth_eval" / f"{set_name}.jsonl", "native_jsonl", {})
    run_analysis(st, s, case["case_id"])
    labels = json.loads((ROOT / "fixtures" / "ground_truth" / f"auth_eval_{set_name}.json").read_text())["labels"]
    alerted, confs = {}, {}
    for a in st.list_alerts(case["case_id"]):
        if a["rule_id"] in ("ARG-AUTH-003", "ARG-AUTH-004"):
            key = f"{a['group']['tenant_id']}|{a['group']['user']}"
            alerted[key] = alerted.get(key, 0) + 1
            confs.setdefault(key, []).append(a["confidence"])
    per = {}
    unlabeled = 0
    for key, n in alerted.items():
        if key not in labels:
            unlabeled += 1
    instances = {}
    for key, lab in labels.items():
        if lab["scenario"] == "B6_cross_tenant_same_username" and key.startswith("tenant-other|"):
            continue  # one instance spans two tenants; count it once (by its success tenant)
        sc = lab["scenario"]
        d = per.setdefault(sc, {"label": lab["label"], "identity_sequences": 0, "sequences_with_alert": 0, "alerts": 0,
                                "alert_confidence": {}})
        for cf in confs.get(key, []):
            d["alert_confidence"][cf] = d["alert_confidence"].get(cf, 0) + 1
        d["identity_sequences"] += 1
        hit = alerted.get(key, 0) + (alerted.get(key.replace("tenant-eval|", "tenant-other|"), 0) if sc.startswith("B6") else 0)
        d["alerts"] += hit
        d["sequences_with_alert"] += 1 if hit else 0
        instances[sc] = d["identity_sequences"]
    for d in per.values():
        d["fraction_sequences_alerted"] = round(d["sequences_with_alert"] / d["identity_sequences"], 3)
    st.close()
    shutil.rmtree(tmp, ignore_errors=True)
    tot_b = sum(d["identity_sequences"] for d in per.values() if d["label"] == "benign")
    tot_m = sum(d["identity_sequences"] for d in per.values() if d["label"] == "malicious")
    return {"set": set_name, "rule": "ARG-AUTH-003 v1" if rule_version == "v1" else "ARG-AUTH-003 v2 + ARG-AUTH-004 v1", "unit": "identity sequence (one tenant+account scenario instance)",
            "per_scenario": per, "benign_sequences": tot_b, "benign_sequences_alerted": sum(d["sequences_with_alert"] for d in per.values() if d["label"] == "benign"),
            "malicious_sequences": tot_m, "malicious_sequences_alerted": sum(d["sequences_with_alert"] for d in per.values() if d["label"] == "malicious"),
            "alerts_not_mapped_to_a_labeled_sequence": unlabeled}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-fixtures", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    if a.write_fixtures or not (ROOT / "fixtures" / "auth_eval" / "tuning.jsonl").exists():
        write_fixtures()
    res = [evaluate(s, v) for s in ("tuning", "heldout") for v in ("v1", "v2")]
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=2))
    for r in res:
        print(f"\n== {r['set']} / {r['rule']} — benign alerted {r['benign_sequences_alerted']}/{r['benign_sequences']}, "
              f"malicious alerted {r['malicious_sequences_alerted']}/{r['malicious_sequences']}")
        for sc, d in r["per_scenario"].items():
            print(f"  {sc:<42} {d['label']:<9} {d['sequences_with_alert']:>3}/{d['identity_sequences']:<3} sequences alerted ({d['alerts']} alerts; confidence {d['alert_confidence']})")
    return res


if __name__ == "__main__":
    main()
