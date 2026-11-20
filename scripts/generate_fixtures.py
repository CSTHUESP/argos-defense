"""Regenerate deterministic SYNTHETIC fixtures. Ground truth goes to fixtures/ground_truth/,
which is never imported or read by the detector (only by tests/validation)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from argos.synthetic import GROUND_TRUTH, generate_demo, ts  # noqa: E402


def same_trace():
    rows = []
    for i in range(12):
        rows.append({"event_time": ts(i * 7), "event_kind": "authentication", "tenant_id": "tenant-acc", "user": f"acct{i}@acc.example",
                     "src_ip": "203.0.113.70", "outcome": "failure"})
    for i in range(3):
        rows.append({"event_time": ts(200 + i * 30), "event_kind": "authentication", "tenant_id": "tenant-acc", "user": "target@acc.example",
                     "src_ip": "203.0.113.70", "outcome": "failure"})
    rows.append({"event_time": ts(400), "event_kind": "authentication", "tenant_id": "tenant-acc", "user": "target@acc.example",
                 "src_ip": "203.0.113.70", "outcome": "success", "session_id": "s-acc-1"})
    rows.append({"event_time": ts(900), "event_kind": "cloud_operation", "tenant_id": "tenant-acc", "user": "target@acc.example",
                 "action": "credential_add", "resource": "app:payroll", "session_id": "s-acc-1"})
    return rows


def main():
    demo = ROOT / "fixtures" / "demo"
    generate_demo(demo)
    gt = ROOT / "fixtures" / "ground_truth"
    gt.mkdir(parents=True, exist_ok=True)
    (gt / "demo.json").write_text(json.dumps(GROUND_TRUTH, indent=2))
    acc = ROOT / "fixtures" / "acceptance"
    acc.mkdir(parents=True, exist_ok=True)
    with open(acc / "same_trace.jsonl", "w") as fh:
        for r in same_trace():
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    labels = {"_note": "External operator labels for the SAME observable trace. Never imported; the detector cannot see them.",
              "labels": {"human": "operator typed every command", "script": "bash loop", "llm": "LLM agent (simulated label)"}}
    (gt / "same_trace_labels.json").write_text(json.dumps(labels, indent=2))
    print("fixtures written")


if __name__ == "__main__":
    main()
