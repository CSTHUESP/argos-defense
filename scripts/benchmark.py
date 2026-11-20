"""Reproducible ingest/analysis benchmark with budgets declared BEFORE running (feature C).

    python scripts/benchmark.py --sizes 12000 100000 1000000 --out reports/benchmark.json

Each phase (generate, ingest, analyze) runs in a child process. The parent samples the child's RSS
every 0.25 s (Linux /proc) and terminates it when the time or memory budget is exceeded; a stopped
phase is recorded as `budget_exceeded`, never as a success. Data: the deterministic synthetic
background generator (argos.synthetic.generate_bulk) - mixed identity/proxy/endpoint/DNS records.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Budgets per size: (seconds, MiB peak RSS) for ingest and analyze. Declared before any run of v0.3.0;
# chosen for the 2-vCPU / 7 GiB sandbox the release was prepared on.
BUDGETS = {
    12000: {"ingest": (60, 1024), "analyze": (120, 1536)},
    100000: {"ingest": (300, 2048), "analyze": (900, 4096)},
    1000000: {"ingest": (1800, 4096), "analyze": (3600, 6144)},
}

CHILD = r"""
import json, sys, time
sys.path.insert(0, {src!r})
from pathlib import Path
from argos.config import Settings
from argos.resources import rules_dir, default_config_dir
from argos.store import Store
phase, home, data = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
s = Settings(); s.home = home; s.rules_dir = rules_dir(); s.config_dir = default_config_dir()
s.max_file_bytes = 8 << 30
t = time.monotonic()
if phase == "generate":
    from argos.synthetic import generate_bulk
    generate_bulk(data, int(sys.argv[4]))
    out = {{"bytes": data.stat().st_size}}
elif phase == "ingest":
    s.ensure(); st = Store(s.db_path)
    from argos.ingest.pipeline import ingest_file
    c = st.create_case("bench", True)
    r = ingest_file(st, s, c, data, "native_jsonl", {{}})
    out = {{k: r[k] for k in ("status", "accepted", "rejected", "total")}}
else:
    st = Store(s.db_path)
    from argos.analysis import run_analysis
    r = run_analysis(st, s, "bench")
    out = {{"stats": r["stats"]}}
out["seconds"] = round(time.monotonic() - t, 2)
print("RESULT " + json.dumps(out))
"""


def rss_mib(pid: int) -> float:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return 0.0


def run_phase(args, budget_s, budget_mib):
    code = CHILD.format(src=str(ROOT / "src"))
    t0 = time.monotonic()
    p = subprocess.Popen([sys.executable, "-c", code, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peak, reason = 0.0, None
    while p.poll() is None:
        peak = max(peak, rss_mib(p.pid))
        el = time.monotonic() - t0
        if budget_s and el > budget_s:
            reason = f"time budget {budget_s}s exceeded"
        elif budget_mib and peak > budget_mib:
            reason = f"memory budget {budget_mib} MiB exceeded"
        if reason:
            p.kill()
            p.wait()
            return {"status": "budget_exceeded", "reason": reason, "elapsed_s": round(el, 1), "peak_rss_mib": round(peak, 1)}
        time.sleep(0.25)
    out, err = p.communicate()
    el = time.monotonic() - t0
    res = {"status": "ok" if p.returncode == 0 else "error", "elapsed_s": round(el, 1), "peak_rss_mib": round(peak, 1)}
    for line in out.splitlines():
        if line.startswith("RESULT "):
            res["result"] = json.loads(line[7:])
    if p.returncode != 0:
        res["error"] = err[-800:]
    return res


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[12000, 100000])
    ap.add_argument("--out", default="reports/benchmark.json")
    a = ap.parse_args(argv)
    meminfo = Path("/proc/meminfo").read_text().splitlines()[0] if Path("/proc/meminfo").exists() else ""
    report = {"declared_budgets": {str(k): v for k, v in BUDGETS.items()},
              "hardware": {"platform": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count(), "memory": meminfo,
                           "python": platform.python_version()},
              "dataset": "argos.synthetic.generate_bulk: deterministic synthetic mix (identity, proxy/http, endpoint, dns), 300+ identities",
              "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "runs": []}
    for n in a.sizes:
        b = BUDGETS.get(n, {"ingest": (None, None), "analyze": (None, None)})
        with tempfile.TemporaryDirectory(prefix=f"bench-{n}-") as td:
            data, home = Path(td) / "bulk.jsonl", Path(td) / "home"
            gen = run_phase(["generate", str(home), str(data), str(n)], None, None)
            entry = {"events": n, "file_mib": round(data.stat().st_size / 2**20, 1) if data.exists() else None, "generate": gen}
            entry["ingest"] = run_phase(["ingest", str(home), str(data)], *b["ingest"])
            if entry["ingest"]["status"] == "ok":
                entry["analyze"] = run_phase(["analyze", str(home), str(data)], *b["analyze"])
            else:
                entry["analyze"] = {"status": "not_run", "reason": "ingest did not complete within budget"}
            entry["db_mib"] = round(sum(f.stat().st_size for f in home.glob("argos.sqlite3*")) / 2**20, 1) if home.exists() else None
        report["runs"].append(entry)
        print(json.dumps(entry), flush=True)
        Path(a.out).write_text(json.dumps(report, indent=2))
    report["finished_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    Path(a.out).write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
