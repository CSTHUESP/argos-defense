"""Synthetic batch of >=10,000 events: chunked ingestion + analysis. Records the measured
elapsed time and memory for this machine only (no performance guarantee)."""
import json
import platform
import time
import tracemalloc

import psutil

from argos.synthetic import generate_bulk
from conftest import ROOT

N = 12000


def test_bulk_12k_events(env):
    env.settings.chunk_size = 1000
    p = env.tmp / "bulk.jsonl"
    generate_bulk(p, N)
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    tracemalloc.start()
    c = env.case("bulk")
    t0 = time.perf_counter()
    r = env.ingest(c, p)
    t1 = time.perf_counter()
    res = env.analyze(c)
    t2 = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss1 = proc.memory_info().rss
    assert r["accepted"] == N and r["rejected"] == 0 and env.store.count_events(c["case_id"]) == N
    assert res["stats"]["events"] == N
    # re-import is idempotent at scale
    assert env.ingest(c, p)["new_events"] == 0
    out = {"events": N, "chunk_size": env.settings.chunk_size, "ingest_seconds": round(t1 - t0, 3),
           "analyze_seconds": round(t2 - t1, 3), "python_tracemalloc_peak_mb": round(peak / 1e6, 1),
           "rss_delta_mb": round((rss1 - rss0) / 1e6, 1), "alerts": res["stats"]["alerts"],
           "machine": f"{platform.system()} {platform.machine()} py{platform.python_version()} cpus={psutil.cpu_count()}",
           "note": "single run on the build sandbox; not a performance guarantee"}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "perf_bulk_12k.json").write_text(json.dumps(out, indent=2))
    print(out)
