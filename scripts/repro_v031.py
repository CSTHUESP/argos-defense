"""Reproduce the v0.3.1 review findings R01-R09 against a source tree (synthetic data only).

    python scripts/repro_v031.py --root /path/to/checkout [--json out.json]

`--root` may be the reviewed v0.3.0 commit (an isolated worktree) or the current checkout. Each check
prints REPRODUCED (the defect is present in that tree) or NOT REPRODUCED. Checks that are only
static (R07, R09) inspect the tree's files.
"""
from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--root", required=True)
ap.add_argument("--json")
A = ap.parse_args()
ROOT = Path(A.root).resolve()
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from conftest import Env  # noqa: E402

from argos.synthetic import ts  # noqa: E402

R = {}


def env():
    return Env(Path(tempfile.mkdtemp(prefix="r031-")))


def serve(e):
    from test_web_e2e import Client, Server
    tok = "repro-token"
    srv = Server(e.settings, tok)
    srv.__enter__()
    return srv, Client(srv.port, tok)


def r01():
    leaks = {}
    e = env()
    srv, cl = serve(e)
    try:
        st, _, body = cl.req("POST", "/api/cases", json.dumps({"name": "r01", "synthetic": True,
                                                              "description": "api_key: SYNTH_CASE_SECRET"}),
                             {"Content-Type": "application/json"}, bearer=True)
        leaks["case_create"] = "SYNTH_CASE_SECRET" in body
        st, _, body = cl.req("GET", "/api/cases", bearer=True)
        leaks["case_list"] = "SYNTH_CASE_SECRET" in body
        c = e.store.get_case("r01")
        rows = [{"event_time": ts(0), "event_kind": "dns", "dns_query": "a.example", "token": ["SYNTH_LIST_SECRET"]},
                {"event_time": ts(1), "event_kind": "dns", "dns_query": "b.example", "credentials": {"value": "SYNTH_NESTED_SECRET"}}]
        e.ingest(c, rows)
        p = e.tmp / "auth.csv"
        p.write_text("_time,user,src_ip,outcome,password\n" + f"{ts(5)},bob@x,192.0.2.1,failure,SYNTH_CSV_SECRET\n")
        e.ingest(c, p, fmt="splunk_csv", options={"profile": "auth"})
        for ev in e.store.iter_events(c["case_id"]):
            st, _, body = cl.req("GET", f"/api/events/{ev['event_id']}", bearer=True)
            for s in ("SYNTH_LIST_SECRET", "SYNTH_NESTED_SECRET", "SYNTH_CSV_SECRET"):
                if s in body:
                    leaks[f"event_api:{s}"] = True
                    leaks[f"event_api:{s}:labelled_redacted"] = bool(re.search(r'"redacted":\s*true', body))
    finally:
        srv.__exit__()
    bad = {k: v for k, v in leaks.items() if v and not k.endswith("labelled_redacted")}
    return bool(bad), leaks


def r02():
    from argos.backup import create_backup, restore_backup, verify_backup
    from argos.config import Settings
    e = env()
    c = e.run("r02", [{"event_time": ts(i), "event_kind": "dns", "dns_query": f"q{i}"} for i in range(3)])
    inp = e.store.list_inputs(c["case_id"])[0]
    sp = Path(inp["stored_path"])
    os.chmod(sp, 0o600)
    sp.unlink()
    try:
        res = create_backup(e.settings, e.tmp / "b.zip")
        verify_backup(Path(res["backup"]))
    except Exception as exc:  # noqa: BLE001
        return False, f"backup refused: {type(exc).__name__}: {exc}"[:200]
    s2 = Settings()
    s2.home = e.tmp / "restored"
    out = restore_backup(Path(res["backup"]), s2)
    from argos.store import Store
    st = Store(s2.db_path)
    ref = st.list_inputs(c["case_id"])[0]["stored_path"]
    st.close()
    return True, {"backup": "created+verified despite missing original", "restored_reference": ref,
                  "points_to_old_home": str(e.settings.home) in ref, "restore_result_keys": sorted(out)}


def r03():
    from argos.watch import add_source, poll_once
    e = env()
    d = e.tmp / "SYNTHETIC-watch"
    d.mkdir()
    first = json.dumps({"event_time": ts(0), "event_kind": "dns", "dns_query": "shared.example"}) + "\n"
    (d / "a.jsonl").write_text(first + json.dumps({"event_time": ts(1), "event_kind": "dns", "dns_query": "only-in-a.example"}) + "\n")
    (d / "b.jsonl").write_text(first + json.dumps({"event_time": ts(1), "event_kind": "dns", "dns_query": "only-in-b.example"}) + "\n")
    c = e.case("r03")
    src = add_source(e.store, c, d, "*.jsonl", "native_jsonl")
    s = poll_once(e.store, e.settings, src)
    qs = sorted(ev["dns_query"] for ev in e.store.iter_events(c["case_id"]))
    return "only-in-b.example" not in qs or "only-in-a.example" not in qs, {"events": qs, "errors": s["errors"]}


def r04():
    out = {}
    e = env()
    m = {"event_time": ts(0), "event_kind": "model_interaction", "session_id": "session|part", "tool_call_id": "call",
         "model_tool_name": "bash", "tenant_id": "t", "source_type": "gw", "host": "h1"}
    x = {"event_time": ts(5), "event_kind": "tool_execution", "session_id": "session", "tool_call_id": "part|call",
         "tool_name": "bash", "tenant_id": "t", "source_type": "gw", "host": "h2"}
    c = e.run("r04a", [m, x])
    out["delimiter_collision_linked"] = bool(e.alerts(c, "ARG-LLM-002"))
    c2 = e.case("r04b")
    e.ingest(c2, [{k: v for k, v in m.items() if k not in ("tenant_id", "source_type")} | {"session_id": "s1", "tool_call_id": "c1"}],
             name="collector-one.jsonl")
    e.ingest(c2, [{k: v for k, v in x.items() if k not in ("tenant_id", "source_type")} | {"session_id": "s1", "tool_call_id": "c1"}],
             name="collector-two.jsonl")
    e.analyze(c2)
    out["independent_collectors_linked"] = bool(e.alerts(c2, "ARG-LLM-002"))
    return any(out.values()), out


def r05():
    e = env()
    c = e.case("r05")
    sp = {"tenant_id": "t", "app_id": "app-x", "account_type": "service_principal", "source_type": "idp"}
    e.ingest(c, [{"event_time": ts(h * 3600), "event_kind": "authentication", "outcome": "success", **sp} for h in range(30)], name="signins.jsonl")
    e.ingest(c, [{"event_time": ts(30 * 3600 + i * 20), "event_kind": "cloud_operation", "action": "secret_read", "resource": f"kv{i % 3}",
                  "outcome": "success", **sp} for i in range(25)], name="audit.jsonl")
    e.analyze(c)
    al = e.alerts(c, "ARG-SP-002")
    info = [{"abstained": a["abstained"], "baseline": {k: (a.get("baseline") or {}).get(k) for k in ("status", "windows", "covered_window_basis")}} for a in al]
    return any(not a["abstained"] and (a.get("baseline") or {}).get("status") not in ("insufficient_baseline",) for a in al), info


def r06():
    f = ROOT / "scripts" / "eval_v21.py"
    if f.exists():  # current evaluator: alert-level, chain-based allowance
        src = f.read_text()
        independent = "def allowed_llm" in src and "has_chain |= tags" not in src
        return not independent, "eval_v21.py scores each alert against labelled chains" if independent else "unit-level allowance"
    src = (ROOT / "scripts" / "eval_v2.py").read_text()
    weak = 'if e.get("event_kind") in ("model_interaction", "tool_execution"):' in src and "has_chain |= tags" in src
    return weak, "directly_observed allowance derived from any model_interaction/tool_execution record in the unit" if weak else "unit-level union not found"


def r07():
    t = (ROOT / "tests" / "test_remediation.py").read_text()
    m = re.search(r"def test_f05_llm_input_is_redacted.*?(?=\ndef |\Z)", t, re.S)
    body = m.group(0) if m else ""
    from argos.llm import explain as ex
    params = list(inspect.signature(ex.explain).parameters)
    bad = "except Exception" in body and 'if "prompt" in seen' in body
    return bad, {"explain_params": params, "test_calls_with_3_args": "ex.explain(a, env.store.get_events" in body,
                 "provider_method_in_test": "generate" if "def generate" in body else "complete"}


def r08():
    from argos.jobs import JobRunner
    import argos.analysis as AN
    e = env()
    cases = [e.run(f"r08-{i}", [{"event_time": ts(j), "event_kind": "dns", "dns_query": f"q{j}"} for j in range(5)]) for i in range(4)]
    gate = threading.Event()
    running = []
    orig = AN.case_assessment

    def slow(*a, **k):
        running.append(threading.get_ident())
        gate.wait(10)
        return orig(*a, **k)
    AN.case_assessment = slow
    jr = JobRunner(e.settings)
    try:
        jids = [jr.submit_analysis(e.store, c["case_id"]) for c in cases]
        time.sleep(1.0)
        concurrent = len(running)
        gate.set()
        for j in jids:
            jr.wait(j, 30)
    finally:
        AN.case_assessment = orig
    return concurrent > 2, {"jobs_running_simultaneously": concurrent, "cases": len(cases)}


def r09():
    y = (ROOT / ".github/workflows/release.yml").read_text()
    pf = (ROOT / "packaging/release_preflight.py").read_text()
    anon = 'git remote set-url origin "https://github.com/$GITHUB_REPOSITORY.git"' in y and "persist-credentials: false" in y
    auth = "extraheader" in y or "x-access-token" in y or "GIT_CONFIG" in pf or "http.extraheader" in pf
    return anon and not auth, {"anonymous_https_remote_reads": anon, "explicit_git_auth_configured": auth}


for name in ("r01", "r02", "r03", "r04", "r05", "r06", "r07", "r08", "r09"):
    try:
        rep, detail = globals()[name]()
        R[name.upper()] = {"reproduced": bool(rep), "detail": detail}
    except Exception as exc:  # noqa: BLE001
        R[name.upper()] = {"reproduced": None, "detail": f"error: {type(exc).__name__}: {exc}"}
    v = R[name.upper()]
    print(name.upper(), {True: "REPRODUCED", False: "NOT REPRODUCED", None: "ERROR"}[v["reproduced"]], json.dumps(v["detail"], default=str)[:400], flush=True)
if A.json:
    Path(A.json).write_text(json.dumps({"root": str(ROOT), **R}, indent=2, default=str))
os._exit(0)
