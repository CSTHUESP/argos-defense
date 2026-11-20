"""Reproduce audit findings F01-F13 against the current code. Prints REPRODUCED / NOT REPRODUCED per finding.
Synthetic data only. Usage: python scripts/audit_repro.py"""
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
from conftest import Env  # noqa: E402

R = {}


def env():
    return Env(Path(tempfile.mkdtemp(prefix="audit-")))


def ts(s):
    from argos.synthetic import ts as t
    return t(s)


def f01():
    e = env()
    rows = [{"event_time": ts(0), "event_kind": "tool_execution", "host": "h1", "linked_process_guid": "{G}", "session_id": "s1"},
            {"event_time": ts(2), "event_kind": "process_start", "host": "h1", "process_guid": "{G}", "process_image": "/bin/sh"}]
    c = e.run("f01", rows)
    lv = {a["rule_id"]: a["llm"]["level"] for a in e.alerts(c)}
    return any(v == "directly_observed" for v in lv.values()), lv


def f02():
    e = env()
    rows = [{"event_time": ts(0), "event_kind": "model_interaction", "tenant_id": "A", "host": "hA", "session_id": "session-1", "model_tool_name": "read_file"},
            {"event_time": ts(5), "event_kind": "tool_execution", "tenant_id": "B", "host": "hB", "session_id": "session-1", "action": "send_email"}]
    c = e.run("f02", rows)
    a = e.alerts(c, "ARG-LLM-002")
    return bool(a), [x["group"] for x in a]


def f03():
    e = env()
    sp = dict(tenant_id="t", app_id="app", account_type="service_principal")
    rows = [dict(event_time=ts(0), event_kind="authentication", outcome="success", **sp),
            dict(event_time=ts(60), event_kind="cloud_operation", action="credential_add", outcome="failure", **sp)]
    c = e.run("f03", rows)
    a = e.alerts(c, "ARG-SP-001")
    return bool(a) and a[0]["purpose"]["stage"] == "observed_success", a[0]["purpose"] if a else None


def f04():
    e = env()
    # tenant X has old data; principal in tenant Y has no own history -> baseline must not be "covered zero windows"
    rows = [{"event_time": ts(0), "event_kind": "cloud_operation", "tenant_id": "X", "app_id": "other", "action": "signin_noise"}]
    rows += [{"event_time": ts(40 * 3600 + i * 10), "event_kind": "cloud_operation", "tenant_id": "Y", "app_id": "new", "action": "secret_read", "resource": "kv"} for i in range(30)]
    c = e.run("f04", rows)
    a = [x for x in e.alerts(c, "ARG-SP-002")]
    return bool(a) and not a[0]["abstained"], [(x["baseline"] or {}).get("status") for x in a]


def f05():
    e = env()
    rows = [{"event_time": ts(i), "event_kind": "authentication", "tenant_id": "t", "user": f"u{i}@x", "src_ip": "192.0.2.50", "outcome": "failure",
             "message": '{"password":"SYNTHETIC_SECRET_123","nested":{"api_key":"SYNTH_APIKEY_456"}} Authorization: "Bearer SYNTH_TOKEN_789"'} for i in range(12)]
    c = e.run("f05", rows)
    e.store.add_note(c["case_id"], 'creds {"password":"SYNTHETIC_SECRET_123"}')
    from argos.reporting.export import build_case_export
    txt = json.dumps(build_case_export(e.store, e.settings, c["case_id"]))
    leaks = [s for s in ("SYNTHETIC_SECRET_123", "SYNTH_APIKEY_456", "SYNTH_TOKEN_789") if s in txt]
    return bool(leaks), leaks


def f06():
    d = Path(tempfile.mkdtemp())
    db = d / "argos.sqlite3"
    code = f"""
import sqlite3,os,sys
sys.path.insert(0,{str(ROOT / 'src')!r})
from argos.store import SCHEMA
c=sqlite3.connect({str(db)!r}); c.executescript(SCHEMA)
c.execute("INSERT INTO cases VALUES('c1','one',0,'','open','x')"); c.commit()
c.execute("INSERT INTO cases VALUES('c2','two',0,'','open','x')"); c.commit()
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", code], check=True)
    from argos.store import Store
    st = Store(db)
    live = st.conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    st.close()
    bk = next(d.glob("*backup*"), None)
    n = sqlite3.connect(bk).execute("SELECT COUNT(*) FROM cases").fetchone()[0] if bk else None
    return bk is not None and n != live, {"live": live, "backup": n}


def f07():
    e = env()
    c = e.case("f07")
    e.ingest(c, [{"event_time": ts(0), "event_kind": "dns", "dns_query": "a"}])
    modes = {"home": oct(stat.S_IMODE(e.settings.home.stat().st_mode)), "db": oct(stat.S_IMODE(e.settings.db_path.stat().st_mode)),
             "orig": oct(stat.S_IMODE(Path(e.store.list_inputs(c["case_id"])[0]["stored_path"]).stat().st_mode))}
    return any(int(v, 8) & 0o077 for v in modes.values()), modes


def f08():
    e = env()
    c = e.case("f08")
    p = e.tmp / "arr.json"
    p.write_text(json.dumps([{"event_time": ts(0), "event_kind": "dns", "dns_query": "first.example"}], indent=2))
    e.ingest(c, p)
    ev = next(e.store.iter_events(c["case_id"]))
    from starlette.datastructures import State  # noqa
    from argos.api.app import AppState, _original_record
    st = AppState.__new__(AppState)
    st.store = e.store
    rec = _original_record(st, ev)
    return "first.example" not in (rec["record_text"] or ""), rec["record_text"]


def f09():
    e = env()
    rows = [{"event_time": ts(i * 10), "event_kind": "authentication", "tenant_id": "t", "user": f"u{i}@x", "src_ip": "192.0.2.50", "outcome": "failure"} for i in range(12)]
    c = e.run("f09", rows)
    a1 = e.alerts(c)[0]
    inp = e.store.list_inputs(c["case_id"])[0]
    e.store.set_input_trust(inp["input_id"], "analyst_attested", "x")
    e.analyze(c)
    # reproduced if the first run's alert payload is no longer retrievable as it was
    names = [r[0] for r in e.store.conn.execute("SELECT name FROM sqlite_master")]
    if "run_alerts" not in names:
        return True, "no per-run alert snapshots"
    runs = e.store.list_runs(c["case_id"])
    first = {x["alert_id"]: x for x in e.store.run_alerts(runs[0]["run_id"])}
    kept = first.get(a1["alert_id"])
    same = kept is not None and all(kept.get(k) == a1.get(k) for k in ("confidence", "threat", "llm", "provenance") if k in a1)
    return not same, {"runs": len(runs), "first_run_alert_preserved": same}


def f10():
    e = env()
    c = e.case("f10")
    p = e.write("naive.jsonl", [{"event_time": "2026-11-03 10:00:00", "event_kind": "dns", "dns_query": "a"}])
    r1 = e.ingest(c, p)
    r2 = e.ingest(c, p, options={"assume_tz": "UTC"})
    return r2["status"] == "already_imported", (r1["accepted"], r2["status"])


def f12():
    d = Path(tempfile.mkdtemp())
    for t in ("windows-x86_64", "linux-x86_64", "macos-arm64", "macos-x86_64"):
        a = d / f"WRONG-{t}.zip"
        a.write_bytes(b"x")
        import hashlib
        h = hashlib.sha256(b"x").hexdigest()
        (d / f"build-info-{t}.json").write_text(json.dumps({"name": a.name, "sha256": h, "commit": "c", "build_env": {}, "signing": "", "version": "9.9", "target": "linux"}))
        (d / f"smoke-{t}.json").write_text(json.dumps({"overall_pass": True, "checks_passed": 0, "checks_total": 0, "archive_sha256": h, "os": {}}))
    r = subprocess.run([sys.executable, str(ROOT / "packaging/release_manifest.py"), "--assets", str(d), "--version", "0.2.0", "--commit", "c", "--tag", "v0.2.0"],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stdout.strip()[:120]


def f13():
    sys.path.insert(0, str(ROOT / "packaging"))
    import smoke_test
    d = Path(tempfile.mkdtemp())
    (d / "a.txt").write_text("AAAA")
    h1 = smoke_test.tree_fingerprint(d)
    (d / "a.txt").write_text("BBBB")
    return smoke_test.tree_fingerprint(d) == h1, "same-length modification undetected"


def f11():
    y = (ROOT / ".github/workflows/release.yml").read_text()
    return "is-ancestor" not in y, "release.yml lacks main-ancestry/CI preflight"


for name in ("f01", "f02", "f03", "f04", "f05", "f06", "f07", "f08", "f09", "f10", "f11", "f12", "f13"):
    try:
        rep, detail = globals()[name]()
        R[name.upper()] = {"reproduced": bool(rep), "detail": str(detail)[:300]}
    except Exception as exc:  # noqa: BLE001
        R[name.upper()] = {"reproduced": None, "detail": f"error: {type(exc).__name__}: {exc}"[:300]}
    print(name.upper(), "REPRODUCED" if R[name.upper()]["reproduced"] else ("ERROR" if R[name.upper()]["reproduced"] is None else "NOT REPRODUCED"), R[name.upper()]["detail"])
if len(sys.argv) > 1:
    Path(sys.argv[1]).write_text(json.dumps(R, indent=2))
