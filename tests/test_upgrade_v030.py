"""Upgrade from a representative v0.3.0 data directory (schema 3; synthetic demo produced by the v0.3.0 code at
d538dba with two analysis runs, declared coverage on one input and a watcher checkpoint), stored as
packaging/fixtures/legacy-v0.3.0-demo.sql.gz. Preserves data and run snapshots; migrates watcher checkpoints to
an explicit legacy state; never broadens old coverage claims."""
import gzip
import json
import sqlite3

from argos.analysis import CoverageContext, run_analysis
from argos.config import Settings
from argos.reporting.compare import compare_runs
from argos.store import SCHEMA_VERSION, Store
from conftest import ROOT, RULES


def _home(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    con = sqlite3.connect(home / "argos.sqlite3")
    con.executescript(gzip.decompress((ROOT / "packaging/fixtures/legacy-v0.3.0-demo.sql.gz").read_bytes()).decode())
    con.commit()
    con.close()
    s = Settings()
    s.home = home
    s.rules_dir = RULES
    s.ensure()
    return s


def test_v030_database_upgrades_to_v4(tmp_path):
    s = _home(tmp_path)
    st = Store(s.db_path)
    try:
        assert st.schema_version() == SCHEMA_VERSION == 4
        assert st.last_migration["from"] == 3
        b = sqlite3.connect(s.home / "argos.v3-backup.sqlite3")
        assert b.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and b.execute("SELECT COUNT(*) FROM run_alerts").fetchone()[0] == 60
        b.close()
        case = st.get_case("demo-synthetic")
        runs = st.list_runs(case["case_id"])
        assert len(runs) == 2 and all(r["snapshot_available"] for r in runs)
        assert len(st.run_alerts(runs[0]["run_id"])) == 30  # historical snapshots unchanged
        cp = st.conn.execute("SELECT * FROM watch_checkpoints").fetchone()
        assert cp["legacy"] == 1 and cp["ino"] is None and cp["offset"] == 164
        # coverage declared under v0.3.0 has no event kinds -> interpreted narrowly (kinds present in that input)
        inputs = {i["input_id"]: i for i in st.list_inputs(case["case_id"])}
        declared = [i for i in inputs.values() if i.get("coverage")]
        assert declared and "event_kinds" not in json.loads(declared[0]["coverage"])
        ctx = CoverageContext(list(st.iter_events(case["case_id"])), inputs)
        present = {e["event_kind"] for e in st.iter_events(case["case_id"]) if e["input_id"] == declared[0]["input_id"]}
        assert ctx.declared[0]["kinds"] == present and ctx.declared[0]["kinds_basis"].startswith("event kinds present")
        r = run_analysis(st, s, case["case_id"])
        cmp_ = compare_runs(st, runs[-1]["run_id"], r["run_id"])
        assert "engine" in cmp_["inputs_changed"] and cmp_["inputs_changed"]["engine"]
    finally:
        st.close()
    assert Store(s.db_path).schema_version() == 4  # idempotent restart
