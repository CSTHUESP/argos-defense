"""Update path: a genuine v0.2.0 data directory (synthetic demo database produced by the v0.2.0 code at
commit 2919529, stored as packaging/fixtures/legacy-v0.2.0-demo.sql.gz) migrates to schema v3 without
inventing history, keeps a verified backup, and can be re-analysed and compared."""
import gzip
import sqlite3

from argos.analysis import run_analysis
from argos.config import Settings
from argos.reporting.export import build_case_export
from argos.store import Store
from conftest import ROOT, RULES


def test_v020_demo_database_migrates_and_reanalyses(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    con = sqlite3.connect(home / "argos.sqlite3")
    con.executescript(gzip.decompress((ROOT / "packaging/fixtures/legacy-v0.2.0-demo.sql.gz").read_bytes()).decode())
    con.commit()
    con.close()
    s = Settings()
    s.home = home
    s.rules_dir = RULES
    s.ensure()
    st = Store(s.db_path)
    try:
        assert st.schema_version() == 3
        b = sqlite3.connect(home / "argos.v2-backup.sqlite3")
        assert b.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 425
        assert b.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        b.close()
        case = st.get_case("demo-synthetic")
        runs = st.list_runs(case["case_id"])
        assert len(runs) == 1 and runs[0]["snapshot_available"] == 0 and runs[0]["status"] == "succeeded"
        assert st.run_alerts(runs[0]["run_id"]) == []  # never invented
        assert len(st.list_alerts(case["case_id"])) == 29  # legacy latest-alert table kept
        assert st.count_events(case["case_id"]) == 425
        exp = build_case_export(st, s, case["case_id"])
        assert exp["run"]["basis"].startswith("legacy")
        res = run_analysis(st, s, case["case_id"])
        assert st.get_run(res["run_id"])["snapshot_available"] == 1
        assert len(st.run_alerts(res["run_id"])) > 0
        from argos.reporting.compare import compare_runs
        try:
            compare_runs(st, runs[0]["run_id"], res["run_id"])
            raise AssertionError("legacy run must not be compared as if it had a snapshot")
        except ValueError as exc:
            assert "legacy" in str(exc)
    finally:
        st.close()
    st = Store(s.db_path)  # idempotent restart
    assert st.schema_version() == 3
    st.close()
