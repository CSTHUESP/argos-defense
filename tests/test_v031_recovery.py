"""v0.3.1 follow-up 2: import-recovery boundaries (defects A and B).

A: an import's completion must not become durable before its intended revision is active. Failures are injected
   at the real activation boundary with a SQLite trigger (the activation UPDATE aborts), so the test needs no
   private API and inspects persisted state through a freshly opened Store.
B: after a completed delivery whose checkpoint update failed, recovery must re-deliver exactly the committed range
   even if the file grew or the chunk budget changed; occurrences are asserted by file, byte range and value.

Uses only interfaces that also exist in candidate abe0ebb, so the regressions fail there because of the persisted
state, not because of a renamed field or helper.
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

COMPLETED = ("imported", "rejected")
T0 = datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)


def ts(i):
    return (T0 + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ")


def line(i, q):
    return json.dumps({"event_time": ts(i), "event_kind": "dns", "dns_query": q}) + "\n"


TRIGGER = ("CREATE TRIGGER inject_activation_failure BEFORE UPDATE OF active ON inputs WHEN NEW.active=1 "
           "BEGIN SELECT RAISE(ABORT, 'injected failure at revision activation'); END;")


def arm(store):
    store.conn.execute(TRIGGER)
    store.conn.commit()


def disarm(store):
    store.conn.execute("DROP TRIGGER inject_activation_failure")
    store.conn.commit()


def reopen(env):
    from argos.store import Store
    return Store(env.settings.db_path)


def no_completed_marker_without_activation(st, case_id):
    """Persisted invariant: a completed-status input is active, or superseded by a newer completed revision of the same
    content/delivery. Anything else is a completion marker whose activation never happened."""
    rows = [dict(r) for r in st.conn.execute("SELECT * FROM inputs WHERE case_id=?", (case_id,))]
    bad = []
    for r in rows:
        if r["status"] in COMPLETED and not r["active"]:
            newer = [n for n in rows if n["sha256"] == r["sha256"] and n["delivery_key"] == r["delivery_key"]
                     and n["revision"] > r["revision"] and n["status"] in COMPLETED]
            if not newer:
                bad.append((r["input_id"], r["status"], r["active"], r["records_accepted"]))
    return bad


def occurrences(st, case_id):
    rows = []
    for e in st.iter_events(case_id):
        inp = dict(st.conn.execute("SELECT source_ref FROM inputs WHERE input_id=?", (e["input_id"],)).fetchone())
        ref = json.loads(inp["source_ref"])
        loc = e["source_locator"]
        rows.append((ref["file"], ref["byte_start"] + loc["byte_start"], ref["byte_start"] + loc["byte_end"], e["dns_query"]))
    return sorted(rows)


def checkpoint(st):
    return st.conn.execute("SELECT offset FROM watch_checkpoints").fetchone()["offset"]


def expected(name, lines):
    out, off = [], 0
    for text, q in lines:
        out.append((name, off, off + len(text), q))
        off += len(text)
    return sorted(out)


# ---------------------------------------------------------------------------------------------- defect A
def test_a_watch_failure_at_activation_boundary_is_not_certified_and_recovers(env, tmp_path):
    import argos.watch as W
    d = tmp_path / "a-watch"
    d.mkdir()
    lines = [(line(0, "r0.example"), "r0.example"), (line(1, "r1.example"), "r1.example")]
    (d / "feed.jsonl").write_text("".join(t for t, _ in lines))
    c = env.case("recov-a1")
    src = W.add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    arm(env.store)
    try:
        s = W.poll_once(env.store, env.settings, src)
        assert s["errors"]
    except sqlite3.DatabaseError:
        pass  # the failure may surface as an exception; either way nothing may be certified
    disarm(env.store)

    st = reopen(env)  # inspect persisted state, as after a restart
    try:
        assert checkpoint(st) == 0, "the checkpoint consumed a delivery whose finalization failed"
        assert no_completed_marker_without_activation(st, c["case_id"]) == []
        st.recover_interrupted_imports()
        W.poll_once(st, env.settings, src)
        assert occurrences(st, c["case_id"]) == expected("feed.jsonl", lines)
        assert checkpoint(st) == (d / "feed.jsonl").stat().st_size
        W.poll_once(st, env.settings, src)
    finally:
        st.close()
    st = reopen(env)
    try:
        W.poll_once(st, env.settings, src)
        assert occurrences(st, c["case_id"]) == expected("feed.jsonl", lines)
        assert no_completed_marker_without_activation(st, c["case_id"]) == []
    finally:
        st.close()


def test_a_manual_import_failure_at_activation_boundary_recovers_exactly_once(env):
    from argos.ingest.pipeline import ingest_file
    c = env.case("recov-a2")
    p = env.write("m.jsonl", [{"event_time": ts(i), "event_kind": "dns", "dns_query": f"m{i}.example"} for i in range(2)])
    arm(env.store)
    with pytest.raises(sqlite3.DatabaseError):
        ingest_file(env.store, env.settings, c, p, "native_jsonl", {})
    disarm(env.store)
    st = reopen(env)
    try:
        assert no_completed_marker_without_activation(st, c["case_id"]) == []
        r = ingest_file(st, env.settings, c, p, "native_jsonl", {})
        assert r["status"] == "imported"
        assert sorted(e["dns_query"] for e in st.iter_events(c["case_id"])) == ["m0.example", "m1.example"]
        assert ingest_file(st, env.settings, c, p, "native_jsonl", {})["status"] == "already_imported"
        assert st.count_events(c["case_id"]) == 2
    finally:
        st.close()


def test_a_failed_replacement_finalization_keeps_previous_revision_until_replacement_finalized(env):
    from argos.ingest.pipeline import ingest_file
    c = env.case("recov-a3")
    p = env.write("n.jsonl", [{"event_time": "2026-11-03 10:00:0%d" % i, "event_kind": "dns", "dns_query": f"n{i}.example"}
                              for i in range(3)])
    r1 = ingest_file(env.store, env.settings, c, p, "native_jsonl", {"assume_tz": "UTC"})
    assert r1["accepted"] == 3
    arm(env.store)
    with pytest.raises(sqlite3.DatabaseError):
        ingest_file(env.store, env.settings, c, p, "native_jsonl", {"assume_tz": "Europe/Budapest"}, reprocess=True)
    disarm(env.store)
    st = reopen(env)
    try:
        active = [dict(r) for r in st.conn.execute("SELECT input_id FROM inputs WHERE case_id=? AND active=1", (c["case_id"],))]
        assert [a["input_id"] for a in active] == [r1["input_id"]]
        assert {e["input_id"] for e in st.iter_events(c["case_id"])} == {r1["input_id"]} and st.count_events(c["case_id"]) == 3
        assert no_completed_marker_without_activation(st, c["case_id"]) == []
        r2 = ingest_file(st, env.settings, c, p, "native_jsonl", {"assume_tz": "Europe/Budapest"}, reprocess=True)
        assert r2["status"] == "reprocessed"
        active = [r["input_id"] for r in st.conn.execute("SELECT input_id FROM inputs WHERE case_id=? AND active=1", (c["case_id"],))]
        assert active == [r2["input_id"]] != [r1["input_id"]]
        evs = list(st.iter_events(c["case_id"]))
        assert len(evs) == 3 and {e["input_id"] for e in evs} == {r2["input_id"]}
        assert no_completed_marker_without_activation(st, c["case_id"]) == []
    finally:
        st.close()


# ---------------------------------------------------------------------------------------------- defect B
def _crash_checkpoint_once(monkeypatch):
    import argos.watch as W
    real = W._tail_sha
    state = {"armed": True}

    def crash(path, offset):
        if state["armed"] and offset > 0:
            state["armed"] = False
            raise OSError("simulated crash after import, before checkpoint update")
        return real(path, offset)
    monkeypatch.setattr(W, "_tail_sha", crash)


SHARED = line(0, "shared.example")


@pytest.mark.parametrize("first_budget", [1 << 20, len(SHARED)])
def test_b_append_before_checkpoint_recovery_keeps_each_occurrence_once(env, tmp_path, monkeypatch, first_budget):
    import argos.watch as W
    d = tmp_path / f"b-append-{first_budget}"
    d.mkdir()
    f = d / "feed.jsonl"
    lines = [(SHARED, "shared.example"), (line(1, "r1.example"), "r1.example")]
    f.write_text("".join(t for t, _ in lines))
    c = env.case(f"recov-b1-{first_budget}")
    src = W.add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    _crash_checkpoint_once(monkeypatch)
    s = W.poll_once(env.store, env.settings, src, max_chunk_bytes=first_budget)
    assert s["errors"] and checkpoint(env.store) == 0
    committed = occurrences(env.store, c["case_id"])
    assert committed and committed[0] == ("feed.jsonl", 0, len(SHARED), "shared.example")
    # the source grows BEFORE recovery; the appended record is byte-identical to the first one (distinct offset)
    with open(f, "a") as fh:
        fh.write(SHARED)
    lines.append((SHARED, "shared.example"))
    for _ in range(4):
        W.poll_once(env.store, env.settings, src)
    assert occurrences(env.store, c["case_id"]) == expected("feed.jsonl", lines)
    assert checkpoint(env.store) == f.stat().st_size
    st = reopen(env)
    try:
        W.poll_once(st, env.settings, src)
        W.poll_once(st, env.settings, src, max_chunk_bytes=len(SHARED))
        assert occurrences(st, c["case_id"]) == expected("feed.jsonl", lines)
    finally:
        st.close()


@pytest.mark.parametrize("recovery_budget", [len(SHARED), 2 * len(SHARED) + 5, 1 << 20])
def test_b_recovery_with_different_chunk_budget_does_not_change_committed_identity(env, tmp_path, monkeypatch, recovery_budget):
    import argos.watch as W
    d = tmp_path / f"b-budget-{recovery_budget}"
    d.mkdir()
    f = d / "feed.jsonl"
    lines = [(SHARED, "shared.example"), (line(1, "r1.example"), "r1.example"), (SHARED, "shared.example")]
    f.write_text("".join(t for t, _ in lines))
    c = env.case(f"recov-b2-{recovery_budget}")
    src = W.add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    _crash_checkpoint_once(monkeypatch)
    s = W.poll_once(env.store, env.settings, src, max_chunk_bytes=1 << 20)
    assert s["errors"] and checkpoint(env.store) == 0
    assert occurrences(env.store, c["case_id"]) == expected("feed.jsonl", lines)
    for _ in range(4):
        W.poll_once(env.store, env.settings, src, max_chunk_bytes=recovery_budget)
    assert occurrences(env.store, c["case_id"]) == expected("feed.jsonl", lines)
    assert checkpoint(env.store) == f.stat().st_size
    st = reopen(env)
    try:
        for budget in (len(SHARED), 1 << 20):
            W.poll_once(st, env.settings, src, max_chunk_bytes=budget)
        assert occurrences(st, c["case_id"]) == expected("feed.jsonl", lines)
    finally:
        st.close()


def test_b_changed_bytes_of_a_committed_range_pause_instead_of_duplicating(env, tmp_path, monkeypatch):
    import argos.watch as W
    d = tmp_path / "b-changed"
    d.mkdir()
    f = d / "feed.jsonl"
    f.write_text(SHARED + line(1, "r1.example"))
    c = env.case("recov-b3")
    src = W.add_source(env.store, c, d, "*.jsonl", "native_jsonl")
    _crash_checkpoint_once(monkeypatch)
    W.poll_once(env.store, env.settings, src)
    before = occurrences(env.store, c["case_id"])
    # rewrite the second (committed, not yet acknowledged) line in place, same length; first line unchanged
    data = f.read_bytes().replace(b"r1.example", b"rX.example")
    f.write_bytes(data)
    s = W.poll_once(env.store, env.settings, src)
    after = occurrences(env.store, c["case_id"])
    assert after == before and checkpoint(env.store) == 0
    assert any("changed" in e or "rewrite" in e for e in s["errors"])


def test_a_pre_fix_database_distinguishes_superseded_revision_from_interrupted_finalization(env):
    """Upgrade path: a database written before `inputs.finalized` existed. A superseded historical revision stays
    inactive and certified; an input left 'imported' but never activated (defect A state) is NOT certified and is
    re-run on retry -- inactive inputs are not blanket-reactivated."""
    from argos.ingest.pipeline import ingest_file
    c = env.case("recov-upgrade")
    p = env.write("u.jsonl", [{"event_time": "2026-11-03 10:00:0%d" % i, "event_kind": "dns", "dns_query": f"u{i}.example"}
                              for i in range(2)])
    q = env.write("v.jsonl", [{"event_time": ts(i), "event_kind": "dns", "dns_query": f"v{i}.example"} for i in range(2)])
    r1 = ingest_file(env.store, env.settings, c, p, "native_jsonl", {"assume_tz": "UTC"})
    r2 = ingest_file(env.store, env.settings, c, p, "native_jsonl", {"assume_tz": "Europe/Budapest"}, reprocess=True)
    rb = ingest_file(env.store, env.settings, c, q, "native_jsonl", {})
    with env.store.tx() as cx:  # reproduce the pre-fix durable state of defect A for rb, then remove the new column
        cx.execute("UPDATE inputs SET active=0 WHERE input_id=?", (rb["input_id"],))
        cx.execute("ALTER TABLE inputs DROP COLUMN finalized")
    st = reopen(env)
    try:
        fin = {r["input_id"]: (r["finalized"], r["active"]) for r in st.conn.execute("SELECT input_id, finalized, active FROM inputs")}
        assert fin[r1["input_id"]] == (1, 0) and fin[r2["input_id"]] == (1, 1) and fin[rb["input_id"]] == (0, 0)
        assert st.recover_interrupted_imports() == 1
        assert st.get_input(rb["input_id"])["status"] == "interrupted" and st.get_input(r1["input_id"])["status"] == "imported"
        again = ingest_file(st, env.settings, c, q, "native_jsonl", {})
        assert again["status"] == "imported" and again["input_id"] == rb["input_id"]
        assert sorted(e["dns_query"] for e in st.iter_events(c["case_id"])) == ["u0.example", "u1.example", "v0.example", "v1.example"]
        assert [r["input_id"] for r in st.conn.execute("SELECT input_id FROM inputs WHERE active=1 ORDER BY input_id")] == \
            sorted([r2["input_id"], rb["input_id"]])
    finally:
        st.close()
