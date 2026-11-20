"""SQLite persistence. All SQL uses bound parameters; identifiers are constants."""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from argos.normalize.timeutil import now_iso

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, synthetic INTEGER NOT NULL,
  description TEXT, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS inputs (
  input_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
  sha256 TEXT NOT NULL, original_name TEXT, stored_path TEXT NOT NULL, format TEXT NOT NULL,
  parser_version TEXT NOT NULL, options TEXT NOT NULL, size_bytes INTEGER NOT NULL,
  provenance_trust TEXT NOT NULL DEFAULT 'unverified', provenance_note TEXT,
  records_total INTEGER, records_accepted INTEGER, records_rejected INTEGER,
  imported_at TEXT NOT NULL, UNIQUE(case_id, sha256, format));
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, input_id TEXT NOT NULL, record_no INTEGER NOT NULL,
  event_epoch REAL NOT NULL, event_kind TEXT, vantage TEXT, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_events_case_time ON events(case_id, event_epoch);
CREATE TABLE IF NOT EXISTS rejects (
  case_id TEXT NOT NULL, input_id TEXT NOT NULL, record_no INTEGER NOT NULL, reason TEXT NOT NULL,
  excerpt TEXT, PRIMARY KEY(input_id, record_no));
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, seq INTEGER NOT NULL, started_at TEXT NOT NULL,
  finished_at TEXT, manifest TEXT NOT NULL, versions TEXT NOT NULL, stats TEXT);
CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, rule_id TEXT NOT NULL, rule_version INTEGER NOT NULL,
  first_run TEXT NOT NULL, last_run TEXT NOT NULL, current INTEGER NOT NULL DEFAULT 1,
  severity TEXT, confidence TEXT, first_time TEXT, last_time TEXT, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_alerts_case ON alerts(case_id);
CREATE TABLE IF NOT EXISTS alert_runs (alert_id TEXT NOT NULL, run_id TEXT NOT NULL, PRIMARY KEY(alert_id, run_id));
CREATE TABLE IF NOT EXISTS alert_state (
  alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notes (
  note_id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, alert_id TEXT,
  author TEXT, text TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assessments (
  case_id TEXT NOT NULL, run_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(case_id, run_id));
CREATE TABLE IF NOT EXISTS entities (
  entity_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, etype TEXT NOT NULL, ekey TEXT NOT NULL,
  strength TEXT NOT NULL, display TEXT, event_count INTEGER NOT NULL DEFAULT 0, first_time TEXT, last_time TEXT);
CREATE TABLE IF NOT EXISTS relationships (
  case_id TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, rel TEXT NOT NULL, basis TEXT NOT NULL,
  event_count INTEGER NOT NULL, sample_event TEXT, PRIMARY KEY(case_id, src, dst, rel));
CREATE TABLE IF NOT EXISTS event_entities (
  event_id TEXT NOT NULL, entity_id TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY(event_id, entity_id, role));
CREATE INDEX IF NOT EXISTS ix_ee_entity ON event_entities(entity_id);
"""

SCHEMA_VERSION = 2  # v0.1.0 databases have no meta table (implicit version 1)

CASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class Store:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate()

    def _migrate(self):
        c = self.conn
        c.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        row = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        current = int(row[0]) if row else 1
        if current > SCHEMA_VERSION:
            raise RuntimeError(f"database schema {current} is newer than this ARGOS version supports ({SCHEMA_VERSION})")
        if current < 2:
            # 1 -> 2: only adds the meta table; all v0.1 tables are compatible. Keep a backup first.
            if c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]:
                import shutil
                c.commit()
                shutil.copyfile(self.db_path, self.db_path.with_suffix(".v1-backup.sqlite3"))
            c.execute("INSERT OR REPLACE INTO meta VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
            c.execute("INSERT OR REPLACE INTO meta VALUES('migrated_from', ?)", (str(current),))
        c.commit()

    def schema_version(self) -> int:
        return int(self.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0])

    def close(self):
        self.conn.close()

    @contextmanager
    def tx(self):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # ---------------- cases
    def create_case(self, name: str, synthetic: bool, description: str = "") -> dict:
        if not CASE_NAME_RE.match(name or ""):
            raise ValueError("case name must match [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
        existing = self.get_case(name)
        if existing:
            if bool(existing["synthetic"]) != bool(synthetic):
                raise ValueError(f"case {name!r} exists with synthetic={bool(existing['synthetic'])}; synthetic and real data are never mixed")
            return existing
        cid = "case-" + uuid.uuid4().hex[:12]
        with self.tx() as c:
            c.execute("INSERT INTO cases(case_id,name,synthetic,description,created_at) VALUES(?,?,?,?,?)",
                      (cid, name, 1 if synthetic else 0, description, now_iso()))
        return self.get_case(name)

    def get_case(self, ref: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM cases WHERE case_id=? OR name=?", (ref, ref)).fetchone()
        return dict(r) if r else None

    def list_cases(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM cases ORDER BY created_at").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["event_count"] = self.conn.execute("SELECT COUNT(*) FROM events WHERE case_id=?", (d["case_id"],)).fetchone()[0]
            d["alert_count"] = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE case_id=? AND current=1", (d["case_id"],)).fetchone()[0]
            d["reject_count"] = self.conn.execute("SELECT COUNT(*) FROM rejects WHERE case_id=?", (d["case_id"],)).fetchone()[0]
            out.append(d)
        return out

    def set_case_status(self, case_id: str, status: str):
        if status not in ("open", "investigating", "closed_benign", "closed_true_positive", "closed_inconclusive"):
            raise ValueError("invalid case status")
        with self.tx() as c:
            c.execute("UPDATE cases SET status=? WHERE case_id=?", (status, case_id))

    # ---------------- inputs / events
    def find_input(self, case_id: str, sha256: str, fmt: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM inputs WHERE case_id=? AND sha256=? AND format=?", (case_id, sha256, fmt)).fetchone()
        return dict(r) if r else None

    def add_input(self, row: dict):
        cols = ",".join(row)
        with self.tx() as c:
            c.execute(f"INSERT INTO inputs({cols}) VALUES({','.join('?' * len(row))})", tuple(row.values()))

    def update_input_counts(self, input_id: str, total: int, accepted: int, rejected: int):
        with self.tx() as c:
            c.execute("UPDATE inputs SET records_total=?, records_accepted=?, records_rejected=? WHERE input_id=?",
                      (total, accepted, rejected, input_id))

    def set_input_trust(self, input_id: str, trust: str, note: str):
        if trust not in ("unverified", "analyst_attested"):
            raise ValueError("invalid provenance trust")
        with self.tx() as c:
            c.execute("UPDATE inputs SET provenance_trust=?, provenance_note=? WHERE input_id=?", (trust, note, input_id))

    def list_inputs(self, case_id: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM inputs WHERE case_id=? ORDER BY imported_at", (case_id,))]

    def insert_events(self, events: list[dict]) -> int:
        rows = [(e["event_id"], e["case_id"], e["input_id"], e["record_no"], e["event_epoch"], e["event_kind"],
                 e["observation_vantage"], json.dumps(e, sort_keys=True)) for e in events]
        with self.tx() as c:
            before = c.total_changes
            c.executemany("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?)", rows)
            return c.total_changes - before

    def insert_rejects(self, rejects: list[tuple]):
        with self.tx() as c:
            c.executemany("INSERT OR IGNORE INTO rejects VALUES(?,?,?,?,?)", rejects)

    def iter_events(self, case_id: str):
        cur = self.conn.execute("SELECT data FROM events WHERE case_id=? ORDER BY event_epoch, input_id, record_no", (case_id,))
        for (data,) in cur:
            yield json.loads(data)

    def get_events(self, event_ids: list[str]) -> list[dict]:
        out = []
        for i in range(0, len(event_ids), 500):
            chunk = event_ids[i:i + 500]
            q = "SELECT data FROM events WHERE event_id IN (%s)" % ",".join("?" * len(chunk))
            out += [json.loads(r[0]) for r in self.conn.execute(q, chunk)]
        out.sort(key=lambda e: (e["event_epoch"], e["record_no"]))
        return out

    def list_events(self, case_id: str, limit: int = 200, offset: int = 0) -> list[dict]:
        cur = self.conn.execute("SELECT data FROM events WHERE case_id=? ORDER BY event_epoch LIMIT ? OFFSET ?", (case_id, limit, offset))
        return [json.loads(r[0]) for r in cur]

    def count_events(self, case_id: str) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events WHERE case_id=?", (case_id,)).fetchone()[0]

    def list_rejects(self, case_id: str, limit: int = 500) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM rejects WHERE case_id=? ORDER BY input_id, record_no LIMIT ?", (case_id, limit))]

    # ---------------- runs / alerts
    def next_run_seq(self, case_id: str) -> int:
        return (self.conn.execute("SELECT COALESCE(MAX(seq),0) FROM runs WHERE case_id=?", (case_id,)).fetchone()[0]) + 1

    def add_run(self, run: dict):
        with self.tx() as c:
            c.execute("INSERT INTO runs(run_id,case_id,seq,started_at,manifest,versions) VALUES(?,?,?,?,?,?)",
                      (run["run_id"], run["case_id"], run["seq"], run["started_at"], json.dumps(run["manifest"]), json.dumps(run["versions"])))

    def finish_run(self, run_id: str, stats: dict):
        with self.tx() as c:
            c.execute("UPDATE runs SET finished_at=?, stats=? WHERE run_id=?", (now_iso(), json.dumps(stats), run_id))

    def list_runs(self, case_id: str) -> list[dict]:
        out = []
        for r in self.conn.execute("SELECT * FROM runs WHERE case_id=? ORDER BY seq", (case_id,)):
            d = dict(r)
            for k in ("manifest", "versions", "stats"):
                d[k] = json.loads(d[k]) if d[k] else None
            out.append(d)
        return out

    def upsert_alerts(self, case_id: str, run_id: str, alerts: list[dict]) -> dict:
        new = updated = 0
        ids = set()
        with self.tx() as c:
            for a in alerts:
                ids.add(a["alert_id"])
                exists = c.execute("SELECT 1 FROM alerts WHERE alert_id=?", (a["alert_id"],)).fetchone()
                payload = json.dumps(a, sort_keys=True)
                if exists:
                    c.execute("UPDATE alerts SET last_run=?, current=1, severity=?, confidence=?, first_time=?, last_time=?, payload=? WHERE alert_id=?",
                              (run_id, a["threat"]["severity"], a["confidence"], a["first_time"], a["last_time"], payload, a["alert_id"]))
                    updated += 1
                else:
                    c.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?,1,?,?,?,?,?)",
                              (a["alert_id"], case_id, a["rule_id"], a["rule_version"], run_id, run_id,
                               a["threat"]["severity"], a["confidence"], a["first_time"], a["last_time"], payload))
                    new += 1
                c.execute("INSERT OR IGNORE INTO alert_runs VALUES(?,?)", (a["alert_id"], run_id))
            # Alerts not reproduced by this run are kept (history) but flagged non-current.
            stale = 0
            for (aid,) in c.execute("SELECT alert_id FROM alerts WHERE case_id=? AND current=1", (case_id,)).fetchall():
                if aid not in ids:
                    c.execute("UPDATE alerts SET current=0 WHERE alert_id=?", (aid,))
                    stale += 1
        return {"new": new, "updated": updated, "no_longer_produced": stale}

    def list_alerts(self, case_id: str | None = None, include_stale: bool = False) -> list[dict]:
        q = "SELECT a.*, s.status AS analyst_status FROM alerts a LEFT JOIN alert_state s ON s.alert_id=a.alert_id"
        conds, params = [], []
        if case_id:
            conds.append("a.case_id=?")
            params.append(case_id)
        if not include_stale:
            conds.append("a.current=1")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY a.first_time"
        out = []
        for r in self.conn.execute(q, params):
            d = json.loads(r["payload"])
            d.update(case_id=r["case_id"], current=bool(r["current"]), first_run=r["first_run"], last_run=r["last_run"],
                     analyst_status=r["analyst_status"] or "new")
            out.append(d)
        return out

    def get_alert(self, alert_id: str) -> dict | None:
        r = self.conn.execute("SELECT a.*, s.status AS analyst_status FROM alerts a LEFT JOIN alert_state s ON s.alert_id=a.alert_id WHERE a.alert_id=?", (alert_id,)).fetchone()
        if not r:
            return None
        d = json.loads(r["payload"])
        d.update(case_id=r["case_id"], current=bool(r["current"]), first_run=r["first_run"], last_run=r["last_run"],
                 analyst_status=r["analyst_status"] or "new")
        d["runs"] = [x[0] for x in self.conn.execute("SELECT run_id FROM alert_runs WHERE alert_id=?", (alert_id,))]
        return d

    def set_alert_status(self, alert_id: str, status: str):
        if status not in ("new", "triaged", "escalated", "benign", "false_positive", "true_positive"):
            raise ValueError("invalid alert status")
        with self.tx() as c:
            c.execute("INSERT INTO alert_state VALUES(?,?,?) ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
                      (alert_id, status, now_iso()))

    # ---------------- notes
    def add_note(self, case_id: str, text: str, alert_id: str | None = None, author: str = "analyst") -> int:
        text = (text or "").strip()
        if not text or len(text) > 20000:
            raise ValueError("note must be 1..20000 characters")
        with self.tx() as c:
            cur = c.execute("INSERT INTO notes(case_id,alert_id,author,text,created_at) VALUES(?,?,?,?,?)",
                            (case_id, alert_id, author, text, now_iso()))
            return cur.lastrowid

    def list_notes(self, case_id: str, alert_id: str | None = None) -> list[dict]:
        if alert_id:
            rows = self.conn.execute("SELECT * FROM notes WHERE case_id=? AND alert_id=? ORDER BY note_id", (case_id, alert_id))
        else:
            rows = self.conn.execute("SELECT * FROM notes WHERE case_id=? ORDER BY note_id", (case_id,))
        return [dict(r) for r in rows]

    # ---------------- assessments
    def save_assessment(self, case_id: str, run_id: str, payload: dict):
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO assessments VALUES(?,?,?)", (case_id, run_id, json.dumps(payload, sort_keys=True)))

    def latest_assessment(self, case_id: str) -> dict | None:
        r = self.conn.execute("SELECT a.payload FROM assessments a JOIN runs r ON r.run_id=a.run_id WHERE a.case_id=? ORDER BY r.seq DESC LIMIT 1", (case_id,)).fetchone()
        return json.loads(r[0]) if r else None

    # ---------------- entities
    def replace_entities(self, case_id: str, entities: list[dict], rels: list[dict], links: list[tuple]):
        with self.tx() as c:
            c.execute("DELETE FROM event_entities WHERE entity_id IN (SELECT entity_id FROM entities WHERE case_id=?)", (case_id,))
            c.execute("DELETE FROM entities WHERE case_id=?", (case_id,))
            c.execute("DELETE FROM relationships WHERE case_id=?", (case_id,))
            c.executemany("INSERT INTO entities VALUES(?,?,?,?,?,?,?,?,?)",
                          [(e["entity_id"], case_id, e["etype"], e["ekey"], e["strength"], e["display"], e["event_count"], e["first_time"], e["last_time"]) for e in entities])
            c.executemany("INSERT INTO relationships VALUES(?,?,?,?,?,?,?)",
                          [(case_id, r["src"], r["dst"], r["rel"], r["basis"], r["event_count"], r["sample_event"]) for r in rels])
            c.executemany("INSERT OR IGNORE INTO event_entities VALUES(?,?,?)", links)

    def list_entities(self, case_id: str, etype: str | None = None) -> list[dict]:
        if etype:
            rows = self.conn.execute("SELECT * FROM entities WHERE case_id=? AND etype=? ORDER BY event_count DESC", (case_id, etype))
        else:
            rows = self.conn.execute("SELECT * FROM entities WHERE case_id=? ORDER BY etype, event_count DESC", (case_id,))
        return [dict(r) for r in rows]

    def get_entity(self, entity_id: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM entities WHERE entity_id=?", (entity_id,)).fetchone()
        return dict(r) if r else None

    def entity_relationships(self, entity_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT r.*, e1.display AS src_display, e1.etype AS src_type, e2.display AS dst_display, e2.etype AS dst_type "
            "FROM relationships r JOIN entities e1 ON e1.entity_id=r.src JOIN entities e2 ON e2.entity_id=r.dst "
            "WHERE r.src=? OR r.dst=? ORDER BY r.event_count DESC", (entity_id, entity_id))
        return [dict(r) for r in rows]

    def entity_event_ids(self, entity_id: str, limit: int = 200) -> list[str]:
        return [r[0] for r in self.conn.execute("SELECT event_id FROM event_entities WHERE entity_id=? LIMIT ?", (entity_id, limit))]
