"""SQLite persistence. All SQL uses bound parameters; identifiers are constants.

Schema history
  1 (v0.1.0) original tables, no meta table
  2 (v0.2.0) meta table
  3 (v0.3.0) input revisions (reprocessing), immutable per-run alert/assessment snapshots and
             effective-configuration snapshots, run status (atomic commit), alert status history,
             background jobs, watched-directory checkpoints, declared collection coverage.
Migrations take a consistent backup with SQLite's online backup API first (includes committed
WAL content), verify it (integrity_check + row counts), and never invent historical data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

from argos.normalize.timeutil import now_iso

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, synthetic INTEGER NOT NULL,
  description TEXT, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, input_id TEXT NOT NULL, record_no INTEGER NOT NULL,
  event_epoch REAL NOT NULL, event_kind TEXT, vantage TEXT, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_events_case_time ON events(case_id, event_epoch);
CREATE INDEX IF NOT EXISTS ix_events_input ON events(input_id);
CREATE TABLE IF NOT EXISTS rejects (
  case_id TEXT NOT NULL, input_id TEXT NOT NULL, record_no INTEGER NOT NULL, reason TEXT NOT NULL,
  excerpt TEXT, PRIMARY KEY(input_id, record_no));
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

# v1/v2 table definitions that changed in v3 (kept for migration tests and documentation)
LEGACY_INPUTS = """CREATE TABLE IF NOT EXISTS inputs (
  input_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
  sha256 TEXT NOT NULL, original_name TEXT, stored_path TEXT NOT NULL, format TEXT NOT NULL,
  parser_version TEXT NOT NULL, options TEXT NOT NULL, size_bytes INTEGER NOT NULL,
  provenance_trust TEXT NOT NULL DEFAULT 'unverified', provenance_note TEXT,
  records_total INTEGER, records_accepted INTEGER, records_rejected INTEGER,
  imported_at TEXT NOT NULL, UNIQUE(case_id, sha256, format));"""
LEGACY_RUNS = """CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, seq INTEGER NOT NULL, started_at TEXT NOT NULL,
  finished_at TEXT, manifest TEXT NOT NULL, versions TEXT NOT NULL, stats TEXT);"""
SCHEMA = "PRAGMA journal_mode=WAL;\n" + BASE_SCHEMA + LEGACY_INPUTS + "\n" + LEGACY_RUNS  # = v1/v2 schema

V3_INPUTS = """CREATE TABLE IF NOT EXISTS inputs (
  input_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
  sha256 TEXT NOT NULL, original_name TEXT, stored_path TEXT NOT NULL, format TEXT NOT NULL,
  parser_version TEXT NOT NULL, options TEXT NOT NULL, size_bytes INTEGER NOT NULL,
  provenance_trust TEXT NOT NULL DEFAULT 'unverified', provenance_note TEXT,
  records_total INTEGER, records_accepted INTEGER, records_rejected INTEGER,
  imported_at TEXT NOT NULL,
  options_hash TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'imported', supersedes TEXT, coverage TEXT, source_ref TEXT, delivery_key TEXT,
  finalized INTEGER NOT NULL DEFAULT 0,
  UNIQUE(case_id, sha256, format, options_hash));"""
# An input row only certifies a durable import when its status is one of these (follow-up defect 2) AND its
# finalization committed (finalized=1): counts, final status and the activation decision are written in ONE
# transaction (finalize_input). A completed status without finalized=1 can only come from a pre-fix database whose
# finalization was interrupted; such a row is treated as incomplete and re-run, never certified.
COMPLETED_INPUT_STATUSES = ("imported", "rejected", "failed_kept_previous")
_FINALIZED_BACKFILL = """UPDATE inputs SET finalized=1 WHERE finalized=0 AND status IN ('imported','rejected','failed_kept_previous') AND (
  active=1 OR status='failed_kept_previous' OR EXISTS (
    SELECT 1 FROM inputs n WHERE n.case_id=inputs.case_id AND n.sha256=inputs.sha256 AND n.delivery_key IS inputs.delivery_key
      AND n.revision>inputs.revision AND n.status IN ('imported','rejected')))"""
V3_EXTRA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, seq INTEGER NOT NULL, started_at TEXT NOT NULL,
  finished_at TEXT, manifest TEXT NOT NULL, versions TEXT NOT NULL, stats TEXT,
  status TEXT NOT NULL DEFAULT 'succeeded', error TEXT, snapshot_available INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS run_alerts (
  run_id TEXT NOT NULL, alert_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run_id, alert_id));
CREATE TABLE IF NOT EXISTS run_snapshots (
  run_id TEXT PRIMARY KEY, rules TEXT NOT NULL, overrides TEXT, registry TEXT, iocs TEXT, settings TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alert_state_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, status TEXT NOT NULL, rationale TEXT,
  author TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
  progress REAL NOT NULL DEFAULT 0, message TEXT, error TEXT, result TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT);
CREATE TABLE IF NOT EXISTS watch_sources (
  source_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, directory TEXT NOT NULL, pattern TEXT NOT NULL,
  format TEXT NOT NULL, options TEXT NOT NULL, created_at TEXT NOT NULL, last_poll TEXT, last_import TEXT,
  last_event_time TEXT, last_error TEXT);
CREATE TABLE IF NOT EXISTS watch_checkpoints (
  source_id TEXT NOT NULL, file_id TEXT NOT NULL, path TEXT NOT NULL, offset INTEGER NOT NULL, size INTEGER NOT NULL,
  mtime REAL NOT NULL, segments INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL,
  dev INTEGER, ino INTEGER, head_fp TEXT, tail_sha TEXT, legacy INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(source_id, file_id));
"""

SCHEMA_VERSION = 4
CASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
VERIFY_TABLES = ("cases", "inputs", "events", "rejects", "notes", "alerts", "assessments", "runs", "alert_state", "alert_state_history",
                 "run_alerts", "run_snapshots", "entities", "jobs", "watch_sources", "watch_checkpoints")


class MigrationError(RuntimeError):
    pass


def private_file(p: Path):
    """Owner-only permissions where the platform supports POSIX modes (Windows: inherit the
    private directory ACL set by Settings.ensure)."""
    if os.name == "posix":
        try:
            os.chmod(p, 0o600)
        except FileNotFoundError:
            pass


def options_hash(fmt: str, parser_version: str, options: dict) -> str:
    canon = json.dumps({"format": fmt, "parser": parser_version, "options": options}, sort_keys=True, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def table_counts(conn) -> dict:
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in VERIFY_TABLES if t in names}  # noqa: S608 - constant names


def consistent_backup(src: sqlite3.Connection, dest: Path) -> dict:
    """Snapshot with sqlite3's online backup API (includes committed WAL frames), then verify."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".partial")
    tmp.unlink(missing_ok=True)
    out = sqlite3.connect(str(tmp))
    try:
        src.backup(out)
        out.execute("PRAGMA journal_mode=DELETE")
        ok = out.execute("PRAGMA integrity_check").fetchone()[0]
        counts = table_counts(out)
    finally:
        out.close()
    if ok != "ok":
        tmp.unlink(missing_ok=True)
        raise MigrationError(f"backup integrity check failed: {ok}")
    if counts != table_counts(src):
        tmp.unlink(missing_ok=True)
        raise MigrationError("backup row counts differ from the live database")
    os.replace(tmp, dest)
    private_file(dest)
    return {"path": str(dest), "integrity": ok, "counts": counts}


class Store:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.db_path.exists()
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=OFF")
        if new:
            self.conn.executescript(BASE_SCHEMA + V3_INPUTS + V3_EXTRA +
                                    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            self.conn.execute("INSERT OR REPLACE INTO meta VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
            self.conn.commit()
        self.last_migration: dict | None = None
        self._migrate()
        self._ensure_finalization_state()
        for suffix in ("", "-wal", "-shm"):
            private_file(Path(str(self.db_path) + suffix))

    # ------------------------------------------------------------------ migration
    def _version(self) -> int:
        c = self.conn
        if not c.execute("SELECT 1 FROM sqlite_master WHERE name='meta'").fetchone():
            return 1
        row = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        return int(row[0]) if row else 1

    def _ensure_finalization_state(self):
        """Idempotent: add `inputs.finalized` to databases created before it existed (v3 migrations and pre-release v4
        candidates) and classify existing rows. Finalized: completed and active, kept-previous, or superseded by a newer
        completed revision of the same delivery. A completed-status row that is inactive and was never superseded is an
        interrupted finalization (pre-fix defect A) and stays finalized=0, so recovery re-runs it."""
        cols = [r[1] for r in self.conn.execute("PRAGMA table_info(inputs)")]
        if not cols or "finalized" in cols:
            return
        with self.tx() as c:
            c.execute("ALTER TABLE inputs ADD COLUMN finalized INTEGER NOT NULL DEFAULT 0")
            c.execute(_FINALIZED_BACKFILL)

    def _migrate(self):
        current = self._version()
        if current > SCHEMA_VERSION:
            raise MigrationError(f"database schema {current} is newer than this ARGOS version supports ({SCHEMA_VERSION})")
        if current == SCHEMA_VERSION:
            return
        c = self.conn
        backup = None
        if c.execute("SELECT 1 FROM sqlite_master WHERE name='cases'").fetchone() and \
                c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]:
            backup = consistent_backup(c, self.db_path.with_name(f"{self.db_path.stem}.v{current}-backup.sqlite3"))
        try:
            c.execute("BEGIN")
            c.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            if current < 3:
                self._migrate_2_to_3(c)
            if current < 4:
                self._migrate_3_to_4(c)
            c.execute("INSERT OR REPLACE INTO meta VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
            c.execute("INSERT OR REPLACE INTO meta VALUES('migrated_from', ?)", (str(current),))
            c.execute("INSERT OR REPLACE INTO meta VALUES('migrated_at', ?)", (now_iso(),))
            c.commit()
        except Exception as exc:
            c.rollback()
            raise MigrationError(f"migration {current}->{SCHEMA_VERSION} failed and was rolled back "
                                 f"(backup: {backup['path'] if backup else 'none needed'}): {exc}") from exc
        self.last_migration = {"from": current, "to": SCHEMA_VERSION, "backup": backup}

    @staticmethod
    def _migrate_2_to_3(c):
        cols = [r[1] for r in c.execute("PRAGMA table_info(inputs)")]
        if "options_hash" not in cols:
            c.execute("ALTER TABLE inputs RENAME TO inputs_v2")
            c.execute(V3_INPUTS)
            for r in c.execute("SELECT * FROM inputs_v2").fetchall():
                d = dict(r)
                oh = options_hash(d["format"], d["parser_version"], json.loads(d["options"] or "{}"))
                c.execute("INSERT INTO inputs(input_id,case_id,sha256,original_name,stored_path,format,parser_version,options,size_bytes,"
                          "provenance_trust,provenance_note,records_total,records_accepted,records_rejected,imported_at,options_hash,"
                          "revision,active,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,1,'imported')",
                          (d["input_id"], d["case_id"], d["sha256"], d["original_name"], d["stored_path"], d["format"], d["parser_version"],
                           d["options"], d["size_bytes"], d["provenance_trust"], d["provenance_note"], d["records_total"],
                           d["records_accepted"], d["records_rejected"], d["imported_at"], oh))
            c.execute("DROP TABLE inputs_v2")
        rcols = [r[1] for r in c.execute("PRAGMA table_info(runs)")]
        if rcols and "status" not in rcols:
            c.execute("ALTER TABLE runs ADD COLUMN status TEXT NOT NULL DEFAULT 'succeeded'")
            c.execute("ALTER TABLE runs ADD COLUMN error TEXT")
            # Pre-v0.3 runs never stored per-run alert snapshots: label that honestly.
            c.execute("ALTER TABLE runs ADD COLUMN snapshot_available INTEGER NOT NULL DEFAULT 0")
        for stmt in V3_EXTRA.split(";"):
            if stmt.strip():
                c.execute(stmt)

    @staticmethod
    def _migrate_3_to_4(c):
        """v0.3.1: watcher checkpoints gain file-instance identity (device/inode, head fingerprint, tail hash).
        Existing v0.3.0 checkpoints were keyed by a first-line fingerprint only; they are kept but marked
        legacy so the watcher re-establishes identity conservatively instead of trusting them (R03).
        Declared coverage JSON is unchanged; declarations without `event_kinds` are interpreted narrowly
        (only the event kinds present in that input) at analysis time (R05)."""
        icols = [r[1] for r in c.execute("PRAGMA table_info(inputs)")]
        if icols and "delivery_key" not in icols:
            c.execute("ALTER TABLE inputs ADD COLUMN delivery_key TEXT")
        cols = [r[1] for r in c.execute("PRAGMA table_info(watch_checkpoints)")]
        if cols and "dev" not in cols:
            for col, typ in (("dev", "INTEGER"), ("ino", "INTEGER"), ("head_fp", "TEXT"), ("tail_sha", "TEXT"),
                             ("legacy", "INTEGER NOT NULL DEFAULT 0")):
                c.execute(f"ALTER TABLE watch_checkpoints ADD COLUMN {col} {typ}")  # noqa: S608 - constant names
            c.execute("UPDATE watch_checkpoints SET legacy=1")
        c.execute("INSERT OR REPLACE INTO meta VALUES('coverage_semantics', ?)",
                  ("v4: declared coverage applies to its scope, interval and event kinds; declarations without event kinds "
                   "cover only the kinds present in that input",))

    def schema_version(self) -> int:
        return self._version()

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

    def backup_to(self, dest: Path) -> dict:
        return consistent_backup(self.conn, Path(dest))

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
            d["event_count"] = self.count_events(d["case_id"])
            d["alert_count"] = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE case_id=? AND current=1", (d["case_id"],)).fetchone()[0]
            d["reject_count"] = self.conn.execute(
                "SELECT COUNT(*) FROM rejects r JOIN inputs i ON i.input_id=r.input_id WHERE r.case_id=? AND i.active=1", (d["case_id"],)).fetchone()[0]
            out.append(d)
        return out

    def set_case_status(self, case_id: str, status: str):
        if status not in ("open", "investigating", "closed_benign", "closed_true_positive", "closed_inconclusive"):
            raise ValueError("invalid case status")
        with self.tx() as c:
            c.execute("UPDATE cases SET status=? WHERE case_id=?", (status, case_id))

    # ---------------- inputs / revisions / events
    def find_input(self, case_id: str, sha256: str, fmt: str, opt_hash: str | None = None) -> dict | None:
        if opt_hash is None:
            r = self.conn.execute("SELECT * FROM inputs WHERE case_id=? AND sha256=? AND format=? AND active=1",
                                  (case_id, sha256, fmt)).fetchone()
        else:
            r = self.conn.execute("SELECT * FROM inputs WHERE case_id=? AND sha256=? AND format=? AND options_hash=?",
                                  (case_id, sha256, fmt, opt_hash)).fetchone()
        return dict(r) if r else None

    def revisions_of(self, case_id: str, sha256: str, delivery_key: str | None = None) -> list[dict]:
        """Revisions (interpretations) of ONE logical delivery: manual imports of the same content share
        delivery_key NULL; each watcher delivery (source, generation, byte range) has its own key."""
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM inputs WHERE case_id=? AND sha256=? AND delivery_key IS ? ORDER BY revision", (case_id, sha256, delivery_key))]

    def next_revision(self, case_id: str, sha256: str, delivery_key: str | None = None) -> int:
        return (self.conn.execute("SELECT COALESCE(MAX(revision),0) FROM inputs WHERE case_id=? AND sha256=? AND delivery_key IS ?",
                                  (case_id, sha256, delivery_key)).fetchone()[0]) + 1

    def restart_incomplete_input(self, input_id: str) -> None:
        """Remove the partial rows of an import that never completed (processing/interrupted/failed) so it can be
        re-run from its retained original under the same deterministic ids. The row stays inactive."""
        with self.tx() as c:
            st = c.execute("SELECT status, active, finalized FROM inputs WHERE input_id=?", (input_id,)).fetchone()
            if st is None or st[1] or (st[0] in COMPLETED_INPUT_STATUSES and st[2]):
                raise ValueError(f"input {input_id} is not an incomplete import")
            c.execute("DELETE FROM events WHERE input_id=?", (input_id,))
            c.execute("DELETE FROM rejects WHERE input_id=?", (input_id,))
            c.execute("UPDATE inputs SET status='processing', finalized=0, records_total=NULL, records_accepted=NULL, records_rejected=NULL "
                      "WHERE input_id=?", (input_id,))

    def recover_interrupted_imports(self) -> int:
        """At server start (single process per data dir): imports left 'processing' by a dead process are 'interrupted'."""
        with self.tx() as c:
            return c.execute("UPDATE inputs SET status='interrupted' WHERE finalized=0 AND active=0 "
                             "AND status IN ('processing','imported','rejected')").rowcount

    def add_input(self, row: dict):
        cols = ",".join(row)
        with self.tx() as c:
            c.execute(f"INSERT INTO inputs({cols}) VALUES({','.join('?' * len(row))})", tuple(row.values()))  # noqa: S608 - keys are code constants

    def update_input_counts(self, input_id: str, total: int, accepted: int, rejected: int):
        with self.tx() as c:
            c.execute("UPDATE inputs SET records_total=?, records_accepted=?, records_rejected=? WHERE input_id=?",
                      (total, accepted, rejected, input_id))

    def set_input_status(self, input_id: str, status: str):
        with self.tx() as c:
            c.execute("UPDATE inputs SET status=? WHERE input_id=?", (status, input_id))

    def finalize_input(self, input_id: str, total: int, accepted: int, rejected: int, status: str, activate: bool):
        """Finish an import ATOMICALLY (defect A): record counts, final status, finalized=1 and -- when this revision
        becomes the interpretation -- deactivate the superseded revision of the same delivery and activate this one,
        all in one transaction. A failure leaves the row unfinalized and the previous revision untouched."""
        if status not in COMPLETED_INPUT_STATUSES:
            raise ValueError(f"not a completion status: {status}")
        with self.tx() as c:
            r = c.execute("SELECT case_id, sha256, delivery_key FROM inputs WHERE input_id=?", (input_id,)).fetchone()
            if not r:
                raise ValueError("unknown input")
            c.execute("UPDATE inputs SET records_total=?, records_accepted=?, records_rejected=?, status=?, finalized=1 WHERE input_id=?",
                      (total, accepted, rejected, status, input_id))
            if activate:
                c.execute("UPDATE inputs SET active=0 WHERE case_id=? AND sha256=? AND delivery_key IS ? AND input_id<>?",
                          (r[0], r[1], r[2], input_id))
                c.execute("UPDATE inputs SET active=1 WHERE input_id=?", (input_id,))

    def activate_revision(self, input_id: str):
        """Make one revision the active interpretation of its file content (exactly one active per content)."""
        with self.tx() as c:
            r = c.execute("SELECT case_id, sha256, delivery_key, status, finalized FROM inputs WHERE input_id=?", (input_id,)).fetchone()
            if not r:
                raise ValueError("unknown input")
            if r[3] not in COMPLETED_INPUT_STATUSES or not r[4]:
                raise ValueError(f"input {input_id} is {r[3]}{'' if r[4] else ' (finalization incomplete)'}; "
                                 "only completed imports can be activated")
            c.execute("UPDATE inputs SET active=0 WHERE case_id=? AND sha256=? AND delivery_key IS ?", (r[0], r[1], r[2]))
            c.execute("UPDATE inputs SET active=1 WHERE input_id=?", (input_id,))

    def find_delivery_attempt(self, case_id: str, source_id: str, file_id: str, start: int) -> dict | None:
        """Watcher recovery (defect B): an earlier delivery of this source/generation that STARTS at `start` and left a
        durable input row (completed or not). Its recorded byte range must be re-delivered unchanged before any newly
        appended bytes, so recovery never depends on a re-computed chunk end. Finalized deliveries take precedence."""
        prefix = json.dumps([source_id, file_id, start], separators=(",", ":"))[:-1] + ","
        r = self.conn.execute("SELECT * FROM inputs WHERE case_id=? AND delivery_key IS NOT NULL AND substr(delivery_key,1,?)=? "
                              "ORDER BY finalized DESC, imported_at DESC, revision DESC LIMIT 1",
                              (case_id, len(prefix), prefix)).fetchone()
        return dict(r) if r else None

    def rebase_originals(self, cases_dir: Path) -> int:
        """After restore into another data directory: point EVERY original reference at the location the
        original has (or would have) under the restored data directory. References are never left pointing
        at the previous installation, even when the original itself is missing (R02)."""
        n = 0
        with self.tx() as c:
            for r in c.execute("SELECT input_id, case_id, stored_path FROM inputs").fetchall():
                new = Path(cases_dir) / r[1] / "originals" / Path(r[2].replace("\\", "/")).name
                if str(new) != r[2]:
                    c.execute("UPDATE inputs SET stored_path=? WHERE input_id=?", (str(new), r[0]))
                    n += 1
        return n

    def list_inputs_all(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM inputs ORDER BY case_id, input_id")]

    def get_input(self, input_id: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM inputs WHERE input_id=?", (input_id,)).fetchone()
        return dict(r) if r else None

    def set_input_trust(self, input_id: str, trust: str, note: str):
        if trust not in ("unverified", "analyst_attested"):
            raise ValueError("invalid provenance trust")
        with self.tx() as c:
            c.execute("UPDATE inputs SET provenance_trust=?, provenance_note=? WHERE input_id=?", (trust, note, input_id))

    def set_input_coverage(self, input_id: str, coverage: dict | None):
        with self.tx() as c:
            c.execute("UPDATE inputs SET coverage=? WHERE input_id=?", (json.dumps(coverage) if coverage else None, input_id))

    def list_inputs(self, case_id: str, include_inactive: bool = False) -> list[dict]:
        q = "SELECT * FROM inputs WHERE case_id=?" + ("" if include_inactive else " AND active=1") + " ORDER BY imported_at, revision"
        return [dict(r) for r in self.conn.execute(q, (case_id,))]

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

    _ACTIVE = "SELECT e.data FROM events e JOIN inputs i ON i.input_id=e.input_id WHERE e.case_id=? AND i.active=1"

    def iter_events(self, case_id: str):
        cur = self.conn.execute(self._ACTIVE + " ORDER BY e.event_epoch, e.input_id, e.record_no", (case_id,))
        for (data,) in cur:
            yield json.loads(data)

    def get_events(self, event_ids: list[str]) -> list[dict]:
        out = []
        for i in range(0, len(event_ids), 500):
            chunk = event_ids[i:i + 500]
            q = "SELECT data FROM events WHERE event_id IN (%s)" % ",".join("?" * len(chunk))  # noqa: S608 - placeholders only
            out += [json.loads(r[0]) for r in self.conn.execute(q, chunk)]
        out.sort(key=lambda e: (e["event_epoch"], e["record_no"]))
        return out

    def list_events(self, case_id: str, limit: int = 200, offset: int = 0) -> list[dict]:
        cur = self.conn.execute(self._ACTIVE + " ORDER BY e.event_epoch LIMIT ? OFFSET ?", (case_id, limit, offset))
        return [json.loads(r[0]) for r in cur]

    def count_events(self, case_id: str) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events e JOIN inputs i ON i.input_id=e.input_id WHERE e.case_id=? AND i.active=1",
                                 (case_id,)).fetchone()[0]

    def list_rejects(self, case_id: str, limit: int = 500, include_inactive: bool = False) -> list[dict]:
        q = ("SELECT r.* FROM rejects r JOIN inputs i ON i.input_id=r.input_id WHERE r.case_id=?" +
             ("" if include_inactive else " AND i.active=1") + " ORDER BY r.input_id, r.record_no LIMIT ?")
        return [dict(r) for r in self.conn.execute(q, (case_id, limit))]

    # ---------------- runs / alerts (atomic commit, immutable snapshots)
    def next_run_seq(self, case_id: str) -> int:
        return (self.conn.execute("SELECT COALESCE(MAX(seq),0) FROM runs WHERE case_id=?", (case_id,)).fetchone()[0]) + 1

    def add_run(self, run: dict):
        with self.tx() as c:
            c.execute("INSERT INTO runs(run_id,case_id,seq,started_at,manifest,versions,status,snapshot_available) VALUES(?,?,?,?,?,?,'running',1)",
                      (run["run_id"], run["case_id"], run["seq"], run["started_at"], json.dumps(run["manifest"]), json.dumps(run["versions"])))

    def fail_run(self, run_id: str, status: str, error: str):
        with self.tx() as c:
            c.execute("UPDATE runs SET status=?, error=?, finished_at=? WHERE run_id=?", (status, error[:2000], now_iso(), run_id))

    def commit_run(self, case_id: str, run_id: str, alerts: list[dict], assessment: dict, snapshot: dict, stats: dict,
                   entities=None) -> dict:
        """Write all results of one successful run in a single transaction."""
        new = updated = stale = 0
        ids = set()
        with self.tx() as c:
            if entities is not None:
                ents, rels, links = entities
                c.execute("DELETE FROM event_entities WHERE entity_id IN (SELECT entity_id FROM entities WHERE case_id=?)", (case_id,))
                c.execute("DELETE FROM entities WHERE case_id=?", (case_id,))
                c.execute("DELETE FROM relationships WHERE case_id=?", (case_id,))
                c.executemany("INSERT INTO entities VALUES(?,?,?,?,?,?,?,?,?)",
                              [(e["entity_id"], case_id, e["etype"], e["ekey"], e["strength"], e["display"], e["event_count"],
                                e["first_time"], e["last_time"]) for e in ents])
                c.executemany("INSERT INTO relationships VALUES(?,?,?,?,?,?,?)",
                              [(case_id, r["src"], r["dst"], r["rel"], r["basis"], r["event_count"], r["sample_event"]) for r in rels])
                c.executemany("INSERT OR IGNORE INTO event_entities VALUES(?,?,?)", links)
            for a in alerts:
                ids.add(a["alert_id"])
                payload = json.dumps(a, sort_keys=True)
                if c.execute("SELECT 1 FROM alerts WHERE alert_id=?", (a["alert_id"],)).fetchone():
                    c.execute("UPDATE alerts SET last_run=?, current=1, severity=?, confidence=?, first_time=?, last_time=?, payload=? WHERE alert_id=?",
                              (run_id, a["threat"]["severity"], a["confidence"], a["first_time"], a["last_time"], payload, a["alert_id"]))
                    updated += 1
                else:
                    c.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?,1,?,?,?,?,?)",
                              (a["alert_id"], case_id, a["rule_id"], a["rule_version"], run_id, run_id,
                               a["threat"]["severity"], a["confidence"], a["first_time"], a["last_time"], payload))
                    new += 1
                c.execute("INSERT OR IGNORE INTO alert_runs VALUES(?,?)", (a["alert_id"], run_id))
                c.execute("INSERT INTO run_alerts VALUES(?,?,?)", (run_id, a["alert_id"], payload))
            for (aid,) in c.execute("SELECT alert_id FROM alerts WHERE case_id=? AND current=1", (case_id,)).fetchall():
                if aid not in ids:
                    c.execute("UPDATE alerts SET current=0 WHERE alert_id=?", (aid,))
                    stale += 1
            c.execute("INSERT OR REPLACE INTO assessments VALUES(?,?,?)", (case_id, run_id, json.dumps(assessment, sort_keys=True)))
            c.execute("INSERT INTO run_snapshots VALUES(?,?,?,?,?,?)",
                      (run_id, json.dumps(snapshot["rules"]), snapshot.get("overrides"), snapshot.get("registry"),
                       json.dumps(snapshot.get("iocs")), json.dumps(snapshot["settings"])))
            stats = {**stats, "new": new, "updated": updated, "no_longer_produced": stale}
            c.execute("UPDATE runs SET status='succeeded', finished_at=?, stats=? WHERE run_id=?", (now_iso(), json.dumps(stats), run_id))
        return stats

    def list_runs(self, case_id: str) -> list[dict]:
        out = []
        for r in self.conn.execute("SELECT * FROM runs WHERE case_id=? ORDER BY seq", (case_id,)):
            d = dict(r)
            for k in ("manifest", "versions", "stats"):
                d[k] = json.loads(d[k]) if d[k] else None
            out.append(d)
        return out

    def get_run(self, run_id: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        for k in ("manifest", "versions", "stats"):
            d[k] = json.loads(d[k]) if d[k] else None
        return d

    def run_alerts(self, run_id: str) -> list[dict]:
        return [json.loads(r[0]) for r in self.conn.execute("SELECT payload FROM run_alerts WHERE run_id=? ORDER BY alert_id", (run_id,))]

    def run_snapshot(self, run_id: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM run_snapshots WHERE run_id=?", (run_id,)).fetchone()
        if not r:
            return None
        return {"rules": json.loads(r["rules"]), "overrides": r["overrides"], "registry": r["registry"],
                "iocs": json.loads(r["iocs"]) if r["iocs"] else None, "settings": json.loads(r["settings"])}

    def latest_successful_run(self, case_id: str) -> dict | None:
        r = self.conn.execute("SELECT run_id FROM runs WHERE case_id=? AND status='succeeded' ORDER BY seq DESC LIMIT 1", (case_id,)).fetchone()
        return self.get_run(r[0]) if r else None

    def _alert_row(self, r) -> dict:
        d = json.loads(r["payload"])
        d.update(case_id=r["case_id"], current=bool(r["current"]), first_run=r["first_run"], last_run=r["last_run"],
                 analyst_status=r["analyst_status"] or "new")
        return d

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
        return [self._alert_row(r) for r in self.conn.execute(q, params)]

    def get_alert(self, alert_id: str) -> dict | None:
        r = self.conn.execute("SELECT a.*, s.status AS analyst_status FROM alerts a LEFT JOIN alert_state s ON s.alert_id=a.alert_id WHERE a.alert_id=?",
                              (alert_id,)).fetchone()
        if not r:
            return None
        d = self._alert_row(r)
        d["runs"] = [x[0] for x in self.conn.execute("SELECT run_id FROM alert_runs WHERE alert_id=?", (alert_id,))]
        d["status_history"] = [dict(x) for x in self.conn.execute(
            "SELECT status, rationale, author, created_at FROM alert_state_history WHERE alert_id=? ORDER BY id", (alert_id,))]
        return d

    def set_alert_status(self, alert_id: str, status: str, rationale: str = "", author: str = "analyst"):
        if status not in ("new", "triaged", "escalated", "benign", "false_positive", "true_positive"):
            raise ValueError("invalid alert status")
        with self.tx() as c:
            c.execute("INSERT INTO alert_state VALUES(?,?,?) ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
                      (alert_id, status, now_iso()))
            c.execute("INSERT INTO alert_state_history(alert_id,status,rationale,author,created_at) VALUES(?,?,?,?,?)",
                      (alert_id, status, (rationale or "")[:4000], author, now_iso()))

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
    def latest_assessment(self, case_id: str) -> dict | None:
        r = self.conn.execute("SELECT a.payload FROM assessments a JOIN runs r ON r.run_id=a.run_id WHERE a.case_id=? AND r.status='succeeded' "
                              "ORDER BY r.seq DESC LIMIT 1", (case_id,)).fetchone()
        return json.loads(r[0]) if r else None

    def run_assessment(self, run_id: str) -> dict | None:
        r = self.conn.execute("SELECT payload FROM assessments WHERE run_id=?", (run_id,)).fetchone()
        return json.loads(r[0]) if r else None

    # ---------------- entities
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

    # ---------------- jobs
    def create_job(self, case_id: str, kind: str) -> str:
        jid = "job-" + uuid.uuid4().hex[:12]
        with self.tx() as c:
            c.execute("INSERT INTO jobs(job_id,case_id,kind,status,created_at) VALUES(?,?,?,'queued',?)", (jid, case_id, kind, now_iso()))
        return jid

    def update_job(self, job_id: str, **kw):
        if not kw:
            return
        allowed = {"status", "progress", "message", "error", "result", "started_at", "finished_at", "cancel_requested"}
        bad = set(kw) - allowed
        if bad:
            raise ValueError(f"unknown job fields {bad}")
        sets = ", ".join(f"{k}=?" for k in kw)
        with self.tx() as c:
            c.execute(f"UPDATE jobs SET {sets} WHERE job_id=?", (*kw.values(), job_id))  # noqa: S608 - keys validated

    def get_job(self, job_id: str) -> dict | None:
        r = self.conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(r) if r else None

    def list_jobs(self, case_id: str | None = None, limit: int = 50) -> list[dict]:
        if case_id:
            rows = self.conn.execute("SELECT * FROM jobs WHERE case_id=? ORDER BY created_at DESC LIMIT ?", (case_id, limit))
        else:
            rows = self.conn.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def recover_interrupted_jobs(self) -> int:
        """Jobs left 'running'/'queued' by a crashed or killed process are marked interrupted at startup."""
        with self.tx() as c:
            n = c.execute("UPDATE jobs SET status='interrupted', finished_at=?, error='process stopped before completion' "
                          "WHERE status IN ('running','queued')", (now_iso(),)).rowcount
            c.execute("UPDATE runs SET status='interrupted', error='process stopped before completion', finished_at=? WHERE status='running'",
                      (now_iso(),))
        return n
