"""Opt-in, read-only continuous file ingestion from one explicitly configured directory (feature E).

This is continuous *file* ingestion, not an EDR sensor, vendor connector or proof of coverage.

Behaviour
- Only line-oriented formats (native_jsonl, splunk_json, zeek_jsonl) are tailed. Source files are
  opened read-only and never modified, moved or executed.
- Partial writes: only complete lines (ending in "\\n") are consumed; a trailing partial line waits.
- File identity: SHA-256 of the first complete line plus its length, so a renamed/rotated file keeps
  its checkpoint and a new file at the same path starts at offset 0. A file that shrinks below its
  checkpoint (truncate-in-place) is reported and re-read from 0 as a new identity.
- Each new chunk of complete lines is written to an owner-private segment file and imported through
  the normal pipeline (hash, original retention, rejects, unverified provenance). The checkpoint is
  advanced only after the import commits. A crash between the two re-imports the same bytes, which
  the pipeline recognises as already imported (same content hash) -> no duplicate events.
- Backpressure: at most `max_chunk_bytes` per file and `max_cycle_bytes` per poll cycle.
- Freshness: last poll, last import, newest event time and last error are stored per source.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from fnmatch import fnmatch
from pathlib import Path

from argos.config import Settings, make_private_dir
from argos.ingest.pipeline import ImportError_, ingest_file, safe_join
from argos.evidence.assess import iso_from
from argos.normalize.timeutil import now_iso
from argos.store import Store

TAIL_FORMATS = ("native_jsonl", "splunk_json", "zeek_jsonl")


class WatchError(Exception):
    pass


def add_source(store: Store, case: dict, directory: Path, pattern: str, fmt: str, options: dict | None = None) -> dict:
    if fmt not in TAIL_FORMATS:
        raise WatchError(f"watching supports line-oriented formats only: {', '.join(TAIL_FORMATS)}")
    d = Path(directory).expanduser().resolve()
    if not d.is_dir():
        raise WatchError(f"{d} is not a directory")
    row = store.conn.execute("SELECT * FROM watch_sources WHERE case_id=? AND directory=? AND pattern=? AND format=?",
                             (case["case_id"], str(d), pattern, fmt)).fetchone()
    if row:
        return dict(row)
    sid = "ws-" + uuid.uuid4().hex[:12]
    with store.tx() as c:
        c.execute("INSERT INTO watch_sources(source_id,case_id,directory,pattern,format,options,created_at) VALUES(?,?,?,?,?,?,?)",
                  (sid, case["case_id"], str(d), pattern, fmt, json.dumps(options or {}, sort_keys=True), now_iso()))
    return dict(store.conn.execute("SELECT * FROM watch_sources WHERE source_id=?", (sid,)).fetchone())


def list_sources(store: Store, case_id: str | None = None) -> list[dict]:
    q = "SELECT * FROM watch_sources" + (" WHERE case_id=?" if case_id else "") + " ORDER BY created_at"
    out = []
    for r in store.conn.execute(q, (case_id,) if case_id else ()):
        d = dict(r)
        d["files"] = [dict(x) for x in store.conn.execute("SELECT * FROM watch_checkpoints WHERE source_id=? ORDER BY path", (d["source_id"],))]
        d["freshness_seconds"] = None
        if d.get("last_event_time"):
            from argos.normalize.timeutil import parse_timestamp
            try:
                d["freshness_seconds"] = round(time.time() - parse_timestamp(d["last_event_time"])[0].timestamp(), 1)
            except Exception:  # noqa: BLE001
                pass
        out.append(d)
    return out


def _file_identity(path: Path) -> tuple[str | None, int]:
    """Identity from the first complete line; None while no complete line exists."""
    with open(path, "rb") as fh:
        first = fh.readline(1 << 20)
    if not first.endswith(b"\n"):
        return None, 0
    return hashlib.sha256(first).hexdigest()[:32] + f":{len(first)}", len(first)


def _complete_chunk(path: Path, offset: int, limit: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(limit)
    cut = data.rfind(b"\n")
    return data[:cut + 1] if cut >= 0 else b""


def poll_once(store: Store, settings: Settings, source: dict, max_chunk_bytes: int = 8 << 20,
              max_cycle_bytes: int = 64 << 20) -> dict:
    sid, directory = source["source_id"], Path(source["directory"])
    case = store.get_case(source["case_id"])
    options = json.loads(source["options"])
    seg_dir = safe_join(settings.cases_dir, case["case_id"], "watch_segments")
    make_private_dir(seg_dir.parent)
    make_private_dir(seg_dir)
    summary = {"files_seen": 0, "segments_imported": 0, "bytes": 0, "accepted": 0, "rejected": 0, "duplicates": 0,
               "waiting_partial": 0, "rotations": 0, "errors": [], "backpressure": False}
    cycle_bytes = 0
    newest = source.get("last_event_time")
    try:
        files = sorted(p for p in directory.iterdir() if p.is_file() and not p.is_symlink() and fnmatch(p.name, source["pattern"]))
    except OSError as exc:
        summary["errors"].append(f"cannot list {directory}: {exc}")
        files = []
    for p in files:
        summary["files_seen"] += 1
        try:
            st = p.stat()
            fid, _ = _file_identity(p)
            if fid is None:
                summary["waiting_partial"] += 1
                continue
            cp = store.conn.execute("SELECT * FROM watch_checkpoints WHERE source_id=? AND file_id=?", (sid, fid)).fetchone()
            offset = cp["offset"] if cp else 0
            segments = cp["segments"] if cp else 0
            if cp and st.st_size < offset:
                # truncated in place: content behind the checkpoint is gone; restart this identity
                summary["rotations"] += 1
                summary["errors"].append(f"{p.name}: file shrank below checkpoint ({st.st_size} < {offset}); re-reading from start")
                offset = 0
            while offset < st.st_size:
                if cycle_bytes >= max_cycle_bytes:
                    summary["backpressure"] = True
                    break
                budget = min(max_chunk_bytes, max_cycle_bytes - cycle_bytes)
                chunk = _complete_chunk(p, offset, budget)
                if not chunk:
                    if budget < max_chunk_bytes:
                        summary["backpressure"] = True  # cycle budget exhausted; continue next cycle
                    elif st.st_size - offset >= max_chunk_bytes:
                        summary["errors"].append(f"{p.name}@{offset}: line longer than {max_chunk_bytes} bytes; source paused")
                    else:
                        summary["waiting_partial"] += 1
                    break
                seg = seg_dir / f"{sid}-{fid[:16]}-{offset:012d}-{offset + len(chunk):012d}.jsonl"
                if not seg.exists():
                    fd = os.open(seg, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(chunk)
                res = ingest_file(store, settings, case, seg, source["format"], options,
                                  original_name=f"{p.name}@{offset}-{offset + len(chunk)}",
                                  source_ref={"watch_source": sid, "file": p.name, "file_id": fid, "byte_start": offset,
                                              "byte_end": offset + len(chunk)})
                if res["status"] == "already_imported":
                    summary["duplicates"] += 1
                elif res["status"] in ("imported", "reprocessed"):
                    summary["segments_imported"] += 1
                    summary["accepted"] += res.get("accepted", 0)
                    summary["rejected"] += res.get("rejected", 0)
                    mx = store.conn.execute("SELECT MAX(event_epoch) FROM events WHERE input_id=?", (res["input_id"],)).fetchone()[0]
                    if mx is not None:
                        t = iso_from(mx)
                        if not newest or t > newest:
                            newest = t
                else:
                    summary["errors"].append(f"{p.name}@{offset}: {res['status']} {res.get('error', '')}")
                offset += len(chunk)
                cycle_bytes += len(chunk)
                summary["bytes"] += len(chunk)
                segments += 1
                seg.unlink(missing_ok=True)  # the pipeline retained its own private copy of the segment
                with store.tx() as c:
                    c.execute("INSERT INTO watch_checkpoints(source_id,file_id,path,offset,size,mtime,segments,updated_at) VALUES(?,?,?,?,?,?,?,?) "
                              "ON CONFLICT(source_id,file_id) DO UPDATE SET path=excluded.path, offset=excluded.offset, size=excluded.size, "
                              "mtime=excluded.mtime, segments=excluded.segments, updated_at=excluded.updated_at",
                              (sid, fid, p.name, offset, st.st_size, st.st_mtime, segments, now_iso()))
        except (OSError, ImportError_, ValueError) as exc:
            summary["errors"].append(f"{p.name}: {type(exc).__name__}: {exc}"[:500])
    with store.tx() as c:
        c.execute("UPDATE watch_sources SET last_poll=?, last_error=?, last_event_time=COALESCE(?, last_event_time)"
                  + (", last_import=?" if summary["segments_imported"] else "") + " WHERE source_id=?",
                  (now_iso(), "; ".join(summary["errors"])[:2000] or None, newest,
                   *((now_iso(),) if summary["segments_imported"] else ()), sid))
    return summary


def run_watch(store: Store, settings: Settings, source: dict, interval: float = 2.0, cycles: int | None = None,
              stop=None, on_cycle=None) -> int:
    n = 0
    while cycles is None or n < cycles:
        if stop is not None and stop():
            break
        s = poll_once(store, settings, source)
        n += 1
        if on_cycle:
            on_cycle(s)
        if cycles is not None and n >= cycles:
            break
        time.sleep(0 if s["backpressure"] else interval)
        source = dict(store.conn.execute("SELECT * FROM watch_sources WHERE source_id=?", (source["source_id"],)).fetchone())
    return n
