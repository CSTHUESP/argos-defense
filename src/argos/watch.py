"""Opt-in, read-only continuous file ingestion from one explicitly configured directory (feature E).

This is continuous *file* ingestion, not an EDR sensor, vendor connector or proof of coverage.

Behaviour
- Only line-oriented formats (native_jsonl, splunk_json, zeek_jsonl) are tailed. Source files are
  opened read-only and never modified, moved or executed.
- Partial writes: only complete lines (ending in "\\n") are consumed; a trailing partial line waits.
- File identity (v0.3.1): device + inode where available, first-line fingerprint and a hash of the
  consumed tail. A renamed/rotated file keeps its checkpoint; a truncated, copy-truncated or rewritten
  file starts a new generation at offset 0; two different files never share a checkpoint, even with
  identical first lines and sizes.
- Namespace: all segments of one watched source carry the declared collector id `watch:<source id>`.
- Each new chunk of complete lines is written to an owner-private segment file and imported through
  the normal pipeline (hash, original retention, rejects, unverified provenance). The checkpoint is
  advanced only after that delivery's import is COMPLETED (finalized atomically, see pipeline). Recovery
  never recomputes a pending range: if an earlier delivery starting at the checkpoint offset left a durable
  input row (completed before a lost checkpoint update, or interrupted), exactly that recorded byte range is
  re-delivered first (content verified by hash), so appended data or a different chunk budget cannot change the
  identity of committed occurrences. Only then are newly appended bytes read.
- A segment that is not durably imported (error or non-imported status) does not advance the checkpoint.
- Delivery identity vs content identity (v0.3.1 follow-up): every chunk is imported as a delivery identified by
  (source, file generation, byte range). Re-polling or restarting after a completed delivery is idempotent; a
  byte-identical chunk from another file or another offset is a different occurrence and is imported (the raw
  bytes are stored once, the occurrences and their provenance stay distinct). The number of event occurrences
  therefore does not depend on the chunk size. A delivery counts as done only when its input is completed.
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
from argos.store import COMPLETED_INPUT_STATUSES, Store

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
    options = dict(options or {})
    # all segments of one watched source share an explicit collector namespace (R04)
    options.setdefault("collector_id", f"watch:{sid}")
    with store.tx() as c:
        c.execute("INSERT INTO watch_sources(source_id,case_id,directory,pattern,format,options,created_at) VALUES(?,?,?,?,?,?,?)",
                  (sid, case["case_id"], str(d), pattern, fmt, json.dumps(options, sort_keys=True), now_iso()))
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


TAIL = 4096


def _head_fp(path: Path) -> str | None:
    """Fingerprint of the first complete line (one component of identity, never sufficient alone)."""
    with open(path, "rb") as fh:
        first = fh.readline(1 << 20)
    if not first.endswith(b"\n"):
        return None
    return hashlib.sha256(first).hexdigest()[:32] + f":{len(first)}"


def _tail_sha(path: Path, offset: int) -> str:
    """Hash of the (up to) 4 KiB that end at the checkpoint offset: detects truncation/rewrite of the
    consumed prefix without re-hashing the whole file."""
    with open(path, "rb") as fh:
        fh.seek(max(0, offset - TAIL))
        return hashlib.sha256(fh.read(min(offset, TAIL))).hexdigest()


def _complete_chunk(path: Path, offset: int, limit: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(limit)
    cut = data.rfind(b"\n")
    return data[:cut + 1] if cut >= 0 else b""


def _continues(path: Path, size: int, cp) -> bool:
    if cp["offset"] > size:
        return False
    if cp["tail_sha"] is None:
        return cp["offset"] == 0
    return _tail_sha(path, cp["offset"]) == cp["tail_sha"]


def _resolve_generation(store: Store, sid: str, path: Path, st, head: str, summary: dict):
    """Find the checkpoint generation this file instance continues, or start a new one.

    Identity = (device, inode) where the platform provides it (POSIX; NTFS file index on Windows) AND
    the first-line fingerprint AND a hash of the consumed tail. A matching inode whose consumed bytes
    changed (copy-truncate, rewrite, inode reuse) starts a NEW generation from offset 0. Without inode
    support, identity falls back to file name + first line + tail hash. Two distinct files never share
    a generation, even when their first lines and sizes are equal (R03)."""
    dev, ino = st.st_dev, st.st_ino
    rows = store.conn.execute("SELECT * FROM watch_checkpoints WHERE source_id=?", (sid,)).fetchall()
    if ino:
        for cp in rows:
            if cp["ino"] == ino and cp["dev"] == dev and not cp["legacy"]:
                if cp["head_fp"] == head and _continues(path, st.st_size, cp):
                    return cp["file_id"], cp["offset"], cp["segments"]
                summary["rotations"] += 1
                summary["errors"].append(f"{path.name}: consumed content changed (truncate/rewrite); reading as a new generation")
                with store.tx() as c:  # retire the old generation's claim on this inode
                    c.execute("UPDATE watch_checkpoints SET dev=NULL, ino=NULL WHERE source_id=? AND file_id=?", (sid, cp["file_id"]))
                break
    for cp in rows:
        claimed = cp["ino"] is not None and not cp["legacy"]
        if claimed or cp["path"] != path.name or cp["head_fp"] not in (head, None):
            continue
        if cp["legacy"]:
            # v0.3.0 checkpoint (first-line identity only): adopt only for the same file name and first line,
            # and only if the file is not shorter than the checkpoint; the tail cannot be verified.
            if cp["file_id"].split(":")[0] == head.split(":")[0] and cp["offset"] <= st.st_size:
                summary["errors"].append(f"{path.name}: legacy v0.3.0 checkpoint adopted (tail not verifiable)")
                with store.tx() as c:
                    c.execute("UPDATE watch_checkpoints SET dev=?, ino=?, head_fp=?, legacy=0 WHERE source_id=? AND file_id=?",
                              (dev, ino or None, head, sid, cp["file_id"]))
                return cp["file_id"], cp["offset"], cp["segments"]
            continue
        if not ino and _continues(path, st.st_size, cp):
            return cp["file_id"], cp["offset"], cp["segments"]
    fid = "gen-" + uuid.uuid4().hex[:16]
    with store.tx() as c:
        c.execute("INSERT INTO watch_checkpoints(source_id,file_id,path,offset,size,mtime,segments,updated_at,dev,ino,head_fp,tail_sha,legacy) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)", (sid, fid, path.name, 0, st.st_size, st.st_mtime, 0, now_iso(), dev, ino or None, head, None))
    return fid, 0, 0


def poll_once(store: Store, settings: Settings, source: dict, max_chunk_bytes: int = 8 << 20,
              max_cycle_bytes: int = 64 << 20) -> dict:
    sid, directory = source["source_id"], Path(source["directory"])
    case = store.get_case(source["case_id"])
    options = json.loads(source["options"])
    seg_dir = safe_join(settings.cases_dir, case["case_id"], "watch_segments")
    make_private_dir(seg_dir.parent)
    make_private_dir(seg_dir)
    summary = {"files_seen": 0, "segments_imported": 0, "bytes": 0, "accepted": 0, "rejected": 0, "redelivered": 0,
               "redelivered_segments": [], "waiting_partial": 0, "rotations": 0, "errors": [], "backpressure": False}
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
            head = _head_fp(p)
            if head is None:
                summary["waiting_partial"] += 1
                continue
            fid, offset, segments = _resolve_generation(store, sid, p, st, head, summary)
            while offset < st.st_size:
                if cycle_bytes >= max_cycle_bytes:
                    summary["backpressure"] = True
                    break
                budget = min(max_chunk_bytes, max_cycle_bytes - cycle_bytes)
                attempt = store.find_delivery_attempt(case["case_id"], sid, fid, offset)
                if attempt is not None:
                    # defect B: an earlier delivery starting here left a durable input (completed before a lost
                    # checkpoint update, or interrupted). Re-deliver EXACTLY its recorded range -- never a range
                    # recomputed from the current file size or chunk budget -- and verify it is the same content.
                    end = json.loads(attempt["delivery_key"])[3]
                    if end > st.st_size:
                        summary["errors"].append(f"{p.name}@{offset}: earlier delivery {offset}-{end} extends beyond the file; source paused")
                        break
                    with open(p, "rb") as fh:
                        fh.seek(offset)
                        chunk = fh.read(end - offset)
                    if not chunk.endswith(b"\n") or hashlib.sha256(chunk).hexdigest() != attempt["sha256"]:
                        summary["errors"].append(f"{p.name}@{offset}: bytes of earlier delivery {offset}-{end} changed; source paused")
                        break
                else:
                    chunk = _complete_chunk(p, offset, budget)
                if not chunk:
                    if budget < max_chunk_bytes:
                        summary["backpressure"] = True
                    elif st.st_size - offset >= max_chunk_bytes:
                        summary["errors"].append(f"{p.name}@{offset}: line longer than {max_chunk_bytes} bytes; source paused")
                    else:
                        summary["waiting_partial"] += 1
                    break
                seg = seg_dir / f"{sid}-{fid}-{offset:012d}-{offset + len(chunk):012d}.jsonl"
                fd = os.open(seg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(chunk)
                try:
                    res = ingest_file(store, settings, case, seg, source["format"], options,
                                      original_name=f"{p.name}@{offset}-{offset + len(chunk)}",
                                      source_ref={"watch_source": sid, "file": p.name, "generation": fid, "byte_start": offset,
                                                  "byte_end": offset + len(chunk)},
                                      delivery_key=json.dumps([sid, fid, offset, offset + len(chunk)], separators=(",", ":")))
                finally:
                    seg.unlink(missing_ok=True)  # the pipeline retained its own private copy when it succeeded
                if res["status"] == "already_imported" and res.get("completed") and res.get("input_status") in COMPLETED_INPUT_STATUSES:
                    # the SAME delivery (source, generation, byte range) completed earlier, e.g. before a crash that
                    # prevented the checkpoint update: idempotent retry, nothing new to store
                    summary["redelivered"] += 1
                    summary["redelivered_segments"].append(f"{p.name}@{offset}-{offset + len(chunk)}")
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
                    # not durably imported: do NOT advance the checkpoint; the same bytes are retried next poll
                    summary["errors"].append(f"{p.name}@{offset}: {res['status']} {res.get('error', '')}".strip())
                    break
                offset += len(chunk)
                cycle_bytes += len(chunk)
                summary["bytes"] += len(chunk)
                segments += 1
                with store.tx() as c:
                    c.execute("UPDATE watch_checkpoints SET path=?, offset=?, size=?, mtime=?, segments=?, updated_at=?, tail_sha=? "
                              "WHERE source_id=? AND file_id=?",
                              (p.name, offset, st.st_size, st.st_mtime, segments, now_iso(), _tail_sha(p, offset), sid, fid))
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
