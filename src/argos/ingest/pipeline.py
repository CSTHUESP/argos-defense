"""Import pipeline: copy original -> hash -> stream-parse -> normalize -> store in chunks.

Normalization revisions (v0.3): an import is identified by
  (case, original content sha256, adapter format, parser version, canonical effective options/mapping hash).
* Importing the same file with the same effective options again is idempotent (`already_imported`).
* Importing the same content with different options is refused unless `reprocess=True`, which creates
  a new revision; exactly one revision per content is active, so analyses never double count.
* A failed reprocess (file rejected, or no accepted records while the active revision has some)
  is kept for inspection but does not replace the usable active revision.
* Original bytes and every revision's events/rejects are retained; past runs keep their manifests.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import threading
from pathlib import Path

from argos import PARSER_VERSIONS
from argos.config import Settings
from argos.evidence.redact import redact, redact_obj
from argos.ingest.adapters import READERS, AdapterError
from argos.normalize import mappers
from argos.normalize.timeutil import TimestampError, iso, now_iso, parse_timestamp
from argos.store import COMPLETED_INPUT_STATUSES, Store, options_hash

# Unicode letters/digits allowed (e.g. "Prüfung é.xml"); path separators, control chars and ".." are not.
SAFE_NAME_RE = re.compile(r"^[^\W_][\w .,()+\-]{0,200}$", re.UNICODE)
ALLOWED_EXT = {".jsonl", ".json", ".ndjson", ".log", ".csv", ".xml", ".txt"}
COVERAGE_SCOPE_RE = re.compile(r"^(all|tenant:[^\s]{1,200}|host:[^\s]{1,200}|app_id:[^\s]{1,200})$")


class ImportError_(ValueError):
    pass


def safe_original_name(name: str) -> str:
    """Validate a client-supplied filename. Rejects traversal and separators."""
    if not name or "/" in name or "\\" in name or "\x00" in name or name in (".", "..") or ".." in name:
        raise ImportError_("unsafe file name (path components are not allowed)")
    if not SAFE_NAME_RE.match(name):
        raise ImportError_("file name contains disallowed characters")
    if Path(name).suffix.lower() not in ALLOWED_EXT:
        raise ImportError_(f"file type not accepted; allowed extensions: {', '.join(sorted(ALLOWED_EXT))}")
    return name


def safe_join(base: Path, *parts: str) -> Path:
    base = base.resolve()
    p = base.joinpath(*parts).resolve()
    if p != base and base not in p.parents:
        raise ImportError_("path escapes the case directory")
    return p


def _private_dir(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(d, 0o700)


def _copy_and_hash(src: Path, dest_dir: Path, max_bytes: int) -> tuple[str, Path, int]:
    if src.is_symlink() or not src.is_file():
        raise ImportError_("input must be a regular file (symlinks are not followed)")
    size = src.stat().st_size
    if size > max_bytes:
        raise ImportError_(f"file is {size} bytes; limit is {max_bytes}")
    _private_dir(dest_dir)
    tmp = dest_dir / (".incoming-" + os.urandom(6).hex())
    h = hashlib.sha256()
    n = 0
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with open(src, "rb") as fi, os.fdopen(fd, "wb") as fo:
        while True:
            b = fi.read(1024 * 1024)
            if not b:
                break
            n += len(b)
            if n > max_bytes:
                fo.close()
                tmp.unlink(missing_ok=True)
                raise ImportError_("file grew beyond size limit while copying")
            h.update(b)
            fo.write(b)
    digest = h.hexdigest()
    final = dest_dir / f"{digest}{src.suffix.lower() or '.dat'}"
    if final.exists():
        tmp.unlink()
    else:
        os.replace(tmp, final)
        os.chmod(final, stat.S_IRUSR)  # owner read-only local copy (integrity aid; not tamper-proof)
    return digest, final, n


COLLECTOR_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def effective_options(fmt: str, options: dict | None) -> tuple[dict, dict | None]:
    """Canonical options used for parsing (custom mapping content inlined; file paths dropped)."""
    options = dict(options or {})
    profile = None
    if fmt in ("splunk_json", "splunk_csv"):
        if fmt == "splunk_json" and not options.get("profile") and not options.get("mapping"):
            options["profile"] = "native"
        profile = mappers.load_profile(options.get("profile"), options.get("mapping"))
        if options.get("mapping"):
            options["mapping_inline"] = profile
            options.pop("mapping", None)  # temp/user path is not part of the interpretation
            options.pop("profile", None)
    assume_tz = options.get("assume_tz") or None
    if assume_tz:
        try:
            parse_timestamp("2000-01-01T00:00:00", assume_tz)
        except TimestampError as exc:
            raise ImportError_(str(exc)) from exc
    cid = options.get("collector_id")
    if cid not in (None, "") and not COLLECTOR_RE.match(str(cid)):
        raise ImportError_("collector_id must be 1-128 characters of letters, digits and . _ : -")
    return {k: v for k, v in options.items() if v not in (None, "")}, profile


def validate_coverage(cov: dict | None) -> dict | None:
    """Analyst-declared collection coverage for an input (never taken from inside the file)."""
    if not cov:
        return None
    start, end, scope = cov.get("start"), cov.get("end"), (cov.get("scope") or "all")
    if not start or not end:
        raise ImportError_("declared coverage needs start and end")
    try:
        s, _ = parse_timestamp(start)
        e, _ = parse_timestamp(end)
    except TimestampError as exc:
        raise ImportError_(f"coverage: {exc}") from exc
    if e <= s:
        raise ImportError_("coverage end must be after start")
    if not COVERAGE_SCOPE_RE.match(scope):
        raise ImportError_("coverage scope must be 'all', 'tenant:<id>', 'host:<name>' or 'app_id:<id>'")
    kinds = cov.get("event_kinds") or []
    if isinstance(kinds, str):
        kinds = [k.strip() for k in kinds.split(",") if k.strip()]
    from argos.models import EVENT_KINDS
    bad = [k for k in kinds if k not in EVENT_KINDS]
    if bad:
        raise ImportError_(f"coverage event_kinds not recognised: {bad}; known: {', '.join(EVENT_KINDS)}")
    return {"start": iso(s), "end": iso(e), "start_epoch": s.timestamp(), "end_epoch": e.timestamp(), "scope": scope,
            "event_kinds": sorted(set(kinds)),
            "basis": "analyst-declared (not verified by ARGOS)", "note": (cov.get("note") or "")[:500]}


_IMPORT_LOCKS: dict = {}
_IMPORT_LOCKS_GUARD = threading.Lock()


def _import_lock(key):
    with _IMPORT_LOCKS_GUARD:
        return _IMPORT_LOCKS.setdefault(key, threading.Lock())


def ingest_file(store: Store, settings: Settings, case: dict, path: str | Path, fmt: str,
                options: dict | None = None, original_name: str | None = None, reprocess: bool = False,
                coverage: dict | None = None, source_ref: dict | None = None, delivery_key: str | None = None) -> dict:
    """Import one file as one input revision.

    Completion (follow-up defect 2): an input row certifies a durable import only when its status is in
    COMPLETED_INPUT_STATUSES. A row left 'processing'/'interrupted'/'failed' (e.g. the process died or a write
    failed after some batches committed) is restarted: its partial events/rejects are removed and the import is
    re-run from the retained original under the same deterministic input and event ids. Imports of the same
    content+options are serialized in-process; event ids are deterministic and inserted with INSERT OR IGNORE, so
    a retry cannot create duplicate occurrences.

    Delivery identity (follow-up defect 3): `delivery_key` (used by the watcher: source, file generation, byte range)
    is part of the input identity. A retry of the same delivery is idempotent; another delivery with byte-identical
    content is a different occurrence and is imported separately (the original bytes are stored once)."""
    if fmt not in READERS:
        raise ImportError_(f"unknown format {fmt!r}; supported: {', '.join(READERS)}")
    opts, profile = effective_options(fmt, options)
    cov = validate_coverage(coverage)
    parser_version = PARSER_VERSIONS[fmt]
    oh = options_hash(fmt, parser_version, {**opts, "_delivery": delivery_key} if delivery_key else opts)
    src = Path(path)
    case_dir = safe_join(settings.cases_dir, case["case_id"])
    _private_dir(case_dir)
    digest, stored, size = _copy_and_hash(src, case_dir / "originals", settings.max_file_bytes)
    with _import_lock((case["case_id"], digest, fmt, oh)):
        return _ingest_locked(store, settings, case, src, fmt, opts, profile, cov, parser_version, oh, digest, stored, size,
                              original_name, reprocess, source_ref, delivery_key)


def _ingest_locked(store, settings, case, src, fmt, opts, profile, cov, parser_version, oh, digest, stored, size,
                   original_name, reprocess, source_ref, delivery_key):
    same = store.find_input(case["case_id"], digest, fmt, oh)
    resumed = False
    if same and same["status"] in COMPLETED_INPUT_STATUSES and same.get("finalized"):
        return {"status": "already_imported", "completed": True, "input_id": same["input_id"], "sha256": digest,
                "revision": same["revision"], "active": bool(same["active"]), "input_status": same["status"],
                "accepted": same["records_accepted"], "rejected": same["records_rejected"],
                "total": same["records_total"], "new_events": 0}
    if same:
        # an earlier attempt of exactly this import did not complete (including an interrupted finalization):
        # discard its partial rows and redo it
        store.restart_incomplete_input(same["input_id"])
        resumed = True
    revisions = [r for r in store.revisions_of(case["case_id"], digest, delivery_key) if not same or r["input_id"] != same["input_id"]]
    active = next((r for r in revisions if r["active"]), None)
    if revisions and not reprocess and not resumed:
        return {"status": "different_options_require_reprocess", "sha256": digest, "active_input_id": active["input_id"] if active else None,
                "message": "this file content was already imported with other parsing options; use reprocess to create a new revision",
                "accepted": 0, "rejected": 0, "total": 0, "new_events": 0}
    if resumed:
        revision, input_id = same["revision"], same["input_id"]
    else:
        revision = store.next_revision(case["case_id"], digest, delivery_key)
        input_id = "in-" + digest[:16] + "-" + hashlib.sha256(f"{case['case_id']}|{fmt}|{oh}".encode()).hexdigest()[:6]
    if not resumed:
        store.add_input({
            "input_id": input_id, "case_id": case["case_id"], "sha256": digest,
            "original_name": original_name or src.name, "stored_path": str(stored), "format": fmt,
            "parser_version": parser_version, "options": json.dumps(opts, sort_keys=True, default=str),
            "size_bytes": size, "provenance_trust": "unverified",
            "provenance_note": "imported file; origin not independently verified (sha256 establishes integrity only)",
            "imported_at": now_iso(), "options_hash": oh, "revision": revision, "active": 0, "status": "processing",
            "supersedes": active["input_id"] if active else None, "coverage": json.dumps(cov) if cov else None,
            "source_ref": json.dumps(source_ref) if source_ref else None, "delivery_key": delivery_key,
        })
    ingested_at = now_iso()
    total = accepted = rejected = new = 0
    chunk, rej_chunk = [], []
    replaced = (active["records_accepted"] or 0) if active else 0
    count_cap = settings.max_events_per_case - store.count_events(case["case_id"]) + replaced
    assume_tz = opts.get("assume_tz") or None

    def flush():
        nonlocal new, chunk, rej_chunk
        if chunk:
            new += store.insert_events(chunk)
        if rej_chunk:
            store.insert_rejects(rej_chunk)
        chunk, rej_chunk = [], []

    file_error = None
    try:
        records = READERS[fmt](stored, settings.max_record_bytes)
    except Exception:
        store.set_input_status(input_id, "interrupted")
        raise
    try:
        for record_no, raw, err, locator in records:
            total += 1
            ev = None
            ts_raw = None
            if err is None:
                try:
                    if fmt == "native_jsonl":
                        ev, ts_raw = mappers.map_native(raw)
                    elif fmt in ("splunk_json", "splunk_csv"):
                        ev, ts_raw = mappers.map_profile(raw, profile)
                    elif fmt == "sysmon_xml":
                        ev, ts_raw, err = mappers.map_sysmon(raw)
                    elif fmt == "zeek_jsonl":
                        ev, ts_raw, err = mappers.map_zeek(raw, opts.get("zeek_log"))
                except Exception as exc:  # noqa: BLE001 - record and continue
                    err = f"normalization error: {type(exc).__name__}"
            if err is None:
                err = mappers.finalize_kind_vantage(ev)
            if err is None:
                try:
                    tz_opt = "UTC" if fmt == "sysmon_xml" else assume_tz  # Sysmon 'UtcTime' is defined as UTC by the producer
                    dt, note = parse_timestamp(ts_raw, tz_opt)
                    if fmt == "sysmon_xml":
                        note = "sysmon_UtcTime_documented_as_UTC"
                except TimestampError as exc:
                    err = f"timestamp: {exc}"
            if err is None and accepted >= count_cap:
                err = "case event limit reached"
            if err is not None:
                rejected += 1
                # F05: redact the whole value first, then truncate (truncation must not split a secret past the pattern)
                excerpt = redact(json.dumps(redact_obj(raw) if isinstance(raw, (dict, list)) else raw, default=str, ensure_ascii=False))[:300] \
                    if raw is not None else None
                rej_chunk.append((case["case_id"], input_id, record_no, redact(err)[:300], excerpt))
            else:
                accepted += 1
                ev.update(
                    event_id=hashlib.sha256(f"{case['case_id']}|{digest}|{fmt}|{oh}|{record_no}".encode()).hexdigest()[:32],
                    case_id=case["case_id"], input_id=input_id, record_no=record_no, revision=revision,
                    event_time=iso(dt), event_epoch=dt.timestamp(), original_timestamp=str(ts_raw),
                    timestamp_note=note, ingested_at=ingested_at, source_format=fmt,
                    evidence_ref=f"ev:{digest[:16]}:{record_no}", source_locator=locator,
                )
                if ev["source_type"] is None:
                    ev["source_type"] = fmt
                # explicit collector namespace from the ingestion configuration (R04); absent -> per-input namespace
                ev["collector_id"] = opts.get("collector_id")
                chunk.append(ev)
            if len(chunk) + len(rej_chunk) >= settings.chunk_size:
                flush()
        flush()
    except AdapterError as exc:
        flush()
        file_error = str(exc)
        rejected += 1
        store.insert_rejects([(case["case_id"], input_id, 0, f"file rejected: {exc}"[:300], None)])
    except BaseException:
        # write failure, cancellation, ...: committed batches stay but the input is NOT complete and stays inactive
        try:
            store.set_input_status(input_id, "interrupted")
        except Exception:  # noqa: BLE001 - the original error matters more; a later import treats 'processing' alike
            pass
        raise
    # decide whether this revision becomes the active interpretation, then finalize ATOMICALLY (defect A)
    previous_usable = active is not None and (active["records_accepted"] or 0) > 0
    keep_previous = bool(file_error and previous_usable or (accepted == 0 and previous_usable))
    final = "failed_kept_previous" if keep_previous else ("rejected" if file_error else "imported")
    try:
        store.finalize_input(input_id, total, accepted, rejected, final, activate=not keep_previous)
    except BaseException:
        try:
            store.set_input_status(input_id, "interrupted")
        except Exception:  # noqa: BLE001
            pass
        raise
    status = "reprocess_failed_previous_kept" if keep_previous else ("rejected" if file_error else ("reprocessed" if active else "imported"))
    res = {"status": status, "input_id": input_id, "sha256": digest, "revision": revision, "options_hash": oh,
           "accepted": accepted, "rejected": rejected, "skipped": max(0, total - accepted - rejected), "total": total,
           "new_events": new, "stored_copy": str(stored), "superseded": active["input_id"] if active and status == "reprocessed" else None,
           "completed": True, "recovered_incomplete_attempt": resumed}
    if file_error:
        res["error"] = file_error
    return res


def remove_copy_dir(path: Path):  # used by tests only
    shutil.rmtree(path, ignore_errors=True)
