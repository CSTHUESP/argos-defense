"""Import pipeline: copy original -> hash -> stream-parse -> normalize -> store in chunks.

Re-importing the same file into the same case is idempotent: event ids derive
from (case, file sha256, format, record number), so identical-looking but
distinct records are preserved while the same record never duplicates.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path

from argos import PARSER_VERSIONS
from argos.config import Settings
from argos.ingest.adapters import READERS, AdapterError
from argos.normalize import mappers
from argos.normalize.timeutil import TimestampError, iso, now_iso, parse_timestamp
from argos.store import Store

# Unicode letters/digits allowed (e.g. "Prüfung é.xml"); path separators, control chars and ".." are not.
SAFE_NAME_RE = re.compile(r"^[^\W_][\w .,()+\-]{0,200}$", re.UNICODE)
ALLOWED_EXT = {".jsonl", ".json", ".ndjson", ".log", ".csv", ".xml", ".txt"}


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


def _copy_and_hash(src: Path, dest_dir: Path, max_bytes: int) -> tuple[str, Path, int]:
    if src.is_symlink() or not src.is_file():
        raise ImportError_("input must be a regular file (symlinks are not followed)")
    size = src.stat().st_size
    if size > max_bytes:
        raise ImportError_(f"file is {size} bytes; limit is {max_bytes}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp = dest_dir / (".incoming-" + os.urandom(6).hex())
    h = hashlib.sha256()
    n = 0
    with open(src, "rb") as fi, open(tmp, "wb") as fo:
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
        tmp.rename(final)
        os.chmod(final, stat.S_IRUSR | stat.S_IRGRP)  # read-only local copy (not tamper-proof)
    return digest, final, n


def ingest_file(store: Store, settings: Settings, case: dict, path: str | Path, fmt: str,
                options: dict | None = None, original_name: str | None = None) -> dict:
    options = dict(options or {})
    if fmt not in READERS:
        raise ImportError_(f"unknown format {fmt!r}; supported: {', '.join(READERS)}")
    profile = None
    if fmt in ("splunk_json", "splunk_csv"):
        if fmt == "splunk_json" and not options.get("profile") and not options.get("mapping"):
            options["profile"] = "native"
        profile = mappers.load_profile(options.get("profile"), options.get("mapping"))
        if options.get("mapping"):
            options["mapping_inline"] = profile  # recorded for reproducibility
    assume_tz = options.get("assume_tz") or None
    if assume_tz:
        try:
            parse_timestamp("2000-01-01T00:00:00", assume_tz)
        except TimestampError as exc:
            raise ImportError_(str(exc)) from exc
    src = Path(path)
    case_dir = safe_join(settings.cases_dir, case["case_id"])
    digest, stored, size = _copy_and_hash(src, case_dir / "originals", settings.max_file_bytes)
    existing = store.find_input(case["case_id"], digest, fmt)
    if existing:
        return {"status": "already_imported", "input_id": existing["input_id"], "sha256": digest,
                "accepted": existing["records_accepted"], "rejected": existing["records_rejected"],
                "total": existing["records_total"], "new_events": 0}
    input_id = "in-" + digest[:16] + "-" + hashlib.sha256((case["case_id"] + fmt).encode()).hexdigest()[:6]
    store.add_input({
        "input_id": input_id, "case_id": case["case_id"], "sha256": digest,
        "original_name": original_name or src.name, "stored_path": str(stored), "format": fmt,
        "parser_version": PARSER_VERSIONS[fmt], "options": json.dumps(options, sort_keys=True, default=str),
        "size_bytes": size, "provenance_trust": "unverified",
        "provenance_note": "imported file; origin not independently verified (sha256 establishes integrity only)",
        "imported_at": now_iso(),
    })
    ingested_at = now_iso()
    total = accepted = rejected = new = 0
    chunk, rej_chunk = [], []
    count_cap = settings.max_events_per_case - store.count_events(case["case_id"])

    def flush():
        nonlocal new, chunk, rej_chunk
        if chunk:
            new += store.insert_events(chunk)
        if rej_chunk:
            store.insert_rejects(rej_chunk)
        chunk, rej_chunk = [], []

    try:
        records = READERS[fmt](stored, settings.max_record_bytes)
        for record_no, raw, err in records:
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
                        ev, ts_raw, err = mappers.map_zeek(raw, options.get("zeek_log"))
                except Exception as exc:  # noqa: BLE001 - record and continue
                    err = f"normalization error: {type(exc).__name__}"
            if err is None:
                err = mappers.finalize_kind_vantage(ev)
            if err is None:
                try:
                    tz_opt = assume_tz
                    if fmt == "sysmon_xml":
                        tz_opt = "UTC"  # Sysmon 'UtcTime' is defined as UTC by the producer
                    dt, note = parse_timestamp(ts_raw, tz_opt)
                    if fmt == "sysmon_xml":
                        note = "sysmon_UtcTime_documented_as_UTC"
                except TimestampError as exc:
                    err = f"timestamp: {exc}"
            if err is None and accepted >= count_cap:
                err = "case event limit reached"
            if err is not None:
                rejected += 1
                excerpt = None
                if raw is not None:
                    excerpt = json.dumps(raw, default=str)[:300]
                rej_chunk.append((case["case_id"], input_id, record_no, err[:300], excerpt))
            else:
                accepted += 1
                ev.update(
                    event_id=hashlib.sha256(f"{case['case_id']}|{digest}|{fmt}|{record_no}".encode()).hexdigest()[:32],
                    case_id=case["case_id"], input_id=input_id, record_no=record_no,
                    event_time=iso(dt), event_epoch=dt.timestamp(), original_timestamp=str(ts_raw),
                    timestamp_note=note, ingested_at=ingested_at, source_format=fmt,
                    evidence_ref=f"ev:{digest[:16]}:{record_no}",
                )
                if ev["source_type"] is None:
                    ev["source_type"] = fmt
                chunk.append(ev)
            if len(chunk) + len(rej_chunk) >= settings.chunk_size:
                flush()
        flush()
    except AdapterError as exc:
        flush()
        rejected += 1
        store.insert_rejects([(case["case_id"], input_id, 0, f"file rejected: {exc}"[:300], None)])
        store.update_input_counts(input_id, total, accepted, rejected)
        return {"status": "rejected", "input_id": input_id, "sha256": digest, "error": str(exc),
                "accepted": accepted, "rejected": rejected, "total": total, "new_events": new}
    store.update_input_counts(input_id, total, accepted, rejected)
    return {"status": "imported", "input_id": input_id, "sha256": digest, "accepted": accepted,
            "rejected": rejected, "total": total, "new_events": new, "stored_copy": str(stored)}


def remove_copy_dir(path: Path):  # used by tests only
    shutil.rmtree(path, ignore_errors=True)
