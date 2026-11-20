"""Retrieve the original record behind a normalized event (F08).

Retrieval uses the versioned, format-aware `source_locator` captured at import time. Before any
excerpt is returned the retained original is re-hashed and compared with the import digest; on a
mismatch no excerpt is shown. Events imported before locators existed (v0.2 and earlier) carry only
a record number; for those a best-effort lookup is returned and labelled `legacy_record_number`.
The excerpt is redacted unless the caller explicitly asks for the raw record.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

from .redact import is_secret_key, redact, redact_obj

MAX_EXCERPT = 16384


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _jsonl(path: Path, loc: dict) -> str:
    with open(path, "rb") as fh:
        fh.seek(int(loc["byte_start"]))
        data = fh.read(min(int(loc["byte_end"]) - int(loc["byte_start"]), MAX_EXCERPT))
    return data.decode("utf-8", "replace").rstrip("\r\n")


def _json_array(path: Path, loc: dict) -> str:
    data = json.loads(path.read_text("utf-8-sig"))
    return json.dumps(data[int(loc["index"])], ensure_ascii=False, indent=2)[:MAX_EXCERPT]


def _csv(path: Path, loc: dict) -> str:
    start, end = int(loc["line_start"]), int(loc["line_end"])
    out_header, out_rows = [], []
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        for no, line in enumerate(fh, start=1):
            if no <= int(loc.get("header_lines", 1)):
                out_header.append(line)
            if start <= no <= end:
                out_rows.append(line)
            if no > end:
                break
    return ("".join(out_header) + "".join(out_rows))[:MAX_EXCERPT]


def _xml(path: Path, loc: dict) -> str:
    import xml.etree.ElementTree as ET

    from ..ingest.adapters import iter_xml_events
    for ordinal, elem in iter_xml_events(path):
        if ordinal == int(loc["ordinal"]):
            return ET.tostring(elem, encoding="unicode")[:MAX_EXCERPT]
    raise LookupError("XML element ordinal not found")


def _legacy(path: Path, fmt: str, record_no: int) -> str | None:
    if fmt == "sysmon_xml":
        return _xml(path, {"ordinal": record_no})
    with open(path, "rb") as fh:
        head = fh.read(64).lstrip(b"\xef\xbb\xbf").lstrip()
    if head.startswith(b"[") and fmt in ("native_jsonl", "splunk_json"):
        return _json_array(path, {"index": record_no - 1})
    with open(path, "rb") as fh:
        for no, line in enumerate(fh, start=1):
            if no == record_no:
                return line[:MAX_EXCERPT].decode("utf-8", "replace").rstrip("\r\n")
    return None


def _redact_json_text(text: str) -> str | None:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    return json.dumps(redact_obj(obj), ensure_ascii=False, indent=2 if "\n" in text else None)


def _redact_csv_text(text: str) -> str | None:
    """Header-aware: a column whose header is a sensitive key is masked in every row; every other cell
    is pattern-redacted. Uses the csv module, so quoting, embedded delimiters and multi-line cells
    keep their record boundaries. Returns None if the excerpt cannot be parsed as CSV."""
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error:
        return None
    if not rows:
        return None
    header = rows[0]
    secret_cols = {i for i, h in enumerate(header) if is_secret_key(h)}
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow([redact(h) for h in header])
    for row in rows[1:]:
        w.writerow(["[REDACTED]" if (i in secret_cols and cell != "") else redact(cell) for i, cell in enumerate(row)])
    return buf.getvalue()


def _redact_xml_text(text: str) -> str | None:
    """Event XML: <Data Name="..."> values with a sensitive name are masked; all text and attribute
    values are pattern-redacted. Input is the excerpt produced by our own safe parser."""
    import defusedxml.ElementTree as DET
    import xml.etree.ElementTree as ET
    try:
        root = DET.fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception:  # noqa: BLE001 - any parse problem -> cannot redact structurally
        return None
    for el in root.iter():
        name = el.get("Name")
        if el.text and el.text.strip():
            el.text = "[REDACTED]" if (name and is_secret_key(name)) else redact(el.text)
        for k, v in list(el.attrib.items()):
            if k != "Name":
                el.set(k, redact(v))
    return ET.tostring(root, encoding="unicode")


def redact_record(kind: str | None, fmt: str, text: str) -> tuple[str | None, str]:
    """Return (redacted_text or None, basis). None means the excerpt could not be redacted safely and
    must not be shown in the redacted view."""
    if kind == "csv_record" or fmt == "splunk_csv":
        r = _redact_csv_text(text)
        return (r, "structured-csv (header-aware)") if r is not None else (None, "unavailable: CSV excerpt could not be parsed")
    if kind == "xml_element" or fmt == "sysmon_xml":
        r = _redact_xml_text(text)
        return (r, "structured-xml (Data Name-aware)") if r is not None else (None, "unavailable: XML excerpt could not be parsed")
    r = _redact_json_text(text)
    if r is not None:
        return r, "structured-json (key-aware)"
    return None, "unavailable: record is not valid JSON, so key-aware redaction is impossible"


READERS = {"jsonl_line": _jsonl, "json_array_index": _json_array, "csv_record": _csv, "xml_element": _xml}


def original_record(input_row: dict, event: dict, raw: bool = False) -> dict:
    info = {k: input_row.get(k) for k in ("input_id", "original_name", "format", "sha256", "provenance_trust", "revision")}
    info.update(record_text=None, redacted=not raw, redaction=None, locator=event.get("source_locator"), status="unavailable", detail="")
    path = Path(input_row["stored_path"])
    if not path.is_file():
        info["detail"] = "retained original is missing"
        return info
    actual = _sha256(path)
    if actual != input_row["sha256"]:
        info.update(status="integrity_mismatch",
                    detail=f"retained original hash {actual[:16]}… differs from import digest {input_row['sha256'][:16]}…; no excerpt shown")
        return info
    loc = event.get("source_locator")
    try:
        if isinstance(loc, dict) and loc.get("kind") in READERS:
            text = READERS[loc["kind"]](path, loc)
            info.update(status="located", detail=f"locator v{loc.get('v')} {loc['kind']}")
        else:
            text = _legacy(path, input_row["format"], int(event.get("record_no") or 0))
            info.update(status="legacy_record_number",
                        detail="imported before format-aware locators; best-effort lookup by record number")
    except (OSError, ValueError, LookupError, IndexError, KeyError, csv.Error, io.UnsupportedOperation) as exc:
        info.update(status="lookup_failed", detail=str(exc)[:300])
        return info
    except Exception as exc:  # adapter errors (e.g. XML rejected)
        info.update(status="lookup_failed", detail=str(exc)[:300])
        return info
    if raw:
        info["record_text"], info["redaction"] = text, "none (explicit raw view)"
    else:
        red, basis = redact_record(loc.get("kind") if isinstance(loc, dict) else None, input_row["format"], text or "")
        info["record_text"], info["redaction"] = red, basis
        if red is None:
            info["redacted"] = False
            info["status"] = "redacted_view_unavailable"
            info["detail"] = basis + "; the excerpt is withheld from the redacted view (use the explicit raw view if needed)"
    info["location"] = json.dumps(loc, sort_keys=True) if isinstance(loc, dict) else f"record {event.get('record_no')}"
    return info
