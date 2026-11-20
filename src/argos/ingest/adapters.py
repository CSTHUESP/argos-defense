"""Format adapters. Each adapter yields (record_no, raw_record | None, error | None)
from a locally retained copy of the original file, streaming line by line or
element by element. Adapters never execute or follow anything in the data."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from defusedxml import ElementTree as DET
from defusedxml.common import DefusedXmlException


class AdapterError(ValueError):
    pass


def _iter_lines(path: Path, max_record_bytes: int):
    with open(path, "rb") as fh:
        for no, line in enumerate(fh, start=1):
            if len(line) > max_record_bytes:
                yield no, None, f"record exceeds {max_record_bytes} bytes"
                continue
            s = line.strip()
            if not s:
                continue
            try:
                yield no, s.decode("utf-8"), None
            except UnicodeDecodeError:
                yield no, None, "invalid UTF-8"


def read_jsonl(path: Path, max_record_bytes: int):
    first = True
    for no, text, err in _iter_lines(path, max_record_bytes):
        if err:
            yield no, None, err
            continue
        if text.startswith("#"):
            # Zeek TSV header/comment lines (#separator, #fields...) - only Zeek JSON logs are supported
            yield no, None, "comment/TSV header line (only JSON logs are supported; Zeek TSV is not)"
            continue
        if first and text.startswith("["):
            # JSON array file (e.g. Splunk JSON export of a result list). Bounded by max file size.
            first = False
            yield from _read_json_array(path)
            return
        first = False
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            yield no, None, f"malformed JSON: {exc.msg} at col {exc.colno}"
            continue
        if not isinstance(obj, dict):
            yield no, None, "record is not a JSON object"
            continue
        yield no, obj, None


def _read_json_array(path: Path):
    try:
        data = json.loads(path.read_text("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        yield 0, None, f"malformed JSON array file: {exc}"
        return
    for i, obj in enumerate(data, start=1):
        if isinstance(obj, dict):
            yield i, obj, None
        else:
            yield i, None, "array element is not an object"


def read_csv(path: Path, max_record_bytes: int):
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:  # tolerate a UTF-8 BOM (Excel/Splunk exports)
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            yield 0, None, "CSV without header row"
            return
        try:
            for row in reader:
                no = reader.line_num
                if None in row:
                    yield no, None, "row has more columns than header"
                    continue
                if sum(len(v or "") for v in row.values()) > max_record_bytes:
                    yield no, None, "record too large"
                    continue
                yield no, dict(row), None
        except csv.Error as exc:
            yield reader.line_num, None, f"CSV error: {exc}"


SYSMON_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def read_sysmon_xml(path: Path, max_record_bytes: int):
    head = path.read_bytes()[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
        raise AdapterError("XML document type declarations / entities are not accepted")
    source = str(path)
    raw = path.read_bytes()
    body = raw.lstrip(b"\xef\xbb\xbf").lstrip()
    if body.startswith(b"<?xml"):
        body = body[body.index(b"?>") + 2:].lstrip()
    if body.startswith(b"<Event ") or body.startswith(b"<Event>"):
        # wevtutil qe /f:xml and Get-WinEvent ...ToXml() emit concatenated <Event> elements without a
        # root element; wrap them so the document is well-formed (bounded by the file size limit).
        import io
        source = io.BytesIO(b"<Events>" + body + b"</Events>")
    try:
        ordinal = 0
        for _evt, elem in DET.iterparse(source, events=("end",), forbid_dtd=True, forbid_entities=True, forbid_external=True):
            tag = elem.tag.replace(SYSMON_NS, "")
            if tag != "Event":
                continue
            ordinal += 1
            rec: dict = {}
            system = elem.find(f"{SYSMON_NS}System")
            if system is None:
                system = elem.find("System")
            if system is not None:
                for child in system:
                    name = child.tag.replace(SYSMON_NS, "")
                    if name == "TimeCreated":
                        rec["_TimeCreated"] = child.get("SystemTime")
                    elif name == "Provider":
                        rec["_Provider"] = child.get("Name")
                    else:
                        rec["_" + name] = (child.text or "").strip()
            data = elem.find(f"{SYSMON_NS}EventData")
            if data is None:
                data = elem.find("EventData")
            if data is not None:
                for d in data:
                    n = d.get("Name")
                    if n:
                        rec[n] = (d.text or "").strip()
            elem.clear()
            yield ordinal, rec, None
    except (DET.ParseError, DefusedXmlException) as exc:
        raise AdapterError(f"XML rejected: {exc}") from exc


READERS = {
    "native_jsonl": read_jsonl,
    "splunk_json": read_jsonl,
    "splunk_csv": read_csv,
    "sysmon_xml": read_sysmon_xml,
    "zeek_jsonl": read_jsonl,
}

FORMAT_HELP = {
    "native_jsonl": "ARGOS native JSONL (documented schema, all event kinds incl. identity/cloud/model-audit)",
    "splunk_json": "Splunk JSON/JSONL export (records may be wrapped in 'result'); needs a mapping profile",
    "splunk_csv": "Splunk CSV export; requires an explicit column mapping profile",
    "sysmon_xml": "Sysmon events exported to XML (EventID 1, 3, 11, 22). Binary EVTX is NOT supported",
    "zeek_jsonl": "Zeek JSON logs: conn, http, dns",
}

