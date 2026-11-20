"""Mapping of raw adapter records to the normalized event schema.

Rules: unavailable fields stay None; nothing is guessed. Byte counters are only
mapped when the mapping declares their direction (`bytes_basis`).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from argos.models import EVENT_FIELDS, EVENT_KINDS, INT_FIELDS, KIND_VANTAGE, VANTAGES, empty_event


class MappingError(ValueError):
    pass


NATIVE_ALLOWED = set(EVENT_FIELDS) - {
    "schema_version", "event_id", "case_id", "input_id", "record_no", "event_epoch", "ingested_at",
    "original_timestamp", "timestamp_note", "quality_warnings", "evidence_ref", "source_format", "source_locator", "revision",
}
# Fields that an imported record might use to claim trust. They are never honoured.
SELF_TRUST_FIELDS = {"provenance_trust", "trusted", "verified", "provenance", "trust"}


def _coerce(ev: dict, key: str, value):
    if value in ("", "-", None):
        return
    if key in INT_FIELDS:
        try:
            ev[key] = int(float(value))
        except (TypeError, ValueError):
            ev["quality_warnings"].append(f"non_integer:{key}")
        return
    if isinstance(value, (dict, list)):
        ev["quality_warnings"].append(f"non_scalar_ignored:{key}")
        return
    ev[key] = str(value) if not isinstance(value, bool) else str(value).lower()


def map_native(raw: dict) -> tuple[dict, object]:
    ev = empty_event()
    ignored = []
    for k, v in raw.items():
        if k in NATIVE_ALLOWED:
            _coerce(ev, k, v)
        elif k.lower() in SELF_TRUST_FIELDS:
            ev["quality_warnings"].append(f"self_declared_trust_field_ignored:{k}")
        elif k != "event_time":
            ignored.append(k)
    if ignored:
        ev["quality_warnings"].append("unknown_fields_ignored:" + ",".join(sorted(ignored)[:10]))
    return ev, raw.get("event_time")


# --- Splunk / CSV mapping profiles -------------------------------------------------
BUILTIN_PROFILES = {
    # W3C Extended Log Format convention: the "cs-" prefix denotes client-to-server,
    # "sc-" server-to-client. Proxy products following that convention (and their
    # Splunk add-ons that keep the field names) record cs_bytes as bytes sent by the
    # client. Verify against your product's documentation before relying on it.
    "proxy": {
        "time": "_time",
        "fields": {
            "src_ip": "c_ip", "http_host": "cs_host", "http_method": "cs_method", "http_uri": "cs_uri",
            "http_status": "sc_status", "bytes_src_to_dst": "cs_bytes", "bytes_dst_to_src": "sc_bytes",
            "http_user_agent": ["cs_User_Agent", "cs(User-Agent)", "http_user_agent"], "user": "cs_username",
            "dst_ip": "s_ip", "host": "s_computername",
        },
        "constants": {"event_kind": "http", "observation_vantage": "victim_network", "source_type": "proxy"},
        "bytes_basis": "w3c_elf: cs_bytes=client_to_server, sc_bytes=server_to_client (declared by profile 'proxy')",
    },
    "auth": {
        "time": "_time",
        "fields": {"user": "user", "src_ip": "src_ip", "tenant_id": "tenant_id", "outcome": "outcome",
                   "action": "action", "app_id": "app_id", "session_id": "session_id", "account_type": "account_type",
                   "http_user_agent": "user_agent"},
        "constants": {"event_kind": "authentication", "observation_vantage": "identity_cloud", "source_type": "splunk_auth"},
    },
    # Splunk export of events already using ARGOS native field names.
    "native": {"time": "event_time", "fields": "native"},
}


def load_profile(profile: str | None, mapping_path: str | None) -> dict:
    if mapping_path:
        p = Path(mapping_path)
        if p.suffix.lower() not in (".yaml", ".yml", ".json") or not p.is_file():
            raise MappingError("mapping must be an existing .yaml/.yml/.json file")
        if p.stat().st_size > 256 * 1024:
            raise MappingError("mapping file too large")
        prof = yaml.safe_load(p.read_text("utf-8"))
    elif profile:
        if profile not in BUILTIN_PROFILES:
            raise MappingError(f"unknown profile {profile!r}; built-in: {', '.join(BUILTIN_PROFILES)}")
        prof = BUILTIN_PROFILES[profile]
    else:
        raise MappingError("an explicit mapping profile (--profile) or mapping file (--mapping) is required")
    return validate_profile(prof)


def validate_profile(prof) -> dict:
    if not isinstance(prof, dict) or "time" not in prof or "fields" not in prof:
        raise MappingError("mapping needs 'time' and 'fields'")
    if prof["fields"] != "native":
        if not isinstance(prof["fields"], dict):
            raise MappingError("'fields' must map ARGOS field -> source column")
        for k in prof["fields"]:
            if k not in NATIVE_ALLOWED:
                raise MappingError(f"cannot map unknown ARGOS field {k!r}")
        if any(k.startswith("bytes_") for k in prof["fields"]) and not prof.get("bytes_basis"):
            raise MappingError("mapping of byte counters requires an explicit 'bytes_basis' declaring their direction")
    for k, v in (prof.get("constants") or {}).items():
        if k not in NATIVE_ALLOWED:
            raise MappingError(f"unknown constant field {k!r}")
        if k == "event_kind" and v not in EVENT_KINDS:
            raise MappingError(f"invalid event_kind {v!r}")
        if k == "observation_vantage" and v not in VANTAGES:
            raise MappingError(f"invalid observation_vantage {v!r}")
    return prof


def map_profile(raw: dict, prof: dict) -> tuple[dict, object]:
    if "result" in raw and isinstance(raw["result"], dict):
        raw = raw["result"]
    if prof["fields"] == "native":
        ev, _ = map_native({k: v for k, v in raw.items() if not k.startswith("_") or k == "event_time"})
        return ev, raw.get(prof["time"]) or raw.get("_time")
    ev = empty_event()
    for target, src in prof["fields"].items():
        cands = src if isinstance(src, list) else [src]
        for c in cands:
            if c in raw and raw[c] not in ("", "-", None):
                _coerce(ev, target, raw[c])
                break
    for k, v in (prof.get("constants") or {}).items():
        if ev.get(k) is None:
            ev[k] = v
    if ev["bytes_src_to_dst"] is not None or ev["bytes_dst_to_src"] is not None:
        ev["bytes_basis"] = prof.get("bytes_basis")
    if ev["http_uri"] is None and raw.get("cs_uri_stem"):
        q = raw.get("cs_uri_query")
        ev["http_uri"] = raw["cs_uri_stem"] + (("?" + q) if q and q != "-" else "")
    return ev, raw.get(prof["time"])


# --- Sysmon --------------------------------------------------------------------------
SYSMON_KIND = {"1": "process_start", "3": "network_connection", "11": "file_create", "22": "dns"}


def map_sysmon(raw: dict) -> tuple[dict | None, object, str | None]:
    eid = raw.get("_EventID")
    kind = SYSMON_KIND.get(eid)
    if not kind:
        return None, None, f"unsupported Sysmon EventID {eid!r} (supported: 1, 3, 11, 22)"
    ev = empty_event()
    ev.update(event_kind=kind, observation_vantage="managed_endpoint", source_type="sysmon",
              host=raw.get("_Computer") or None, action=f"sysmon_{eid}")
    g = raw.get
    _coerce(ev, "process_guid", g("ProcessGuid"))
    _coerce(ev, "process_id", g("ProcessId"))
    _coerce(ev, "process_image", g("Image"))
    _coerce(ev, "user", g("User"))
    if kind == "process_start":
        _coerce(ev, "process_command_line", g("CommandLine"))
        _coerce(ev, "parent_process_guid", g("ParentProcessGuid"))
        _coerce(ev, "parent_process_id", g("ParentProcessId"))
        _coerce(ev, "parent_image", g("ParentImage"))
        if g("LogonId") and ev["host"]:
            ev["session_id"] = f"{ev['host']}:logon:{g('LogonId')}"
        ev["outcome"] = "success"
    elif kind == "network_connection":
        _coerce(ev, "src_ip", g("SourceIp"))
        _coerce(ev, "src_port", g("SourcePort"))
        _coerce(ev, "dst_ip", g("DestinationIp"))
        _coerce(ev, "dst_port", g("DestinationPort"))
        _coerce(ev, "protocol", g("Protocol"))
        _coerce(ev, "http_host", g("DestinationHostname"))
        if g("Initiated") == "false":
            ev["quality_warnings"].append("inbound_connection")
    elif kind == "file_create":
        _coerce(ev, "file_path", g("TargetFilename"))
        ev["outcome"] = "success"
    elif kind == "dns":
        _coerce(ev, "dns_query", g("QueryName"))
        _coerce(ev, "dns_rcode", g("QueryStatus"))
    ts = g("UtcTime")
    return ev, ts, None


# --- Zeek ----------------------------------------------------------------------------
def map_zeek(raw: dict, log_type: str | None) -> tuple[dict | None, object, str | None]:
    lt = log_type or ("http" if "method" in raw or "status_code" in raw else
                      "dns" if "query" in raw or "qtype_name" in raw else
                      "conn" if "conn_state" in raw or "proto" in raw else None)
    if lt not in ("conn", "http", "dns"):
        return None, None, "cannot determine Zeek log type (supported: conn, http, dns); pass zeek_log option"
    ev = empty_event()
    ev.update(observation_vantage="victim_network", source_type=f"zeek_{lt}")
    _coerce(ev, "zeek_uid", raw.get("uid"))
    _coerce(ev, "src_ip", raw.get("id.orig_h"))
    _coerce(ev, "src_port", raw.get("id.orig_p"))
    _coerce(ev, "dst_ip", raw.get("id.resp_h"))
    _coerce(ev, "dst_port", raw.get("id.resp_p"))
    if lt == "conn":
        ev["event_kind"] = "network_connection"
        _coerce(ev, "protocol", raw.get("proto"))
        _coerce(ev, "bytes_src_to_dst", raw.get("orig_bytes"))
        _coerce(ev, "bytes_dst_to_src", raw.get("resp_bytes"))
        if ev["bytes_src_to_dst"] is not None or ev["bytes_dst_to_src"] is not None:
            ev["bytes_basis"] = "zeek_conn: orig_bytes=originator->responder payload, resp_bytes=responder->originator payload"
        _coerce(ev, "action", raw.get("conn_state"))
    elif lt == "http":
        ev["event_kind"] = "http"
        _coerce(ev, "http_method", raw.get("method"))
        _coerce(ev, "http_host", raw.get("host"))
        _coerce(ev, "http_uri", raw.get("uri"))
        _coerce(ev, "http_status", raw.get("status_code"))
        _coerce(ev, "http_user_agent", raw.get("user_agent"))
        _coerce(ev, "bytes_src_to_dst", raw.get("request_body_len"))
        _coerce(ev, "bytes_dst_to_src", raw.get("response_body_len"))
        if ev["bytes_src_to_dst"] is not None or ev["bytes_dst_to_src"] is not None:
            ev["bytes_basis"] = "zeek_http: request_body_len=client->server body, response_body_len=server->client body"
    else:
        ev["event_kind"] = "dns"
        _coerce(ev, "dns_query", raw.get("query"))
        _coerce(ev, "dns_rcode", raw.get("rcode_name"))
    return ev, raw.get("ts"), None


# Conservative outcome normalization: only unambiguous words are mapped. Numeric vendor
# result codes (e.g. "0", "50126") are NOT interpreted; map them in a custom profile.
OUTCOME_SYNONYMS = {
    "success": "success", "succeeded": "success", "successful": "success", "ok": "success", "allowed": "success",
    "failure": "failure", "failed": "failure", "fail": "failure", "denied": "failure", "blocked": "failure",
    "unknown": "unknown",
}


# Network-type records without a declared vantage default to victim_network (the
# conservative choice: it grants no endpoint process context and no model-gateway
# visibility). If such a record carries endpoint-only process fields it is ambiguous
# and rejected rather than guessed.
AMBIGUOUS_NETWORK_KINDS = {"http", "dns", "network_connection"}
ENDPOINT_ONLY_FIELDS = ("process_guid", "process_image", "process_id")


def finalize_kind_vantage(ev: dict) -> str | None:
    if ev["event_kind"] not in EVENT_KINDS:
        return f"invalid or missing event_kind {ev['event_kind']!r}"
    if ev["observation_vantage"] is None:
        if ev["event_kind"] in AMBIGUOUS_NETWORK_KINDS and any(ev.get(f) is not None for f in ENDPOINT_ONLY_FIELDS):
            # Could be EDR/Sysmon-style endpoint telemetry or network-sensor data: do not guess.
            return ("ambiguous observation_vantage: network record carries endpoint process fields "
                    "(process_guid/process_image/process_id); set observation_vantage explicitly")
        v = KIND_VANTAGE.get(ev["event_kind"])
        if not v:
            return "missing observation_vantage"
        ev["observation_vantage"] = v
        ev["quality_warnings"].append("vantage_defaulted_from_event_kind" if ev["event_kind"] not in AMBIGUOUS_NETWORK_KINDS
                                      else "vantage_defaulted_conservatively:victim_network")
    if ev["observation_vantage"] not in VANTAGES:
        return f"invalid observation_vantage {ev['observation_vantage']!r}"
    if ev["outcome"] is not None:
        o = str(ev["outcome"]).strip().lower()
        if o in OUTCOME_SYNONYMS:
            if o != OUTCOME_SYNONYMS[o]:
                ev["quality_warnings"].append(f"outcome_normalized:{ev['outcome']}->{OUTCOME_SYNONYMS[o]}")
            ev["outcome"] = OUTCOME_SYNONYMS[o]
        else:
            ev["quality_warnings"].append(f"outcome_unrecognized:{ev['outcome']}")
            ev["outcome"] = "unknown"
    return None
