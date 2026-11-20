"""ARGOS Defense - local defensive investigation of supplied telemetry.

ARGOS analyses telemetry files supplied by an analyst. It is not a real-time
sensor, an EDR agent or a live product integration.
"""

__version__ = "0.3.0"
ENGINE_VERSION = "argos-engine/0.3.0"
SCHEMA_VERSION = "argos-event/2"  # /2 adds tool_call_id, tool_name, source_locator, revision

# Parser versions are recorded on every imported input and every analysis run.
PARSER_VERSIONS = {
    "native_jsonl": "native_jsonl/1.0",
    "splunk_json": "splunk_json/1.0",
    "splunk_csv": "splunk_csv/1.0",
    "sysmon_xml": "sysmon_xml/1.0",
    "zeek_jsonl": "zeek_jsonl/1.0",
}
