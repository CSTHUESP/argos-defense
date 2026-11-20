"""Normalized event schema and assessment vocabularies.

The six assessment dimensions (threat, automation, LLM involvement, framework,
purpose, entities) are kept as separate vocabularies on purpose: none of them
is derived from another.
"""
from __future__ import annotations

from enum import Enum

from argos import SCHEMA_VERSION


class Vantage(str, Enum):
    victim_network = "victim_network"
    managed_endpoint = "managed_endpoint"
    identity_cloud = "identity_cloud"
    agent_or_model_audit = "agent_or_model_audit"


VANTAGES = [v.value for v in Vantage]

EVENT_KINDS = [
    "http", "dns", "network_connection", "process_start", "file_create",
    "authentication", "cloud_operation", "model_interaction", "tool_execution",
    "human_approval", "other",
]

# Default vantage implied by an event kind (used only when an adapter does not set one).
KIND_VANTAGE = {
    "http": "victim_network", "dns": "victim_network", "network_connection": "victim_network",
    "process_start": "managed_endpoint", "file_create": "managed_endpoint",
    "authentication": "identity_cloud", "cloud_operation": "identity_cloud",
    "model_interaction": "agent_or_model_audit", "tool_execution": "agent_or_model_audit",
    "human_approval": "agent_or_model_audit",
}

OUTCOMES = ["success", "failure", "unknown", None]


class Automation(str, Enum):
    unknown = "unknown"
    consistent = "consistent_with_automation"
    observed = "observed_automation"
    manual_component = "observed_manual_component"
    mixed = "mixed"


class LLMInvolvement(str, Enum):
    unknown = "unknown"
    possible = "possible"
    observed = "directly_observed"


class FrameworkLevel(str, Enum):
    unknown = "unknown"
    consistent = "consistent_with"
    presence = "corroborated_presence"
    execution = "corroborated_execution"


class Confidence(str, Enum):
    insufficient = "insufficient_evidence"
    low = "low"
    medium = "medium"
    high = "high"


CONF_ORDER = ["insufficient_evidence", "low", "medium", "high"]
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
AUTOMATION_ORDER = ["unknown", "consistent_with_automation", "observed_automation"]
LLM_ORDER = ["unknown", "possible", "directly_observed"]
FRAMEWORK_ORDER = ["unknown", "consistent_with", "corroborated_presence", "corroborated_execution"]

PURPOSES = [
    "reconnaissance", "credential_access", "initial_access", "execution", "persistence",
    "privilege_escalation", "lateral_movement", "collection", "possible_exfiltration",
    "command_and_control", "unknown",
]

PROVENANCE_LEVELS = ["unverified", "analyst_attested"]

# Every normalized event has exactly these keys. Missing values are None, never invented.
EVENT_FIELDS = [
    "schema_version", "event_id", "case_id", "input_id", "record_no", "event_time", "event_epoch",
    "original_timestamp", "timestamp_note", "ingested_at", "source_type", "source_format",
    "observation_vantage", "event_kind", "action", "outcome",
    "tenant_id", "host", "user", "account_type", "app_id",
    "process_guid", "process_id", "process_image", "process_command_line",
    "parent_process_guid", "parent_process_id", "parent_image",
    "session_id", "correlation_id",
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "http_method", "http_host", "http_uri", "http_status", "http_user_agent",
    "dns_query", "dns_rcode",
    "resource", "resource_type", "file_path",
    "bytes_src_to_dst", "bytes_dst_to_src", "bytes_basis",
    "model_provider", "model_name_declared", "model_tool_name", "model_tool_input",
    "linked_process_guid", "tool_call_id", "tool_name", "message",
    "quality_warnings", "evidence_ref", "zeek_uid", "source_locator", "revision",
]

INT_FIELDS = {"src_port", "dst_port", "http_status", "bytes_src_to_dst", "bytes_dst_to_src", "process_id", "parent_process_id"}


def empty_event() -> dict:
    ev = {k: None for k in EVENT_FIELDS}
    ev["schema_version"] = SCHEMA_VERSION
    ev["quality_warnings"] = []
    return ev
