"""Declarative rule schema (validated) and loader. Rules are data: YAML is read
with yaml.safe_load, validated against this schema, and evaluated by a fixed
set of operators. Rules cannot execute Python or shell commands."""
from __future__ import annotations

import copy
import hashlib
import re
from pathlib import Path
from typing import Any, Literal, Optional, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from argos.models import EVENT_FIELDS, VANTAGES

OPERATORS = {"eq", "ne", "in", "not_in", "contains", "not_contains", "startswith", "endswith", "regex", "gt", "gte", "lt", "lte",
             "exists", "not_exists", "cidr", "not_cidr", "ioc_valid", "ioc_any"}
DERIVED_FIELDS = {"uri_path", "process_name", "parent_name", "file_ext", "dst_is_private", "src_is_private",
                  "http_status_class", "domain", "proc_link", "remote"}
KNOWN_FIELDS = set(EVENT_FIELDS) | DERIVED_FIELDS
FAMILIES = ["automation_burst", "enumeration_adaptation", "auth_sequence", "service_principal_abuse",
            "endpoint_process", "model_tool_linkage", "framework_candidate", "collection_exfil_persistence", "ioc_context"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Predicate(Strict):
    field: str
    op: str
    value: Any = None

    @field_validator("field")
    @classmethod
    def _f(cls, v):
        if v not in KNOWN_FIELDS:
            raise ValueError(f"unknown field {v!r}")
        return v

    @field_validator("op")
    @classmethod
    def _o(cls, v):
        if v not in OPERATORS:
            raise ValueError(f"operator {v!r} not allowed; allowed: {sorted(OPERATORS)}")
        return v

    @model_validator(mode="after")
    def _v(self):
        if self.op == "regex":
            if not isinstance(self.value, str) or len(self.value) > 200:
                raise ValueError("regex must be a string of at most 200 characters")
            re.compile(self.value)
        if self.op in ("in", "not_in", "cidr", "not_cidr") and not isinstance(self.value, list):
            raise ValueError(f"{self.op} requires a list")
        return self


class Cond(Strict):
    all: Optional[list["CondT"]] = None
    any: Optional[list["CondT"]] = None
    not_: Optional["CondT"] = Field(default=None, alias="not")

    @model_validator(mode="after")
    def _one(self):
        if sum(x is not None for x in (self.all, self.any, self.not_)) != 1:
            raise ValueError("condition needs exactly one of all/any/not")
        return self


CondT = Union[Predicate, Cond]
Cond.model_rebuild()


class Step(Strict):
    name: str
    where: CondT
    min_count: int = 1
    min_distinct: Optional[int] = None
    distinct_field: Optional[str] = None
    # Events matching reset_where (in the same group) discard the events collected so far
    # for this step, i.e. the step requires an uninterrupted run (e.g. consecutive failures).
    reset_where: Optional[CondT] = None


class Aggregate(Strict):
    type: Literal["each", "threshold", "sequence", "baseline"]
    min_count: int = 1
    distinct_field: Optional[str] = None
    min_distinct: Optional[int] = None
    ratio_where: Optional[CondT] = None
    min_ratio: Optional[float] = None
    max_median_interarrival_s: Optional[float] = None
    steps: Optional[list[Step]] = None
    history_lookback_s: Optional[int] = None
    min_history_windows: Optional[int] = None
    factor: Optional[float] = None

    @model_validator(mode="after")
    def _chk(self):
        if self.type == "sequence" and not self.steps:
            raise ValueError("sequence aggregate needs steps")
        if self.type == "baseline" and not (self.history_lookback_s and self.min_history_windows and self.factor):
            raise ValueError("baseline aggregate needs history_lookback_s, min_history_windows and factor")
        if (self.distinct_field is None) != (self.min_distinct is None):
            raise ValueError("distinct_field and min_distinct go together")
        return self


class Reference(Strict):
    type: Literal["explicit_threshold", "configured_expected", "observed_history", "not_applicable"]
    description: str


class Threat(Strict):
    activity: str
    suspicion: Literal["informational", "suspicious", "likely_malicious"]


class FrameworkContribution(Strict):
    name: str
    level: Literal["unknown", "consistent_with"]  # rules alone can never corroborate
    fingerprint_ids: list[str] = []
    independence_family: Optional[str] = None  # None = weak (never counts toward corroboration)


class Purpose(Strict):
    observed_action: str
    hypothesis: str
    stage: Literal["indicator", "attempt", "observed_success"] = "indicator"


class Contributes(Strict):
    threat: Threat
    automation: Optional[Literal["consistent_with_automation", "observed_automation", "observed_manual_component"]] = None
    llm: Optional[Literal["possible", "directly_observed"]] = None
    framework: Optional[FrameworkContribution] = None
    purpose: Purpose


class Absence(Strict):
    where: CondT
    within_s: int
    label: str
    vantage: str
    join_fields: Optional[list[str]] = None  # default: all group_by fields


class SourceHistory(Strict):
    """Context check: did `field` (e.g. src_ip) previously satisfy `where` for the same
    join_fields BEFORE the match started? Uses prior events only. A known source caps
    confidence at 'low' (it does not suppress the alert)."""
    field: str
    where: CondT
    join_fields: list[str]
    lookback_s: int = 2592000


class Fingerprint(Strict):
    id: str
    url: str
    commit: str
    file: str
    location: str
    observed_pattern: str
    required_vantage: str
    required_telemetry: list[str]
    covered_versions: str
    spoofability: str
    benign_overlap: str
    validation_status: str


class Rule(Strict):
    id: str
    version: int
    title: str
    description: str
    family: str
    status: Literal["experimental", "test", "stable"]
    validation_status: str
    observation_vantage: list[str]
    required_telemetry: list[str]
    select: CondT
    group_by: list[str] = []
    window_s: int
    aggregate: Aggregate
    reference: Reference
    severity: Literal["informational", "low", "medium", "high", "critical"]
    base_confidence: Literal["low", "medium", "high"]
    contributes: Contributes
    evidence_family: str
    required_evidence: str
    explanation: str
    alternatives: list[str]
    false_positives: list[str]
    missing_visibility_hints: list[str] = []
    resolving_data: list[str] = []
    sources: list[str]
    suppressible_by_registry: bool = False
    absence_check: Optional[Absence] = None
    source_history: Optional[SourceHistory] = None
    fingerprint: Optional[Fingerprint] = None
    recommendation: Optional[str] = None

    @field_validator("family")
    @classmethod
    def _fam(cls, v):
        if v not in FAMILIES:
            raise ValueError(f"family must be one of {FAMILIES}")
        return v

    @field_validator("observation_vantage")
    @classmethod
    def _van(cls, v):
        for x in v:
            if x not in VANTAGES:
                raise ValueError(f"unknown vantage {x!r}")
        return v

    @field_validator("required_telemetry", "group_by")
    @classmethod
    def _flds(cls, v):
        for x in v:
            if x not in KNOWN_FIELDS:
                raise ValueError(f"unknown field {x!r}")
        return v

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not re.fullmatch(r"ARG-[A-Z0-9]+-[A-Z0-9]+", v):
            raise ValueError("rule id must look like ARG-FAMILY-NNN")
        return v


class RuleError(ValueError):
    pass


def _apply_override(doc: dict, dotted: str, value):
    cur = doc
    parts = dotted.split(".")
    for p in parts[:-1]:
        if p.isdigit():
            cur = cur[int(p)]
        else:
            cur = cur.setdefault(p, {})
    last = parts[-1]
    if last.isdigit():
        cur[int(last)] = value
    else:
        cur[last] = value


def load_rules(rules_dir: Path, overrides_path: Path | None = None) -> tuple[list[Rule], str, list[str]]:
    """Return (rules, rules_hash, errors). Invalid rules are reported, never half-loaded."""
    h = hashlib.sha256()
    overrides = {}
    if overrides_path and overrides_path.is_file():
        raw = overrides_path.read_text("utf-8")
        h.update(b"overrides:" + raw.encode())
        overrides = yaml.safe_load(raw) or {}
        if not isinstance(overrides, dict):
            raise RuleError("overrides file must be a mapping rule_id -> {dotted.path: value}")
    rules, errors, seen = [], [], set()
    for p in sorted((rules_dir / "detections").glob("*.yaml")):
        text = p.read_text("utf-8")
        h.update(p.name.encode() + b"\0" + text.encode())
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            errors.append(f"{p.name}: YAML error {exc}")
            continue
        for doc in docs:
            if doc is None:
                continue
            try:
                doc = copy.deepcopy(doc)
                for k, v in (overrides.get(doc.get("id")) or {}).items():
                    _apply_override(doc, k, v)
                r = Rule.model_validate(doc)
                if r.id in seen:
                    raise ValueError(f"duplicate rule id {r.id}")
                seen.add(r.id)
                rules.append(r)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{p.name}:{doc.get('id') if isinstance(doc, dict) else '?'}: {exc}")
    return rules, h.hexdigest()[:16], errors
