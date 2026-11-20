"""Secret redaction for display and export (originals are kept unmodified on disk)."""
from __future__ import annotations

import re

PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|client[_-]?secret)(\s*[=:]\s*)([^\s&\"',;]+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "sk-[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(-p\s*|--password[= ])('[^']*'|\"[^\"]*\"|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://([^:/\s]+):([^@\s]+)@"), r"\1://\2:[REDACTED]@"),
]


def redact(value):
    if not isinstance(value, str):
        return value
    for rx, rep in PATTERNS:
        value = rx.sub(rep, value)
    return value


def redact_obj(obj):
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    return redact(obj)


FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Neutralize spreadsheet formulas (CSV injection)."""
    s = "" if value is None else str(value)
    if s.startswith(FORMULA_PREFIX):
        return "'" + s
    return s
