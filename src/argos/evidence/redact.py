"""Secret redaction for display, API responses, exports, logs and optional LLM input.

Default policy (v0.3): every value shown or exported is redacted. Originals stay unmodified in the
owner-private original store; an authenticated analyst can request an explicitly labelled raw view
of a single record (`?raw=1` on the event page/API). Redaction is pattern- and key-based and cannot
detect every secret format (see docs/THREAT_MODEL.md).
"""
from __future__ import annotations

import json
import re

MASK = "[REDACTED]"
SECRET_KEY_RE = re.compile(
    r"(?i)^(?:[a-z0-9_.-]*?[_.-])?(password|passwd|passphrase|pwd|pass|secret|client[_-]?secret|token|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|session[_-]?token|auth|authorization|api[_-]?key|apikey|x[_-]?api[_-]?key|private[_-]?key|"
    r"access[_-]?key|secret[_-]?key|cookie|set[_-]?cookie|credential|credentials|sas|sig|signature|connection[_-]?string)$")
_KEYS = (r"password|passwd|passphrase|pwd|pass|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
         r"session[_-]?token|api[_-]?key|apikey|x[_-]?api[_-]?key|private[_-]?key|access[_-]?key|secret[_-]?key|credential|sig|signature|sas")

PATTERNS = [
    # JSON / dict-like quoted pairs: "password": "x", 'api_key': 'x'  (inside larger strings)
    (re.compile(r"""(?i)(["'](?:[\w.-]*[_.-])?(?:""" + _KEYS + r"""|authorization|cookie)["']\s*:\s*)(["'])(?:\\.|(?!\2).)*\2"""), r"\1\2" + MASK + r"\2"),
    # header lines, quoted or not: Authorization: Bearer x / Authorization: "Basic x" / Cookie: a=b
    (re.compile(r"""(?i)\b(authorization|proxy-authorization)(\s*[:=]\s*["']?)(?:bearer|basic|negotiate|ntlm|digest|token)?\s*[^\s"',;]+(?:[^\n"']*)"""), r"\1\2" + MASK),
    (re.compile(r"""(?i)\b(cookie|set-cookie)(\s*:\s*)[^\n"']+"""), r"\1\2" + MASK),
    # key=value / key: value (env, query strings, config, command lines)
    (re.compile(r"""(?i)(\b(?:[\w.-]*[_.-])?(?:""" + _KEYS + r""")\b)(\s*[=:]\s*)(["']?)[^\s&"',;}]+\3"""), r"\1\2\3" + MASK + r"\3"),
    # URL userinfo: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@"), r"\1" + MASK + "@"),
    # command-line flags: --password x, --token=x, -p 'x' (mysql style), /p:x (net use style)
    (re.compile(r"""(?i)(--(?:password|passwd|pass|token|secret|api-key|apikey|client-secret)(?:=|\s+))(["']?)[^\s"']+\2"""), r"\1\2" + MASK + r"\2"),
    (re.compile(r"""(?i)((?:^|\s)-p\s*)(["'])[^"']*\2"""), r"\1\2" + MASK + r"\2"),
    (re.compile(r"""(?i)((?:^|\s)/(?:p|password|pass):)\S+"""), r"\1" + MASK),
    # well-known token shapes
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "sk-" + MASK),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AKIA" + MASK),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "gh_" + MASK),
    (re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"), "xox-" + MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def redact(value):
    if not isinstance(value, str):
        return value
    s = value
    # strings that are themselves JSON objects/arrays: redact structurally, then re-serialize
    st = s.strip()
    if len(st) < 1_000_000 and st[:1] in "{[" and st[-1:] in "}]":
        try:
            obj = json.loads(st)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, (dict, list)):
            s = json.dumps(redact_obj(obj), ensure_ascii=False)
    for rx, rep in PATTERNS:
        s = rx.sub(rep, s)
    return s


def _mask_all(v):
    """Everything below a sensitive key is secret material: keep the structure (keys, list length,
    null/boolean markers) so the analyst can see what was present, but mask every value."""
    if isinstance(v, dict):
        return {k: _mask_all(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_mask_all(x) for x in v]
    if v is None or isinstance(v, bool):
        return v
    return MASK


def is_secret_key(k) -> bool:
    return isinstance(k, str) and bool(SECRET_KEY_RE.match(k.strip()))


def redact_obj(obj, _key: str | None = None):
    """Default output policy (v0.3.1): a sensitive key masks its whole value, including list items and
    nested objects (R01); other values are redacted by pattern, recursively."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = _mask_all(v) if is_secret_key(k) else redact_obj(v, k)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, _key) for v in obj]
    return redact(obj)


FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Neutralize spreadsheet formulas (CSV injection)."""
    s = "" if value is None else str(value)
    if s.startswith(FORMULA_PREFIX):
        return "'" + s
    return s
