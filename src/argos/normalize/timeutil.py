"""Timestamp validation. Ambiguous (zone-less) timestamps are never silently
assumed to be UTC: the import must state an explicit `assume_tz` option."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo


class TimestampError(ValueError):
    pass


_EPOCH_RE = re.compile(r"^\d{9,13}(\.\d+)?$")


def _tz(name: str):
    if name.upper() in ("UTC", "Z"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", name)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    try:
        return ZoneInfo(name)
    except Exception as exc:  # noqa: BLE001
        raise TimestampError(f"unknown time zone option {name!r}") from exc


def parse_timestamp(value, assume_tz: str | None = None) -> tuple[datetime, str | None]:
    """Return (aware UTC datetime, note). Raises TimestampError.

    note is set when an import option was needed (e.g. assumed zone).
    """
    if value is None or value == "":
        raise TimestampError("missing timestamp")
    if isinstance(value, (int, float)) or (isinstance(value, str) and _EPOCH_RE.match(value.strip())):
        f = float(value)
        if f > 1e12:  # milliseconds
            f /= 1000.0
        if not (0 < f < 4102444800):
            raise TimestampError(f"epoch out of range: {value!r}")
        return datetime.fromtimestamp(f, tz=timezone.utc), "epoch_seconds_utc"
    if not isinstance(value, str):
        raise TimestampError(f"unsupported timestamp type {type(value).__name__}")
    s = value.strip()
    s2 = s.replace("Z", "+00:00") if s.endswith("Z") else s
    # Sysmon UtcTime: '2026-11-03 10:00:01.123' (documented UTC by the field name)
    try:
        dt = datetime.fromisoformat(s2)
    except ValueError:
        dt = None
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S %z", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            raise TimestampError(f"unparseable timestamp {value!r}")
    note = None
    if dt.tzinfo is None:
        if not assume_tz:
            raise TimestampError(f"ambiguous timestamp without zone {value!r}; re-import with an explicit assume_tz option")
        dt = dt.replace(tzinfo=_tz(assume_tz))
        note = f"zone_assumed:{assume_tz}"
    return dt.astimezone(timezone.utc), note


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_iso() -> str:
    return iso(datetime.now(timezone.utc))
