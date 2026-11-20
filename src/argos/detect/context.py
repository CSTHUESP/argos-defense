"""Analysis context data: authorized-automation registry and IOC sets."""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from argos.normalize.timeutil import TimestampError, parse_timestamp

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


class RegistryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    description: str
    owner: str  # descriptive only; not an identity assertion
    match: dict[str, list[str]]
    scope: dict[str, list[str]]
    schedule: dict | None = None
    expires: str


class Registry:
    """Authorized automation. An entry only covers alerts whose *every* evidence
    event matches the entry, its scope and schedule, before expiry."""

    MATCH_FIELDS = {"src_ip", "host", "user", "app_id", "process_name"}

    def __init__(self, entries: list[RegistryEntry], digest: str):
        self.entries = entries
        self.digest = digest
        self._exp = {}
        for e in entries:
            bad = set(e.match) - self.MATCH_FIELDS
            if bad:
                raise ValueError(f"registry {e.id}: unsupported match fields {bad}")
            if not set(e.scope) <= {"event_kinds", "rule_families"}:
                raise ValueError(f"registry {e.id}: scope supports event_kinds, rule_families")
            self._exp[e.id] = parse_timestamp(e.expires)[0].timestamp()

    @classmethod
    def load(cls, path: Path) -> "Registry":
        if not path.is_file():
            return cls([], "none")
        text = path.read_text("utf-8")
        data = yaml.safe_load(text) or []
        return cls([RegistryEntry.model_validate(d) for d in data], hashlib.sha256(text.encode()).hexdigest()[:16])

    def _match_event(self, e: RegistryEntry, ev: dict) -> bool:
        if ev["event_epoch"] >= self._exp[e.id]:
            return False
        if ev.get("event_kind") not in e.scope.get("event_kinds", [ev.get("event_kind")]):
            return False
        ok = False
        for f, vals in e.match.items():
            v = ev.get(f)
            if v is None:
                continue
            if f == "src_ip":
                try:
                    a = ipaddress.ip_address(v)
                    if any(a in ipaddress.ip_network(c, strict=False) for c in vals):
                        ok = True
                except ValueError:
                    pass
            elif str(v).lower() in {x.lower() for x in vals}:
                ok = True
        if not ok:
            return False
        if e.schedule:
            dt = datetime.fromtimestamp(ev["event_epoch"], tz=timezone.utc)
            days = e.schedule.get("days")
            if days and DAYS[dt.weekday()] not in days:
                return False
            hrs = e.schedule.get("hours_utc")
            if hrs and not (hrs[0] <= dt.hour < hrs[1]):
                return False
        return True

    def evaluate(self, family: str, events: list[dict]) -> dict | None:
        best = None
        for e in self.entries:
            if family not in e.scope.get("rule_families", []):
                continue
            n = sum(1 for ev in events if self._match_event(e, ev))
            res = {"entry_id": e.id, "description": e.description, "owner": e.owner, "expires": e.expires,
                   "matched_events": n, "total_events": len(events), "covers_all": n == len(events)}
            if n and (best is None or n > best["matched_events"]):
                best = res
        return best


class IOCSet:
    def __init__(self, items: list[dict], digest: str):
        self.items = {}
        self.digest = digest
        for it in items:
            for k in ("value", "type", "source", "observed_date", "valid_from", "valid_until", "context"):
                if k not in it:
                    raise ValueError(f"IOC missing {k}: {it}")
            try:
                it["_from"] = parse_timestamp(str(it["valid_from"]))[0].timestamp()
                it["_until"] = parse_timestamp(str(it["valid_until"]))[0].timestamp()
            except TimestampError as exc:
                raise ValueError(f"IOC {it['value']}: {exc}") from exc
            self.items.setdefault(str(it["value"]).lower(), []).append(it)

    @classmethod
    def load(cls, d: Path) -> "IOCSet":
        items, h = [], hashlib.sha256()
        for p in sorted(d.glob("*.yaml")) if d.is_dir() else []:
            text = p.read_text("utf-8")
            h.update(p.name.encode() + text.encode())
            doc = yaml.safe_load(text) or {}
            if doc.get("enabled", True):
                items += doc.get("iocs", [])
        return cls(items, h.hexdigest()[:16])

    def lookup(self, value: str, epoch: float) -> list[dict]:
        out = []
        for it in self.items.get(value.lower(), []):
            valid = it["_from"] <= epoch < it["_until"]
            out.append({"value": it["value"], "type": it["type"], "source": it["source"], "observed_date": str(it["observed_date"]),
                        "valid_from": str(it["valid_from"]), "valid_until": str(it["valid_until"]), "context": it["context"],
                        "valid_at_event_time": valid, "cutoff_used": "event_time"})
        return out
