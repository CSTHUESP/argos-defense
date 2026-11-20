import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from argos.analysis import run_analysis  # noqa: E402
from argos.config import Settings  # noqa: E402
from argos.ingest.pipeline import ingest_file  # noqa: E402
from argos.store import Store  # noqa: E402
from argos.resources import default_config_dir, rules_dir  # noqa: E402

RULES = rules_dir()

T = "2026-11-03T"


class Env:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.settings = Settings()
        self.settings.home = tmp / "home"
        self.settings.rules_dir = RULES
        # private copy: tests must never modify the packaged default configuration
        cfg = tmp / "config"
        cfg.mkdir(parents=True, exist_ok=True)
        for src in default_config_dir().glob("*.yaml"):
            (cfg / src.name).write_bytes(src.read_bytes())
        self.settings.config_dir = cfg
        self.settings.ensure()
        self.store = Store(self.settings.db_path)
        self._n = 0

    def write(self, name: str, rows) -> Path:
        p = self.tmp / name
        if isinstance(rows, str):
            p.write_text(rows, encoding="utf-8")
        else:
            with open(p, "w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r) + "\n")
        return p

    def case(self, name: str, synthetic: bool = True):
        return self.store.create_case(name, synthetic)

    def ingest(self, case, rows_or_path, fmt="native_jsonl", options=None, name=None, coverage=None):
        if isinstance(rows_or_path, Path):
            p = rows_or_path
        else:
            self._n += 1
            p = self.write(name or f"in{self._n}.jsonl", rows_or_path)
        return ingest_file(self.store, self.settings, case, p, fmt, options or {}, coverage=coverage)

    def analyze(self, case):
        return run_analysis(self.store, self.settings, case["case_id"])

    def alerts(self, case, rule=None):
        out = self.store.list_alerts(case["case_id"])
        return [a for a in out if rule is None or a["rule_id"] == rule]

    def assessment(self, case):
        return self.store.latest_assessment(case["case_id"])

    def run(self, name, rows, synthetic=True, fmt="native_jsonl", options=None, coverage=None):
        c = self.case(name, synthetic)
        self.ingest(c, rows, fmt, options, coverage=coverage)
        self.analyze(c)
        return c


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.store.close()


def ev(sec, **kw):
    """Native event at T0+sec seconds."""
    from argos.synthetic import ts
    d = {"event_time": ts(sec)}
    d.update(kw)
    return d
