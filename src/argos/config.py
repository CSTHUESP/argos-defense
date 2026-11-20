"""Runtime configuration.

Mutable data (database, retained originals, user config, reports, token) lives in a
user-writable data directory - never inside the installed package or a PyInstaller
bundle. Resolution order: --data-dir / --home option > ARGOS_HOME > platform default.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from argos.resources import default_config_dir, rules_dir as _rules_dir

APP_NAME = "ARGOS Defense"


def platform_data_dir() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "argos-defense"


def default_home() -> Path:
    env = os.environ.get("ARGOS_HOME")
    return Path(env).expanduser().resolve() if env else platform_data_dir()


@dataclass
class Settings:
    home: Path = field(default_factory=default_home)
    rules_dir: Path = field(default_factory=_rules_dir)
    config_dir_override: Path | None = field(default_factory=lambda: Path(os.environ["ARGOS_CONFIG"]) if os.environ.get("ARGOS_CONFIG") else None)
    max_file_bytes: int = int(os.environ.get("ARGOS_MAX_FILE_BYTES", 200 * 1024 * 1024))
    max_record_bytes: int = 1024 * 1024
    max_events_per_case: int = int(os.environ.get("ARGOS_MAX_EVENTS", 2_000_000))
    chunk_size: int = 1000
    host: str = "127.0.0.1"
    port: int = 8789
    # Optional LLM layer: disabled unless explicitly configured.
    llm_provider: str = os.environ.get("ARGOS_LLM_PROVIDER", "disabled")
    llm_base_url: str = os.environ.get("ARGOS_LLM_BASE_URL", "http://127.0.0.1:11434")
    llm_model: str = os.environ.get("ARGOS_LLM_MODEL", "")
    llm_allow_remote: bool = os.environ.get("ARGOS_LLM_ALLOW_REMOTE", "0") == "1"
    llm_timeout_s: float = float(os.environ.get("ARGOS_LLM_TIMEOUT", "30"))

    @property
    def config_dir(self) -> Path:
        return self.config_dir_override or (self.home / "config")

    @config_dir.setter
    def config_dir(self, value: Path):
        self.config_dir_override = Path(value)

    @property
    def db_path(self) -> Path:
        return self.home / "argos.sqlite3"

    @property
    def cases_dir(self) -> Path:
        return self.home / "cases"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    @property
    def logs_dir(self) -> Path:
        return self.home / "logs"

    def ensure(self) -> None:
        self.home = Path(self.home).expanduser().resolve()
        for d in (self.home, self.cases_dir, self.reports_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)
        if self.config_dir_override is None:
            # First run: copy editable defaults; never overwrite the user's edits.
            self.config_dir.mkdir(parents=True, exist_ok=True)
            for src in default_config_dir().glob("*.yaml"):
                dst = self.config_dir / src.name
                if not dst.exists():
                    shutil.copyfile(src, dst)

    def analysis_config(self) -> dict:
        """The subset of configuration that influences analysis results."""
        return {"max_events_per_case": self.max_events_per_case}

    def config_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.analysis_config(), sort_keys=True).encode()).hexdigest()[:16]

    def public_dict(self) -> dict:
        d = asdict(self)
        d["config_dir"] = str(self.config_dir)
        return {k: str(v) for k, v in d.items()}
