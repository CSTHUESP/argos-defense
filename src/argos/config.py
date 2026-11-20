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


def _windows_private_acl(path: Path) -> bool:
    """Replace inherited ACEs with: current user, SYSTEM, Administrators (full control, inherited by children).
    Uses the built-in icacls tool; returns False if it could not be applied."""
    import subprocess
    user = os.environ.get("USERNAME")
    if not user:
        return False
    dom = os.environ.get("USERDOMAIN")
    principal = f"{dom}\\{user}" if dom else user
    cmd = ["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30)  # bytes: icacls prints in the OEM code page
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _decode_console(b: bytes) -> str:
    """Decode output of Windows console tools (OEM code page); never raises."""
    for enc in ("oem", "utf-8"):
        try:
            return b.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return b.decode("latin-1", "replace")


def make_private_dir(d: Path) -> bool:
    """Create d if needed. Only directories created here get private permissions."""
    d = Path(d)
    if d.exists():
        return False
    d.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(d, 0o700)
    elif sys.platform.startswith("win"):
        _windows_private_acl(d)
    return True


def permission_findings(home: Path) -> list[str]:
    """Report (do not fix) data locations readable by other local accounts."""
    out = []
    home = Path(home)
    if not home.exists():
        return out
    if os.name == "posix":
        import stat as _st
        for p in [home] + [home / n for n in ("cases", "reports", "logs", "backups", "config", "argos.sqlite3", ".session_token")]:
            if p.exists():
                m = _st.S_IMODE(p.stat().st_mode)
                if m & 0o077:
                    out.append(f"{p} is accessible by group/other (mode {oct(m)}); remediation: chmod {'700' if p.is_dir() else '600'} '{p}'")
    elif sys.platform.startswith("win"):
        import subprocess
        try:
            r = subprocess.run(["icacls", str(home)], capture_output=True, timeout=30)
            text = _decode_console(r.stdout or b"")
            broad = [ln.strip() for ln in text.splitlines() if any(x in ln for x in ("Everyone:", "BUILTIN\\Users:", "Authenticated Users:"))]
            if broad:
                out.append(f"{home} grants access to broad groups ({'; '.join(broad)[:200]}); remediation: "
                           f"icacls \"{home}\" /inheritance:r /grant:r \"%USERDOMAIN%\\%USERNAME%:(OI)(CI)F\" *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F")
        except (OSError, subprocess.SubprocessError) as exc:
            out.append(f"could not inspect ACL of {home}: {exc}")
    return out


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
    # Analysis holds a case's active events in memory (measured: ~0.85 GiB peak RSS at 100,000 events;
    # 1,000,000 events exceeded a 7 GiB machine). Larger cases are refused with a clear error.
    max_analysis_events: int = int(os.environ.get("ARGOS_MAX_ANALYSIS_EVENTS", 300_000))
    # Global admission control for background analyses in the (single) server process (R08).
    max_concurrent_jobs: int = int(os.environ.get("ARGOS_MAX_CONCURRENT_JOBS", 1))
    max_queued_jobs: int = int(os.environ.get("ARGOS_MAX_QUEUED_JOBS", 8))
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

    @property
    def backups_dir(self) -> Path:
        return self.home / "backups"

    def ensure(self) -> None:
        """Create the data layout. Directories ARGOS creates are owner-private; existing directories chosen
        by the user are not recursively re-permissioned (see `doctor` for warnings)."""
        self.home = Path(self.home).expanduser().resolve()
        for d in (self.home, self.cases_dir, self.reports_dir, self.logs_dir, self.backups_dir):
            make_private_dir(d)
        if self.config_dir_override is None:
            # First run: copy editable defaults; never overwrite the user's edits.
            make_private_dir(self.config_dir)
            for src in default_config_dir().glob("*.yaml"):
                dst = self.config_dir / src.name
                if not dst.exists():
                    shutil.copyfile(src, dst)
                    if os.name == "posix":
                        os.chmod(dst, 0o600)

    def analysis_config(self) -> dict:
        """The subset of configuration that influences analysis results."""
        return {"max_events_per_case": self.max_events_per_case}

    def config_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.analysis_config(), sort_keys=True).encode()).hexdigest()[:16]

    def public_dict(self) -> dict:
        d = asdict(self)
        d["config_dir"] = str(self.config_dir)
        return {k: str(v) for k, v in d.items()}
