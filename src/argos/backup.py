"""Backup and restore of an ARGOS data directory.

A backup is a single zip containing:
  manifest.json            - format, versions, per-file SHA-256 and sizes, table row counts
  db/argos.sqlite3         - consistent SQLite snapshot made with the sqlite3 backup API (includes committed WAL data)
  cases/<case>/originals/  - retained original evidence bytes
  config/*.yaml            - local configuration (rule overrides, registry, IOCs)

Restore only targets an empty (or not yet existing) data directory, verifies every hash before
writing anything, rejects unsafe member names and checks SQLite integrity and row counts.
Backups contain sensitive investigation data and are written owner-private.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from argos import __version__
from argos.config import Settings, make_private_dir
from argos.normalize.timeutil import now_iso
from argos.store import SCHEMA_VERSION, Store, consistent_backup, table_counts

BACKUP_FORMAT = "argos-backup/1"
MAX_MEMBER = 4 << 30


class BackupError(Exception):
    pass


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def create_backup(settings: Settings, output: Path | None = None) -> dict:
    settings.ensure()
    output = Path(output) if output else settings.backups_dir / f"argos-backup-{now_iso().replace(':', '').replace('.', '')}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="argos-bk-") as td:
        os.chmod(td, 0o700)
        snap = Path(td) / "argos.sqlite3"
        st = Store(settings.db_path)
        try:
            res = st.backup_to(snap)
        finally:
            st.close()
        files = [("db/argos.sqlite3", snap)]
        if settings.cases_dir.is_dir():
            for p in sorted(settings.cases_dir.rglob("*")):
                if p.is_file() and not p.is_symlink() and "originals" in p.relative_to(settings.cases_dir).parts:
                    files.append(("cases/" + p.relative_to(settings.cases_dir).as_posix(), p))
        if settings.config_dir.is_dir():
            for p in sorted(settings.config_dir.glob("*.yaml")):
                files.append(("config/" + p.name, p))
        manifest = {"format": BACKUP_FORMAT, "created_at": now_iso(), "argos_version": __version__, "schema_version": SCHEMA_VERSION,
                    "table_counts": res["counts"], "files": [{"name": n, "sha256": _sha(p), "size": p.stat().st_size} for n, p in files]}
        tmp = output.with_name(output.name + ".partial")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as raw, zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
            for n, p in files:
                z.write(p, n)
        os.replace(tmp, output)
        os.chmod(output, 0o600)
    return {"backup": str(output), "files": len(files), "table_counts": res["counts"], "sha256": _sha(output)}


def _safe_name(name: str) -> PurePosixPath:
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name or not p.parts:
        raise BackupError(f"unsafe member name in backup: {name!r}")
    if p.parts[0] not in ("db", "cases", "config", "manifest.json"):
        raise BackupError(f"unexpected member in backup: {name!r}")
    return p


def verify_backup(path: Path) -> dict:
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            raise BackupError("duplicate member names")
        for n in names:
            _safe_name(n)
        try:
            manifest = json.loads(z.read("manifest.json"))
        except KeyError as exc:
            raise BackupError("manifest.json missing") from exc
        if manifest.get("format") != BACKUP_FORMAT:
            raise BackupError(f"unsupported backup format {manifest.get('format')!r}")
        listed = {f["name"]: f for f in manifest["files"]}
        if set(listed) != set(names) - {"manifest.json"}:
            raise BackupError("backup members do not match the manifest")
        for n, f in listed.items():
            info = z.getinfo(n)
            if info.file_size != f["size"] or info.file_size > MAX_MEMBER:
                raise BackupError(f"size mismatch for {n}")
            h = hashlib.sha256()
            with z.open(n) as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != f["sha256"]:
                raise BackupError(f"hash mismatch for {n}")
        if "db/argos.sqlite3" not in listed:
            raise BackupError("database snapshot missing")
    return manifest


def restore_backup(path: Path, settings: Settings) -> dict:
    manifest = verify_backup(path)
    home = settings.home
    if home.exists() and any(home.iterdir()):
        raise BackupError(f"restore target {home} is not empty; restore into a new data directory")
    make_private_dir(home)
    staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=home))
    try:
        with zipfile.ZipFile(path) as z:
            for f in manifest["files"]:
                rel = _safe_name(f["name"])
                dest = staging.joinpath(*rel.parts)
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as out, z.open(f["name"]) as src:
                    shutil.copyfileobj(src, out)
        db = staging / "db" / "argos.sqlite3"
        conn = sqlite3.connect(db)
        try:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("restored database failed integrity_check")
            counts = table_counts(conn)
        finally:
            conn.close()
        if counts != manifest["table_counts"]:
            raise BackupError(f"row counts differ after restore: {counts} vs {manifest['table_counts']}")
        os.replace(db, settings.db_path)
        for sub in ("cases", "config"):
            if (staging / sub).is_dir():
                os.replace(staging / sub, home / sub)
        for p in [home / "cases", home / "config"]:
            if p.is_dir():
                for q in p.rglob("*"):
                    os.chmod(q, 0o700 if q.is_dir() else (0o400 if "originals" in q.parts else 0o600))
                os.chmod(p, 0o700)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    settings.ensure()
    st = Store(settings.db_path)  # migrates older snapshots with its own pre-migration backup
    try:
        rebased = st.rebase_originals(settings.cases_dir)
        final = table_counts(st.conn)
        schema = st.schema_version()
    finally:
        st.close()
    return {"restored_to": str(home), "schema_version": schema, "originals_rebased": rebased, "table_counts": final, "backup_created_at": manifest["created_at"]}


__all__ = ["create_backup", "verify_backup", "restore_backup", "BackupError", "consistent_backup"]
