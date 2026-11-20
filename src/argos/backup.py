"""Backup and restore of an ARGOS data directory.

A backup is a single zip containing:
  manifest.json            - format, versions, per-file SHA-256 and sizes, table row counts,
                             database-consistency and evidence-completeness results
  db/argos.sqlite3         - consistent SQLite snapshot made with the sqlite3 online backup API
  cases/<case>/originals/  - retained original evidence referenced by that snapshot
  config/*.yaml            - local configuration (rule overrides, registry, IOCs)

Two results are reported separately (R02):
- database consistency: SQLite integrity_check and row counts of the snapshot;
- evidence completeness: the expected inventory of retained originals is derived from the
  `inputs` table of the SNAPSHOT (not from the live directory and not from the archive's own
  manifest); every expected original must be present and hash to the SHA-256 recorded at import.

Concurrency: the snapshot is taken first; only originals referenced by the snapshot are archived.
Originals are immutable (written once under a content-addressed name, mode 0400), so an import that
commits after the snapshot is simply not part of this backup.

A missing or altered original makes a normal backup fail. `allow_incomplete=True` produces an
explicitly INCOMPLETE backup (file name contains .INCOMPLETE) that lists the missing evidence and can
never verify as complete. ARGOS has no retention-exclusion feature, so every referenced original is
expected.

Restore only targets an empty (or not yet existing) data directory, verifies every hash before
writing anything, rejects unsafe member names and links, checks SQLite integrity and row counts, and
rewrites every original reference to the new location (a reference is never left pointing at the old
installation, even when the original was missing).
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

BACKUP_FORMAT = "argos-backup/2"
SUPPORTED_FORMATS = ("argos-backup/1", "argos-backup/2")
MAX_MEMBER = 4 << 30


class BackupError(Exception):
    pass


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _basename(stored_path: str) -> str:
    return PurePosixPath(stored_path.replace("\\", "/")).name


def evidence_inventory(db_path: Path) -> list[dict]:
    """Expected retained originals, derived from a database snapshot: one entry per distinct original
    file (revisions of the same content share one content-addressed original)."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute("SELECT input_id, case_id, stored_path, sha256 FROM inputs ORDER BY case_id, input_id").fetchall()
    finally:
        conn.close()
    inv: dict[str, dict] = {}
    for input_id, case_id, stored_path, digest in rows:
        name = f"cases/{case_id}/originals/{_basename(stored_path)}"
        e = inv.setdefault(name, {"archive_name": name, "case_id": case_id, "sha256": digest, "stored_path": stored_path, "input_ids": []})
        if e["sha256"] != digest:
            raise BackupError(f"database lists two different hashes for {name}")
        e["input_ids"].append(input_id)
    return list(inv.values())


def create_backup(settings: Settings, output: Path | None = None, allow_incomplete: bool = False) -> dict:
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
        inventory, missing = [], []
        for e in evidence_inventory(snap):
            src = settings.cases_dir / e["case_id"] / "originals" / PurePosixPath(e["archive_name"]).name
            if not src.is_file() or src.is_symlink():
                missing.append({**e, "problem": "missing"})
                continue
            if _sha(src) != e["sha256"]:
                missing.append({**e, "problem": "hash mismatch"})
                continue
            files.append((e["archive_name"], src))
            inventory.append({k: e[k] for k in ("archive_name", "case_id", "sha256", "input_ids")})
        if missing and not allow_incomplete:
            raise BackupError("backup refused: retained originals referenced by the database are missing or altered: "
                              + "; ".join(f"{m['archive_name']} ({m['problem']})" for m in missing[:10])
                              + " - restore the originals, or create an explicitly incomplete backup with --allow-incomplete")
        if settings.config_dir.is_dir():
            for p in sorted(settings.config_dir.glob("*.yaml")):
                files.append(("config/" + p.name, p))
        completeness = "complete" if not missing else "incomplete"
        manifest = {"format": BACKUP_FORMAT, "created_at": now_iso(), "argos_version": __version__, "schema_version": SCHEMA_VERSION,
                    "table_counts": res["counts"], "database_consistency": "ok" if res["integrity"] == "ok" else res["integrity"],
                    "evidence_completeness": completeness, "expected_originals": len(inventory) + len(missing),
                    "evidence_inventory": inventory,
                    "missing_originals": [{k: m[k] for k in ("archive_name", "case_id", "sha256", "input_ids", "problem")} for m in missing],
                    "files": [{"name": n, "sha256": _sha(p), "size": p.stat().st_size} for n, p in files]}
        if completeness != "complete" and ".INCOMPLETE" not in output.name:
            output = output.with_name(output.stem + ".INCOMPLETE" + output.suffix)
        tmp = output.with_name(output.name + ".partial")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as raw, zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
            for n, p in files:
                z.write(p, n)
        os.replace(tmp, output)
        if os.name == "posix":
            os.chmod(output, 0o600)
    return {"backup": str(output), "files": len(files), "table_counts": res["counts"], "sha256": _sha(output),
            "database_consistency": manifest["database_consistency"], "evidence_completeness": completeness,
            "expected_originals": manifest["expected_originals"], "archived_originals": len(inventory),
            "missing_originals": manifest["missing_originals"]}


def _safe_name(name: str) -> PurePosixPath:
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name or not p.parts:
        raise BackupError(f"unsafe member name in backup: {name!r}")
    if p.parts[0] not in ("db", "cases", "config", "manifest.json"):
        raise BackupError(f"unexpected member in backup: {name!r}")
    if p.parts[0] == "cases" and (len(p.parts) != 4 or p.parts[2] != "originals"):
        raise BackupError(f"unexpected evidence path in backup: {name!r}")
    return p


def verify_backup(path: Path, require_complete: bool = False) -> dict:
    """Verify archive integrity AND reconcile the archived originals with the inventory derived from the
    database snapshot inside the archive. Returns the manifest plus reconciliation results."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            raise BackupError("duplicate member names")
        for n in names:
            _safe_name(n)
            info = z.getinfo(n)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise BackupError(f"symbolic link member not allowed: {n!r}")
        try:
            manifest = json.loads(z.read("manifest.json"))
        except KeyError as exc:
            raise BackupError("manifest.json missing") from exc
        if manifest.get("format") not in SUPPORTED_FORMATS:
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
        with tempfile.TemporaryDirectory(prefix="argos-vb-") as td:
            db = Path(td) / "s.sqlite3"
            with z.open("db/argos.sqlite3") as src, open(db, "wb") as out:
                shutil.copyfileobj(src, out)
            conn = sqlite3.connect(db)
            try:
                integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            finally:
                conn.close()
            if integrity != "ok":
                raise BackupError(f"database snapshot failed integrity_check: {integrity}")
            expected = evidence_inventory(db)
    missing = []
    for e in expected:
        f = listed.get(e["archive_name"])
        if f is None:
            missing.append(e["archive_name"])
        elif f["sha256"] != e["sha256"]:
            raise BackupError(f"{e['archive_name']}: archived bytes do not match the hash recorded in the database inventory")
    extra = sorted(n for n in listed if n.startswith("cases/") and n not in {e["archive_name"] for e in expected})
    if extra:
        raise BackupError(f"archive contains originals not referenced by the database inventory: {extra[:5]}")
    completeness = "complete" if not missing else "incomplete"
    if manifest.get("evidence_completeness") == "complete" and missing:
        raise BackupError("manifest claims a complete backup but referenced originals are absent")
    result = dict(manifest, database_consistency="ok", evidence_completeness=completeness,
                  expected_originals=len(expected), archived_originals=len(expected) - len(missing), missing_archive_names=missing)
    if require_complete and completeness != "complete":
        raise BackupError(f"backup is incomplete: {len(missing)} referenced original(s) absent")
    return result


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
                if not dest.resolve().is_relative_to(staging.resolve()):
                    raise BackupError(f"member escapes the restore directory: {f['name']!r}")
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
            if p.is_dir() and os.name == "posix":
                for q in p.rglob("*"):
                    os.chmod(q, 0o700 if q.is_dir() else (0o400 if "originals" in q.parts else 0o600))
                os.chmod(p, 0o700)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    settings.ensure()
    st = Store(settings.db_path)  # migrates older snapshots with its own pre-migration backup
    try:
        rebased = st.rebase_originals(settings.cases_dir)
        problems = []
        for i in st.list_inputs_all():
            p = Path(i["stored_path"])
            if not p.resolve().is_relative_to(settings.home.resolve()):
                problems.append(f"{i['input_id']}: reference outside the restored data directory")
            elif not p.is_file():
                problems.append(f"{i['input_id']}: original missing ({p.name})")
            elif _sha(p) != i["sha256"]:
                problems.append(f"{i['input_id']}: original hash mismatch")
        final = table_counts(st.conn)
        schema = st.schema_version()
    finally:
        st.close()
    if problems and manifest["evidence_completeness"] == "complete":
        raise BackupError("restored references failed verification: " + "; ".join(problems[:10]))
    return {"restored_to": str(home), "schema_version": schema, "originals_rebased": rebased, "table_counts": final,
            "backup_created_at": manifest["created_at"], "database_consistency": "ok",
            "evidence_completeness": manifest["evidence_completeness"], "missing_originals": problems}


__all__ = ["create_backup", "verify_backup", "restore_backup", "evidence_inventory", "BackupError", "consistent_backup"]
