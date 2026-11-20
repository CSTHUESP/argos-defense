"""Build the native ARGOS Defense package for the CURRENT OS/architecture.

    python packaging/build_native.py --out dist-native

Steps: PyInstaller onedir build -> add launchers, notices and third-party licenses ->
create the distributable archive -> write build-info JSON (no secrets).
Must run natively on each target (no cross-compilation; an archive is never renamed
to pose as another platform).
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from argos import __version__  # noqa: E402
from collect_licenses import collect  # noqa: E402


def target_id() -> str:
    m = platform.machine().lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(m, m)
    if sys.platform.startswith("win"):
        return f"windows-{arch}"
    if sys.platform == "darwin":
        return f"macos-{arch}"
    return f"linux-{arch}"


README_FIRST = """ARGOS Defense {version} - native package ({target})
==========================================================

Experimental detection; real-world accuracy not measured.

Start:
  {start}

The local web interface opens in your browser (http://127.0.0.1:8789 by default,
loopback only). Data is stored in your user application-data folder:
  Windows: %LOCALAPPDATA%\\ARGOS Defense
  macOS:   ~/Library/Application Support/ARGOS Defense
  Linux:   ~/.local/share/argos-defense
or wherever you point --data-dir. Nothing is written inside this folder.

Command line (same executable):
  {exe} --version
  {exe} doctor
  {exe} demo
  {exe} start --no-browser --port 0
  {exe} ingest FILE --format native_jsonl --case my-case
  {exe} analyze --case my-case
  {exe} report --case my-case --format html

Signing: {signing}
Licenses: LICENSE (Apache-2.0, ARGOS), THIRD_PARTY_NOTICES.md, licenses/ (bundled components).
Documentation: https://github.com/CSTHUESP/argos-defense
"""

WIN_LAUNCHER = r"""@echo off
rem ARGOS Defense launcher: starts the local web UI and opens the browser.
setlocal
cd /d "%~dp0"
"%~dp0argos-defense\argos-defense.exe" start %*
if errorlevel 1 (
  echo.
  echo ARGOS Defense exited with an error. See the message above.
  pause
)
"""

MAC_LAUNCHER = """#!/bin/bash
# ARGOS Defense launcher: starts the local web UI and opens the browser. Close this window to stop.
cd "$(dirname "$0")" || exit 1
"./argos-defense/argos-defense" start "$@"
status=$?
if [ $status -ne 0 ]; then echo; echo "ARGOS Defense exited with an error (status $status)."; read -r -p "Press Enter to close..." _; fi
exit $status
"""

LINUX_LAUNCHER = """#!/bin/sh
# ARGOS Defense launcher: starts the local web UI and opens the browser (Ctrl+C to stop).
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/argos-defense/argos-defense" start "$@"
"""


def sh(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def make_exec(p: Path):
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build(out: Path, commit: str) -> dict:
    tid = target_id()
    work = out / "work"
    shutil.rmtree(work, ignore_errors=True)
    sh([sys.executable, "-m", "PyInstaller", str(ROOT / "packaging" / "argos.spec"), "--noconfirm", "--clean",
        "--distpath", str(work / "dist"), "--workpath", str(work / "build")], cwd=ROOT)
    top = f"ARGOS-Defense-{__version__}-{tid}"
    stage = out / "stage" / top
    shutil.rmtree(stage.parent, ignore_errors=True)
    stage.mkdir(parents=True)
    shutil.copytree(work / "dist" / "argos-defense", stage / "argos-defense", symlinks=True)
    exe_name = "argos-defense.exe" if tid.startswith("windows") else "argos-defense"
    if tid.startswith("windows"):
        (stage / "Start ARGOS Defense.cmd").write_text(WIN_LAUNCHER.replace("\n", "\r\n"), encoding="ascii")
        start, signing = "double-click 'Start ARGOS Defense.cmd'", "NOT Authenticode-signed (no certificate configured)"
    elif tid.startswith("macos"):
        p = stage / "Start ARGOS Defense.command"
        p.write_text(MAC_LAUNCHER)
        make_exec(p)
        start = "double-click 'Start ARGOS Defense.command' (first launch: see README-FIRST for Gatekeeper)"
        signing = "ad-hoc code signature only (applied by PyInstaller); NOT Developer ID signed; NOT notarized"
    else:
        p = stage / "start-argos-defense.sh"
        p.write_text(LINUX_LAUNCHER)
        make_exec(p)
        start, signing = "./start-argos-defense.sh", "not signed (no signing applicable)"
    exe_rel = f"argos-defense/{exe_name}"
    text = README_FIRST.format(version=__version__, target=tid, start=start, exe=exe_rel, signing=signing)
    if tid.startswith("macos"):
        text += ("\nmacOS Gatekeeper: this build is not notarized. If macOS blocks the first launch, open\n"
                 "System Settings > Privacy & Security and choose 'Open Anyway' for the blocked item\n"
                 "(Apple's documented procedure), then launch again.\n")
    if tid.startswith("windows"):
        text += ("\nWindows SmartScreen may warn because the executable is unsigned. Verify the archive\n"
                 "against SHA256SUMS from the release before choosing to run it.\n")
    (stage / "README-FIRST.txt").write_text(text, encoding="utf-8")
    shutil.copyfile(ROOT / "LICENSE", stage / "LICENSE")
    shutil.copyfile(ROOT / "THIRD_PARTY_NOTICES.md", stage / "THIRD_PARTY_NOTICES.md")
    pkgs = collect(stage)
    # archive
    if tid.startswith("linux"):
        archive = out / f"{top}.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(stage, arcname=top)  # preserves executable bits
    elif tid.startswith("macos"):
        archive = out / f"{top}.zip"
        archive.unlink(missing_ok=True)
        sh(["ditto", "-c", "-k", "--keepParent", "--sequesterRsrc", str(stage), str(archive)])
    else:
        archive = out / f"{top}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(stage.rglob("*")):
                zf.write(p, p.relative_to(stage.parent).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    frozen = [f"{d.metadata['Name']}=={d.version}" for d in md.distributions()]
    info = {
        "name": archive.name, "sha256": digest, "size": archive.stat().st_size, "target": tid,
        "version": __version__, "commit": commit, "executable": f"{top}/{exe_rel}",
        "build_env": {"os": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
                      "pyinstaller": md.version("pyinstaller"), "runner": os.environ.get("ImageOS", "") + " " + os.environ.get("ImageVersion", ""),
                      "build_venv_packages": sorted(frozen)},
        "bundled_packages": pkgs,
        "signing": signing,
    }
    (out / f"build-info-{tid}.json").write_text(json.dumps(info, indent=2))
    print(json.dumps({k: info[k] for k in ("name", "sha256", "size", "target")}, indent=2))
    return info


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist-native")
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "unknown"))
    a = ap.parse_args()
    build(Path(a.out).resolve(), a.commit)
