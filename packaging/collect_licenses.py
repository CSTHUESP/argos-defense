"""Copy the license files of every bundled distribution (runtime closure of argos-defense) and
of the CPython runtime into <bundle>/licenses/. Also returns the resolved package list."""
from __future__ import annotations

import importlib.metadata as md
import json
import re
import shutil
import sys
import sysconfig
from pathlib import Path


def runtime_closure(root: str = "argos-defense") -> dict[str, md.Distribution]:
    seen: dict[str, md.Distribution] = {}
    stack = [root]
    env = {"extra": ""}
    while stack:
        name = stack.pop()
        key = re.sub(r"[-_.]+", "-", name).lower()
        if key in seen:
            continue
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue
        seen[key] = dist
        from packaging.requirements import Requirement
        for req in dist.requires or []:
            r = Requirement(req)
            if r.marker and not r.marker.evaluate(env):
                continue
            stack.append(r.name)
    return seen


def license_files(dist: md.Distribution):
    for f in dist.files or []:
        s = str(f)
        if re.search(r"(LICEN[CS]E|COPYING|NOTICE|AUTHORS)", s.split("/")[-1], re.I) and ".dist-info" in s:
            p = Path(dist.locate_file(f))
            if p.is_file():
                yield p


def python_license() -> Path | None:
    for cand in (Path(sys.base_prefix) / "LICENSE.txt", Path(sysconfig.get_paths()["stdlib"]) / "LICENSE.txt",
                 Path(sys.base_prefix) / "LICENSE"):
        if cand.is_file():
            return cand
    return None


def collect(bundle: Path) -> list[dict]:
    out = bundle / "licenses"
    out.mkdir(parents=True, exist_ok=True)
    pkgs = []
    for key, dist in sorted(runtime_closure().items()):
        if key == "argos-defense":
            continue
        dest = out / f"{dist.metadata['Name']}-{dist.version}"
        files = list(license_files(dist))
        dest.mkdir(exist_ok=True)
        for f in files:
            shutil.copyfile(f, dest / f.name)
        pkgs.append({"name": dist.metadata["Name"], "version": dist.version,
                     "license": dist.metadata.get("License-Expression") or dist.metadata.get("License") or "see files",
                     "license_files": [f.name for f in files]})
        if not files:
            raise SystemExit(f"no license file found for bundled package {dist.metadata['Name']} - refusing to build")
    pl = python_license()
    if pl is None:
        raise SystemExit("CPython LICENSE not found - refusing to build")
    (out / "python").mkdir(exist_ok=True)
    shutil.copyfile(pl, out / "python" / "LICENSE.txt")
    (out / "packages.json").write_text(json.dumps(pkgs, indent=2))
    return pkgs


if __name__ == "__main__":
    print(json.dumps(collect(Path(sys.argv[1])), indent=2))
