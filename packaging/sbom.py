"""Minimal CycloneDX 1.5 JSON SBOM for one native package, from its build-info JSON.

Scope (stated in the SBOM itself): ARGOS Defense plus the Python distributions bundled into
the PyInstaller onedir package and the embedded CPython runtime. It does NOT enumerate
operating-system libraries, PyInstaller's bootloader internals, or C libraries vendored
inside wheels (e.g. libyaml in PyYAML wheels if present).
"""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def make(info: dict) -> dict:
    comps = [{"type": "library", "name": p["name"], "version": p["version"], "purl": purl(p["name"], p["version"]),
              "licenses": [{"expression": p["license"]}] if p["license"] and " " not in p["license"].strip() or "OR" in p["license"]
              else [{"license": {"name": p["license"]}}]} for p in info["bundled_packages"]]
    comps.append({"type": "platform", "name": "CPython", "version": info["build_env"]["python"],
                  "licenses": [{"license": {"name": "Python Software Foundation License"}}]})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": "ARGOS Defense", "version": info["version"],
                          "licenses": [{"expression": "Apache-2.0"}],
                          "properties": [{"name": "argos:target", "value": info["target"]},
                                         {"name": "argos:commit", "value": info["commit"]},
                                         {"name": "argos:archive", "value": info["name"]},
                                         {"name": "argos:archive_sha256", "value": info["sha256"]}]},
            "properties": [{"name": "argos:sbom_scope", "value":
                            "ARGOS Defense + bundled Python distributions + embedded CPython runtime; excludes OS libraries, "
                            "PyInstaller bootloader internals and C libraries vendored inside wheels"}],
        },
        "components": comps,
    }


def validate(bom: dict, info: dict) -> list[str]:
    """Structural CycloneDX 1.5 checks plus binding to the build-info of the shipped archive.
    (Not a full JSON-Schema validation: the official schema cannot be fetched in every build environment.)"""
    errs = []
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5" or not isinstance(bom.get("version"), int):
        errs.append("bomFormat/specVersion/version invalid")
    if not str(bom.get("serialNumber", "")).startswith("urn:uuid:"):
        errs.append("serialNumber must be a urn:uuid")
    comp = (bom.get("metadata") or {}).get("component") or {}
    if comp.get("type") != "application" or comp.get("version") != info["version"]:
        errs.append("metadata.component must be the ARGOS application at the build version")
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    for k, v in (("argos:target", info["target"]), ("argos:commit", info["commit"]), ("argos:archive_sha256", info["sha256"])):
        if props.get(k) != v:
            errs.append(f"{k} does not match build-info")
    names = {}
    for c in bom.get("components", []):
        if c.get("type") not in ("library", "platform", "application", "framework") or not c.get("name") or not c.get("version"):
            errs.append(f"invalid component {c}")
        if c.get("purl") and not c["purl"].startswith("pkg:"):
            errs.append(f"invalid purl {c['purl']}")
        if not c.get("licenses"):
            errs.append(f"component {c.get('name')} has no license entry")
        names[(c.get("name") or "").lower()] = c.get("version")
    for p in info["bundled_packages"]:
        if names.get(p["name"].lower()) != p["version"]:
            errs.append(f"bundled package {p['name']}=={p['version']} missing from SBOM")
    return errs


if __name__ == "__main__":
    if sys.argv[1] == "--validate":
        e = validate(json.loads(Path(sys.argv[2]).read_text()), json.loads(Path(sys.argv[3]).read_text()))
        if e:
            print("SBOM INVALID:\n  " + "\n  ".join(e))
            sys.exit(1)
        print(f"SBOM valid and bound to {sys.argv[3]}")
        sys.exit(0)
    info = json.loads(Path(sys.argv[1]).read_text())
    Path(sys.argv[2]).write_text(json.dumps(make(info), indent=2))
    print(f"wrote {sys.argv[2]} ({len(info['bundled_packages']) + 1} components)")
