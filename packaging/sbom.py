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


if __name__ == "__main__":
    info = json.loads(Path(sys.argv[1]).read_text())
    Path(sys.argv[2]).write_text(json.dumps(make(info), indent=2))
    print(f"wrote {sys.argv[2]} ({len(info['bundled_packages']) + 1} components)")
