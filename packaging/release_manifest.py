"""Assemble SHA256SUMS and release-manifest.json from the exact files to be published.

    python packaging/release_manifest.py --assets release-assets --version 0.2.0 --commit <sha> --tag v0.2.0

Refuses to produce a manifest if any native target is missing or its smoke test did not pass
for the exact archive bytes (sha256 must match the tested archive).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_TARGETS = ["windows-x86_64", "linux-x86_64", "macos-arm64", "macos-x86_64"]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--assets", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--run-url", default="")
    a = ap.parse_args(argv)
    d = Path(a.assets)
    errors, targets = [], {}
    for t in REQUIRED_TARGETS:
        info_p = d / f"build-info-{t}.json"
        smoke_p = d / f"smoke-{t}.json"
        if not info_p.exists() or not smoke_p.exists():
            errors.append(f"{t}: build-info or smoke result missing")
            continue
        info, smoke = json.loads(info_p.read_text()), json.loads(smoke_p.read_text())
        arch = d / info["name"]
        if not arch.exists():
            errors.append(f"{t}: archive {info['name']} missing")
            continue
        digest = sha256(arch)
        if digest != info["sha256"] or digest != smoke["archive_sha256"]:
            errors.append(f"{t}: archive bytes differ from built/tested bytes")
        if not smoke["overall_pass"]:
            errors.append(f"{t}: native smoke test failed ({smoke['checks_passed']}/{smoke['checks_total']})")
        if info["commit"] != a.commit:
            errors.append(f"{t}: built from {info['commit']}, expected {a.commit}")
        targets[t] = {"file": info["name"], "sha256": digest, "size": arch.stat().st_size, "build_env": {k: v for k, v in info["build_env"].items() if k != "build_venv_packages"},
                      "signing": info["signing"], "smoke_test": {"overall_pass": smoke["overall_pass"], "checks": f"{smoke['checks_passed']}/{smoke['checks_total']}",
                                                                "tested_os": smoke["os"], "tested_archive_sha256": smoke["archive_sha256"]}}
    if errors:
        print("RELEASE GATE FAILED:\n  " + "\n  ".join(errors))
        return 1
    files = sorted(p for p in d.iterdir() if p.is_file() and p.name not in ("SHA256SUMS", "release-manifest.json"))
    manifest = {
        "name": "ARGOS Defense", "version": a.version, "tag": a.tag, "commit": a.commit,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "workflow_run": a.run_url,
        "detection_maturity": "experimental detection; real-world accuracy not measured",
        "targets": targets,
        "files": [{"name": p.name, "sha256": sha256(p), "size": p.stat().st_size} for p in files],
        "signing": {"windows_authenticode": "not signed (no certificate configured)",
                    "apple_developer_id": "not signed (ad-hoc signature only)", "apple_notarization": "not notarized",
                    "github_attestations": "not generated: artifact attestations for private repositories require GitHub Enterprise Cloud",
                    "checksums_note": "SHA256SUMS provides integrity, not authenticated publisher identity"},
    }
    (d / "release-manifest.json").write_text(json.dumps(manifest, indent=2))
    # SHA256SUMS covers every published file including the manifest (written last).
    allf = sorted(p for p in d.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (d / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in allf))
    print(f"release gate passed; {len(allf)} files listed in SHA256SUMS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
