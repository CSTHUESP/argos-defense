"""Gate + assemble SHA256SUMS and release-manifest.json from the exact files to be published (F12).

    python packaging/release_manifest.py --assets release-assets --version 0.3.0 --commit <40-hex sha> \
        --tag v0.3.0 --source-dir . --expected-out expected-assets.json

Refuses (exit 1) unless the asset directory satisfies the complete release contract in
release_contract.py. Writes, OUTSIDE the asset directory, the expected name/size/SHA-256 of every
asset including SHA256SUMS itself; that file is retained by the workflow and later used to verify
the bytes downloaded back from the draft release (verify_release.py), so verification does not rely
on the uploaded SHA256SUMS alone.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_contract import sha256, validate  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--assets", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--source-dir", default=None)
    ap.add_argument("--expected-out", required=True)
    ap.add_argument("--run-url", default="")
    ap.add_argument("--attestations", default="not generated")
    a = ap.parse_args(argv)
    d = Path(a.assets)
    if a.tag != f"v{a.version}":
        print(f"RELEASE GATE FAILED:\n  tag {a.tag!r} does not match version {a.version!r}")
        return 1
    for n in ("release-manifest.json", "SHA256SUMS"):
        (d / n).unlink(missing_ok=True)
    errors, targets = validate(d, a.version, a.commit, Path(a.source_dir) if a.source_dir else None)
    if errors:
        print("RELEASE GATE FAILED:\n  " + "\n  ".join(errors))
        return 1
    files = sorted(p for p in d.iterdir() if p.is_file())
    manifest = {
        "schema": "argos-release-manifest/2", "name": "ARGOS Defense", "version": a.version, "tag": a.tag, "commit": a.commit,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "workflow_run": a.run_url,
        "detection_maturity": "experimental detection; real-world accuracy not measured",
        "targets": targets,
        "files": [{"name": p.name, "sha256": sha256(p), "size": p.stat().st_size} for p in files],
        "signing": {"windows_authenticode": "not signed (no certificate configured)",
                    "apple_developer_id": "not signed (ad-hoc signature only)", "apple_notarization": "not notarized",
                    "github_attestations": a.attestations,
                    "checksums_note": "SHA256SUMS provides integrity, not authenticated publisher identity"},
    }
    (d / "release-manifest.json").write_text(json.dumps(manifest, indent=2))
    allf = sorted(p for p in d.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (d / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in allf))
    errors, _ = validate(d, a.version, a.commit, Path(a.source_dir) if a.source_dir else None, final=True)
    if errors:
        print("RELEASE GATE FAILED after assembly:\n  " + "\n  ".join(errors))
        return 1
    expected = {"version": a.version, "tag": a.tag, "commit": a.commit,
                "assets": {p.name: {"sha256": sha256(p), "size": p.stat().st_size} for p in sorted(d.iterdir()) if p.is_file()}}
    Path(a.expected_out).write_text(json.dumps(expected, indent=2))
    print(f"release gate passed; {len(expected['assets'])} assets; SHA256SUMS sha256={expected['assets']['SHA256SUMS']['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
