"""Verify release assets downloaded back from GitHub against the expectations retained BEFORE upload (F12).

    python packaging/verify_release.py --downloaded verify/ --expected expected-assets.json \
        --version 0.3.0 --commit <sha> [--release-json release.json]

Checks: exact asset name set; per-file size and SHA-256 equal to the retained pre-upload values
(including SHA256SUMS and release-manifest.json); the downloaded SHA256SUMS is internally
consistent; the full release contract still holds for the downloaded bytes; optionally the release
metadata (draft state, tag) from `gh release view --json`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_contract import parse_sums, sha256, validate  # noqa: E402


def verify(downloaded: Path, expected: dict, version: str, commit: str, release: dict | None = None,
           want_draft: bool | None = None) -> list[str]:
    errors = []
    if expected.get("version") != version or expected.get("commit") != commit:
        errors.append("retained expectations are for a different version/commit")
    exp = expected["assets"]
    got = {p.name: p for p in downloaded.iterdir() if p.is_file()}
    for n in sorted(set(exp) - set(got)):
        errors.append(f"missing after download: {n}")
    for n in sorted(set(got) - set(exp)):
        errors.append(f"unexpected after download: {n}")
    for n in sorted(set(exp) & set(got)):
        p = got[n]
        if p.stat().st_size != exp[n]["size"]:
            errors.append(f"{n}: size {p.stat().st_size} != expected {exp[n]['size']}")
        elif sha256(p) != exp[n]["sha256"]:
            errors.append(f"{n}: SHA-256 differs from the bytes built and tested before upload")
    if "SHA256SUMS" in got:
        try:
            sums = parse_sums(got["SHA256SUMS"].read_text())
            if set(sums) != set(exp) - {"SHA256SUMS"}:
                errors.append("SHA256SUMS does not list exactly the other assets")
            for n, h in sums.items():
                if n in exp and exp[n]["sha256"] != h:
                    errors.append(f"SHA256SUMS entry for {n} disagrees with retained expectation")
        except ValueError as exc:
            errors.append(str(exc))
    if not errors:
        e2, _ = validate(downloaded, version, commit, final=True)
        errors += [f"contract (downloaded bytes): {x}" for x in e2]
        try:
            man = json.loads(got["release-manifest.json"].read_text())
            if man.get("commit") != commit or man.get("version") != version:
                errors.append("release-manifest commit/version mismatch")
        except (KeyError, ValueError) as exc:
            errors.append(f"release-manifest unreadable: {exc}")
    if release is not None:
        if release.get("tagName") != f"v{version}":
            errors.append(f"release tag {release.get('tagName')!r} != v{version}")
        if want_draft is not None and bool(release.get("isDraft")) != want_draft:
            errors.append(f"release isDraft={release.get('isDraft')}, expected {want_draft}")
        names = {a["name"]: a["size"] for a in release.get("assets", [])}
        if names != {n: v["size"] for n, v in exp.items()}:
            errors.append("release asset list (names/sizes) differs from expectations")
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--downloaded", required=True)
    ap.add_argument("--expected", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--release-json")
    ap.add_argument("--want-draft", choices=["true", "false"])
    a = ap.parse_args(argv)
    rel = json.loads(Path(a.release_json).read_text()) if a.release_json else None
    errs = verify(Path(a.downloaded), json.loads(Path(a.expected).read_text()), a.version, a.commit, rel,
                  None if a.want_draft is None else a.want_draft == "true")
    if errs:
        print("UPLOADED-BYTE VERIFICATION FAILED:\n  " + "\n  ".join(errs))
        return 1
    print("uploaded-byte verification passed: names, sizes and SHA-256 match the retained pre-upload expectations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
