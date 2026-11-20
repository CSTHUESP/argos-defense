"""Release asset contract (F12).

The exact set of files a release of version V built from commit C must contain, and the checks every
file must pass. Used by release_manifest.py (before upload) and verify_release.py (after upload).

    TARGETS x {archive, build-info, smoke json, smoke log, sbom}  (4 x 5 = 20)
    wheel, sdist, python-dist-info.json                            (3)
    LICENSE, THIRD_PARTY_NOTICES.md                                (2)
    release-manifest.json, SHA256SUMS                              (2)

A boolean `overall_pass` or a minimum check count is never sufficient: every required smoke-check
identity for the platform must be present and passing, and no check may fail.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path

TARGETS = {
    "windows-x86_64": {"ext": ".zip", "system": "Windows", "machines": {"AMD64", "x86_64"}, "launcher": "Start ARGOS Defense.cmd"},
    "linux-x86_64": {"ext": ".tar.gz", "system": "Linux", "machines": {"x86_64"}, "launcher": "start-argos-defense.sh"},
    "macos-arm64": {"ext": ".zip", "system": "Darwin", "machines": {"arm64"}, "launcher": "Start ARGOS Defense.command"},
    "macos-x86_64": {"ext": ".zip", "system": "Darwin", "machines": {"x86_64"}, "launcher": "Start ARGOS Defense.command"},
}
COMMON_CHECKS = [
    "archive: executable present",
    "exe: --version runs as frozen executable",
    "exe: doctor (bundled templates/static/rules/notices)",
    "exe: demo generation + analysis",
    "exe: ingest sysmon XML",
    "exe: analyze",
    "exe: alerts include EP-001/EP-002",
    "exe: IANA time zone resolves (bundled tz database)",
    "exe: HTML report export",
    "exe: JSON report export",
    "exe: occupied port reported clearly",
    "http: authenticated API",
    "http: unauthenticated API rejected",
    "browser: unauthenticated redirect to login",
    "browser: login form submission",
    "browser: create case form (CSRF)",
    "browser: multipart import form",
    "browser: analyze button (background job with progress page)",
    "browser: alert detail with separate dimensions",
    "browser: note form",
    "browser: evidence page with original record",
    "browser: HTML export download",
    "browser: bundled static assets served",
    "browser: no console errors",
    "exe: clean shutdown via authenticated API",
    "exe: runtime file removed on shutdown",
    "exe: persistence across restart (cases, alerts, notes)",
    "exe: second clean shutdown",
    "launcher: --no-browser does not open a browser",
    "launcher: clean shutdown (no-browser)",
    "launcher: default start opens the browser via BROWSER (login URL on loopback)",
    "launcher: clean shutdown (browser)",
    "update: v0.2.0 database migrated by the native app",
    "update: verified pre-migration backup retained",
    "update: legacy run labelled (no invented snapshot)",
    "update: re-analysis after migration",
    "backup: refuses when referenced evidence is missing",
    "backup: created",
    "backup: verified",
    "restore: into new directory",
    "restore: restored case and alerts readable",
    "restore: refuses non-empty target",
    "restore: re-analysis of restored evidence",
    "bundle: no files written inside the application bundle",
    "logs: session token never printed",
]
# Legitimate platform differences: POSIX permission bits are not meaningful on Windows.
POSIX_ONLY = ["archive: executable permission preserved", "launcher: executable bit preserved"]


def required_checks(target: str) -> list[str]:
    t = TARGETS[target]
    launcher = t["launcher"]
    req = list(COMMON_CHECKS) + [f"launcher: {launcher} present",
                                 f"launcher: {launcher} starts the native app (no-browser, ARGOS_HOME non-ASCII)",
                                 f"launcher: {launcher} starts the native app (browser, ARGOS_HOME non-ASCII)"]
    if t["system"] != "Windows":
        req += POSIX_ONLY
    return req


def archive_name(version: str, target: str) -> str:
    return f"ARGOS-Defense-{version}-{target}{TARGETS[target]['ext']}"


def wheel_name(version: str) -> str:
    return f"argos_defense-{version}-py3-none-any.whl"


def sdist_name(version: str) -> str:
    return f"argos_defense-{version}.tar.gz"


def expected_assets(version: str) -> set[str]:
    names = set()
    for t in TARGETS:
        names |= {archive_name(version, t), f"build-info-{t}.json", f"smoke-{t}.json", f"smoke-{t}.log", f"sbom-{t}.cdx.json"}
    names |= {wheel_name(version), sdist_name(version), "python-dist-info.json", "LICENSE", "THIRD_PARTY_NOTICES.md",
              "release-manifest.json", "SHA256SUMS"}
    return names


SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _load(p: Path, errors: list, label: str):
    try:
        return json.loads(p.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        errors.append(f"{label}: unreadable JSON ({exc})")
        return None


def _wheel_version(p: Path) -> str | None:
    with zipfile.ZipFile(p) as z:
        meta = [n for n in z.namelist() if re.fullmatch(r"argos_defense-[^/]+\.dist-info/METADATA", n)]
        if len(meta) != 1:
            return None
        m = re.search(r"^Version: (\S+)$", z.read(meta[0]).decode("utf-8", "replace"), re.M)
        return m.group(1) if m else None


def _sdist_version(p: Path) -> str | None:
    with tarfile.open(p) as tf:
        names = [n for n in tf.getnames() if re.fullmatch(r"argos_defense-[^/]+/PKG-INFO", n)]
        if len(names) != 1:
            return None
        data = tf.extractfile(names[0]).read().decode("utf-8", "replace")
        m = re.search(r"^Version: (\S+)$", data, re.M)
        return m.group(1) if m else None


def validate(assets: Path, version: str, commit: str, source_dir: Path | None = None, final: bool = False) -> tuple[list[str], dict]:
    """Return (errors, targets_summary). `final` = also require release-manifest.json and SHA256SUMS."""
    errors: list[str] = []
    if not SEMVER.match(version):
        errors.append(f"version {version!r} is not MAJOR.MINOR.PATCH")
    if not SHA40.match(commit):
        errors.append(f"commit {commit!r} is not a full 40-hex SHA")
    present = {p.name for p in assets.iterdir() if p.is_file()}
    expected = expected_assets(version)
    if not final:
        expected -= {"release-manifest.json", "SHA256SUMS"}
        present -= {"release-manifest.json", "SHA256SUMS"}
    for n in sorted(expected - present):
        errors.append(f"missing asset: {n}")
    for n in sorted(present - expected):
        errors.append(f"unexpected asset: {n}")
    if [p for p in assets.iterdir() if not p.is_file()]:
        errors.append("asset directory contains non-file entries")
    summary = {}
    for t, spec in TARGETS.items():
        an = archive_name(version, t)
        arch = assets / an
        info_p, smoke_p, sbom_p, log_p = (assets / f"build-info-{t}.json", assets / f"smoke-{t}.json",
                                          assets / f"sbom-{t}.cdx.json", assets / f"smoke-{t}.log")
        if not all(p.is_file() for p in (arch, info_p, smoke_p, sbom_p, log_p)):
            continue  # already reported as missing
        digest, size = sha256(arch), arch.stat().st_size
        info = _load(info_p, errors, f"build-info-{t}")
        smoke = _load(smoke_p, errors, f"smoke-{t}")
        sbom = _load(sbom_p, errors, f"sbom-{t}")
        if info is None or smoke is None or sbom is None:
            continue
        # build-info
        for k, want in (("name", an), ("target", t), ("version", version), ("commit", commit), ("sha256", digest), ("size", size)):
            if info.get(k) != want:
                errors.append(f"{t}: build-info {k}={info.get(k)!r}, expected {want!r}")
        if not info.get("signing"):
            errors.append(f"{t}: build-info lacks a signing status")
        # smoke
        if smoke.get("schema") != "argos-smoke/2":
            errors.append(f"{t}: smoke schema {smoke.get('schema')!r} unsupported")
        if smoke.get("archive") != an or smoke.get("archive_sha256") != digest or smoke.get("archive_size") != size:
            errors.append(f"{t}: smoke result was not produced for these exact archive bytes")
        if smoke.get("browser_part") is not True:
            errors.append(f"{t}: browser part of the smoke test was skipped")
        res = smoke.get("results") or []
        names = [r.get("check") for r in res]
        if len(names) != len(set(names)):
            errors.append(f"{t}: duplicate smoke check identities")
        failed = [r.get("check") for r in res if r.get("pass") is not True]
        if failed:
            errors.append(f"{t}: failed smoke checks: {failed}")
        missing = [c for c in required_checks(t) if c not in names]
        if missing:
            errors.append(f"{t}: required smoke checks missing: {missing}")
        if smoke.get("checks_total") != len(res) or smoke.get("checks_passed") != len(res) or not res:
            errors.append(f"{t}: smoke counters inconsistent ({smoke.get('checks_passed')}/{smoke.get('checks_total')}, {len(res)} results)")
        if smoke.get("overall_pass") is not True:
            errors.append(f"{t}: smoke overall_pass is not true")
        osinfo = smoke.get("os") or {}
        if osinfo.get("system") != spec["system"] or osinfo.get("machine") not in spec["machines"]:
            errors.append(f"{t}: smoke ran on {osinfo.get('system')}/{osinfo.get('machine')}, expected {spec['system']}/{sorted(spec['machines'])}")
        # sbom
        props = {p.get("name"): p.get("value") for p in ((sbom.get("metadata") or {}).get("component") or {}).get("properties", [])}
        if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") not in ("1.5", "1.6"):
            errors.append(f"{t}: SBOM is not CycloneDX 1.5/1.6 JSON")
        if ((sbom.get("metadata") or {}).get("component") or {}).get("version") != version:
            errors.append(f"{t}: SBOM component version mismatch")
        if props.get("argos:target") != t or props.get("argos:commit") != commit or props.get("argos:archive_sha256") != digest:
            errors.append(f"{t}: SBOM not bound to this target/commit/archive")
        comp_names = {(c.get("name") or "").lower() for c in sbom.get("components", [])}
        bundled = {(p.get("name") or "").lower() for p in info.get("bundled_packages", [])}
        if not bundled or not bundled <= comp_names:
            errors.append(f"{t}: SBOM components do not cover the bundled packages {sorted(bundled - comp_names)}")
        summary[t] = {"file": an, "sha256": digest, "size": size, "signing": info.get("signing"),
                      "build_env": {k: v for k, v in (info.get("build_env") or {}).items() if k != "build_venv_packages"},
                      "smoke_test": {"checks": f"{len(res)}/{len(res)}" if not failed else f"{len(res) - len(failed)}/{len(res)}",
                                     "required_checks": len(required_checks(t)), "tested_os": osinfo, "tested_archive_sha256": smoke.get("archive_sha256")}}
    # python distributions
    whl, sd, pdi = assets / wheel_name(version), assets / sdist_name(version), assets / "python-dist-info.json"
    if whl.is_file() and sd.is_file() and pdi.is_file():
        info = _load(pdi, errors, "python-dist-info")
        if info is not None:
            if info.get("version") != version or info.get("commit") != commit:
                errors.append(f"python-dist-info: version/commit {info.get('version')}/{info.get('commit')} != {version}/{commit}")
            files = {f.get("name"): f for f in info.get("files", [])}
            for p in (whl, sd):
                f = files.get(p.name)
                if not f or f.get("sha256") != sha256(p) or f.get("size") != p.stat().st_size:
                    errors.append(f"{p.name}: bytes differ from the built and install-tested distribution")
            if set(files) != {whl.name, sd.name}:
                errors.append("python-dist-info lists unexpected files")
            if info.get("install_test") != "passed":
                errors.append("python-dist-info: wheel install test not recorded as passed")
        try:
            if _wheel_version(whl) != version:
                errors.append(f"wheel METADATA version {_wheel_version(whl)!r} != {version}")
            if _sdist_version(sd) != version:
                errors.append(f"sdist PKG-INFO version {_sdist_version(sd)!r} != {version}")
        except (OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
            errors.append(f"python distributions unreadable: {exc}")
    if source_dir is not None:
        for n in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            if (assets / n).is_file() and sha256(assets / n) != sha256(source_dir / n):
                errors.append(f"{n} differs from the source commit's file")
    return errors, summary


def parse_sums(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        if not m:
            raise ValueError(f"malformed SHA256SUMS line: {line!r}")
        if m.group(2) in out:
            raise ValueError(f"duplicate SHA256SUMS entry {m.group(2)}")
        out[m.group(2)] = m.group(1)
    return out
