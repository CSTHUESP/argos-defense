"""F11/F12/F13: release preflight structure, strict asset contract (positive + negative), uploaded-byte
verification and content-hash bundle fingerprint. Assets here are tiny synthetic stand-ins."""
import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "packaging"))
import release_contract as RC  # noqa: E402
import release_manifest  # noqa: E402
import verify_release  # noqa: E402

V, C = "0.3.0", "a" * 40


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_assets(d: Path):
    d.mkdir(parents=True, exist_ok=True)
    src = d.parent / "src"
    src.mkdir(exist_ok=True)
    for n in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        (src / n).write_bytes((ROOT / n).read_bytes())
        (d / n).write_bytes((ROOT / n).read_bytes())
    for t, spec in RC.TARGETS.items():
        an = RC.archive_name(V, t)
        data = f"archive-bytes-{t}".encode()
        (d / an).write_bytes(data)
        pk = [{"name": "starlette", "version": "1.7.0", "license": "BSD-3-Clause"}]
        (d / f"build-info-{t}.json").write_text(json.dumps({"name": an, "target": t, "version": V, "commit": C, "sha256": sha(data),
                                                             "size": len(data), "signing": "not signed", "build_env": {"os": "x"},
                                                             "bundled_packages": pk}))
        res = [{"check": c, "pass": True} for c in RC.required_checks(t)]
        machine = sorted(spec["machines"])[0]
        (d / f"smoke-{t}.json").write_text(json.dumps({"schema": "argos-smoke/2", "overall_pass": True, "checks_total": len(res),
                                                        "checks_passed": len(res), "browser_part": True, "archive": an,
                                                        "archive_sha256": sha(data), "archive_size": len(data),
                                                        "os": {"system": spec["system"], "machine": machine}, "results": res}))
        (d / f"smoke-{t}.log").write_text("log")
        (d / f"sbom-{t}.cdx.json").write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {
            "version": V, "properties": [{"name": "argos:target", "value": t}, {"name": "argos:commit", "value": C},
                                         {"name": "argos:archive_sha256", "value": sha(data)}]}},
            "components": [{"name": "starlette", "version": "1.7.0"}]}))
    whl = d / RC.wheel_name(V)
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr(f"argos_defense-{V}.dist-info/METADATA", f"Metadata-Version: 2.4\nName: argos-defense\nVersion: {V}\n")
    sd = d / RC.sdist_name(V)
    with tarfile.open(sd, "w:gz") as tf:
        b = f"Metadata-Version: 2.4\nName: argos-defense\nVersion: {V}\n".encode()
        ti = tarfile.TarInfo(f"argos_defense-{V}/PKG-INFO")
        ti.size = len(b)
        tf.addfile(ti, io.BytesIO(b))
    (d / "python-dist-info.json").write_text(json.dumps({"version": V, "commit": C, "install_test": "passed", "files": [
        {"name": p.name, "sha256": RC.sha256(p), "size": p.stat().st_size} for p in (whl, sd)]}))
    return src


@pytest.fixture
def assets(tmp_path):
    d = tmp_path / "assets"
    src = make_assets(d)
    return d, src


def gate(d, src, tmp_path, version=V, commit=C, tag=None):
    return release_manifest.main(["--assets", str(d), "--version", version, "--commit", commit, "--tag", tag or f"v{version}",
                                  "--source-dir", str(src), "--expected-out", str(tmp_path / "expected.json")])


def test_valid_asset_set_passes_and_lists_everything(assets, tmp_path):
    d, src = assets
    assert gate(d, src, tmp_path) == 0
    exp = json.loads((tmp_path / "expected.json").read_text())
    assert set(exp["assets"]) == RC.expected_assets(V) and len(exp["assets"]) == 27
    sums = RC.parse_sums((d / "SHA256SUMS").read_text())
    assert "SHA256SUMS" not in sums and "release-manifest.json" in sums


def _mutate_json(p: Path, fn):
    x = json.loads(p.read_text())
    fn(x)
    p.write_text(json.dumps(x))


NEG = {
    "missing archive": lambda d: (d / RC.archive_name(V, "macos-x86_64")).unlink(),
    "missing sbom": lambda d: (d / "sbom-linux-x86_64.cdx.json").unlink(),
    "missing wheel": lambda d: (d / RC.wheel_name(V)).unlink(),
    "missing sdist": lambda d: (d / RC.sdist_name(V)).unlink(),
    "missing license": lambda d: (d / "LICENSE").unlink(),
    "extra asset": lambda d: (d / "random.bin").write_bytes(b"x"),
    "renamed (wrong version) archive": lambda d: (d / RC.archive_name(V, "linux-x86_64")).rename(d / RC.archive_name("0.2.0", "linux-x86_64")),
    "wrong build-info version": lambda d: _mutate_json(d / "build-info-windows-x86_64.json", lambda x: x.update(version="9.9.9")),
    "wrong build-info target": lambda d: _mutate_json(d / "build-info-macos-arm64.json", lambda x: x.update(target="macos-x86_64")),
    "wrong commit": lambda d: _mutate_json(d / "build-info-linux-x86_64.json", lambda x: x.update(commit="b" * 40)),
    "archive bytes changed after test": lambda d: (d / RC.archive_name(V, "linux-x86_64")).write_bytes(b"archive-bytes-linux-x86_6X"),
    "0/0 checks with overall_pass": lambda d: _mutate_json(d / "smoke-windows-x86_64.json",
                                                            lambda x: x.update(results=[], checks_total=0, checks_passed=0, overall_pass=True)),
    "failed mandatory check": lambda d: _mutate_json(d / "smoke-macos-arm64.json", lambda x: x["results"][3].update({"pass": False})),
    "required check missing": lambda d: _mutate_json(d / "smoke-linux-x86_64.json", lambda x: x.update(
        results=[r for r in x["results"] if r["check"] != "restore: into new directory"], checks_total=len(x["results"]) - 1,
        checks_passed=len(x["results"]) - 1)),
    "browser part skipped": lambda d: _mutate_json(d / "smoke-linux-x86_64.json", lambda x: x.update(browser_part=False)),
    "smoke on wrong architecture": lambda d: _mutate_json(d / "smoke-macos-x86_64.json", lambda x: x["os"].update(machine="arm64")),
    "duplicate check identities": lambda d: _mutate_json(d / "smoke-linux-x86_64.json", lambda x: x.update(
        results=x["results"] + [x["results"][0]], checks_total=len(x["results"]) + 1, checks_passed=len(x["results"]) + 1)),
    "sbom bound to other archive": lambda d: _mutate_json(d / "sbom-windows-x86_64.cdx.json",
                                                          lambda x: x["metadata"]["component"]["properties"][2].update(value="0" * 64)),
    "sbom missing bundled package": lambda d: _mutate_json(d / "sbom-windows-x86_64.cdx.json", lambda x: x.update(components=[])),
    "wheel provenance mismatch": lambda d: _mutate_json(d / "python-dist-info.json", lambda x: x.update(commit="c" * 40)),
    "wheel bytes not the tested ones": lambda d: (d / RC.wheel_name(V)).write_bytes(b"PK-not-the-same"),
    "wheel install test not passed": lambda d: _mutate_json(d / "python-dist-info.json", lambda x: x.update(install_test="skipped")),
    "license differs from source": lambda d: (d / "LICENSE").write_text("other"),
}


@pytest.mark.parametrize("name", sorted(NEG))
def test_negative_contract_cases_stop_publication(assets, tmp_path, name, capsys):
    d, src = assets
    NEG[name](d)
    assert gate(d, src, tmp_path) == 1, name
    assert "RELEASE GATE FAILED" in capsys.readouterr().out
    assert not (tmp_path / "expected.json").exists()


def test_bad_version_tag_and_short_sha_rejected(assets, tmp_path):
    d, src = assets
    assert gate(d, src, tmp_path, tag="v0.3.1") == 1
    assert gate(d, src, tmp_path, commit="abc123") == 1
    assert gate(d, src, tmp_path, version="0.3") == 1


def _published_copy(d, tmp_path):
    out = tmp_path / "downloaded"
    shutil.copytree(d, out)
    return out


def test_uploaded_byte_verification(assets, tmp_path):
    d, src = assets
    assert gate(d, src, tmp_path) == 0
    exp = json.loads((tmp_path / "expected.json").read_text())
    dl = _published_copy(d, tmp_path)
    rel = {"tagName": f"v{V}", "isDraft": True, "assets": [{"name": n, "size": v["size"]} for n, v in exp["assets"].items()]}
    assert verify_release.verify(dl, exp, V, C, rel, want_draft=True) == []
    # draft expectation mismatch
    assert verify_release.verify(dl, exp, V, C, rel, want_draft=False)
    # consistent substitution: attacker replaces an archive AND rewrites SHA256SUMS -> caught by retained expectations
    a = dl / RC.archive_name(V, "linux-x86_64")
    a.write_bytes(b"evil-bytes-linux-x86_64")
    lines = [(RC.sha256(p), p.name) for p in sorted(dl.iterdir()) if p.name != "SHA256SUMS"]
    (dl / "SHA256SUMS").write_text("".join(f"{h}  {n}\n" for h, n in lines))
    errs = verify_release.verify(dl, exp, V, C)
    assert any("differs from the bytes built and tested" in e or "size" in e for e in errs)
    # missing file
    dl2 = tmp_path / "dl2"
    shutil.copytree(d, dl2)
    (dl2 / "smoke-linux-x86_64.log").unlink()
    assert any("missing after download" in e for e in verify_release.verify(dl2, exp, V, C))


# ---------------------------------------------------------------- F13
def test_f13_tree_fingerprint_detects_content_mode_and_symlink_changes(tmp_path):
    import smoke_test
    d = tmp_path / "bundle"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("AAAA")
    (d / "sub" / "b.bin").write_bytes(b"\x00\x01")
    h0 = smoke_test.tree_fingerprint(d)
    assert smoke_test.tree_fingerprint(d) == h0
    (d / "a.txt").write_text("BBBB")  # same length
    h1 = smoke_test.tree_fingerprint(d)
    assert h1 != h0
    if os.name != "nt":
        os.chmod(d / "a.txt", 0o755)
        assert smoke_test.tree_fingerprint(d) != h1
        os.symlink("a.txt", d / "link")
        h2 = smoke_test.tree_fingerprint(d)
        (d / "link").unlink()
        os.symlink("sub/b.bin", d / "link")
        assert smoke_test.tree_fingerprint(d) != h2
    (d / "sub" / "new").write_text("")
    assert smoke_test.tree_fingerprint(d) != h1


# ---------------------------------------------------------------- F11
def test_f11_release_workflow_uses_shared_preflight_and_pins_sha():
    import yaml
    wf = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    jobs = wf["jobs"]
    assert "preflight" in jobs
    pre_steps = json.dumps(jobs["preflight"]["steps"])
    assert "release_preflight.py" in pre_steps
    for name, job in jobs.items():
        if name == "preflight":
            continue
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        assert "preflight" in needs or any("preflight" in json.dumps(jobs[n].get("needs", [])) for n in needs), name
        for st in job.get("steps", []):
            if "actions/checkout" in str(st.get("uses", "")):
                assert st["with"]["ref"] == "${{ needs.preflight.outputs.sha }}", (name, st["with"])
    text = (ROOT / ".github/workflows/release.yml").read_text()
    assert "continue-on-error" not in text and "--prerelease" not in text
    assert "--verify-tag" in text and "verify_release.py" in text
    for w in (ROOT / ".github/workflows").glob("*.yml"):
        for line in w.read_text().splitlines():
            if "uses:" in line and "@" in line:
                ref = line.split("@", 1)[1].split()[0]
                assert len(ref) == 40, (w.name, line)
    ct = yaml.safe_load((ROOT / ".github/workflows/create-tag.yml").read_text())
    assert "release_preflight.py" in json.dumps(ct["jobs"])


def test_f11_preflight_logic(tmp_path):
    import release_preflight as P
    assert P.check_semver("0.3.0") and not P.check_semver("v0.3.0") and not P.check_semver("0.3")
    assert P.version_errors("0.3.0", {"pyproject": "0.3.0", "package": "0.3.0"}, notes_exist=True) == []
    assert P.version_errors("0.3.0", {"pyproject": "0.3.0", "package": "0.2.0"}, notes_exist=True)
    assert P.version_errors("0.3.0", {"pyproject": "0.3.0", "package": "0.3.0"}, notes_exist=False)
    runs = [{"head_sha": "a" * 40, "conclusion": "success", "status": "completed", "name": "CI", "event": "push"}]
    assert P.ci_errors("a" * 40, runs) == []
    assert P.ci_errors("b" * 40, runs)
    assert P.ci_errors("a" * 40, [dict(runs[0], conclusion="failure")])


def test_sbom_generation_and_validation_binding():
    import sbom
    info = {"version": V, "target": "linux-x86_64", "commit": C, "name": "x.tar.gz", "sha256": "1" * 64,
            "build_env": {"python": "3.12.9"}, "bundled_packages": [{"name": "Jinja2", "version": "3.1.6", "license": "BSD-3-Clause"}]}
    bom = sbom.make(info)
    assert sbom.validate(bom, info) == []
    bad = copy.deepcopy(bom)
    bad["components"] = [c for c in bad["components"] if c["name"] != "Jinja2"]
    assert sbom.validate(bad, info)
    assert sbom.validate(bom, dict(info, sha256="2" * 64))
