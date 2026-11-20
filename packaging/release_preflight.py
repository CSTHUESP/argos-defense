"""Shared release preflight (F11). Every release entry point calls this before building anything.

    # tag-triggered or dispatched release of an existing tag
    python packaging/release_preflight.py --mode release --tag v0.3.0
    # dry run: explicit full SHA, never publishes
    python packaging/release_preflight.py --mode dry-run --sha <40-hex>
    # tag helper: the tag must not exist yet
    python packaging/release_preflight.py --mode create-tag --version 0.3.0 --sha <40-hex>
    # immediately before draft creation / publication: the remote tag still names the same commit
    python packaging/release_preflight.py --mode recheck --tag v0.3.0 --expect-sha <40-hex>

The tag/ref is resolved ONCE to a full commit SHA; later jobs check out that SHA (never the moving
tag or branch). Checks: semantic version, version agreement (pyproject.toml, src/argos/__init__.py),
release notes present at that commit, commit is an ancestor of origin/main, and a successful CI run
(ci.yml) exists for that exact SHA. Writes sha/version/tag to $GITHUB_OUTPUT when available.
Requires: git with full history and tags fetched; `gh` authenticated with the workflow token.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def check_semver(v: str) -> bool:
    return bool(SEMVER.match(v or ""))


def version_errors(version: str, found: dict, notes_exist: bool) -> list[str]:
    errs = []
    if not check_semver(version):
        errs.append(f"version {version!r} is not MAJOR.MINOR.PATCH")
    for where, v in found.items():
        if v != version:
            errs.append(f"{where} version is {v!r}, expected {version!r}")
    if not notes_exist:
        errs.append(f"docs/release-notes/v{version}.md is missing at the release commit")
    return errs


def ci_errors(sha: str, runs: list[dict]) -> list[str]:
    ok = [r for r in runs if r.get("head_sha") == sha and r.get("status") == "completed" and r.get("conclusion") == "success"]
    return [] if ok else [f"no successful completed CI (ci.yml) run for {sha}"]


def git_env() -> dict:
    """Environment for git remote reads (R09, v0.3.1).

    Actions checkouts run with persist-credentials: false, and GH_TOKEN alone only authenticates `gh`;
    plain `git fetch`/`ls-remote` over HTTPS would be anonymous, which works for a public repository and
    fails for a private one. When GH_TOKEN is set, an Authorization header for https://github.com/ is
    passed through git's GIT_CONFIG_COUNT/KEY/VALUE environment variables: it never appears in argv, in a
    remote URL, in .git/config or in logs (Actions masks the token value), and it is scoped to this
    process tree. Interactive prompts are disabled so a missing credential fails fast."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        import base64
        basic = base64.b64encode(f"x-access-token:{tok}".encode()).decode()
        n = int(env.get("GIT_CONFIG_COUNT", "0") or 0)  # keep any entries the runner already configured
        env[f"GIT_CONFIG_KEY_{n}"] = "http.https://github.com/.extraheader"
        env[f"GIT_CONFIG_VALUE_{n}"] = f"AUTHORIZATION: basic {basic}"
        env["GIT_CONFIG_COUNT"] = str(n + 1)
    return env


def git(*args, check=True) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True, env=git_env())
    if check and r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def remote_tag_sha(tag: str) -> str | None:
    out = git("ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}", check=False)
    refs = dict(reversed(line.split("\t")) for line in out.splitlines() if "\t" in line)
    return refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")


def file_at(sha: str, path: str) -> str | None:
    r = subprocess.run(["git", "show", f"{sha}:{path}"], capture_output=True, text=True, env=git_env())
    return r.stdout if r.returncode == 0 else None


def versions_at(sha: str) -> dict:
    py = file_at(sha, "pyproject.toml") or ""
    ini = file_at(sha, "src/argos/__init__.py") or ""
    m1 = re.search(r'^version = "([^"]+)"', py, re.M)
    m2 = re.search(r'^__version__ = "([^"]+)"', ini, re.M)
    return {"pyproject": m1.group(1) if m1 else None, "package": m2.group(1) if m2 else None}


def ci_runs(sha: str) -> list[dict]:
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise SystemExit("GITHUB_REPOSITORY not set")
    r = subprocess.run(["gh", "api", f"repos/{repo}/actions/workflows/ci.yml/runs?head_sha={sha}&per_page=50"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"cannot query CI runs: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout).get("workflow_runs", [])


def emit(**kw):
    out = os.environ.get("GITHUB_OUTPUT")
    for k, v in kw.items():
        print(f"{k}={v}")
    if out:
        with open(out, "a") as fh:
            for k, v in kw.items():
                fh.write(f"{k}={v}\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["release", "dry-run", "create-tag", "recheck"])
    ap.add_argument("--tag")
    ap.add_argument("--sha")
    ap.add_argument("--version")
    ap.add_argument("--expect-sha")
    a = ap.parse_args(argv)
    errs: list[str] = []
    git("fetch", "--quiet", "--tags", "--force", "origin", "+refs/heads/main:refs/remotes/origin/main")

    if a.mode == "recheck":
        if not a.tag or not a.expect_sha:
            raise SystemExit("--tag and --expect-sha required")
        now = remote_tag_sha(a.tag)
        if now != a.expect_sha:
            print(f"PREFLIGHT FAILED: remote tag {a.tag} now names {now}, expected {a.expect_sha}")
            return 1
        print(f"remote tag {a.tag} still names {a.expect_sha}")
        return 0

    if a.mode == "release":
        if not a.tag or not a.tag.startswith("v"):
            raise SystemExit("--tag vX.Y.Z required")
        version, tag = a.tag[1:], a.tag
        sha = remote_tag_sha(tag)
        if not sha:
            errs.append(f"tag {tag} does not exist on the remote")
        else:
            local = git("rev-parse", f"refs/tags/{tag}^{{commit}}", check=False)
            if local != sha:
                errs.append(f"local tag {tag} ({local}) differs from remote ({sha})")
    elif a.mode == "dry-run":
        if not a.sha or not SHA40.match(a.sha):
            raise SystemExit("dry runs require an explicit full 40-hex --sha")
        sha = a.sha
        version = versions_at(sha)["pyproject"] or ""
        tag = f"v{version}"
    else:  # create-tag
        if not a.version or not a.sha or not SHA40.match(a.sha):
            raise SystemExit("--version and a full --sha are required")
        sha, version, tag = a.sha, a.version, f"v{a.version}"
        if remote_tag_sha(tag):
            errs.append(f"tag {tag} already exists - existing version tags are never moved")
    if sha:
        if git("cat-file", "-t", sha, check=False) != "commit":
            errs.append(f"{sha} is not a commit in this repository")
        else:
            if subprocess.run(["git", "merge-base", "--is-ancestor", sha, "origin/main"], env=git_env()).returncode != 0:
                errs.append(f"{sha} is not an ancestor of origin/main")
            errs += version_errors(version, versions_at(sha), file_at(sha, f"docs/release-notes/v{version}.md") is not None)
            errs += ci_errors(sha, ci_runs(sha))
    if errs:
        print("PREFLIGHT FAILED:\n  " + "\n  ".join(errs))
        return 1
    emit(sha=sha, version=version, tag=tag)
    print(f"preflight passed: {tag} -> {sha} ({a.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
