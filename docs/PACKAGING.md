# Packaging

## Artifacts per release
| Asset | Built on | Contents |
|---|---|---|
| `ARGOS-Defense-<v>-windows-x86_64.zip` | `windows-2022` (x64) | PyInstaller onedir `argos-defense/argos-defense.exe`, `Start ARGOS Defense.cmd`, `README-FIRST.txt`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `licenses/` |
| `ARGOS-Defense-<v>-linux-x86_64.tar.gz` | `ubuntu-22.04` (x64, glibc 2.35 baseline) | onedir `argos-defense/argos-defense`, `start-argos-defense.sh` (exec bits preserved by tar) |
| `ARGOS-Defense-<v>-macos-arm64.zip` | `macos-15` (Apple Silicon) | onedir + `Start ARGOS Defense.command` (archived with `ditto`) |
| `ARGOS-Defense-<v>-macos-x86_64.zip` | `macos-15-intel` (Intel) | onedir + `Start ARGOS Defense.command` |
| `argos_defense-<v>-py3-none-any.whl`, `argos_defense-<v>.tar.gz` | `ubuntu-22.04` | source install options |
| `build-info-<target>.json`, `sbom-<target>.cdx.json`, `smoke-<target>.json/.log` | per target | build environment, bundled packages, CycloneDX SBOM, native smoke-test results (tokens redacted) |
| `python-dist-info.json` | wheel/sdist job | commit, version, SHA-256 of the wheel and sdist that were install-tested |
| `LICENSE`, `THIRD_PARTY_NOTICES.md` | source commit | licence texts (must equal the tagged source) |
| `SHA256SUMS`, `release-manifest.json` | gate job | hashes of every other asset; versions, commit, targets, smoke results, signing/attestation status |

The exact set (27 files) and the checks applied to each are defined in `packaging/release_contract.py`.

Each native target is built **on its own OS/architecture**; the workflow fails if `runner.arch` does not match the target. Nothing is cross-compiled or renamed.

## Build (`packaging/build_native.py`)
1. `pyinstaller packaging/argos.spec` (onedir, console app, `upx=False`). Templates, static files, rules, default config and notices are added at the same package-relative paths used by source and wheel installs; `argos.resources` resolves them relative to the module, never the working directory.
2. Launcher scripts, `README-FIRST.txt`, `LICENSE`, `THIRD_PARTY_NOTICES.md` are added.
3. `packaging/collect_licenses.py` copies the license files of every bundled distribution (runtime closure of `argos-defense`) and the CPython license into `licenses/`; the build fails if any is missing.
4. The archive is written and hashed; `build-info-<target>.json` records the build environment and the bundled package list.

Pinned inputs: `requirements-ci.lock` — universal hashed resolution of runtime, test and build tooling (PyInstaller 6.22.3, build 1.6.1, Playwright 1.65.2, setuptools 84.2.1, wheel 0.48.0) installed with `pip install --require-hashes`; wheels/sdists are built with `--no-isolation` so the backend also comes from the lock (docs/DEPENDENCIES.md). The fully resolved build environment of each target is recorded in its build-info. Pinning does not make binaries bit-for-bit reproducible.

## Runtime behaviour of the frozen app
- No arguments → `start` (opens the browser). The frozen executable never re-invokes `sys.executable` as a Python interpreter.
- Mutable data only in the data directory (`--data-dir`, `ARGOS_HOME`, or the platform default); the smoke test verifies the bundle tree is unchanged after a full run.
- Loopback only; `--port 0` picks a free port; an occupied port exits with code 3 and a clear message; `POST /api/shutdown` (authenticated) stops cleanly; Ctrl+C also works.

## Native smoke test (`packaging/smoke_test.py`) — release gate
Runs on the build runner against the **extracted archive**, in a directory whose path contains spaces and non-ASCII characters, with `PYTHON*`, `VIRTUAL_ENV`, `ARGOS_*` removed from the environment and the harness venv removed from `PATH`. Every check must pass, and the release contract requires every check identity listed in `release_contract.required_checks(target)` (46 on Windows, 48 on POSIX targets):
- archive: executable present, executable bit (POSIX), `--version` reports `frozen=True`, `doctor`, `demo`, Sysmon XML ingest with a non-ASCII file name, `analyze`, alerts, IANA time zones, HTML + JSON reports, occupied-port error, authenticated / unauthenticated API;
- **Playwright Chromium** against the native server: login form, create-case form (CSRF), multipart import form, analyze button → background job page → case, alert detail dimensions, note form, evidence page showing the exact original record, HTML export download, static assets, no console errors;
- clean API shutdown, restart with the same data dir (cases/alerts/notes persist);
- **distributed launcher** (`Start ARGOS Defense.cmd` / `.command` / `start-argos-defense.sh`) with `ARGOS_HOME` in a non-ASCII path: `--no-browser` start and clean shutdown; default start opens the browser through the `BROWSER` environment variable (a recorder script) with a loopback login URL;
- **update**: a v0.2.0 database (synthetic demo, `packaging/fixtures/legacy-v0.2.0-demo.sql.gz`, produced by the v0.2.0 code) is migrated with a verified backup, legacy runs are labelled, re-analysis works;
- **backup / verify / restore** into a new non-ASCII directory, restored alerts readable, restore into a non-empty directory refused;
- bundle unchanged (content hash of every file, modes and symlink targets), session tokens absent from logs.

The harness and Playwright run in the runner's Python; the application under test is the native executable. The browser opening check uses `BROWSER`, so it verifies ARGOS's launch path, not a desktop's default-browser association.

## Desktop acceptance procedure (pending)
Not performed for 0.3.0 (no desktop machines available). On a clean, standard-user Windows 11 / macOS / Linux desktop without Python:
1. Download the archive with a normal browser (to keep quarantine/mark-of-the-web attributes) and verify its SHA-256 against `SHA256SUMS`.
2. Extract it to a folder whose path contains spaces and non-ASCII characters; double-click the launcher (Linux: run the `.sh`).
3. Record the exact SmartScreen/Gatekeeper prompts. Use only the platform's documented opening procedure; do not disable protections.
4. Confirm the browser opens logged in; run *demo*, import `fixtures/demo/endpoint_sysmon.xml`, analyze, open an alert and an evidence record, export HTML; stop with Ctrl+C or by closing the window; restart and check persistence.
5. Record OS edition/version/build, architecture, install path and results in docs/RELEASE_VALIDATION.md.

## Signing status
- Windows: **not Authenticode-signed** (no certificate available). SmartScreen may warn; verify `SHA256SUMS` first. Do not disable SmartScreen or antivirus.
- macOS: **ad-hoc signature only** (applied by PyInstaller); **not Developer ID signed, not notarized**. Gatekeeper may block the first launch of a downloaded copy; Apple's documented path is System Settings → Privacy & Security → *Open Anyway*.
- Linux: not signed.
- GitHub artifact attestations (SLSA build provenance via `actions/attest-build-provenance`): generated for the native archives, wheel and sdist when the repository is public, and verified with `gh attestation verify` after download; for private repositories they require GitHub Enterprise Cloud and are skipped. `release-manifest.json` records the status. Checksums give integrity, not publisher authenticity.
- Secure integration for real certificates (not configured): Authenticode signing with `signtool` and an organization certificate stored as an encrypted Actions secret in a protected environment, before archiving; Apple `codesign --options runtime` with a Developer ID certificate, `notarytool submit --wait` and `stapler staple`, before archiving. Signing must happen before the smoke test and before hashes are computed.

## Release procedure
1. Merge to `main`; CI (`ci.yml`) must be green **for that exact commit**. Optional: dispatch `release.yml` with `dry_run=true` and `sha=<full SHA>` (builds, smoke-tests and runs the release contract; never creates a release).
2. Create the tag with **Create release tag** (`create-tag.yml`, inputs `version`, `commit`, optional `publish`). It runs `packaging/release_preflight.py --mode create-tag` (semantic version, pyproject/package version equal to the input, release notes present at the commit, commit on `main`, successful CI for that SHA, tag not existing), pushes an annotated tag, re-checks it on the remote and dispatches `release.yml`. A maintainer may instead push the tag; `release.yml` runs the same preflight.
3. `release.yml`: **preflight** resolves the tag once to a full SHA; native builds (4 runners), wheel/sdist and the gate all check out that SHA. The **gate** enforces the full contract and records the expected name/size/SHA-256 of every asset (including SHA256SUMS) *before* upload. The **draft** job re-checks the remote tag, refuses an existing release, runs `gh release create --verify-tag --draft`, downloads the draft and verifies it against the retained expectations (`packaging/verify_release.py`), and verifies attestations when generated.
4. With `publish=true`, the **publish** job re-checks the tag and the draft bytes once more, publishes, then downloads the published release (and, for public repositories, every anonymous download URL) and verifies again.
5. Published tags and assets are never moved or replaced; a change to published bytes requires a new version.
