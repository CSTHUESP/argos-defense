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
| `SHA256SUMS`, `release-manifest.json` | release job | hashes of every published file; versions, commit, targets, smoke results, signing status |

Each native target is built **on its own OS/architecture**; the workflow fails if `runner.arch` does not match the target. Nothing is cross-compiled or renamed.

## Build (`packaging/build_native.py`)
1. `pyinstaller packaging/argos.spec` (onedir, console app, `upx=False`). Templates, static files, rules, default config and notices are added at the same package-relative paths used by source and wheel installs; `argos.resources` resolves them relative to the module, never the working directory.
2. Launcher scripts, `README-FIRST.txt`, `LICENSE`, `THIRD_PARTY_NOTICES.md` are added.
3. `packaging/collect_licenses.py` copies the license files of every bundled distribution (runtime closure of `argos-defense`) and the CPython license into `licenses/`; the build fails if any is missing.
4. The archive is written and hashed; `build-info-<target>.json` records the build environment and the bundled package list.

Pinned inputs: `requirements.lock` (runtime, with Windows-only `tzdata`/`colorama`), `requirements-dev.lock`, `requirements-build.lock` (PyInstaller 6.22.3, build 1.6.1, Playwright 1.65.2). The fully resolved build environment of each target is recorded in its build-info.

## Runtime behaviour of the frozen app
- No arguments → `start` (opens the browser). The frozen executable never re-invokes `sys.executable` as a Python interpreter.
- Mutable data only in the data directory (`--data-dir`, `ARGOS_HOME`, or the platform default); the smoke test verifies the bundle tree is unchanged after a full run.
- Loopback only; `--port 0` picks a free port; an occupied port exits with code 3 and a clear message; `POST /api/shutdown` (authenticated) stops cleanly; Ctrl+C also works.

## Native smoke test (`packaging/smoke_test.py`) — release gate
Runs on the build runner against the **extracted archive**, in a directory whose path contains spaces and non-ASCII characters, with `PYTHON*`, `VIRTUAL_ENV`, `ARGOS_*` removed from the environment and the harness venv removed from `PATH`. Checks (all must pass; ≥20 checks):
executable present/executable bit, `--version` reports `frozen=True`, `doctor` (all bundled resources), `demo`, `ingest` (Sysmon XML with non-ASCII file name), `analyze`, alerts, HTML + JSON report, occupied-port error, authenticated/unauthenticated API, **Playwright Chromium**: login form, create-case form (CSRF), multipart import form, analyze button, alert detail dimensions, note form, evidence page, HTML export download, static assets, no console errors; clean API shutdown; restart with the same data dir and verify cases/alerts/notes persist; bundle unchanged; session token absent from logs.
The harness and Playwright run in the runner's Python; the application under test is the native executable.

## Signing status
- Windows: **not Authenticode-signed** (no certificate configured). SmartScreen may warn; verify `SHA256SUMS` first.
- macOS: **ad-hoc signature only** (applied by PyInstaller); **not Developer ID signed, not notarized**. Gatekeeper may block the first launch of a downloaded copy; Apple's documented path is System Settings → Privacy & Security → *Open Anyway*.
- Linux: not signed.
- GitHub artifact attestations: not generated — for private repositories they require GitHub Enterprise Cloud (GitHub docs). Checksums give integrity, not publisher authenticity.

## Release procedure
1. Merge to `main`; CI green. Optional: dispatch `release.yml` with `dry_run=true` (builds, smoke-tests, runs the gate; creates nothing).
2. Create an annotated tag `vX.Y.Z` on the reviewed commit and push it. `release.yml` builds/tests all four targets, runs the gate (`packaging/release_manifest.py`: all targets present, same commit, smoke-tested on the exact archive bytes) and creates a **draft** release with `gh release create --verify-tag --draft`, then downloads the draft's assets and checks them against `SHA256SUMS`.
3. After reviewing the draft, publish it (`gh release edit vX.Y.Z --draft=false`). Published tags/assets are never replaced; fixes ship as a new version.
