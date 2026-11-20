# Dependencies, locks and vulnerability review

## Files
| File | Role |
|---|---|
| `requirements.in` | Runtime top-level exact pins (input). |
| `requirements-dev.in` | Test tooling pins (input). |
| `requirements-build.in` | Native packaging / smoke-test / build-backend pins (PyInstaller, build, Playwright, setuptools, wheel). |
| `requirements.lock` | **Generated.** Universal (Windows, Linux, macOS; Python ≥ 3.11) resolution of `requirements.in` with SHA-256 hashes for every distribution file and platform markers (e.g. `tzdata`, `colorama` on Windows). |
| `requirements-ci.lock` | **Generated.** Same for runtime + test + build tooling together; used by CI and release builds with `pip install --require-hashes`. |

Generation: `.github/workflows/deps.yml` (manual dispatch and monthly schedule) runs `uv pip compile --universal --generate-hashes --python-version 3.11` and `pip-audit --require-hashes --disable-pip --no-deps` on both locks, prints the locks and the audit summary to the job log and uploads them as an artifact. A maintainer reviews the diff and commits the regenerated locks. Wheel and sdist builds use `python -m build --no-isolation` so the build backend comes from the hashed lock.

The actually resolved environment of every native build is additionally recorded in that target's `build-info-*.json` (`build_env.build_venv_packages`) and its SBOM.

Pinned versions do **not** make native binaries bit-for-bit reproducible (PyInstaller bootloader, timestamps, OS toolchains and code-signing metadata differ between builds).

## Review log
| Date (UTC) | Tools | Result | Action |
|---|---|---|---|
| 2026-11-20 13:12 | uv 0.13.9, pip-audit 2.10.1 (PyPI advisory data via OSV at run time) — run 44742521205 | `setuptools==84.0.0` (build tooling only): **GHSA-xmj3-9gf7-h52w**. Runtime and test sets: no known findings. | Moved build backend pin to `setuptools==84.2.1`. |
| 2026-11-20 13:17 | same — run 44743018079 | `requirements.lock` 17 packages, `requirements-ci.lock` 32 packages: **no known vulnerabilities in the queried databases**. | Locks committed. |

"No known findings" means no advisory matched in the databases queried at that time; it is not proof that the dependencies are free of vulnerabilities.

## Coverage limits of the inventory
- The SBOM (CycloneDX 1.5, one per native target) lists ARGOS, the Python distributions bundled by PyInstaller and the embedded CPython version. It does not enumerate operating-system libraries, the PyInstaller bootloader's internals, or C libraries vendored inside wheels (e.g. OpenSSL inside CPython builds, libyaml if present). pip-audit covers Python distributions only.
- SBOM validation (`packaging/sbom.py --validate`, release contract) is structural (required fields, purls, licences) and binds the SBOM to the archive hash, target and commit; it is not a full JSON-Schema validation against the official CycloneDX schema.
- Native component vulnerabilities (CPython runtime, bootloader) are reviewed only through the CPython version recorded in the SBOM.

## Updating
1. Edit the relevant `*.in` pin.
2. Dispatch **Dependency locks and vulnerability review** (`deps.yml`), review the audit summary and the lock diff.
3. Commit the regenerated `requirements.lock` / `requirements-ci.lock`; CI installs with `--require-hashes` and will fail on any mismatch.
4. Add an entry to the review log above; justify any accepted finding (affected component, exposure, mitigation, review date).
