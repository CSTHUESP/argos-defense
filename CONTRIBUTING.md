# Contributing

## Development setup
```bash
python3 -m venv .venv && source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.lock -r requirements-dev.lock
pip install --no-deps -e .
python -m pytest
python scripts/validate.py          # synthetic demo scenarios
python scripts/auth_eval.py         # labeled auth-rule evaluation (tuning + held-out)
```
Native package locally (on the OS/arch you are on): `pip install -r requirements-build.lock && python packaging/build_native.py --out dist-native`, then `python -m playwright install chromium` and `python packaging/smoke_test.py --archive dist-native/<archive>`.

## Rules of the project
- Keep the six assessment dimensions separate; never infer a person, group, nationality or exact model.
- Every rule declares vantage, required telemetry, reference type, alternatives, false positives, sources and validation status. Add positive **and** negative tests.
- Do not change test expectations to make a failing change pass; fix the cause or document a justified fixture correction in the commit message.
- Synthetic data uses RFC 5737 addresses and invented names; ground truth stays in `fixtures/ground_truth/` and must never be imported.
- Do not commit data directories, databases, tokens, `.venv`, or `reference/ARTEX` (AGPL; retrieve with `scripts/fetch_artex_reference.sh`). Never copy ARTEX code into ARGOS.
- Releases are cut only by `.github/workflows/release.yml` from a tag; published tags are never moved.
