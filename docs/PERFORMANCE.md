# Performance and supported limits (v0.3.0)

Reproduce: `python scripts/benchmark.py --sizes 12000 100000 [1000000] --out reports/benchmark.json`.

## Method
- Dataset: `argos.synthetic.generate_bulk` — deterministic synthetic mix of HTTP, authentication, DNS, network-connection and process-start records (seed 7), several hundred identities. It is background-style data; alert counts are not meaningful.
- Each phase (generate, ingest, analyze) runs in a child process; the parent samples its resident set size every 0.25 s and stops it when the budget below is exceeded. A stopped or crashed phase is recorded as a failure, never as a result.
- **Budgets declared before running** (`scripts/benchmark.py: BUDGETS`): 12k — ingest 60 s / 1 GiB, analyze 120 s / 1.5 GiB; 100k — ingest 300 s / 2 GiB, analyze 900 s / 4 GiB; 1M — ingest 1800 s / 4 GiB, analyze 3600 s / 6 GiB.
- Hardware: build sandbox, Linux x86_64 (glibc 2.39), 2 vCPU, 8,216,636 kB RAM visible with a ~7 GiB memory cgroup limit, Python 3.13.18. Single run per size.

## Results (2026-11-20)
| Events | Input file | Ingest | Ingest peak RSS | Analyze | Analyze peak RSS | Database | Outcome |
|---|---|---|---|---|---|---|---|
| 12,000 | 2.1 MiB | 0.8 s | 29 MiB | 1.8 s | 137 MiB | 37 MiB | within budget |
| 100,000 | 17.7 MiB | 7.3 s | 29 MiB | 21.3 s | 836 MiB | 283 MiB | within budget |
| 1,000,000 | 176.7 MiB | 114.2 s | 29 MiB | **failed** after 215.6 s | 6,116 MiB when killed | 2,078 MiB | **analysis killed by the kernel's memory-cgroup OOM killer** (just below the 6 GiB budget) |

Ingest streams records in chunks (constant memory). Analysis loads all active events of a case into memory and evaluates every rule over them; peak memory grows roughly linearly (~8–9 KiB per event on this dataset).

## Supported limits
- **Analysis: up to 300,000 active events per case** (default `ARGOS_MAX_ANALYSIS_EVENTS=300000`, extrapolated ≈ 2.5 GiB peak). Larger cases are refused before any work starts with a clear error that suggests splitting the case; the previous successful run is kept. 1,000,000 events is **not supported** on a 7–8 GiB machine (measured failure above).
- Import file size: 200 MiB per file by default (`ARGOS_MAX_FILE_BYTES`).
- The web UI stays responsive during analysis because analysis runs in a background job with its own database connection; conflicting operations on the same case (a second analysis, import, reprocess or activation) are refused while it runs.
- These numbers come from one synthetic dataset on one machine; rule mix, entity cardinality and record size change them.
