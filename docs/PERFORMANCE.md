# Performance and supported limits (v0.3.1)

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

## v0.3.1 stress-profile measurement (R08)
Reproduce: `python scripts/benchmark.py --profile stress --sizes 100000 300000 --out reports/benchmark_stress_v031.json`.
- **Profile** (`argos.synthetic.generate_stress`, seed 11): 9 event kinds (HTTP with long URIs and user agents, authentication over 5 tenants, DNS, endpoint network connections, process starts with long command lines, service-principal cloud operations, model interactions, tool executions, file creation), timestamps over 7 days, mean record 283–284 bytes.
- **Cardinality:** users = n/20, hosts = n/60, applications = n/300. That is 15,000 users, 5,000 hosts and 1,000 apps at 300k, giving 489,213 entities in the store.
- **Alert density:** low. Background-style data produced 2 alerts.
- **Budgets declared before the first stress run** (`STRESS_BUDGETS`): 100k — ingest 600 s / 2 GiB, analyze 1200 s / 4 GiB; 300k — ingest 1500 s / 2 GiB, analyze 2400 s / 5 GiB.
- **Environment:** the same sandbox as above (2 vCPU, 8,216,636 kB visible RAM, ~7 GiB effective limit; `/sys/fs/cgroup/memory.max` not exposed). Linux x86_64, glibc 2.39, Python 3.13.18, starlette 1.7.0, pydantic 2.13.5, PyYAML 6.0.3. Source commit `8060244`, not modified during the run. Single run per size.

| Events | Input | Ingest | Ingest peak RSS | Analyze | Analyze peak RSS | Database | Entities | Run status / integrity |
|---|---|---|---|---|---|---|---|---|
| 100,000 (stress) | 27.0 MiB | 8.0 s | 29 MiB | 20.3 s | 937 MiB | 339 MiB | 164,271 | succeeded / `integrity_check ok`, alerts stored = alerts produced |
| 300,000 (stress) | 81.3 MiB | 29.6 s | 29 MiB | 69.4 s | **2,759 MiB** | 1,020 MiB | 489,213 | succeeded / `integrity_check ok` |

## Supported limits (capacity decision)
- **Configured cap:** `ARGOS_MAX_ANALYSIS_EVENTS` = 300,000 active events per case. Larger cases are refused before any work starts, and the previous successful run is kept.
- **Measured successful workload:** 300,000 events of the stress profile above analysed in 69 s with a 2.8 GiB peak, on one 2-vCPU machine. This is a measured result for that profile, not a guarantee for every 300,000-event case. Workloads with many alerts, much larger records or higher cardinality were **not** measured at this size, and memory grows roughly linearly with active events (~9.4 KiB per event here).
- **Resource recommendation:** at least 4 GiB of free RAM per concurrent analysis for cases near the cap. The default global concurrency is 1 (`ARGOS_MAX_CONCURRENT_JOBS`), with up to 8 queued analyses (`ARGOS_MAX_QUEUED_JOBS`). Raise concurrency only with proportionally more memory.
- **Not supported:** 1,000,000 events (measured failure above), and multiple server processes on one data directory (refused through a file lock).
- Import file size: 200 MiB per file by default (`ARGOS_MAX_FILE_BYTES`).
- The web UI stays responsive during analysis: jobs run in the background with their own database connection, are admitted first-in first-out under the global limit, and conflicting operations on the same case are refused while a job is queued or running.
