# Evaluation scripts for the JISA revision

These scripts produce every number, table and figure in the evaluation of *Runtime-Enforceable Application-Layer Zero Trust with Continuous Trust-Aware Authorization*. Section numbers refer to the revised manuscript.

## Execution traces (Section X)

The evaluation uses a frozen copy of the prototype database. Every record after 19 Jul 2026 07:17:15 UTC was removed from the copy.

| Script | Produces |
|---|---|
| `freeze_and_extract.py` | The frozen snapshot, every count in Table X, and Figs. 10–12. `snapshot_manifest.json` records the snapshot's SHA-256 digest. |
| `fig_trust_timeseries_r3.py` | Fig. 9 (trust score per account). |

The snapshot itself is not published because it contains authentication secrets (TOTP seeds). Its digest is given in the paper and in `snapshot_manifest.json`.

## Simulation (Section VI-H)

| Script | Produces |
|---|---|
| `sensitivity_v2.py` | Table VI and Fig. 5 (`sensitivity_v2_results.json`). |
| `replicate_v1.py` | A replication of the previous version's simulation, showing why its 0% false-positive rate held by construction (`v1_replication.json`). |

## Latency (Section VIII)

| Script | Produces |
|---|---|
| `bench_latency_r3.py` | The benchmark runs in three server configurations (`ZTNA_BENCH_MODE` = `none`, `no_middleware` or `full`), against copies of the snapshot. |
| `analyze_bench_r3.py` | Statistics and Figs. 7–8 (`bench_r3/latency_r3_stats.json`). |
| `latency_macros_r3.py` | The latency numbers used in the paper text, generated from the statistics file. |
| `count_queries_r3.py` | Table VIII, database statements per request (`query_counts_r3.jsonl`). |
| `profile_request_r3.py` | The profiling cited in Section VIII-B. |
| `latency_stats_r3.py` | A re-analysis of the previous version's latency captures (`latency_stats_r3.json`). |

`bench_r3_discarded_attempt1/` holds the summary of an earlier run. It was abandoned because the host entered standby, and its results are not used in the paper.

## Figures of the system (Figs. 1–4 and 6)

`fig_architecture_r3.py` and `fig_components_r3.py` draw the architecture, application, TrustBroker, policy-engine and request-flow diagrams. They show only components that exist in the code.

## Running

Use the project's Python environment and run each script from `ztna_proj/`. Scripts that read the database need `db.sqlite3` or the frozen snapshot, neither of which is distributed. The benchmark seeds a throwaway account (`seed_bench_user.py`) in a copy of the database only.
