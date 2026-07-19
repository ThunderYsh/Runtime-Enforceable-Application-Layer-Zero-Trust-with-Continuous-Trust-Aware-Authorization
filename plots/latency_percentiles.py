"""
plots/latency_percentiles.py

Computes p50/p95/p99 from the real captured latency CSVs and prints a
LaTeX table (Table V equivalent). Run after ab_latency_harness.py +
extract_latency_csv.py have produced fresh latency_baseline.csv /
latency_ztna.csv.
"""

import sys
import numpy as np
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.stdout.reconfigure(encoding="utf-8")

baseline = pd.read_csv(BASE_DIR / "latency_baseline.csv")["latency_ms"].dropna()
ztna = pd.read_csv(BASE_DIR / "latency_ztna.csv")["latency_ms"].dropna()


def pct(series, q):
    return float(np.percentile(series, q))


rows = [
    ("Baseline (No ZTNA)", baseline),
    ("ZTNA Enabled", ztna),
]

print("=== Latency Percentiles (real captured data) ===")
for label, series in rows:
    print(f"{label}: N={len(series)}  p50={pct(series,50):.2f}ms  "
          f"p95={pct(series,95):.2f}ms  p99={pct(series,99):.2f}ms  "
          f"max={series.max():.2f}ms")

latex = r"""
\begin{table}[htbp]
\centering
\caption{Latency Percentile Comparison Between Baseline and ZTNA-Enabled Execution}
\label{tab:latency_percentiles}
\begin{tabular}{lccc}
\toprule
\textbf{Configuration} & \textbf{p50 (ms)} & \textbf{p95 (ms)} & \textbf{p99 (ms)} \\
\midrule
""" + \
    f"Baseline (No ZTNA) & {pct(baseline,50):.2f} & {pct(baseline,95):.2f} & {pct(baseline,99):.2f} \\\\\n" + \
    f"ZTNA Enabled & {pct(ztna,50):.2f} & {pct(ztna,95):.2f} & {pct(ztna,99):.2f} \\\\\n" + \
    r"""\bottomrule
\end{tabular}
\end{table}
"""

print("\n" + latex)

with open(BASE_DIR / "latency_percentiles_latex.txt", "w", encoding="utf-8") as f:
    f.write(latex)
print("Saved: latency_percentiles_latex.txt")
