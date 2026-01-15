import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

baseline = pd.read_csv(BASE_DIR / "latency_baseline.csv")["latency_ms"].dropna()
ztna = pd.read_csv(BASE_DIR / "latency_ztna.csv")["latency_ms"].dropna()

def compute_cdf(data):
    x = np.sort(data)
    y = np.arange(1, len(x) + 1) / len(x)
    return x, y

x_base, y_base = compute_cdf(baseline)
x_ztna, y_ztna = compute_cdf(ztna)

plt.figure(figsize=(6, 4))
plt.plot(x_base, y_base, label="Baseline (No ZTNA)", linewidth=2)
plt.plot(x_ztna, y_ztna, label="ZTNA Enabled", linewidth=2)

plt.xlabel("Latency (ms)")
plt.ylabel("Cumulative Probability")
plt.title("CDF of Request Latency")
plt.legend()
plt.grid(alpha=0.3)

plt.tight_layout()
plt.savefig(BASE_DIR / "latency_cdf.png", dpi=300)
plt.close()

print("[OK] Generated latency_cdf.png")
