import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

baseline = pd.read_csv(BASE_DIR / "latency_baseline.csv")
ztna = pd.read_csv(BASE_DIR / "latency_ztna.csv")

baseline = baseline.dropna(subset=["latency_ms"])
ztna = ztna.dropna(subset=["latency_ms"])

plt.figure(figsize=(7, 3))

plt.plot(baseline["latency_ms"].values, label="Without ZTNA", linewidth=1.5)
plt.plot(ztna["latency_ms"].values, label="With ZTNA", linewidth=1.5)

plt.yscale("log")  # 🔥 CRITICAL FIX

plt.xlabel("Request Index")
plt.ylabel("Latency (ms, log scale)")
plt.title("Request Latency Comparison (Log Scale)")
plt.legend()
plt.grid(alpha=0.3, which="both")

plt.tight_layout()
plt.savefig(BASE_DIR / "latency_comparison.png", dpi=300)
plt.close()

