import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = BASE_DIR / "latency_ztna.csv"
OUT_PNG = BASE_DIR / "latency_with_ztna.png"

df = pd.read_csv(CSV_FILE)

# Clean
df = df.dropna(subset=["latency_ms"])

plt.figure(figsize=(7, 3))
plt.plot(df["latency_ms"].values, linewidth=1.5)

plt.xlabel("Request Number")
plt.ylabel("Latency (ms)")
plt.title("Request Latency with ZTNA Enforcement")
plt.grid(alpha=0.3)

plt.tight_layout()
plt.savefig(OUT_PNG, dpi=300)
plt.close()

print(f"[OK] Generated {OUT_PNG}")
