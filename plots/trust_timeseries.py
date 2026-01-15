import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from pathlib import Path

# -----------------------------
# Paths
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
CSV_PATH = BASE_DIR / "trust_timeseries.csv"
OUT_PATH = BASE_DIR / "trust_score_timeseries.png"

# -----------------------------
# Load + preprocess
# -----------------------------
df = pd.read_csv(CSV_PATH)

df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("timestamp")

# Reduce noise: keep only meaningful changes
df = df.loc[df["old_score"] != df["new_score"]]

# Optional: limit to recent window if needed
# df = df.tail(40)

# -----------------------------
# Plot (STEP = event-driven)
# -----------------------------
plt.figure(figsize=(7.2, 3.2))

plt.step(
    df["timestamp"],
    df["new_score"],
    where="post",
    linewidth=1.6
)

# Axis labels
plt.xlabel("Time")
plt.ylabel("Trust Score")

# Title (journal tone)
plt.title("Event-Driven Trust Score Evolution")

# Y-axis bounds = semantic meaning
plt.ylim(0.75, 1.02)
plt.yticks([0.8, 0.9, 1.0])

# Clean time formatting
ax = plt.gca()
ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))

plt.grid(True, linestyle="--", alpha=0.35)
plt.tight_layout()

plt.savefig(OUT_PATH, dpi=300)
plt.close()

print(f"[OK] Generated: {OUT_PATH}")
