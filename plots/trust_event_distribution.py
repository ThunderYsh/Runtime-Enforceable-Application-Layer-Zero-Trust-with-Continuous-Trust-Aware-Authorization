import matplotlib.pyplot as plt
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUT_PATH = BASE_DIR / "trust_event_distribution.png"

# Exact numbers from YOUR shell output
event_counts = {
    "blocked": 37,
    "trust_recovery_hourly": 243,
    "trust_recovery_safe": 213,
    "trust_recovery_mfa": 203,
    "night_access": 103,
    "mfa_fail": 63,
    "link_fail": 3,
}

plt.figure(figsize=(7, 3))
plt.bar(event_counts.keys(), event_counts.values())

plt.ylabel("Event Count")
plt.title("Distribution of Trust Events")
plt.xticks(rotation=45, fontsize=7)
plt.grid(axis="y", alpha=0.3)

plt.tight_layout()
plt.savefig(OUT_PATH, dpi=300)
plt.close()

print(f"[OK] Generated: {OUT_PATH}")
