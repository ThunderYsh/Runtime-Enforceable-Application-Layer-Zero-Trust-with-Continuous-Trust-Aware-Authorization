"""
run_sensitivity_analysis.py
===========================
Reviewer #1 Comment 1 + Reviewer #2 Comment 3
----------------------------------------------
Runs a sensitivity analysis over mfa_fail penalty values.
Simulates N sessions with a mix of benign / adversarial events
and measures: enforcement trigger counts, average trust, false-positive
rate (benign user hits restricted-mode).

Usage:
    python run_sensitivity_analysis.py

Output:
    sensitivity_results.csv   — raw data for each penalty set
    sensitivity_summary.csv   — aggregated table ready for the paper
    sensitivity_plot.png      — bar chart (Penalty vs Enforcement Actions)
"""

import csv
import random
import math
import os

# ── reproducibility ──────────────────────────────────────────────────────────
random.seed(42)

# ── penalty sets to test ─────────────────────────────────────────────────────
PENALTY_SETS = [
    {"label": "Set A (α=0.03)", "mfa_fail": 0.03, "bad_password": 0.08,
     "blocked": 0.10, "link_fail": 0.07},
    {"label": "Set B (α=0.06, baseline)", "mfa_fail": 0.06, "bad_password": 0.08,
     "blocked": 0.10, "link_fail": 0.07},
    {"label": "Set C (α=0.10)", "mfa_fail": 0.10, "bad_password": 0.08,
     "blocked": 0.10, "link_fail": 0.07},
    {"label": "Set D (α=0.15)", "mfa_fail": 0.15, "bad_password": 0.08,
     "blocked": 0.10, "link_fail": 0.07},
]

# ── recovery values (fixed across all sets) ──────────────────────────────────
RECOVERY_HOURLY   = 0.02
RECOVERY_SAFE     = 0.02
RECOVERY_MFA      = 0.10

# ── simulation parameters ─────────────────────────────────────────────────────
TRUST_INIT        = 0.70
RESTRICT_THRESH   = 0.60
BLOCK_THRESH      = 0.30
N_SESSIONS        = 200          # total simulated sessions
EVENTS_PER_SESSION = 20          # events per session
ADVERSARIAL_RATIO  = 0.35        # 35% sessions are adversarial

# ── event distribution for adversarial session ────────────────────────────────
ADV_EVENT_DIST  = ["mfa_fail"] * 4 + ["bad_password"] * 3 + ["link_fail"] * 2 + \
                  ["safe_action"] * 6 + ["mfa_success"] * 2 + ["idle"] * 3
# ── event distribution for benign session ─────────────────────────────────────
BENIGN_EVENT_DIST = ["safe_action"] * 12 + ["mfa_success"] * 4 + \
                    ["idle"] * 4

def clamp(v):
    return max(0.0, min(1.0, round(v, 4)))

def simulate_session(penalty_map, is_adversarial):
    trust = TRUST_INIT
    dist  = ADV_EVENT_DIST if is_adversarial else BENIGN_EVENT_DIST

    mfa_triggers    = 0
    restrict_hits   = 0
    block_hits      = 0

    for _ in range(EVENTS_PER_SESSION):
        event = random.choice(dist)

        # apply penalty or recovery
        if event in penalty_map:
            trust = clamp(trust - penalty_map[event])
        elif event == "safe_action":
            trust = clamp(trust + RECOVERY_SAFE)
        elif event == "mfa_success":
            trust = clamp(trust + RECOVERY_MFA)
        # idle: no change

        # enforcement check
        if trust <= BLOCK_THRESH:
            block_hits += 1
        elif trust <= RESTRICT_THRESH:
            restrict_hits += 1
            # step-up MFA triggered
            mfa_triggers += 1

    return trust, mfa_triggers, restrict_hits, block_hits

def run_analysis():
    rows = []          # per-session rows for CSV
    summary = []       # aggregated

    for pset in PENALTY_SETS:
        label       = pset["label"]
        penalty_map = {k: v for k, v in pset.items() if k != "label"}

        all_trust     = []
        total_mfa     = 0
        total_restrict = 0
        total_block   = 0
        fp_sessions   = 0   # benign session that hit restricted mode

        for i in range(N_SESSIONS):
            is_adv = (i < int(N_SESSIONS * ADVERSARIAL_RATIO))
            final_trust, mfa_t, restr, blk = simulate_session(penalty_map, is_adv)

            all_trust.append(final_trust)
            total_mfa     += mfa_t
            total_restrict += restr
            total_block   += blk

            if not is_adv and restr > 0:
                fp_sessions += 1

            rows.append({
                "penalty_set": label,
                "session_id": i,
                "adversarial": is_adv,
                "final_trust": final_trust,
                "mfa_triggers": mfa_t,
                "restrict_hits": restr,
                "block_hits": blk,
            })

        n    = len(all_trust)
        mean = sum(all_trust) / n
        var  = sum((x - mean) ** 2 for x in all_trust) / (n - 1)
        std  = math.sqrt(var)
        # 95% CI
        se   = std / math.sqrt(n)
        ci95 = 1.96 * se

        benign_sessions  = N_SESSIONS - int(N_SESSIONS * ADVERSARIAL_RATIO)
        fp_rate = fp_sessions / benign_sessions if benign_sessions else 0

        summary.append({
            "penalty_set":      label,
            "mfa_fail_penalty": pset["mfa_fail"],
            "avg_trust_mean":   round(mean, 4),
            "avg_trust_ci95":   round(ci95, 4),
            "total_mfa_triggers":   total_mfa,
            "total_restrict_hits":  total_restrict,
            "total_block_hits":     total_block,
            "fp_rate":          round(fp_rate, 4),
        })

    return rows, summary

def write_csvs(rows, summary):
    with open("sensitivity_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    with open("sensitivity_summary.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary[0].keys())
        writer.writeheader()
        writer.writerows(summary)

    print("=== Sensitivity Analysis Summary ===")
    for r in summary:
        print(f"\n{r['penalty_set']}")
        print(f"  MFA penalty       : {r['mfa_fail_penalty']}")
        print(f"  Avg final trust   : {r['avg_trust_mean']} ± {r['avg_trust_ci95']} (95% CI)")
        print(f"  MFA triggers      : {r['total_mfa_triggers']}")
        print(f"  Restrict hits     : {r['total_restrict_hits']}")
        print(f"  Block hits        : {r['total_block_hits']}")
        print(f"  False-positive rate: {r['fp_rate'] * 100:.1f}%")

def plot_results(summary):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        labels   = [s["penalty_set"].split(" ")[0] + " " + s["penalty_set"].split(" ")[1] for s in summary]
        mfa_t    = [s["total_mfa_triggers"]   for s in summary]
        restrict = [s["total_restrict_hits"]   for s in summary]
        blocks   = [s["total_block_hits"]      for s in summary]
        fp       = [s["fp_rate"] * 100         for s in summary]

        x = np.arange(len(labels))
        w = 0.2

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        # left: enforcement counts
        ax = axes[0]
        ax.bar(x - w, mfa_t,    w, label="MFA Triggers",   color="#4C72B0")
        ax.bar(x,     restrict,  w, label="Restrict Hits",  color="#DD8452")
        ax.bar(x + w, blocks,    w, label="Block Hits",     color="#55A868")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylabel("Count (200 sessions)")
        ax.set_title("Enforcement Actions vs MFA Penalty")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)

        # right: false-positive rate
        ax2 = axes[1]
        bars = ax2.bar(x, fp, color="#C44E52", alpha=0.8)
        ax2.set_xticks(x)
        ax2.set_xticklabels(labels, fontsize=9)
        ax2.set_ylabel("False-Positive Rate (%)")
        ax2.set_title("False-Positive Rate (Benign Sessions Hitting Restricted Mode)")
        for bar, val in zip(bars, fp):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                     f"{val:.1f}%", ha="center", va="bottom", fontsize=9)
        ax2.grid(axis="y", alpha=0.3)
        ax2.set_ylim(0, 5)
        plt.subplots_adjust(bottom=0.20)
        plt.savefig("sensitivity_plot.png", dpi=150)
        print("\nPlot saved: sensitivity_plot.png")
    except ImportError:
        print("\n[INFO] matplotlib not installed — skipping plot generation.")
        print("       Install with: pip install matplotlib numpy")

if __name__ == "__main__":
    rows, summary = run_analysis()
    write_csvs(rows, summary)
    plot_results(summary)
