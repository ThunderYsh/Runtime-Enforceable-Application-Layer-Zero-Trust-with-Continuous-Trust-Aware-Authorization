"""
analyze_bench_r3.py -- statistics and figures for the R3 latency re-run
(bench_r3/raw_*.csv produced by bench_latency_r3.py).

Primary comparison: full ZTNA vs true no-enforcement baseline ("none"),
client-side latency, sequential phase. Secondary: the R2 baseline
("no_middleware") is reported so the decomposition
  total ZTNA cost = view-level cost (no_middleware - none)
                  + middleware cost (full - no_middleware)
is explicit. Tests: Mann-Whitney U, Welch t, Hodges-Lehmann shift,
bootstrap 95% CIs for the difference in medians and means (20 000 resamples),
Cohen's d. Repetition-level medians are reported to show run-to-run spread.
Outputs: bench_r3/latency_r3_stats.json, latency_r3_table.tex,
         fig_latency_r3_box.(png|pdf), fig_latency_r3_cdf.(png|pdf)
"""
import json, pathlib
import numpy as np, pandas as pd
from scipy import stats

H = pathlib.Path(__file__).resolve().parent
B = H / "bench_r3"
MODES = ["none", "no_middleware", "full"]
LABEL = {"none": "No enforcement", "no_middleware": "View-level only (R2 baseline)", "full": "Full ZTNA"}
RNG = np.random.default_rng(20261012)


def desc(x):
    return dict(n=int(len(x)), mean=float(x.mean()), sd=float(x.std(ddof=1)),
                ci95_mean=float(1.96 * x.std(ddof=1) / np.sqrt(len(x))), median=float(np.median(x)),
                p95=float(np.percentile(x, 95)), p99=float(np.percentile(x, 99)), max=float(x.max()))


def boot(a, b, f, n=20000):
    d = [f(RNG.choice(b, len(b))) - f(RNG.choice(a, len(a))) for _ in range(n)]
    return [float(v) for v in np.percentile(d, [2.5, 97.5])]


def compare(a, b):
    """b relative to a (positive = b slower)."""
    sp = np.sqrt(((len(a) - 1) * a.var(ddof=1) + (len(b) - 1) * b.var(ddof=1)) / (len(a) + len(b) - 2))
    w = stats.ttest_ind(b, a, equal_var=False)
    u = stats.mannwhitneyu(b, a, alternative="two-sided")
    return dict(median_diff_ms=float(np.median(b) - np.median(a)), median_diff_ci95=boot(a, b, np.median),
                mean_diff_ms=float(b.mean() - a.mean()), mean_diff_ci95=boot(a, b, np.mean),
                rel_median_pct=float(100 * (np.median(b) - np.median(a)) / np.median(a)),
                hodges_lehmann_ms=float(np.median(np.subtract.outer(b, a))),
                mwu_p=float(u.pvalue), welch_t=float(w.statistic), welch_df=float(w.df), welch_p=float(w.pvalue),
                cohens_d=float((b.mean() - a.mean()) / sp))


def main():
    seq = pd.read_csv(B / "raw_sequential.csv"); conc = pd.read_csv(B / "raw_concurrent.csv")
    srv = pd.read_csv(B / "server_side.csv"); runs = json.loads((B / "run_log.json").read_text())["runs"]
    out = {"non_200": {"sequential": int((seq.status != 200).sum()), "concurrent": int((conc.status != 200).sum())}}
    seq = seq[seq.status == 200]; conc = conc[conc.status == 200]
    for phase, df in (("sequential", seq), ("concurrent", conc)):
        x = {m: df[df["mode"] == m].client_ms.to_numpy() for m in MODES}
        out[phase] = {"client": {m: desc(x[m]) for m in MODES},
                      "full_vs_none": compare(x["none"], x["full"]),
                      "no_middleware_vs_none": compare(x["none"], x["no_middleware"]),
                      "full_vs_no_middleware": compare(x["no_middleware"], x["full"]),
                      "per_rep_median": {m: [float(np.median(df[(df["mode"] == m) & (df.rep == r)].client_ms))
                                             for r in sorted(df.rep.unique())] for m in MODES},
                      "per_route_median": {m: {rt: float(np.median(df[(df["mode"] == m) & (df.route == rt)].client_ms))
                                               for rt in sorted(df.route.unique())} for m in MODES}}
        s = {m: srv[(srv.phase == phase) & (srv["mode"] == m)].server_ms.to_numpy() for m in MODES}
        out[phase]["server"] = {m: desc(s[m]) for m in MODES if len(s[m])}
        if len(s["none"]) and len(s["full"]):
            out[phase]["server_full_vs_none"] = compare(s["none"], s["full"])
    out["throughput_rps"] = {m: [r["requests"] / r["wall_s"] for r in runs if r["phase"] == "concurrent" and r["mode"] == m]
                             for m in MODES}
    (B / "latency_r3_stats.json").write_text(json.dumps(out, indent=1))

    # LaTeX rows
    rows = []
    for phase in ("sequential", "concurrent"):
        for m in MODES:
            d = out[phase]["client"][m]
            rows.append(f"{phase.capitalize()} & {LABEL[m]} & {d['n']} & {d['median']:.2f} & {d['p95']:.2f} & {d['p99']:.2f} & {d['mean']:.2f} \\\\")
    (B / "latency_r3_table.tex").write_text("\n".join(rows) + "\n")

    # Drawn at printed (single-column, 3.5 in) size; names match the paper's
    # configuration names ("No checks", "View-level only", "Full").
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 7, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5})
    col = {"none": "#8C8C8C", "no_middleware": "#4C72B0", "full": "#DD8452"}
    PAPER = {"none": "No checks", "no_middleware": "View-level only", "full": "Full"}
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 2.2))
    for ax, (phase, df) in zip(axes, (("One client", seq), ("Eight clients", conc))):
        data = [df[df["mode"] == m].client_ms for m in MODES]
        bp = ax.boxplot(data, showfliers=False, patch_artist=True, widths=0.55,
                        medianprops={"color": "k", "lw": 0.9})
        for p, m in zip(bp["boxes"], MODES): p.set_facecolor(col[m]); p.set_alpha(0.7)
        ax.set_xticks([1, 2, 3], ["No\nchecks", "View-\nlevel", "Full"], fontsize=6.5)
        ax.set_title(phase, fontsize=7); ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("Client-side latency (ms)")
    plt.tight_layout(w_pad=0.6)
    for e in ("png", "pdf"): plt.savefig(H / f"fig_latency_r3_box.{e}", dpi=300)
    plt.close()
    plt.figure(figsize=(3.5, 2.2))
    for m in MODES:
        v = np.sort(seq[seq["mode"] == m].client_ms.to_numpy())
        plt.plot(v, np.arange(1, len(v) + 1) / len(v), color=col[m], label=PAPER[m], lw=1.1)
    plt.xscale("log"); plt.xlabel("Client-side latency (ms, log scale)"); plt.ylabel("Cumulative share of requests")
    from matplotlib.ticker import FixedLocator, FixedFormatter, NullLocator
    ticks = [15, 20, 30, 50, 100, 200, 400]
    ax = plt.gca(); ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.xaxis.set_major_formatter(FixedFormatter([str(t) for t in ticks])); ax.xaxis.set_minor_locator(NullLocator())
    plt.legend(fontsize=6.5, loc="lower right"); plt.grid(alpha=0.3); plt.tight_layout()
    for e in ("png", "pdf"): plt.savefig(H / f"fig_latency_r3_cdf.{e}", dpi=300)
    plt.close()
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
