"""latency_stats_r3.py -- re-analysis of the frozen R2 A/B latency captures
(../latency_baseline.csv, ../latency_ztna.csv, captured 2026-07-18 by
ab_latency_harness.py). Adds robust tests and a cold-start sensitivity check.
Output: latency_stats_r3.json"""
import json, pathlib, numpy as np, pandas as pd
from scipy import stats
H = pathlib.Path(__file__).resolve().parent
b = pd.read_csv(H.parent / "latency_baseline.csv").latency_ms.to_numpy()
z = pd.read_csv(H.parent / "latency_ztna.csv").latency_ms.to_numpy()
def desc(x): return dict(n=len(x), mean=x.mean(), ci95=1.96*x.std(ddof=1)/np.sqrt(len(x)), median=np.median(x),
                         p95=np.percentile(x,95), p99=np.percentile(x,99), max=x.max())
def compare(b, z, seed=20261012):
    w = stats.ttest_ind(b, z, equal_var=False); u = stats.mannwhitneyu(b, z, alternative="two-sided")
    sp = np.sqrt(((len(b)-1)*b.var(ddof=1)+(len(z)-1)*z.var(ddof=1))/(len(b)+len(z)-2))
    rng = np.random.default_rng(seed)
    bm = [rng.choice(z,len(z)).mean()-rng.choice(b,len(b)).mean() for _ in range(20000)]
    bmed = [np.median(rng.choice(z,len(z)))-np.median(rng.choice(b,len(b))) for _ in range(20000)]
    return dict(welch_t=w.statistic, welch_p=w.pvalue, welch_df=w.df, cohens_d=(b.mean()-z.mean())/sp,
                mwu_U=u.statistic, mwu_p=u.pvalue, hodges_lehmann_shift_ms=float(np.median(np.subtract.outer(z,b))),
                mean_diff_ms=z.mean()-b.mean(), mean_diff_boot95=list(np.percentile(bm,[2.5,97.5])),
                median_diff_ms=np.median(z)-np.median(b), median_diff_boot95=list(np.percentile(bmed,[2.5,97.5])))
out = {"all_requests": {"baseline": desc(b), "ztna": desc(z), "test": compare(b, z)},
       "excluding_first_cold_start_request": {"baseline": desc(b[1:]), "ztna": desc(z[1:]), "test": compare(b[1:], z[1:])},
       "first_request_ms": {"baseline": b[0], "ztna": z[0]}}
conv = lambda o: float(o) if isinstance(o,(np.floating,np.integer)) else o
s = json.dumps(out, indent=1, default=conv); (H/"latency_stats_r3.json").write_text(s); print(s)
