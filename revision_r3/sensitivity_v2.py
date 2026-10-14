"""
sensitivity_v2.py -- R3 revision, Reviewer #6 comments 1 and 2.

Replaces the R2 sensitivity simulation (../run_sensitivity_analysis.py), whose
benign event mix contained no trust-reducing event (so a 0% false-positive
rate was guaranteed by construction) and whose "MFA trigger" counter was
post-event occupancy of the 0.30 < T <= 0.60 band (so it fell when states
moved into the T <= 0.30 band).  The R2 script is kept unchanged for
traceability; see replicate_v1.py.

What this model mirrors from the implementation (file:function):
  * trust update + clamp/round ........ trustbroker/models.py TrustScore
  * penalties bad_password .08, mfa_fail alpha, blocked .10, link_fail .07
    (expired / unshared link), night_access .05 (default) ....... trustbroker/utils.py event_penalty
  * every dashboard load applies hourly_recovery (+.02) THEN
    recovery_after_safe_action (+.02), neither time-gated ... ztna/views.py dashboard
  * MFA success (login or step-up) +.10 ........ recovery_after_mfa
  * login: bad password -> penalty, retry; TOTP failure -> -alpha, retry
  * sensitive action (create/edit/share file, commands): if no valid step-up
    window and T < 0.60 -> step-up challenge (REQUIRE_MFA) ... require_stepup_mfa_if_low_trust
  * step-up success opens a 5-minute window (modelled as W actions)
  * there is NO behavioural-trust hard-block threshold in the implementation
    (blocking is policy / temporary-block / middleware driven), so none is
    modelled here.
Not modelled: daily +.05 recovery (needs >= 24 h, longer than a session),
device-familiarity gate (disabled here to isolate the trust model; this is
the worst case for the trust model -- e.g. a replayed device cookie).

Assumptions that are NOT taken from the implementation are listed in
ASSUMPTIONS and written to the output file.

Outputs (this directory):
  sensitivity_v2_results.json   all metrics, every condition, 95% intervals
  sensitivity_v2_table.tex      LaTeX rows for the manuscript table
  fig_sensitivity_v2.png/pdf    figure
Run:  python sensitivity_v2.py
"""
import json, math, random, pathlib, statistics as st

HERE = pathlib.Path(__file__).resolve().parent

# ---------------- implementation constants ----------------
PEN = {"bad_password": 0.08, "blocked": 0.10, "link_fail": 0.07, "night_access": 0.05}
REC_HOURLY, REC_SAFE, REC_MFA = 0.02, 0.02, 0.10
THETA = 0.60                     # step-up threshold (strict <), ztna/views.py
ALPHAS = (0.03, 0.06, 0.10, 0.15)

# ---------------- simulation assumptions ------------------
ASSUMPTIONS = {
    "sessions_per_replication": 200, "benign": 130, "adversarial": 70,
    "actions_per_session": 30, "replications": 100, "base_seed": 20261012,
    "stepup_window_actions": 5,
    "max_totp_attempts_per_challenge": 3,
    "max_login_attempts": 5,
    "benign_action_mix": {"dashboard": 0.35, "read": 0.35, "sensitive": 0.25, "shared_link": 0.05},
    "adversary_model": "post-authentication session hijacker (valid session cookie, no TOTP factor); "
                       "never passes a step-up challenge; device gate assumed bypassed",
    "adversary_action_mix": {"dashboard": 0.15, "read": 0.25, "sensitive": 0.30,
                             "link_probe": 0.15, "admin_probe": 0.15},  # link_probe = unauthorised shared link
    "benign_error_rates_epsilon": [0.0, 0.05, 0.10, 0.20],
    "epsilon_applies_to": "each password entry, each TOTP entry (mistyped), and each shared-link access (expired / not shared with the user -> link_fail, as in ztna/views.py shared_file_view)",
    "initial_trust_T0": [1.0, 0.7],
    "T0_note": "1.0 = TrustScore model default for a new account; 0.7 = degraded start used in R2",
}


def clamp(v):
    return max(0.0, min(1.0, round(v, 4)))


def recover(t, inc):
    return clamp(t + inc) if t < 1.0 else t


def pick(rng, mix):
    r, acc = rng.random(), 0.0
    for k, p in mix.items():
        acc += p
        if r < acc:
            return k
    return k


def draw_session(rng, adversarial):
    """Pre-draw every random number a session can consume so that all alpha
    values see identical behaviour (common random numbers)."""
    n = ASSUMPTIONS["actions_per_session"]
    mix = ASSUMPTIONS["adversary_action_mix" if adversarial else "benign_action_mix"]
    return {
        "actions": [pick(rng, mix) for _ in range(n)],
        "u_login_pw": [rng.random() for _ in range(ASSUMPTIONS["max_login_attempts"])],
        "u_login_otp": [rng.random() for _ in range(ASSUMPTIONS["max_login_attempts"])],
        "u_action": [[rng.random() for _ in range(ASSUMPTIONS["max_totp_attempts_per_challenge"])]
                     for _ in range(n)],
    }


def run_session(s, adversarial, alpha, eps, t0, gated_hourly=False):
    t = t0
    m = dict(challenges=0, sensitive_attempts=0, sensitive_done=0, sensitive_denied=0,
             first_challenge_at=None, min_trust=t0, penalty_events=0)
    W = ASSUMPTIONS["stepup_window_actions"]
    K = ASSUMPTIONS["max_totp_attempts_per_challenge"]

    if not adversarial:                       # login phase (adversary already holds a session)
        for u in s["u_login_pw"]:
            if u < eps:
                t = clamp(t - PEN["bad_password"]); m["penalty_events"] += 1
            else:
                break
        for u in s["u_login_otp"]:
            if u < eps:
                t = clamp(t - alpha); m["penalty_events"] += 1
            else:
                t = recover(t, REC_MFA); break

    window = 0
    hourly_used = False
    for i, a in enumerate(s["actions"]):
        window = max(0, window - 1)
        if a == "dashboard":
            if not (gated_hourly and hourly_used):
                t = recover(t, REC_HOURLY); hourly_used = True
            t = recover(t, REC_SAFE)
        elif a == "shared_link":               # benign: may open an expired / unshared link
            if s["u_action"][i][0] < eps:
                t = clamp(t - PEN["link_fail"]); m["penalty_events"] += 1
        elif a == "link_probe":
            t = clamp(t - PEN["link_fail"]); m["penalty_events"] += 1
        elif a == "admin_probe":
            t = clamp(t - PEN["blocked"]); m["penalty_events"] += 1
        elif a == "sensitive":
            m["sensitive_attempts"] += 1
            if window == 0 and t < THETA:
                m["challenges"] += 1
                if m["first_challenge_at"] is None:
                    m["first_challenge_at"] = i + 1
                passed = False
                for u in s["u_action"][i][:K]:
                    ok = (not adversarial) and u >= eps
                    if ok:
                        t = recover(t, REC_MFA); window = W; passed = True; break
                    t = clamp(t - alpha); m["penalty_events"] += 1
                if passed:
                    m["sensitive_done"] += 1
                else:
                    m["sensitive_denied"] += 1
            else:
                m["sensitive_done"] += 1
        m["min_trust"] = min(m["min_trust"], t)
    m["final_trust"] = t
    return m


def pct(xs, q):
    xs = sorted(xs); k = (len(xs) - 1) * q; f = math.floor(k); c = math.ceil(k)
    return xs[f] if f == c else xs[f] + (xs[c] - xs[f]) * (k - f)


def summarize(reps):
    keys = reps[0].keys()
    return {k: {"mean": st.mean(r[k] for r in reps),
                "lo95": pct([r[k] for r in reps], 0.025),
                "hi95": pct([r[k] for r in reps], 0.975)} for k in keys}


def replicate_metrics(sessions, alpha, eps, t0, gated_hourly):
    ben = [run_session(s, False, alpha, eps, t0, gated_hourly) for adv, s in sessions if not adv]
    adv = [run_session(s, True, alpha, eps, t0, gated_hourly) for adv_, s in sessions if adv_]
    b_sens = sum(m["sensitive_attempts"] for m in ben) or 1
    a_sens = sum(m["sensitive_attempts"] for m in adv) or 1
    fc = [m["first_challenge_at"] for m in adv if m["first_challenge_at"] is not None]
    return {
        # benign friction ("false positive" = trust-driven challenge on a benign session)
        "benign_session_fpr": sum(m["challenges"] > 0 for m in ben) / len(ben),
        "benign_challenges_per_100_sensitive": 100 * sum(m["challenges"] for m in ben) / b_sens,
        "benign_sensitive_denied_pct": 100 * sum(m["sensitive_denied"] for m in ben) / b_sens,
        "benign_sessions_with_failure_pct": 100 * sum(m["penalty_events"] > 0 for m in ben) / len(ben),
        # adversary containment (ground truth: every adversarial session is malicious)
        "adv_session_tpr": sum(m["challenges"] > 0 for m in adv) / len(adv),
        "adv_sensitive_completed_pct": 100 * sum(m["sensitive_done"] for m in adv) / a_sens,
        "adv_median_actions_to_first_challenge": (st.median(fc) if fc else float("nan")),
        "adv_mean_min_trust": st.mean(m["min_trust"] for m in adv),
    }


def main():
    A = ASSUMPTIONS
    results = []
    for gated in (False, True):
        for t0 in A["initial_trust_T0"]:
            for eps in A["benign_error_rates_epsilon"]:
                per_alpha = {a: [] for a in ALPHAS}
                for r in range(A["replications"]):
                    rng = random.Random(A["base_seed"] + r)
                    sessions = [(i < A["adversarial"], draw_session(rng, i < A["adversarial"]))
                                for i in range(A["sessions_per_replication"])]
                    for a in ALPHAS:
                        per_alpha[a].append(replicate_metrics(sessions, a, eps, t0, gated))
                for a in ALPHAS:
                    results.append({"recovery": "hourly-gated (corrected)" if gated else "as evaluated (per dashboard load)",
                                    "T0": t0, "epsilon": eps, "alpha": a,
                                    "metrics": summarize(per_alpha[a])})
    # Analytical check (login phase only): benign user restricted after k consecutive
    # TOTP typos then success iff T0 - k*alpha + 0.10 < 0.60
    analytic = {f"T0={t0}": {f"alpha={a}": math.floor((t0 + REC_MFA - THETA) / a + 1e-9) + 1
                             for a in ALPHAS} for t0 in A["initial_trust_T0"]}
    out = {"assumptions": A, "implementation_constants":
           {"penalties": PEN, "mfa_fail": "alpha", "recovery": {"hourly": REC_HOURLY, "safe": REC_SAFE, "mfa": REC_MFA},
            "stepup_threshold_strict_lt": THETA},
           "analytic_min_consecutive_login_totp_typos_to_restrict": analytic,
           "results": results}
    (HERE / "sensitivity_v2_results.json").write_text(json.dumps(out, indent=1))
    write_table(results); plot(results)
    for r in results:
        if r["recovery"].startswith("as") and r["epsilon"] in (0.0, 0.10):
            m = r["metrics"]
            print(f"T0={r['T0']} eps={r['epsilon']:.2f} a={r['alpha']:.2f} | "
                  f"FPR={m['benign_session_fpr']['mean']*100:5.1f}% "
                  f"[{m['benign_session_fpr']['lo95']*100:.1f},{m['benign_session_fpr']['hi95']*100:.1f}] "
                  f"TPR={m['adv_session_tpr']['mean']*100:5.1f}% "
                  f"advDone={m['adv_sensitive_completed_pct']['mean']:5.1f}% "
                  f"ttc={m['adv_median_actions_to_first_challenge']['mean']:.1f}")
    print("analytic:", analytic)


def f(m, k, scale=100, d=1):
    v = m[k]
    return f"{v['mean']*scale:.{d}f} [{v['lo95']*scale:.{d}f}, {v['hi95']*scale:.{d}f}]"


def write_table(results):
    lines = []
    for r in results:
        if not r["recovery"].startswith("as") or r["epsilon"] != 0.10:
            continue
        m = r["metrics"]
        lines.append(f"{r['T0']:.1f} & {r['alpha']:.2f} & {f(m,'benign_session_fpr')} & "
                     f"{f(m,'benign_challenges_per_100_sensitive',1)} & {f(m,'adv_session_tpr')} & "
                     f"{f(m,'adv_sensitive_completed_pct',1)} & "
                     f"{m['adv_median_actions_to_first_challenge']['mean']:.1f} \\\\")
    (HERE / "sensitivity_v2_table.tex").write_text("\n".join(lines) + "\n")


def plot(results):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 7, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5})
    fig, axes = plt.subplots(1, 3, figsize=(7.1, 2.3))   # printed width of a two-column figure
    colors = {0.0: "#8C8C8C", 0.05: "#4C72B0", 0.10: "#DD8452", 0.20: "#C44E52"}
    for t0, ls in ((1.0, "-"), (0.7, "--")):
        for eps, c in colors.items():
            rs = [r for r in results if r["recovery"].startswith("as") and r["T0"] == t0 and r["epsilon"] == eps]
            x = [r["alpha"] for r in rs]
            for ax, key, sc in ((axes[0], "benign_session_fpr", 100),
                                (axes[1], "adv_session_tpr", 100),
                                (axes[2], "adv_sensitive_completed_pct", 1)):
                y = [r["metrics"][key]["mean"] * sc for r in rs]
                lo = [r["metrics"][key]["lo95"] * sc for r in rs]
                hi = [r["metrics"][key]["hi95"] * sc for r in rs]
                if key != "benign_session_fpr" and eps not in (0.10,):
                    continue          # adversary metrics do not depend on epsilon
                ax.plot(x, y, ls, color=c if key == "benign_session_fpr" else "k", marker="o", ms=3,
                        label=(f"$T_0$={t0}, $\\epsilon$={eps:.2f}" if key == "benign_session_fpr" else f"$T_0$={t0}"))
                ax.fill_between(x, lo, hi, color=c if key == "benign_session_fpr" else "k", alpha=0.10)
    axes[0].set_title("Legitimate sessions challenged (FPR, %)", fontsize=7)
    axes[1].set_title("Attacker sessions challenged (TPR, %)", fontsize=7)
    axes[2].set_title("Attacker sensitive actions succeeded (%)", fontsize=7)
    for ax in axes:
        ax.set_xlabel(r"MFA failure penalty $\alpha$"); ax.set_xticks(ALPHAS); ax.grid(alpha=0.3)
    axes[0].legend(fontsize=5, ncol=2, handlelength=2.2); axes[1].legend(fontsize=6); axes[2].legend(fontsize=6)
    plt.tight_layout()
    for ext in ("png", "pdf"):
        plt.savefig(HERE / f"fig_sensitivity_v2.{ext}", dpi=300)
    plt.close()


if __name__ == "__main__":
    main()
