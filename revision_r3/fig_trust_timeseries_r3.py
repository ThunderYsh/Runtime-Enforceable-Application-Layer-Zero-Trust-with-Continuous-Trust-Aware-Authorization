"""fig_trust_timeseries_r3.py -- per-user TrustEvent trajectories from the
frozen snapshot (replaces Fig. 9, whose source CSV had no user column and whose
y-axis was clipped at 0.75, hiding 83 events below 0.60; and Fig. 11).
x-axis = event index per user (the window spans 8 months with long idle gaps).
Output: fig_trust_timeseries_r3.(png|pdf)"""
import pathlib, sqlite3
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
plt.rcParams.update({"font.size": 7, "xtick.labelsize": 6, "ytick.labelsize": 6})  # drawn at column width
H = pathlib.Path(__file__).resolve().parent
c = sqlite3.connect(f"file:{H/'snapshot_r2_20260719.sqlite3'}?mode=ro", uri=True)
rows = c.execute("""select u.username, e.event_type, e.old_score, e.new_score from trustbroker_trustevent e
  join idp_userprofile p on p.id=e.user_profile_id join auth_user u on u.id=p.user_id
  order by e.user_profile_id, e.timestamp, e.id""").fetchall()
anon = {"admin": "U1 (admin)", "ZtnaTest": "U2", "abc": "U3", "guest": "U4", "ztna_bench_user": "U5 (validation)"}
users = list(dict.fromkeys(r[0] for r in rows))
fig, axes = plt.subplots(len(users), 1, figsize=(3.5, 0.82 * len(users) + 0.5), sharey=True)
mk = {"mfa_fail": ("v", "#C44E52"), "bad_password": ("x", "#C44E52"), "blocked": ("s", "#8C1C13"),
      "link_fail": ("D", "#C44E52"), "night_access": ("^", "#937860")}
plain = {"mfa_fail": "MFA failure", "bad_password": "Bad password", "blocked": "Policy block",
         "link_fail": "Unauthorised link", "night_access": "Night access"}
for ax, u in zip(axes, users):
    ev = [r for r in rows if r[0] == u]
    ys = [ev[0][2]] + [r[3] for r in ev]
    ax.step(range(len(ys)), ys, where="post", lw=0.9, color="#4C72B0")
    for i, r in enumerate(ev, start=1):
        if r[1] in mk:
            ax.plot(i, r[3], mk[r[1]][0], color=mk[r[1]][1], ms=2.2)
    ax.axhline(0.60, ls="--", lw=0.6, color="k")
    ax.set_ylim(-0.05, 1.05); ax.set_yticks([0, 0.6, 1.0]); ax.grid(alpha=0.25)
    ax.text(0.01, 0.08, f"{anon.get(u, u)}  (n={len(ev)})", transform=ax.transAxes, fontsize=6)
axes[-1].set_xlabel("Trust-log record (per account)")
fig.text(0.005, 0.5, "Trust score $T_u$", rotation=90, va="center", fontsize=7)
handles = [plt.Line2D([], [], marker=m, ls="", color=col, label=plain[k]) for k, (m, col) in mk.items()]
fig.legend(handles=handles, fontsize=6, ncol=3, loc="upper center", frameon=False, handletextpad=0.2, columnspacing=1.0)
plt.tight_layout(rect=(0.03, 0, 1, 0.93), h_pad=0.3)
for e in ("png", "pdf"): plt.savefig(H / f"fig_trust_timeseries_r3.{e}", dpi=300)
print("ok", len(rows))
