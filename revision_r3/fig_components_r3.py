"""fig_components_r3.py -- component diagrams of the prototype, drawn only from
what the code implements (they replace illustrative images that contained
details not present in the system). Single-column width (3.5 in).

  fig_app_r3        protected application: features and the gate in front of each
                    (ztna/views.py; Table "feature availability")
  fig_trustbroker_r3  trust events, update rule, trust log, step-up feedback
                    (trustbroker/models.py, trustbroker/utils.py)
  fig_policy_r3     policy engine as implemented (policy/trust.py, policy/enforcer.py,
                    trustbroker/dashboard_trust.py)
  fig_flow_r3       per-request decision sequence (Algorithm 1)
"""
import pathlib
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Polygon

H = pathlib.Path(__file__).resolve().parent
plt.rcParams.update({"font.size": 6.3, "font.family": "DejaVu Sans"})
PEP, PDP, TRUST, IDP, STORE, EDGE, DENY, OK = ("#FCE8D5", "#DCE8F7", "#DFF0DF", "#EFE6F7", "#EEEEEE",
                                               "#555555", "#F6D5D5", "#D9EFD9")


def canvas(w_in, h_in, ymax):
    fig = plt.figure(figsize=(w_in, h_in))
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 100); ax.set_ylim(0, ymax); ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, title, sub="", fc="white", fs=6.3, bold=True, align="center"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=1.2", fc=fc, ec=EDGE, lw=0.7))
    tx = x + w / 2 if align == "center" else x + 1.5
    if sub:
        ax.text(tx, y + h * 0.68, title, ha=align, va="center", fontsize=fs, weight="bold" if bold else "normal")
        ax.text(tx, y + h * 0.30, sub, ha=align, va="center", fontsize=fs - 0.9, color="#333333", linespacing=1.2)
    else:
        ax.text(tx, y + h / 2, title, ha=align, va="center", fontsize=fs, weight="bold" if bold else "normal",
                linespacing=1.2)


def arrow(ax, p, q, both=False, dashed=False, text=None, tpos=0.5, toff=(1.0, 0)):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="<|-|>" if both else "-|>", mutation_scale=6, lw=0.7,
                                 color="#333333", linestyle=(0, (2, 1.5)) if dashed else "-"))
    if text:
        ax.text(p[0] + (q[0] - p[0]) * tpos + toff[0], p[1] + (q[1] - p[1]) * tpos + toff[1], text,
                fontsize=5.3, color="#333333")


def save(fig, name):
    for e in ("pdf", "png"):
        fig.savefig(H / f"{name}.{e}", dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------- application
fig, ax = canvas(3.5, 2.75, 78)
box(ax, 25, 68, 50, 7.5, "Authenticated request", "after password and TOTP at login")
arrow(ax, (50, 68), (50, 62.7))
box(ax, 3, 30, 29, 31.5, "", fc=OK)
ax.text(17.5, 58.5, "Low-risk features", ha="center", fontsize=6.2, weight="bold")
ax.text(17.5, 55.3, "always available", ha="center", fontsize=5.3, color="#333333")
for i, f in enumerate(["Dashboard", "Audit-log view", "Trust analytics", "Device report", "MFA reset*"]):
    ax.text(17.5, 50.5 - i * 4.2, f, ha="center", fontsize=5.8)
box(ax, 35.5, 30, 29, 31.5, "", fc=PEP)
ax.text(50, 58.5, "Sensitive actions", ha="center", fontsize=6.2, weight="bold")
ax.text(50, 55.3, "step-up gate", ha="center", fontsize=5.3, color="#333333")
for i, f in enumerate(["Create file", "Edit file", "Share file", "Run command"]):
    ax.text(50, 50.5 - i * 4.2, f, ha="center", fontsize=5.8)
box(ax, 68, 30, 29, 31.5, "", fc=DENY)
ax.text(82.5, 58.5, "Administrative", ha="center", fontsize=6.2, weight="bold")
ax.text(82.5, 55.3, "administrators only", ha="center", fontsize=5.3, color="#333333")
for i, f in enumerate(["Policy management", "User and block", "management"]):
    ax.text(82.5, 50.5 - i * 4.2, f, ha="center", fontsize=5.8)
for x in (17.5, 50, 82.5):
    arrow(ax, (50, 62.5), (x, 61.8))
box(ax, 35.5, 13, 29, 11, "MFA challenge", "if $T_u<0.60$ or $D_u<40$\nand none passed in 5 min", fc=PEP)
arrow(ax, (50, 30), (50, 24.3))
box(ax, 68, 13, 29, 11, "Denied for", "standard users;\npenalty $-0.10$", fc=DENY)
arrow(ax, (82.5, 30), (82.5, 24.3))
ax.text(3, 21, "*after password re-entry", fontsize=5.0, color="#444444")
ax.text(50, 4.5, "Visits to protected pages are written to the request log.", ha="center", fontsize=5.2, color="#444444")
save(fig, "fig_app_r3")

# ---------------------------------------------------------------- TrustBroker
fig, ax = canvas(3.5, 3.5, 100)
box(ax, 2, 50, 44, 46, "", fc="white")
ax.text(24, 92.5, "Trust events and $\\Delta_e$", ha="center", fontsize=6.3, weight="bold")
pen = [("Bad password", "$-0.08$"), ("MFA failure", "$-\\alpha=-0.06$"), ("Policy block", "$-0.10$"),
       ("Unauthorised link", "$-0.07$"), ("Night access", "$-0.05$")]
rec = [("Dashboard load", "$+0.02$ (hourly)"), ("Dashboard load", "$+0.02$ (safe)"),
       ("Correct MFA code", "$+0.10$"), ("24 h without recovery", "$+0.05$")]
y = 88
for n, d in pen:
    ax.text(4.5, y, n, fontsize=5.6, color="#8C1C13"); ax.text(43.5, y, d, fontsize=5.6, ha="right", color="#8C1C13"); y -= 3.6
y -= 1.2
for n, d in rec:
    ax.text(4.5, y, n, fontsize=5.6, color="#2E6B2E"); ax.text(43.5, y, d, fontsize=5.6, ha="right", color="#2E6B2E"); y -= 3.6
box(ax, 54, 74, 44, 22, "Update rule", "$T_u \\leftarrow \\min(1,\\max(0,T_u+\\Delta_e))$\nrounded to 4 decimals;\nrecovery only if $T_u<1$", fc=TRUST)
arrow(ax, (46.3, 85), (54, 85))
box(ax, 54, 50, 44, 18, "Trust score $T_u$", "one per user, start $T_0=1.0$\n(always within $[0,1]$)", fc=TRUST)
arrow(ax, (76, 74), (76, 68.3))
box(ax, 2, 22, 44, 20, "Trust log", "one record per change:\nevent, $\\Delta_e$, old and new\nscore, time", fc=STORE)
arrow(ax, (54, 59), (46.3, 32))
ax.text(36, 45.5, "every change", fontsize=5.3, color="#333333", ha="center")
box(ax, 54, 18, 44, 24, "Step-up gate", "sensitive action and $T_u<0.60$:\nMFA challenge; correct code\n$+0.10$, wrong code $-\\alpha$", fc=PEP)
arrow(ax, (76, 50), (76, 42.3), text="read", tpos=0.5, toff=(1.2, 0))
ax.text(50, 10, "Penalties are larger than each passive recovery step, so trust falls faster than it recovers.",
        ha="center", fontsize=5.1, color="#444444")
ax.text(50, 5.5, "Hourly increment: applied per dashboard load in the evaluated version, now once per hour.",
        ha="center", fontsize=5.1, color="#444444")
save(fig, "fig_trustbroker_r3")

# ---------------------------------------------------------------- policy engine
fig, ax = canvas(3.5, 3.6, 104)
box(ax, 2, 70, 30, 30, "", fc="white")
ax.text(17, 96, "Request context", ha="center", fontsize=6.3, weight="bold")
for i, c in enumerate(["role", "hour of day", "recent failures", "device score $D_u$", "trust score $T_u$",
                       "IP reputation*", "country*"]):
    ax.text(17, 91.5 - i * 3.3, c, ha="center", fontsize=5.6)
box(ax, 38, 80, 60, 20, "Enabled rules, in priority order", "each rule: one condition + one action;\nfirst match recorded as policy_rule_id", fc=PDP)
arrow(ax, (32.3, 90), (38, 90))
box(ax, 38, 54, 28, 19, "deny / block", "denial and temporary\nblock 15/60/360 min", fc=DENY)
box(ax, 70, 54, 28, 19, "require MFA,\nescalate, critical", "lower a rule score\n(computed, not used)$^{\\dagger}$", fc=STORE)
arrow(ax, (52, 80), (52, 73.3)); arrow(ax, (84, 80), (84, 73.3))
box(ax, 2, 30, 30, 20, "Policy score $T_{dash}$", "from $D_u$ only:\n65 or 100", fc=PDP)
arrow(ax, (17, 70), (17, 50.3))
box(ax, 38, 30, 60, 20, "Decision returned to the middleware", "DENY if a block rule matched or $T_{dash}<60$;\notherwise ALLOW (step-up decided in the page)", fc=PEP)
arrow(ax, (32.3, 40), (38, 40)); arrow(ax, (52, 54), (52, 50.3))
ax.text(2, 20, "*fixed placeholder values in the prototype", fontsize=5.1, color="#444444")
ax.text(2, 15.5, "$^{\\dagger}$in the evaluated configuration no rule changed a decision:", fontsize=5.1, color="#444444")
ax.text(4.5, 11.5, "the deny rules never matched and $T_{dash}$ never fell below 60", fontsize=5.1, color="#444444")
save(fig, "fig_policy_r3")

# ---------------------------------------------------------------- request flow (Algorithm 1)
fig, ax = canvas(3.5, 4.9, 140)


def diamond(cx, cy, w, h, text):
    ax.add_patch(Polygon([(cx, cy + h / 2), (cx + w / 2, cy), (cx, cy - h / 2), (cx - w / 2, cy)],
                         closed=True, fc=PDP, ec=EDGE, lw=0.7))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=5.5, linespacing=1.15)


box(ax, 14, 130, 62, 7, "Protected request of a standard user", fs=5.9)
CX = 45
steps = [(116, "Administrative\npage?", "policy-block penalty"),
         (100, "Between\n00:00 and 07:00?", "night-access penalty"),
         (84, "Active temporary\nblock?", "policy-block penalty"),
         (68, "Block rule matched\nor $T_{dash}<60$?", "temporary block,\npolicy-block penalty")]
arrow(ax, (CX, 130), (CX, 123.5))
for i, (cy, q, pen) in enumerate(steps):
    diamond(CX, cy, 42, 13, q)
    box(ax, 74, cy - 5, 24, 10, "DENY", pen, fc=DENY, fs=5.8)
    arrow(ax, (CX + 21, cy), (73.6, cy), text="yes", tpos=0.25, toff=(0, 1.2))
    nxt = steps[i + 1][0] + 6.5 if i + 1 < len(steps) else 52 + 6.5
    arrow(ax, (CX, cy - 6.5), (CX, nxt), text="no", tpos=0.35, toff=(1.2, 0))
diamond(CX, 52, 42, 13, "Sensitive action and\nno challenge passed\nin last 5 min?")
box(ax, 74, 47, 24, 10, "ALLOW", "", fc=OK, fs=5.8)
arrow(ax, (CX + 21, 52), (73.6, 52), text="no", tpos=0.25, toff=(0, 1.2))
arrow(ax, (CX, 45.5), (CX, 42.5), text="yes", tpos=0.2, toff=(1.2, 0))
diamond(CX, 36, 42, 13, "$T_u<0.60$ or\n$D_u<40$?")
arrow(ax, (CX + 21, 36), (85.5, 47), text="no", tpos=0.25, toff=(0, 1.2))
arrow(ax, (CX, 29.5), (CX, 25.3), text="yes", tpos=0.2, toff=(1.2, 0))
box(ax, 20, 15, 50, 10, "MFA challenge (STEP_UP)", "logged in the audit log", fc=PEP, fs=5.9)
box(ax, 4, 2, 40, 9, "correct code: $+0.10$,", "browser recorded as verified, ALLOW", fc=OK, fs=5.3)
box(ax, 50, 2, 40, 9, "wrong code: $-\\alpha$", "action not performed", fc=DENY, fs=5.3)
arrow(ax, (38, 15), (26, 11.3)); arrow(ax, (52, 15), (66, 11.3))
ax.text(2.5, 125, "Every decision and penalty\nis written to the logs.", fontsize=5.0, color="#444444")
save(fig, "fig_flow_r3")
print("ok")
