"""fig_architecture_r3.py -- architecture diagram of the prototype, drawn only
from components that exist in the code (replaces five illustrative images that
contained details not present in the system, e.g. a PostgreSQL database and a
geo-location check).

Request pipeline (ztna_proj/settings.py MIDDLEWARE order, ztna/views.py):
  identity provider (login + TOTP)          ztna/views.py login_view, mfa_view
  fingerprint middleware -> D_u             ztna/device_fingerprint_middleware.py
  administrative-path middleware            ztna_proj/middleware.py
  night-access middleware (00:00-07:00)     policy/middleware.py
  policy-enforcement middleware             policy/middleware_enforcer.py
  application pages + step-up gate          ztna/views.py require_stepup_mfa_if_low_trust
Side components and who talks to them:
  verified-device registry  <- looked up by the fingerprint middleware,
                               written by the step-up gate after a passed challenge
  policy engine (PDP)       <- called by the policy-enforcement middleware and the pages
  TrustBroker               <- penalties/recoveries from identity provider, middleware,
                               step-up gate; read by the step-up gate; writes the trust log
Storage: one SQLite database (request log, audit log, trust log, registry).
Output: fig_architecture_r3.(pdf|png) at single-column width (3.5 in).
"""
import pathlib
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

H = pathlib.Path(__file__).resolve().parent
plt.rcParams.update({"font.size": 6.3, "font.family": "DejaVu Sans"})
PEP, PDP, TRUST, IDP, STORE, EDGE = "#FCE8D5", "#DCE8F7", "#DFF0DF", "#EFE6F7", "#EEEEEE", "#555555"

fig = plt.figure(figsize=(3.5, 4.45))
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 100); ax.set_ylim(0, 127); ax.axis("off")


def box(x, y, w, h, title, sub="", fc="white", fs=6.3):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=1.2",
                                fc=fc, ec=EDGE, lw=0.7))
    ax.text(x + w / 2, y + h * (0.67 if sub else 0.5), title, ha="center", va="center",
            fontsize=fs, weight="bold")
    if sub:
        ax.text(x + w / 2, y + h * 0.29, sub, ha="center", va="center", fontsize=fs - 0.9,
                color="#333333", linespacing=1.15)


def arrow(p, q, both=False, dashed=False):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="<|-|>" if both else "-|>", mutation_scale=6,
                                 lw=0.7, color="#333333", linestyle=(0, (2, 1.5)) if dashed else "-"))


def path(points, dashed=False):
    xs, ys = zip(*points)
    ax.plot(xs[:-1], ys[:-1], color="#333333", lw=0.7, linestyle=(0, (2, 1.5)) if dashed else "-")
    arrow(points[-2], points[-1], dashed=dashed)


# browser
box(22, 116, 56, 9, "User's browser", "password + one-time code; fingerprint cookie")
arrow((50, 116), (50, 111.2))

# application container
ax.add_patch(FancyBboxPatch((1.5, 17.5), 97, 93, boxstyle="round,pad=0.3,rounding_size=1.5",
                            fc="#FAFAFA", ec="#888888", lw=0.8, linestyle=(0, (4, 2))))
ax.text(4, 107.6, "Django application (single host)", fontsize=6, style="italic", color="#444444")

# request pipeline (left)
X, W = 4, 54
rows = [  # (y, h, title, subtitle, colour)
    (95.0, 9.2, "Identity provider", "password and TOTP check", IDP),
    (83.5, 9.2, "Fingerprint middleware", "computes device-familiarity score $D_u$", PEP),
    (72.0, 9.2, "Administrative-path middleware", "denies standard users (PEP)", PEP),
    (60.5, 9.2, "Night-access middleware", "denies standard users 00:00-07:00 (PEP)", PEP),
    (49.0, 9.2, "Policy-enforcement middleware", "denies on a policy block (PEP)", PEP),
    (35.5, 10.5, "Application pages + step-up gate", "MFA challenge if $T_u<0.60$ or $D_u<40$ (PEP)", PEP),
]
for y, h, t, s, c in rows:
    box(X, y, W, h, t, s, fc=c)
for (y1, h1, *_), (y2, h2, *_) in zip(rows[:-1], rows[1:]):
    arrow((X + W / 2, y1), (X + W / 2, y2 + h2 + 0.2))

# side components (right), aligned with the pipeline stage that uses them
RX, RW = 63, 33
box(RX, 82.5, RW, 11.5, "Verified-device", "registry: browsers that\npassed a challenge", fc=STORE)
box(RX, 47.5, RW, 12, "Policy engine", "decision point (PDP):\nrules, temporary blocks", fc=PDP)
box(RX, 32.5, RW, 12, "TrustBroker", "trust score $T_u\\in[0,1]$;\npenalties, recoveries", fc=TRUST)

arrow((X + W, 88.1), (RX, 88.1), both=True)          # fingerprint middleware <-> registry (lookup)
arrow((X + W, 53.6), (RX, 53.6), both=True)          # policy-enforcement middleware <-> policy engine
arrow((X + W - 0.5, 45.6), (RX + 3, 47.5), both=True)  # pages also call the policy engine
arrow((X + W, 39.5), (RX, 39.5), both=True)          # step-up gate <-> TrustBroker (read T_u, +/-)
path([(X + W, 43.5), (60.5, 43.5), (60.5, 82.0), (RX, 84.0)])  # passed challenge -> registry
path([(X + W, 99.6), (97.4, 99.6), (97.4, 41.0), (RX + RW + 0.3, 41.0)])  # identity events -> TrustBroker

# storage
ax.add_patch(FancyBboxPatch((4, 20.5), 92, 9.5, boxstyle="round,pad=0.25,rounding_size=1.2",
                            fc=STORE, ec=EDGE, lw=0.7))
ax.text(50, 27.4, "SQLite database: three logs", ha="center", fontsize=6.3, weight="bold")
for i, (t, s) in enumerate([("Request log", "page visits, decisions"), ("Audit log", "security events"),
                            ("Trust log", "every change of $T_u$")]):
    cx = 18 + i * 32
    ax.text(cx, 24.4, t, ha="center", fontsize=5.8, weight="bold")
    ax.text(cx, 21.9, s, ha="center", fontsize=5.1, color="#333333")
arrow((X + W / 2, 35.5), (X + W / 2, 30.4))           # pages write request and audit logs
arrow((RX + RW / 2, 32.5), (RX + RW / 2, 30.4))       # TrustBroker writes the trust log

# legend
items = [(IDP, "identity"), (PEP, "enforcement (PEP)"), (PDP, "decision (PDP)"), (TRUST, "trust"), (STORE, "storage")]
lx = 3
for c, lab in items:
    ax.add_patch(FancyBboxPatch((lx, 10.3), 2.6, 2.6, boxstyle="round,pad=0.1", fc=c, ec=EDGE, lw=0.5))
    ax.text(lx + 3.6, 11.6, lab, va="center", fontsize=5.3)
    lx += 3.6 + len(lab) * 1.12 + 2.2
ax.text(50, 5.0, "Single-headed arrows: request path and log writes; double-headed: lookups and updates.",
        ha="center", fontsize=4.9, color="#444444")

for e in ("pdf", "png"):
    fig.savefig(H / f"fig_architecture_r3.{e}", dpi=300)
print("ok")
