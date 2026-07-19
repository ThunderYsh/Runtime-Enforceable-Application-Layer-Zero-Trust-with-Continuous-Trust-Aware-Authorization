"""
plots/enforcement_outcome_breakdown.py

Regenerates the "Enforcement Outcome Breakdown" figure (paper Fig. 12) from
ZTNARequest.status -- the SAME model/field used for Table VII (dataset
characteristics). Using one canonical source for both the table and the
figure is a deliberate fix: the previous draft had three different
"blocked" counts (2 in Table VII, ~37 in the old Fig. 12, 156 in the
Table IV *simulation*) with no stated definition tying them together,
which is exactly what Reviewer #6 flagged as an internal inconsistency.

Run with:
    python manage.py shell -c "exec(open('plots/enforcement_outcome_breakdown.py').read())"
or as a standalone script (see Django bootstrap below).
"""

import os
import sys
import django
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ztna_proj.settings")
django.setup()

from django.db.models import Count
from ztna.models import ZTNARequest

# Group by whatever status values actually exist in the DB -- do not assume
# only APPROVED/DENIED/BLOCKED/PENDING, so nothing is silently dropped from
# the chart the way it was when this figure and Table VII disagreed.
counts = dict(
    ZTNARequest.objects.values_list("status")
    .annotate(n=Count("id"))
    .order_by("-n")
)

print("=== Enforcement Outcome Breakdown (ZTNARequest.status, live DB) ===")
for k, v in counts.items():
    print(f"  {k:<22}: {v}")
total = sum(counts.values())
print(f"  {'TOTAL':<22}: {total}")

PALETTE = ["#4C72B0", "#DD8452", "#55A868", "#C44E52", "#8C8C8C", "#937860"]
labels = list(counts.keys())
values = list(counts.values())

plt.figure(figsize=(6, 4))
bars = plt.bar(labels, values, color=PALETTE[: len(labels)])
for bar, val in zip(bars, values):
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
              str(val), ha="center", va="bottom", fontsize=10)
plt.ylabel("Number of Requests")
plt.title("Enforcement Outcome Breakdown (ZTNARequest.status)")
plt.tight_layout()
plt.savefig(BASE_DIR / "enforcement_outcome_breakdown.png", dpi=300)
plt.close()
print(f"\n[OK] Saved enforcement_outcome_breakdown.png (N={total})")
