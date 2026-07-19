"""
collect_experiment_stats.py
============================
Reviewer #2 Comment 4 — Evaluation Scale / Dataset Characteristics
-------------------------------------------------------------------
Run this inside your Django project (python manage.py shell < collect_experiment_stats.py)
OR set up Django settings manually and run directly.

It queries your actual DB and prints:
  - Number of users, sessions, requests, devices, policies, attack scenarios
  - Produces LaTeX table snippet
"""

import os
import sys
import django

# ── Django setup ─────────────────────────────────────────────────────────────
# Adjust the path to match your project root (where manage.py lives)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ztna_proj.settings")

try:
    django.setup()
    DJANGO_AVAILABLE = True
except Exception as e:
    print(f"[WARN] Django setup failed: {e}")
    print("[INFO] Running in placeholder mode — update numbers manually.")
    DJANGO_AVAILABLE = False


def collect_stats():
    if not DJANGO_AVAILABLE:
        return {
            "total_users": "N/A",
            "total_sessions": "N/A",
            "total_requests": "N/A",
            "total_devices": "N/A",
            "total_policies": "N/A",
            "total_policy_rules": "N/A",
            "total_trust_events": "N/A",
            "total_audit_logs": "N/A",
            "adversarial_scenarios": 6,  # from your paper: 4 scenarios + 2 extra
            "enforcement_outcomes_full_access": "N/A",
            "enforcement_outcomes_restricted": "N/A",
            "enforcement_outcomes_mfa": "N/A",
            "enforcement_outcomes_blocked": "N/A",
        }

    from django.contrib.auth.models import User
    from idp.models import UserProfile
    from trustbroker.models import TrustScore, TrustEvent
    from policy.models import Policy, PolicyRule, DeviceRecord
    from siem.models import AuditLog
    from ztna.models import ZTNARequest

    stats = {}

    stats["total_users"]        = User.objects.count()
    stats["total_sessions"]     = User.objects.filter(last_login__isnull=False).count()
    stats["total_requests"]     = ZTNARequest.objects.count()
    stats["total_devices"]      = DeviceRecord.objects.count()
    stats["total_policies"]     = Policy.objects.count()
    stats["total_policy_rules"] = PolicyRule.objects.count()
    stats["total_trust_events"] = TrustEvent.objects.count()
    stats["total_audit_logs"]   = AuditLog.objects.count()

    # Adversarial scenarios: manually defined in the paper
    stats["adversarial_scenarios"] = 6

    # Enforcement outcome breakdown
    stats["enforcement_outcomes_full_access"] = \
        ZTNARequest.objects.filter(status="APPROVED").count()
    stats["enforcement_outcomes_restricted"]  = \
        ZTNARequest.objects.filter(status="DENIED").count()
    stats["enforcement_outcomes_blocked"]     = \
        ZTNARequest.objects.filter(status="BLOCKED").count()

    # MFA escalations: count from audit logs
    stats["enforcement_outcomes_mfa"] = \
        AuditLog.objects.filter(action__icontains="mfa").count()

    return stats


def print_latex_table(stats):
    latex = r"""
\begin{table}[htbp]
\centering
\caption{Experimental Evaluation Dataset Characteristics}
\label{tab:dataset}
\renewcommand{\arraystretch}{1.25}
\begin{tabular}{lc}
\toprule
\textbf{Parameter} & \textbf{Count} \\
\midrule
""" + \
    f"Registered Users & {stats['total_users']} \\\\\n" + \
    f"Active Sessions (users with login records) & {stats['total_sessions']} \\\\\n" + \
    f"Total ZTNA Requests Evaluated & {stats['total_requests']} \\\\\n" + \
    f"Registered Device Records & {stats['total_devices']} \\\\\n" + \
    f"Configured Access Policies & {stats['total_policies']} \\\\\n" + \
    f"Active Policy Rules & {stats['total_policy_rules']} \\\\\n" + \
    f"Trust Events Logged & {stats['total_trust_events']} \\\\\n" + \
    f"Audit Log Entries & {stats['total_audit_logs']} \\\\\n" + \
    f"Adversarial Attack Scenarios & {stats['adversarial_scenarios']} \\\\\n" + \
    r"""\bottomrule
\end{tabular}
\end{table}
"""
    print(latex)

    with open("dataset_characteristics_latex.txt", "w") as f:
        f.write(latex)
    print("Saved: dataset_characteristics_latex.txt")


if __name__ == "__main__":
    stats = collect_stats()
    print("=== Experimental Dataset Characteristics ===")
    for k, v in stats.items():
        print(f"  {k:<45}: {v}")
    print()
    print_latex_table(stats)
