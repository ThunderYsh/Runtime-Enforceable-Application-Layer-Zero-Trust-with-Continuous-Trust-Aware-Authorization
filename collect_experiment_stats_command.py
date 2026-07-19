"""
management/commands/collect_experiment_stats.py
================================================
Place this file at:
    ztna/management/commands/collect_experiment_stats.py
    (create the management/ and commands/ directories with __init__.py)

Run from your project root:
    python manage.py collect_experiment_stats

Outputs a LaTeX table snippet with your actual DB counts.
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Collect experimental dataset characteristics for the journal paper."

    def handle(self, *args, **options):
        from django.contrib.auth.models import User
        from idp.models import UserProfile
        from trustbroker.models import TrustScore, TrustEvent
        from policy.models import Policy, PolicyRule, DeviceRecord
        from siem.models import AuditLog
        from ztna.models import ZTNARequest

        stats = {
            "Registered Users":
                User.objects.count(),
            "Active Sessions (users with any login record)":
                User.objects.filter(last_login__isnull=False).count(),
            "Total ZTNA Requests Evaluated":
                ZTNARequest.objects.count(),
            "Registered Device Records":
                DeviceRecord.objects.count(),
            "Configured Access Policies":
                Policy.objects.count(),
            "Active Policy Rules":
                PolicyRule.objects.filter(enabled=True).count(),
            "Trust Events Logged":
                TrustEvent.objects.count(),
            "Audit Log Entries":
                AuditLog.objects.count(),
            "ZTNA Requests — APPROVED":
                ZTNARequest.objects.filter(status="APPROVED").count(),
            "ZTNA Requests — DENIED":
                ZTNARequest.objects.filter(status="DENIED").count(),
            "ZTNA Requests — BLOCKED":
                ZTNARequest.objects.filter(status="BLOCKED").count(),
        }

        self.stdout.write("\n=== Experimental Dataset Characteristics ===\n")
        for k, v in stats.items():
            self.stdout.write(f"  {k:<50}: {v}")

        # LaTeX table
        latex_rows = "\n".join(
            f"  {k} & {v} \\\\"
            for k, v in list(stats.items())[:9]  # first 9 for clean table
        )
        latex = f"""
\\begin{{table}}[htbp]
\\centering
\\caption{{Experimental Evaluation Dataset Characteristics}}
\\label{{tab:dataset}}
\\renewcommand{{\\arraystretch}}{{1.25}}
\\begin{{tabular}}{{lc}}
\\toprule
\\textbf{{Parameter}} & \\textbf{{Count}} \\\\
\\midrule
{latex_rows}
  Adversarial Attack Scenarios & 6 \\\\
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""
        self.stdout.write("\n=== LaTeX Table ===")
        self.stdout.write(latex)

        # Also save to file
        with open("dataset_characteristics_latex.txt", "w") as f:
            f.write(latex)
        self.stdout.write("\nSaved: dataset_characteristics_latex.txt")
