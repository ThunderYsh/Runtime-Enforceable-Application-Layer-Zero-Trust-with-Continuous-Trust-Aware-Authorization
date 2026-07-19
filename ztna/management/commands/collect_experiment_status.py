"""
management/commands/collect_experiment_status.py
=================================================
Run from the project root:
    python manage.py collect_experiment_status

Queries the live Django DB and prints the dataset characteristics table
used in the paper (Table VII / tab:dataset). Every field is a direct
count against a real model -- nothing here is simulated or hand-entered.
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Collect experimental dataset characteristics for the journal paper."

    def handle(self, *args, **options):
        from django.contrib.auth.models import User
        from trustbroker.models import TrustEvent
        from policy.models import Policy, PolicyRule, DeviceFingerprintRecord
        from siem.models import AuditLog
        from ztna.models import ZTNARequest

        from django.db.models import Count

        # Group by whatever status values actually exist -- do not assume
        # only the four declared STATUS_CHOICES are present. Historical rows
        # ("ATTEMPT": a pre-decision "user opened this page" log event, plus
        # now-fixed casing bugs "allow"/"ALLOW"/"DENY") must not silently
        # vanish from the total the way they did in the original table.
        status_counts = dict(
            ZTNARequest.objects.values_list("status")
            .annotate(n=Count("id"))
            .order_by("-n")
        )
        total_requests = ZTNARequest.objects.count()

        stats = {
            "Registered Users": User.objects.count(),
            "Active Sessions (users with any login record)":
                User.objects.filter(last_login__isnull=False).count(),
            "Total ZTNA Requests Evaluated": total_requests,
            # DeviceRecord (policy app) was dead code -- never written to by any
            # view or middleware -- and has been removed (migration 0005).
            # Device history is actually tracked in DeviceFingerprintRecord,
            # written on every MFA success and every /device-trust/ view hit.
            "Registered Device Fingerprint Records":
                DeviceFingerprintRecord.objects.count(),
            "Distinct Devices (user, fingerprint pairs)":
                DeviceFingerprintRecord.objects.values("user_profile", "fingerprint").distinct().count(),
            "Configured Access Policies": Policy.objects.count(),
            "Active Policy Rules": PolicyRule.objects.filter(enabled=True).count(),
            "Trust Events Logged": TrustEvent.objects.count(),
            "Audit Log Entries": AuditLog.objects.count(),
        }
        for status_value, count in status_counts.items():
            stats[f"ZTNA Requests — {status_value}"] = count

        reconciled = sum(status_counts.values()) == total_requests
        stats["Status breakdown reconciles with total"] = "Yes" if reconciled else "NO -- INVESTIGATE"

        self.stdout.write("\n=== Experimental Dataset Characteristics ===\n")
        for k, v in stats.items():
            self.stdout.write(f"  {k:<50}: {v}")

        if not reconciled:
            self.stdout.write(self.style.WARNING(
                f"\n[WARNING] status breakdown {status_counts} sums to "
                f"{sum(status_counts.values())}, not total ({total_requests})."
            ))

        latex_rows = "\n".join(
            f"  {k} & {v} \\\\"
            for k, v in stats.items()
            if k != "Status breakdown reconciles with total"
        )
        latex = f"""
\\begin{{table}}[htbp]
\\centering
\\caption{{Experimental Evaluation Dataset Characteristics (deployed prototype, live query)}}
\\label{{tab:dataset}}
\\renewcommand{{\\arraystretch}}{{1.25}}
\\begin{{tabular}}{{lc}}
\\toprule
\\textbf{{Parameter}} & \\textbf{{Count}} \\\\
\\midrule
{latex_rows}
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""
        self.stdout.write("\n=== LaTeX Table ===")
        self.stdout.write(latex)

        with open("dataset_characteristics_latex.txt", "w", encoding="utf-8") as f:
            f.write(latex)
        self.stdout.write("\nSaved: dataset_characteristics_latex.txt")
