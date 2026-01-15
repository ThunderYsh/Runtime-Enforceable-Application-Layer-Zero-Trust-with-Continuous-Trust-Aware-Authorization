import csv
import os
import django

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ztna_proj.settings")
django.setup()

from siem.utils import audit_log

OUTPUT_FILE = "latency_data.csv"

def run():
    logs = (
        AuditLog.objects
        .exclude(latency_ms__isnull=True)
        .order_by("timestamp")
    )

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp",
            "latency_ms",
            "action",
            "status"
        ])

        for log in logs:
            writer.writerow([
                log.timestamp,
                log.latency_ms,
                log.action,
                log.status
            ])

    print(f"[OK] Exported {logs.count()} rows to {OUTPUT_FILE}")

if __name__ == "__main__":
    run()
