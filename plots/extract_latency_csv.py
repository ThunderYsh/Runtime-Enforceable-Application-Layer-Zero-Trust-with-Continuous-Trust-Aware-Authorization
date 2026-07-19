# plots/extract_latency_csv.py
#
# Usage:
#   python plots/extract_latency_csv.py <out.csv> [since_iso_timestamp]
#
# Exports AuditLog rows with action="request_latency" to CSV, optionally
# filtered to timestamp >= since_iso_timestamp (used to isolate a single
# benchmark run's window from the rest of the log history).

import os
import sys
import django
import csv
from pathlib import Path

# -----------------------------
# Fix Python path (CRITICAL)
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

# -----------------------------
# Django setup
# -----------------------------
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ztna_proj.settings")
django.setup()

from siem.models import AuditLog

OUT_CSV = Path(sys.argv[1]) if len(sys.argv) > 1 else BASE_DIR / "latency_measurements.csv"
SINCE = sys.argv[2] if len(sys.argv) > 2 else None

# -----------------------------
# Query latency logs
# -----------------------------
logs = (
    AuditLog.objects
    .filter(action="request_latency")
    .exclude(latency_ms__isnull=True)
    .order_by("timestamp")
)
if SINCE:
    logs = logs.filter(timestamp__gte=SINCE)

print(f"[INFO] Extracting {logs.count()} latency records")

# -----------------------------
# Write CSV
# -----------------------------
with open(OUT_CSV, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "timestamp",
        "action",
        "latency_ms",
        "status"
    ])

    for log in logs:
        writer.writerow([
            log.timestamp,
            log.action,
            log.latency_ms,
            log.status
        ])

print(f"[OK] CSV generated: {OUT_CSV}")
