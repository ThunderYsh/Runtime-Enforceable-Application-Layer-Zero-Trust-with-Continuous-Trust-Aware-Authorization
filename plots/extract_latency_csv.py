# plots/extract_latency_csv.py

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

from siem.utils import audit_log

OUT_CSV = BASE_DIR / "latency_measurements.csv"

# -----------------------------
# Query latency logs
# -----------------------------
logs = (
    AuditLog.objects
    .exclude(latency_ms__isnull=True)
    .order_by("timestamp")  
)

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
