"""
seed_bench_user.py
===================
Creates (or resets) a single dedicated test account used ONLY for the
baseline-vs-ZTNA latency benchmark (ab_latency_harness.py). Deterministic
TOTP secret so the harness can compute valid codes without a QR flow.

Run once before the benchmark:
    python seed_bench_user.py
"""

import os
import sys
import django

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ztna_proj.settings")
django.setup()

from django.contrib.auth.models import User
from idp.models import UserProfile
from trustbroker.models import TrustScore
from appsrv.models import ApplicationResource

BENCH_USERNAME = "ztna_bench_user"
BENCH_PASSWORD = "BenchmarkOnly!2026"
BENCH_TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # same fixed secret already assumed by locustfile.py

user, created = User.objects.get_or_create(username=BENCH_USERNAME)
user.set_password(BENCH_PASSWORD)
user.is_staff = False
user.is_superuser = False
user.save()

profile, _ = UserProfile.objects.get_or_create(user=user)
profile.totp_secret = BENCH_TOTP_SECRET
profile.is_device_registered = True
profile.save()

ts, _ = TrustScore.objects.get_or_create(user_profile=profile)
if ts.overall_trust < 0.9:
    ts.overall_trust = 1.0
    ts.save(update_fields=["overall_trust"])

print(f"[OK] user={'created' if created else 'reset'} username={BENCH_USERNAME} "
      f"password={BENCH_PASSWORD} totp_secret={BENCH_TOTP_SECRET}")
print(f"[INFO] trust score reset to {ts.overall_trust}")
print(f"[INFO] ApplicationResource rows available: {ApplicationResource.objects.count()}")
