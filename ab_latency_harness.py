"""
ab_latency_harness.py
======================
Real HTTP client that logs into the running dev server and repeatedly hits
protected ZTNA routes so RequestLatencyMiddleware records genuine
server-side latency for every request into AuditLog.

Run this TWICE against two separately-started server processes:
  1) with ZTNA_ENFORCEMENT_ENABLED=false   (baseline)
  2) with ZTNA_ENFORCEMENT_ENABLED=true    (ZTNA-enabled, default)

Usage:
    python ab_latency_harness.py <n_requests> <host>

Prints the UTC start timestamp to stdout -- pass that to
plots/extract_latency_csv.py as the "since" filter so each run's CSV only
contains rows from that run, not leftover history from earlier sessions.
"""

import sys
import time
import random
import re
from datetime import datetime, timezone

import requests
import pyotp

USERNAME = "ztna_bench_user"
PASSWORD = "BenchmarkOnly!2026"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"

ROUTES = [
    "/ztna/dashboard/",
    "/ztna/trust/analytics/",
    "/ztna/logs/",
]


def extract_csrf(html):
    m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
    if not m:
        raise RuntimeError("csrfmiddlewaretoken not found in response body")
    return m.group(1)


def login(session, host):
    r = session.get(f"{host}/ztna/login/")
    r.raise_for_status()
    token = extract_csrf(r.text)

    r = session.post(
        f"{host}/ztna/login/",
        data={"username": USERNAME, "password": PASSWORD, "csrfmiddlewaretoken": token},
        headers={"Referer": f"{host}/ztna/login/"},
    )
    r.raise_for_status()

    if "/ztna/mfa/" not in r.url:
        raise RuntimeError(f"expected redirect to MFA page, got {r.url}")

    token = extract_csrf(r.text)
    totp = pyotp.TOTP(TOTP_SECRET)
    r = session.post(
        f"{host}/ztna/mfa/",
        data={"token": totp.now(), "csrfmiddlewaretoken": token},
        headers={"Referer": f"{host}/ztna/mfa/"},
    )
    r.raise_for_status()

    if "/ztna/dashboard/" not in r.url:
        raise RuntimeError(f"MFA did not reach dashboard, got {r.url} -- body: {r.text[:300]}")


def main():
    n_requests = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    host = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8000"

    start_ts = datetime.now(timezone.utc).isoformat()
    print(f"[START] {start_ts}")

    session = requests.Session()
    login(session, host)
    print("[OK] logged in + MFA verified")

    ok, failed = 0, 0
    for i in range(n_requests):
        route = random.choice(ROUTES)
        try:
            r = session.get(f"{host}{route}", timeout=15)
            if r.status_code == 200:
                ok += 1
            else:
                failed += 1
                print(f"  [WARN] {route} -> HTTP {r.status_code}")
        except Exception as e:
            failed += 1
            print(f"  [ERROR] {route} -> {e}")
        time.sleep(random.uniform(0.05, 0.3))

    print(f"[DONE] ok={ok} failed={failed}")
    print(f"[SINCE] {start_ts}")


if __name__ == "__main__":
    main()
