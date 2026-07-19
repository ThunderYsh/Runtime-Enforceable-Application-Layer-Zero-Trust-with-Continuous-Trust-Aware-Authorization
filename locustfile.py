"""
locustfile.py
=============
Reviewer #1 Comment 3 — Stress Testing / Scalability Evaluation
----------------------------------------------------------------
Run with:
    pip install locust
    locust -f locustfile.py --headless -u 100 -r 10 --run-time 60s \
           --host http://127.0.0.1:8000 --csv=locust_results

This simulates users hitting the ZTNA-protected dashboard endpoint.
Results give avg_latency, p95_latency, throughput, error_rate at
100, 500, 1000 concurrent users (run separately with -u flag).

For the paper: run three times (-u 100, -u 500, -u 1000) and
collect the CSV outputs. The generate_scalability_table.py script
merges them into a LaTeX table.
"""

from locust import HttpUser, task, between
import random
import string


def random_token(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class ZTNAUser(HttpUser):
    """
    Simulates an authenticated user hitting protected ZTNA endpoints.
    Django session cookie must be set; in a real run you would log in
    first. For benchmarking we target the dashboard and trust analytics
    endpoints (read-only, no DB writes except TrustEvent.
    """
    wait_time = between(0.5, 2.0)

    def on_start(self):
        """Log in once per simulated user."""
        resp = self.client.post("/ztna/login/", data={
            "username": "testuser",
            "password": "testpass123",
        }, allow_redirects=True)
        # If login redirects to MFA, submit a fixed TOTP (pre-configure a
        # test user with a known TOTP secret for load testing).
        if "/ztna/mfa/" in resp.url:
            # Use pyotp to generate a valid token for the test account
            try:
                import pyotp
                totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")   # test secret
                self.client.post("/ztna/mfa/", data={"token": totp.now()})
            except Exception:
                pass

    @task(6)
    def dashboard(self):
        self.client.get("/ztna/dashboard/")

    @task(3)
    def trust_analytics(self):
        self.client.get("/ztna/trust/analytics/")

    @task(2)
    def view_logs(self):
        self.client.get("/ztna/logs/")

    @task(1)
    def fire_cmds(self):
        """High-risk action — will be restricted under low trust."""
        self.client.get("/ztna/fire-cmds/")
