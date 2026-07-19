

# Runtime-Enforceable Application-Layer ZTNA with Continuous Trust-Aware Authorization

A deployable Django-based application-layer Zero Trust Network Access (ZTNA) prototype. Unlike gateway or session-level ZTNA, enforcement here happens on every request, inside the application itself: identity, device posture, and a
continuously updated behavioral trust score jointly decide whether a request is allowed, feature-restricted, escalated to step-up MFA, or blocked.

This repository is the prototype implementation behind the paper:

**"Runtime-Enforceable Application-Layer Zero Trust with Continuous Trust-Based Authorization"**
Yash Tukaram Bhole — Department of Computer Science and Engineering, COEP Technological University, Pune, India

---

## What's implemented

- **Identity Provider (IdP)** — Django auth + TOTP-based MFA (QR enrollment, standard authenticator apps)
- **TrustBroker** — a bounded, event-driven behavioral trust score `T_u ∈ [0,1]` per user, updated on every security-relevant event:
  - Penalties: bad password (`-0.08`), MFA failure (`-0.06`), policy block / admin denial (`-0.10`), unauthorized link access (`-0.07`)
  - Recovery: hourly time-based (`+0.02`), safe action (`+0.02`), MFA re-authentication (`+0.10`)
  - Recovery increments are always smaller than penalties, so sustained misuse drives trust down monotonically
- **Device posture scoring** — a per-user fingerprint registry (`DeviceFingerprintRecord`). A never-before-seen fingerprint is scored low regardless of hash quality; a fingerprint verified through a prior successful step-up challenge is scored high. Device posture and behavioral trust are independent enforcement signals — a trusted user on an unrecognized device is still gated, and a recognized device doesn't waive behavioral-trust checks.
- **Policy Engine (PDP)** — deterministic condition→action rules over trust score, device score, role, time-of-day, and failure counts (`allow` / `require_mfa` / `deny` / `escalate` / `block_1h`)
- **Enforcement Middleware (PEP)** — Django middleware enforcing the policy decision on every request; also includes a time-based night-access rule and a device-fingerprint middleware
- **Step-up MFA** — sensitive actions (file create/edit/share, command execution) trigger a step-up MFA challenge when behavioral trust drops below threshold *or* the requesting device is unrecognized; completing step-up records the device as known and restores trust
- **SIEM-style audit logging** — every authentication event, trust update, policy decision, and enforcement outcome is logged with enough metadata (`request_id`, `policy_rule_id`) to reconstruct why any given decision was made

---

## Tech stack

- Django 5.x, Django REST Framework
- SQLite (development database)
- pyotp / qrcode (TOTP MFA)
- matplotlib, numpy, pandas (analysis/plotting scripts, not required to run the app itself)

---

## Setup

```bash
git clone https://github.com/ThunderYsh/Runtime-Enforceable-Application-Layer-Zero-Trust-with-Continuous-Trust-Aware-Authorization.git
cd Runtime-Enforceable-Application-Layer-Zero-Trust-with-Continuous-Trust-Aware-Authorization

python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
Then visit http://127.0.0.1:8000/ztna/login/.

Environment variables
Email-based alerts (e.g. auto-block notifications) need SMTP credentials. Create a .env file in the project root:


EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-app-password
This is optional for basic local use — the app runs without it, email sending will just silently fail.

Toggling enforcement (for A/B comparison)
Set ZTNA_ENFORCEMENT_ENABLED=false before starting the server to run with device-fingerprint, night-access, and policy-enforcement middleware removed from the request pipeline — useful for reproducing the baseline-vs-enabled latency comparison described in the paper:


set ZTNA_ENFORCEMENT_ENABLED=false   # Windows
python manage.py runserver
Reproducing the paper's experimental results
Script	Produces
python manage.py collect_experiment_status	Dataset characteristics table (registered users, requests, devices, policy rules, trust/audit event counts)
python run_sensitivity_analysis.py	Sensitivity analysis over MFA penalty values across simulated sessions
python seed_bench_user.py + python ab_latency_harness.py <n> <host>	Seeds a benchmark account and drives real HTTP traffic against a running server for the baseline-vs-enabled latency comparison
python plots/extract_latency_csv.py <out.csv> [since]	Exports captured request latency from the audit log to CSV
python statistical_validation.py <baseline.csv> <ztna.csv>	Welch's t-test / Cohen's d on two real latency CSVs (no synthetic data mode — both inputs must be real captures)
python plots/latency_percentiles.py, plot_latency_comparison.py, plot_latency_cdf.py	Latency percentile table and figures
python plots/enforcement_outcome_breakdown.py	Enforcement outcome breakdown figure, from the same query as the dataset table
python plots/mfa_escalation_breakdown.py	Step-up MFA escalation breakdown, by trigger reason (trust / device / both)
All of these query the live db.sqlite3 directly — none of them accept synthetic input as a substitute for real captured data.

Project structure

idp/            # Identity provider: auth, TOTP MFA, user profiles
trustbroker/    # Trust score computation, recovery, trust events
policy/         # Policy engine, enforcement middleware, device fingerprint records
ztna/           # Application views (dashboard, file ops, command execution),
                # device scoring, step-up MFA gate
siem/           # Audit logging
appsrv/         # Protected application resources
plots/          # Analysis and figure-generation scripts used in the paper
License
See LICENSE.

Citation
If you use this work, please cite:

Y. T. Bhole, "Runtime-Enforceable Application-Layer Zero Trust with Continuous Trust-Based Authorization," (under review).
