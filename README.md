# Runtime-Enforceable Application-Layer ZTNA with Continuous Trust-Aware Authorization

A deployable Django-based application-layer ZTNA prototype implementing:
continuous trust evaluation, policy decision enforcement, device posture scoring
(using fingerprint stability), event-driven TrustBroker, audit logging (SIEM-like),
and risk-adaptive step-up MFA for sensitive operations.

This repository contains the prototype implementation for the research paper:

**"Runtime-Enforceable Application-Layer Zero Trust with Continuous Trust-Based Authorization"**

---

## Features
- Application-layer ZTNA enforcement (per-request)
- Policy engine (deny / require MFA / mark critical)
- Device fingerprint scoring & device trust reporting
- Behavioral trust scoring + recovery
- Step-up MFA escalation
- Trust analytics + audit logging (SIEM-like)

---

## Tech Stack
- Django
- Python
- SQLite (dev)
- Tailwind UI templates

---

## Setup
```bash
git clone <repo-url>
cd <project>

python -m venv venv
venv\Scripts\activate   # Windows

pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
