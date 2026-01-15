# policy/middleware_enforcer.py

from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden

from .enforcer import enforce_access
from trustbroker.utils import event_penalty
from idp.models import UserProfile


class PolicyEnforcementMiddleware(MiddlewareMixin):
    def process_request(self, request):
        path = request.path

        # --------------------------------------------------
        # 0) NEVER enforce on auth, MFA, admin paths
        # --------------------------------------------------
        if (
            path.startswith("/ztna/login")
            or path.startswith("/ztna/logout")
            or path.startswith("/ztna/mfa")
            or path.startswith("/ztna/register")
            or path.startswith("/admin")
        ):
            return None

        # --------------------------------------------------
        # 1) Anonymous users → always allow
        # --------------------------------------------------
        if not request.user.is_authenticated:
            request.ztna_decision = {
                "allowed": True,
                "action": "allow",
                "reason": "anonymous",
                "trust_score": 100,
                "notes": ["anonymous"],
            }
            return None

        user = request.user
        ip = request.META.get("REMOTE_ADDR", "")

        # --------------------------------------------------
        # 2) Superuser / staff override
        # --------------------------------------------------
        if user.is_superuser or user.is_staff:
            request.ztna_decision = {
                "allowed": True,
                "action": "allow",
                "reason": "admin_override",
                "trust_score": 100,
                "notes": ["admin_override"],
            }
            return None

        # --------------------------------------------------
        # 3) Normal user → enforce policy
        # --------------------------------------------------
        device_score = getattr(request, "device_score", None)
        if device_score is None:
            try:
                device_score = int(request.META.get("HTTP_X_DEVICE_SCORE", "50"))
            except Exception:
                device_score = 50

        decision = enforce_access(
            user=user,
            ip=ip,
            protected_link=None,
            device_score=device_score,
            mfa_passed=request.session.get("mfa_passed", False),
        )

        # Store decision once (for UI / logging)
        request.ztna_decision = decision

        # --------------------------------------------------
        # 4) Hard block
        # --------------------------------------------------
        if decision.get("action") == "blocked":
            profile = UserProfile.objects.get(user=user)
            event_penalty(profile, "blocked", ip)
            return HttpResponseForbidden("Blocked by ZTNA Policy Engine")

        # --------------------------------------------------
        # 5) Allow request to continue
        # --------------------------------------------------
        return None
