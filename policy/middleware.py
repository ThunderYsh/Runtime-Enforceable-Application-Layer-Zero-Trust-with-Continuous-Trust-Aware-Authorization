# policy/middleware.py
from django.utils import timezone
from django.http import HttpResponseForbidden

from trustbroker.utils import event_penalty
from idp.models import UserProfile
from siem.utils import audit_log


class NightAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        # ALWAYS allow login, logout, mfa, register
        if (
            path.startswith("/ztna/login")
            or path.startswith("/ztna/logout")
            or path.startswith("/ztna/mfa")
            or path.startswith("/ztna/register")
        ):
            return self.get_response(request)

        now_hour = timezone.localtime().hour
        user = request.user

        # NIGHT BLOCK (0–7 AM)
        if 0 <= now_hour < 7:
            # Superusers still get access
            if user.is_authenticated and user.is_superuser:
                return self.get_response(request)

            # Apply trust penalty + SIEM log
            if user.is_authenticated:
                profile = UserProfile.objects.filter(user=user).first()
                if profile:
                    event_penalty(profile, "night_access", request.META.get("REMOTE_ADDR"))

                    audit_log(
                        user_profile=profile,
                        action="Night access attempt",
                        status="BLOCKED",
                        ip=request.META.get("REMOTE_ADDR"),
                        policy_rule_id=None,  # optional (you can map to a fixed rule id if you want)
                    )

            return HttpResponseForbidden("Access denied between 12 AM — 7 AM")

        return self.get_response(request)
