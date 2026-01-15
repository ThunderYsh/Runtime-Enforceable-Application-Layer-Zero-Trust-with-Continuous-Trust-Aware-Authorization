import time
from django.utils.deprecation import MiddlewareMixin
from siem.utils import audit_log
from idp.models import UserProfile


class RequestLatencyMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request._start_time = time.perf_counter()

    def process_response(self, request, response):
        if hasattr(request, "_start_time") and getattr(request, "user", None) and request.user.is_authenticated:
            profile = UserProfile.objects.filter(user=request.user).first()
            if not profile:
                return response  # fail safely

            latency = (time.perf_counter() - request._start_time) * 1000

            # ✅ FIX: use audit_log helper (no AuditLog direct call)
            audit_log(
                user_profile=profile,
                action="request_latency",
                ip=request.META.get("REMOTE_ADDR"),
                latency_ms=round(latency, 2),
                status="SUCCESS",
                policy_rule_id=None,
            )

        return response
