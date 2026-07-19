import time
from django.utils.deprecation import MiddlewareMixin
from siem.utils import audit_log
from idp.models import UserProfile


class RequestLatencyMiddleware(MiddlewareMixin):

    #  Paths we never want to log latency for (they create spam)
    SKIP_PREFIXES = (
        "/static/",
        "/admin/",
        "/ztna/logs/",   
    )

    def process_request(self, request):
        request._start_time = time.perf_counter()

    def process_response(self, request, response):

        # Basic safety
        if not hasattr(request, "_start_time"):
            return response

        if not getattr(request, "user", None) or not request.user.is_authenticated:
            return response

        #  Don't log latency for skipped routes
        path = request.path or ""
        for prefix in self.SKIP_PREFIXES:
            if path.startswith(prefix):
                return response

        profile = UserProfile.objects.filter(user=request.user).first()
        if not profile:
            return response  # fail safely

        latency = (time.perf_counter() - request._start_time) * 1000

        audit_log(
            user_profile=profile,
            action="request_latency",
            ip=request.META.get("REMOTE_ADDR"),
            latency_ms=round(latency, 2),
            status="SUCCESS",
            policy_rule_id=None,
        )

        return response
