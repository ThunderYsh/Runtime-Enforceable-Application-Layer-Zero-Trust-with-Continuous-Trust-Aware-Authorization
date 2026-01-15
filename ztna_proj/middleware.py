from django.shortcuts import render
from siem.utils import audit_log
from idp.models import UserProfile
from trustbroker.utils import event_penalty


def admin_only_middleware(get_response):

    def middleware(request):
        path = request.path

        # Check only admin URLs
        if path.startswith("/admin/"):

            # Let Django admin login page work normally
            if path.startswith("/admin/login"):
                return get_response(request)

            # If logged in
            if request.user.is_authenticated:

                # SUPERUSER → FULL ACCESS
                if request.user.is_superuser:
                    return get_response(request)

                # NORMAL USER → BLOCK + TRUST PENALTY + LOG
                profile = UserProfile.objects.filter(user=request.user).first()
                if profile:
                    # Trust penalty
                    event_penalty(profile, "blocked", request.META.get("REMOTE_ADDR"))

                   
                    audit_log(
                        user_profile=profile,
                        action="Unauthorized admin access attempt",
                        ip=request.META.get("REMOTE_ADDR"),
                        status="BLOCKED",
                        policy_rule_id=None,
                    )

                return render(request, "admin_access_denied.html", status=403)

            # Not logged in → allow Django admin to handle login
            return get_response(request)

        return get_response(request)

    return middleware
