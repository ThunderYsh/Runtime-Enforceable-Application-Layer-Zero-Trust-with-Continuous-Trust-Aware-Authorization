# ztna/utils.py
from idp.models import UserProfile
from appsrv.models import ApplicationResource
from trustbroker.models import TrustScore

# enforce_access() returns a lowercase "action" ("allow" / "blocked" / "mfa" /
# ...) that never matches ZTNARequest.STATUS_CHOICES ("APPROVED" / "BLOCKED" /
# "DENIED" / "PENDING"). Writing decision["action"] straight into `status`
# silently created rows no status-based query could ever find. This map is
# the single normalization point.
ACTION_TO_STATUS = {
    "allow": "APPROVED",
    "blocked": "BLOCKED",
}


def log_ztna(
    user,
    app_name,
    ip,
    status=None,
    reason="",
    device_score=50,
    mfa_passed=False,
    decision=None,
):
    """
    Logs ZTNA access activity.

    IMPORTANT:
    - Never recompute enforce_access here (avoid mismatched decisions)
    - Uses lazy import for ZTNARequest to avoid circular import crash
    """

    # ✅ lazy import (break circular import)
    from .models import ZTNARequest

    profile = UserProfile.objects.filter(user=user).first()
    if not profile:
        return None

    app = ApplicationResource.objects.filter(name__iexact=app_name).first()
    if not app:
        return None

    ts = TrustScore.objects.filter(user_profile=profile).first()

    if decision is None:
        return ZTNARequest.objects.create(
            user_profile=profile,
            app_resource=app,
            trust_score=ts,
            ip_address=ip,
            status=status or "PENDING",
            decision_reason=reason or "",
            location="Unknown",
            policy_rule_id=None,
        )

    action = decision.get("action")
    normalized_status = ACTION_TO_STATUS.get(action, "DENIED" if action else (status or "PENDING"))

    return ZTNARequest.objects.create(
        user_profile=profile,
        app_resource=app,
        trust_score=ts,
        ip_address=ip,
        status=normalized_status,
        decision_reason=decision.get("reason", reason or ""),
        location="Unknown",
        policy_rule_id=decision.get("policy_rule_id"),
    )
