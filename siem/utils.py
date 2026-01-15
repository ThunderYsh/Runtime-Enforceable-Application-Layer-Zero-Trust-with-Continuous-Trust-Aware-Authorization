# siem/utils.py
from idp.models import UserProfile
from siem.models import AuditLog

def audit_log(
    *,
    user=None,
    user_profile=None,
    action="",
    status="SUCCESS",
    ip=None,
    latency_ms=None,
    policy_rule_id=None,
):
    """
    Central SIEM logging helper.
    Prevents schema mismatch and enforces consistent telemetry.
    """

    if user_profile is None and user is not None:
        user_profile = UserProfile.objects.filter(user=user).first()

    if user_profile is None:
        return None

    return AuditLog.objects.create(
        user_profile=user_profile,
        action=action,
        status=status,
        ip=ip,
        latency_ms=latency_ms,
        policy_rule_id=policy_rule_id,
    )
