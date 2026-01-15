# trustbroker/utils.py
from django.utils import timezone
from .models import TrustScore, TrustEvent

PENALTY_MAP = {
    "bad_password": 0.08,
    "mfa_fail": 0.06,
    "blocked": 0.10,
    "link_fail": 0.07,
}


def event_penalty(profile, event_type, ip="unknown"):
    """
    Apply a negative trust event and log it.
    event_type must exist in PENALTY_MAP or default to a small penalty.
    """
    ts, _ = TrustScore.objects.get_or_create(user_profile=profile)
    ts.daily_recovery()  

    amount = float(PENALTY_MAP.get(event_type, 0.05))

    old, new = ts.apply_penalty(amount)

    TrustEvent.objects.create(
        user_profile=profile,
        event_type=event_type,
        delta=new - old,   
        old_score=old,
        new_score=new,
        ip=ip,
    )

    return new
