# policy/enforcer.py

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import (
    PolicyRule,
    LinkAccessAttempt,
    UserTemporaryBlock,
    ProtectedLink,
)
from .tasks import send_async_email

from trustbroker.utils import event_penalty
from trustbroker.models import TrustScore, TrustEvent
from idp.models import UserProfile
from trustbroker.dashboard_trust import calculate_dashboard_trust
from policy.trust import evaluate_rules


# -------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------
FAILED_WINDOW_MINUTES = 60          # look back 60 minutes for failures
FAILED_THRESHOLD = 3                # used for escalation logic
BLOCK_DURATIONS = [15, 60, 360]     # minutes: 15m, 1h, 6h


# -------------------------------------------------------------------
# HELPERS: FAILURE COUNT / TEMP BLOCKS
# -------------------------------------------------------------------
def _count_recent_failures(protected_link_id, user, ip):
    since = timezone.now() - timedelta(minutes=FAILED_WINDOW_MINUTES)
    q = LinkAccessAttempt.objects.filter(
        protected_link_id=protected_link_id,
        timestamp__gte=since,
        success=False,
        failure_reason__in=[
            "bad_password",
            "bad_token",
            "bad_credentials",
            "bad_password_or_token",
        ],
    )
    if user:
        q = q.filter(user=user)
    else:
        q = q.filter(ip=ip)
    return q.count()


def _count_recent_mfa_failures(user, ip):
    """
    Counts recent MFA failures from TrustEvent logs.
    This powers deterministic step-up behavior in dashboard trust.
    """
    since = timezone.now() - timedelta(minutes=FAILED_WINDOW_MINUTES)
    q = TrustEvent.objects.filter(
        timestamp__gte=since,
        event_type="mfa_fail",
    )
    # If your TrustEvent model links user_profile instead of user directly:
    profile = UserProfile.objects.filter(user=user).first() if user else None
    if profile:
        q = q.filter(user_profile=profile)
    else:
        # fallback: if you store IP inside TrustEvent meta fields
        # (ignore if not applicable)
        pass
    return q.count()


def _get_block_for_actor(user, ip):
    now = timezone.now()
    q = UserTemporaryBlock.objects.filter(blocked_until__gt=now)
    if user:
        q = q.filter(user=user)
    else:
        q = q.filter(ip=ip)
    return q.order_by("-blocked_until").first()


def _create_or_escalate_block(user, ip, reason="too_many_failures"):
    """
    Creates or escalates a temporary block record and emails admins.
    """
    now = timezone.now()
    blk = _get_block_for_actor(user, ip)

    if not blk:
        blk = UserTemporaryBlock.objects.create(
            user=user,
            ip=ip,
            block_level=1,
            blocked_until=now + timedelta(minutes=BLOCK_DURATIONS[0]),
        )
    else:
        lvl = min(blk.block_level + 1, len(BLOCK_DURATIONS))
        blk.block_level = lvl
        blk.blocked_until = now + timedelta(minutes=BLOCK_DURATIONS[lvl - 1])
        blk.save()

    emails = [e for _, e in getattr(settings, "ADMINS", [])]
    if emails:
        who = user.username if user else ip
        send_async_email(
            "[ZTNA] Auto-block triggered",
            f"Actor: {who}\nReason: {reason}\nBlocked until: {blk.blocked_until}",
            emails,
        )
    return blk


# -------------------------------------------------------------------
# RULE MATCHING + CONTEXT EVALUATION
# -------------------------------------------------------------------
def _cond_matches(cond, ctx):
    """
    Minimal condition matcher for PolicyRule.condition JSON.

    Supported fields / ops here MUST match how you define rules:
      - field: "role", op: "is"
      - field: "hour", op: "between"
      - field: "failed_count", op: "gte"
      - field: "device_score", op: lt/lte/gt/gte
    """
    field = cond.get("field")
    op = cond.get("op")
    val = cond.get("value")
    if not field:
        return False

    if field == "role" and op == "is":
        return ctx.get("role") == val

    if field == "hour" and op == "between":
        h = int(ctx.get("hour", timezone.localtime().hour))
        a, b = map(int, str(val).split("-"))
        return a <= h <= b

    if field == "failed_count" and op == "gte":
        return int(ctx.get("failed_count", 0)) >= int(val)

    if field == "device_score" and op in ("lt", "lte", "gt", "gte"):
        ds = int(ctx.get("device_score", 0))
        v = int(val)
        if op == "lt":
            return ds < v
        if op == "lte":
            return ds <= v
        if op == "gt":
            return ds > v
        if op == "gte":
            return ds >= v

    return False


def evaluate_request_context(ctx):
    """
    (Optional legacy evaluator)
    Your system uses evaluate_rules(ctx), so this remains as backup.
    """
    decision = {
        "action": "allow",
        "require_mfa": False,
        "trust_delta": 0,
        "notes": [],
    }

    if ctx.get("role") == "admin":
        decision["notes"].append("admin_override")
        decision["trust_score"] = 100
        return decision

    rules = PolicyRule.objects.filter(
        enabled=True,
        policy__status="active",
    ).order_by("priority")

    for r in rules:
        if _cond_matches(r.condition or {}, ctx):
            decision["notes"].append(f"rule:{r.name}")

            if r.action in ("deny", "block_1h"):
                decision["action"] = "blocked"
                decision["trust_delta"] -= 40
                break

            if r.action == "require_mfa":
                decision["require_mfa"] = True
                decision["trust_delta"] -= 10
                decision["action"] = "mfa"

            if r.action == "escalate":
                decision["trust_delta"] -= 20

            if r.action == "mark_critical":
                decision["trust_delta"] -= 40

    base = 100
    final_score = max(0, min(100, base + decision["trust_delta"]))
    decision["trust_score"] = final_score
    return decision


# -------------------------------------------------------------------
# MAIN ENFORCEMENT ENTRYPOINT
# -------------------------------------------------------------------
@transaction.atomic
def enforce_access(
    user,
    ip,
    protected_link=None,
    device_score: int = 50,
    mfa_passed: bool = False,  # kept for API compatibility, NOT used
):
    """
    Unified Zero Trust Policy Engine (Paper-aligned).

    RETURNS ONLY:
        - allow
        - blocked
    """

    # ----------------------------------------------------------------
    # 0) ADMIN OVERRIDE (NEVER BLOCKED)
    # ----------------------------------------------------------------
    if user and user.is_authenticated and (user.is_superuser or user.is_staff):
        return {
            "allowed": True,
            "action": "allow",
            "reason": "admin_override",
            "policy_rule_id": None,
            "dashboard_trust": 100,
            "trust_score": 100,
            "policy_flags": {},
            "notes": ["admin_override"],
            "block_record": None,
        }

    # ----------------------------------------------------------------
    # 1) ANONYMOUS SAFETY NET
    # ----------------------------------------------------------------
    if not user or not getattr(user, "is_authenticated", False):
        return {
            "allowed": True,
            "action": "allow",
            "reason": "anonymous",
            "policy_rule_id": None,
            "dashboard_trust": 100,
            "trust_score": 100,
            "policy_flags": {},
            "notes": ["anonymous"],
            "block_record": None,
        }

    # ----------------------------------------------------------------
    # 2) EXISTING TEMPORARY BLOCK?
    # ----------------------------------------------------------------
    existing = _get_block_for_actor(user, ip)
    if existing:
        profile = UserProfile.objects.filter(user=user).first()
        if profile:
            event_penalty(profile, "blocked", ip)

        return {
            "allowed": False,
            "action": "blocked",
            "reason": "existing_block",
            "policy_rule_id": None,
            "dashboard_trust": 0,
            "trust_score": 0,
            "policy_flags": {"blocked": True},
            "notes": ["existing_block"],
            "block_record": existing,
        }

    # ----------------------------------------------------------------
    # 3) CONTEXT BUILDING
    # ----------------------------------------------------------------
    profile = UserProfile.objects.filter(user=user).first()

    behavioral_trust = 1.0
    if profile:
        ts, _ = TrustScore.objects.get_or_create(user_profile=profile)
        behavioral_trust = getattr(ts, "overall_trust", 1.0) or 1.0

    hour = timezone.localtime().hour
    ip_reputation = "clean"  # placeholder
    failed_count = 0
    link_id = None

    if protected_link:
        link_id = protected_link.id
        failed_count = _count_recent_failures(link_id, user, ip)

    ctx = {
        "user": user,
        "role": "user",
        "ip": ip,
        "hour": hour,
        "device_score": device_score,
        "failed_count": failed_count,
        "protected_link_id": link_id,
        "trust_score": behavioral_trust,  # 0–1
        "ip_reputation": ip_reputation,
        "country": "IN",
    }

    # ----------------------------------------------------------------
    # 4) POLICY ENGINE
    # ----------------------------------------------------------------
    policy_score, policy_flags, policy_rule_id = evaluate_rules(ctx)

    policy_flags_for_dashboard = {
        "blocked": policy_flags.get("block", False),
        "high_risk": policy_flags.get("high_risk", False),
        "medium_risk": policy_flags.get("medium_risk", False),
        "low_risk": policy_flags.get("low_risk", False),
    }

    # ----------------------------------------------------------------
    # 5) DASHBOARD TRUST (0–100)
    # ----------------------------------------------------------------
    dashboard_trust = calculate_dashboard_trust(
        ip_reputation=ip_reputation,
        device_score=device_score,
        mfa_passed=True,  # MFA NOT used for enforcement
        policy_flags=policy_flags_for_dashboard,
        mfa_fail_count=0,
    )

    trust_score = dashboard_trust

    # ----------------------------------------------------------------
    # 6) HARD POLICY BLOCK
    # ----------------------------------------------------------------
    if policy_flags.get("block"):
        blk = _create_or_escalate_block(user, ip, reason="policy_block")

        if profile:
            event_penalty(profile, "blocked", ip)

        return {
            "allowed": False,
            "action": "blocked",
            "reason": "policy_block",
            "policy_rule_id": policy_rule_id,
            "dashboard_trust": 0,
            "trust_score": 0,
            "policy_flags": {"blocked": True},
            "notes": ["policy:block"],
            "block_record": blk,
        }

    # ----------------------------------------------------------------
    # 7) TRUST-BASED HARD DENY (Paper threshold)
    # ----------------------------------------------------------------
    if trust_score < 60:
        if profile:
            event_penalty(profile, "blocked", ip)

        return {
            "allowed": False,
            "action": "blocked",
            "reason": "trust_below_threshold",
            "policy_rule_id": policy_rule_id,
            "dashboard_trust": trust_score,
            "trust_score": trust_score,
            "policy_flags": {"blocked": True},
            "notes": ["tier:restricted"],
            "block_record": None,
        }

    # ----------------------------------------------------------------
    # 8) FINAL ALLOW
    # ----------------------------------------------------------------
    notes = []
    if trust_score >= 80:
        notes.append("tier:safe")
    else:
        notes.append("tier:moderate")

    return {
        "allowed": True,
        "action": "allow",
        "reason": "ok",
        "policy_rule_id": policy_rule_id,
        "dashboard_trust": trust_score,
        "trust_score": trust_score,
        "policy_flags": policy_flags_for_dashboard,
        "notes": notes,
        "block_record": None,
    }

