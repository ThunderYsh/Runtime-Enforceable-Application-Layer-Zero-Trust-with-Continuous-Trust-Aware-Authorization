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
    DeviceRecord,
)
from .tasks import send_async_email
from trustbroker.utils import event_penalty
from trustbroker.models import TrustScore
from idp.models import UserProfile
from trustbroker.dashboard_trust import calculate_dashboard_trust
from policy.trust import evaluate_rules

# -------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------
FAILED_WINDOW_MINUTES = 60          # look back 60 minutes for failures
FAILED_THRESHOLD = 3                # (not used yet, but fine to keep)
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

    # role-based (admin override, critical ops, etc.)
    if field == "role" and op == "is":
        return ctx.get("role") == val

    # time window
    if field == "hour" and op == "between":
        h = int(ctx.get("hour", timezone.localtime().hour))
        a, b = map(int, str(val).split("-"))
        return a <= h <= b

    # failed login / failures
    if field == "failed_count" and op == "gte":
        return int(ctx.get("failed_count", 0)) >= int(val)

    # device score thresholds
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
    Evaluates contextual risk and returns a normalized decision object.

    Returns dict:
      {
        "action": "allow" | "mfa" | "blocked",
        "require_mfa": bool,
        "trust_score": int,
        "trust_delta": int,
        "notes": [ ... ]
      }
    """

    decision = {
        "action": "allow",
        "require_mfa": False,
        "trust_delta": 0,
        "notes": [],
    }

    # ADMIN OVERRIDE at context level (usually not used since enforce_access
    # already handles admin, but kept safe)
    if ctx.get("role") == "admin":
        decision["notes"].append("admin_override")
        decision["trust_score"] = 100
        return decision

    # Load active rules
    rules = PolicyRule.objects.filter(
        enabled=True,
        policy__status="active",
    ).order_by("priority")

    # Evaluate in priority order
    for r in rules:
        if _cond_matches(r.condition or {}, ctx):
            decision["notes"].append(f"rule:{r.name}")

            # HARD BLOCK
            if r.action in ("deny", "block_1h"):
                decision["action"] = "blocked"
                decision["trust_delta"] -= 40
                break

            # REQUIRE MFA
            if r.action == "require_mfa":
                decision["require_mfa"] = True
                decision["trust_delta"] -= 10
                decision["action"] = "mfa"

            # ESCALATE
            if r.action == "escalate":
                decision["trust_delta"] -= 20

            # CRITICAL
            if r.action == "mark_critical":
                decision["trust_delta"] -= 40

    # Final trust score in [0, 100]
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
    mfa_passed: bool = False,
):
    """
    Unified Zero Trust Policy Engine.

    RETURN VALUE IS ALWAYS A DICT:
        {
          "allowed": bool,
          "action": "allow" | "mfa" | "blocked",
          "reason": str,

          # ✅ REQUIRED FOR Q1 TRACEABILITY
          "policy_rule_id": int | None,

          "dashboard_trust": int(0-100),
          "trust_score": int(0-100),   # same as dashboard_trust for safety
          "policy_flags": dict,
          "notes": list[str],
          "block_record": object | None,
        }
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
    # 3) CONTEXT BUILDING (for evaluate_rules)
    # ----------------------------------------------------------------
    profile = UserProfile.objects.filter(user=user).first()
    behavior_trust = 1.0
    if profile:
        ts, _ = TrustScore.objects.get_or_create(user_profile=profile)
        behavior_trust = getattr(ts, "overall_trust", 1.0) or 1.0

    hour = timezone.localtime().hour
    ip_reputation = "clean"  # placeholder – extend later

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
        "trust_score": behavior_trust,   # 0–1 behavioral trust
        "ip_reputation": ip_reputation,
        "country": "IN",
    }

    # ----------------------------------------------------------------
    # 4) POLICY ENGINE – evaluate_rules(ctx)
    # ----------------------------------------------------------------
    policy_score, policy_flags, policy_rule_id = evaluate_rules(ctx)

    # Normalize flags for dashboard trust scoring
    policy_flags_for_dashboard = {
        "blocked": policy_flags.get("block", False),
        "high_risk": False,
        "medium_risk": False,
        "low_risk": False,
    }

    # ----------------------------------------------------------------
    # 5) DASHBOARD TRUST (0–100)
    # ----------------------------------------------------------------
    dashboard_trust = calculate_dashboard_trust(
        ip_reputation=ip_reputation,
        device_score=device_score,
        mfa_passed=mfa_passed,
        policy_flags=policy_flags_for_dashboard,
    )

    trust_score = dashboard_trust

    # ----------------------------------------------------------------
    # 6) POLICY BLOCK
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
            "policy_flags": policy_flags_for_dashboard,
            "notes": ["policy:block"],
            "block_record": blk,
        }

    # ----------------------------------------------------------------
    # 7) POLICY REQUIRES MFA
    # ----------------------------------------------------------------
    if policy_flags.get("require_mfa") and not mfa_passed:
        return {
            "allowed": False,
            "action": "mfa",
            "reason": "require_mfa",
            "policy_rule_id": policy_rule_id,
            "dashboard_trust": trust_score,
            "trust_score": trust_score,
            "policy_flags": policy_flags_for_dashboard,
            "notes": ["policy:require_mfa"],
            "block_record": None,
        }

    # ----------------------------------------------------------------
    # 8) FINAL ALLOW
    # ----------------------------------------------------------------
    return {
        "allowed": True,
        "action": "allow",
        "reason": "ok",
        "policy_rule_id": policy_rule_id,
        "dashboard_trust": trust_score,
        "trust_score": trust_score,
        "policy_flags": policy_flags_for_dashboard,
        "notes": [],
        "block_record": None,
    }





