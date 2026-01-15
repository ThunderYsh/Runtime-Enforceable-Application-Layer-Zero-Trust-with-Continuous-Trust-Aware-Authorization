# policy/trust.py
from .models import PolicyRule
from datetime import datetime


def evaluate_rules(context):
    """
    Deterministic policy evaluation.

    Returns:
        policy_score (int 0-100),
        flags (dict),
        triggering_rule_id (int | None)

    Rules are evaluated in ascending priority order.
    The FIRST matched rule becomes the triggering_rule_id (lowest priority wins).
    """

    score = 100
    flags = {"block": False, "require_mfa": False}
    triggering_rule_id = None

    qs = (
        PolicyRule.objects
        .filter(enabled=True, policy__status="active")
        .order_by("priority", "id")
    )

    for rule in qs:
        if _matches(rule.condition or {}, context):

            # ✅ lowest priority wins: first match becomes triggering rule
            if triggering_rule_id is None:
                triggering_rule_id = rule.id

            action = (rule.action or "").lower().strip()

            # ✅ hard stop deny
            if action == "deny":
                flags["block"] = True
                return 0, flags, triggering_rule_id

            # ✅ step-up MFA
            if action == "require_mfa":
                flags["require_mfa"] = True
                score -= 30

            # Optional risk scoring actions
            if action == "escalate":
                score -= 20

            if action == "mark_critical":
                score -= 40

            if action == "block_1h":
                flags["block"] = True

    return max(0, score), flags, triggering_rule_id


def _matches(cond, ctx):
    field = cond.get("field")
    op = cond.get("op")
    val = cond.get("value")

    trust_score = float(ctx.get("trust_score", 1.0))
    device_score = int(ctx.get("device_score", 50))
    ip_rep = ctx.get("ip_reputation", "unknown")
    country = (ctx.get("country", "") or "").upper()
    role = ctx.get("role", "")
    hour = int(ctx.get("hour", datetime.now().hour))
    failed_count = int(ctx.get("failed_count", 0))

    # ---- TRUST SCORE ----
    if field == "trust_score":
        v = float(val)
        if op == "<":
            return trust_score < v
        if op == ">":
            return trust_score > v
        if op == "==":
            return trust_score == v
        if op == "!=":
            return trust_score != v

    # ---- DEVICE SCORE ----
    if field == "device_score":
        v = int(val)
        if op == "<":
            return device_score < v
        if op == ">":
            return device_score > v
        if op == "==":
            return device_score == v

    # ---- IP REPUTATION ----
    if field == "ip_reputation":
        if op == "==":
            return ip_rep == val
        if op == "!=":
            return ip_rep != val

    # ---- COUNTRY ----
    if field == "country":
        if isinstance(val, str):
            vals = [c.strip().upper() for c in val.split(",") if c.strip()]
        else:
            vals = [str(v).upper() for v in (val or [])]

        if op == "in":
            return country in vals
        if op == "not in":
            return country not in vals

    # ---- ROLE ----
    if field == "role":
        if op in ("==", "is"):
            return role == val

    # ---- HOUR ----
    if field == "hour":
        if op == "between":
            try:
                a, b = map(int, str(val).split("-"))
            except ValueError:
                return False
            return a <= hour <= b
        if op == "<":
            return hour < int(val)
        if op == ">":
            return hour > int(val)

    # ---- FAILED LOGIN COUNT ----
    if field == "failed_count":
        v = int(val)
        if op == ">":
            return failed_count > v
        if op == "gte":
            return failed_count >= v
        if op == "==":
            return failed_count == v

    # ---- TIME RANGE ----
    if field == "time_range" and op == "in":
        try:
            start, end = map(int, str(val).split("-"))
        except ValueError:
            return False
        return start <= hour <= end

    return False
