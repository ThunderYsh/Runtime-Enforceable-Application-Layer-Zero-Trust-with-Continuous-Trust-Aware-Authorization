def calculate_dashboard_trust(ip_reputation, device_score, mfa_passed, policy_flags, mfa_fail_count=0):
    """
    Deterministic dashboard trust scoring (0–100).

    Principles:
    - MFA is a *gate* for high trust, not a free bonus reset.
    - Device posture imposes an upper trust cap.
    - Repeated MFA failures reduce trust even if MFA later succeeds.
    - Policy flags can hard block.
    """

    debug = []
    score = 100
    debug.append("----- DASHBOARD TRUST DEBUG REPORT -----")

    # -------------------------------------------------
    # 0) HARD POLICY BLOCK
    # -------------------------------------------------
    if policy_flags.get("blocked"):
        debug.append("[HARD BLOCK] Policy system flagged BLOCK -> score = 0")
        print("\n".join(debug))
        return 0

    # -------------------------------------------------
    # 1) DEVICE POSTURE PENALTY + TRUST CAP
    # -------------------------------------------------
    debug.append(f"[Device] Device score = {device_score}")

    if device_score < 20:
        score -= 50
        cap = 40
        debug.append("[Penalty] Device <20 (critical risk) -> -50, cap=40")
    elif device_score < 40:
        score -= 35
        cap = 70
        debug.append("[Penalty] Device <40 (high risk) -> -35, cap=70")
    elif device_score < 60:
        score -= 20
        cap = 85
        debug.append("[Penalty] Device <60 (medium risk) -> -20, cap=85")
    elif device_score < 75:
        score -= 10
        cap = 95
        debug.append("[Penalty] Device <75 (light risk) -> -10, cap=95")
    else:
        cap = 100
        debug.append("[OK] Device >=75 (healthy), cap=100")

    # -------------------------------------------------
    # 2) IP REPUTATION PENALTY
    # -------------------------------------------------
    debug.append(f"[IP] Reputation = {ip_reputation}")
    if ip_reputation == "bad":
        score -= 40
        debug.append("[Penalty] IP BAD -> -40")
    elif ip_reputation == "unknown":
        score -= 15
        debug.append("[Penalty] IP UNKNOWN -> -15")
    else:
        debug.append("[OK] IP clean")

    # -------------------------------------------------
    # 3) MFA GATING (industry behavior)
    # -------------------------------------------------
    if not mfa_passed:
        score -= 25
        debug.append("[Penalty] MFA not passed -> -25")

        # Without MFA, never let trust become "safe"
        score = min(score, 59)
        debug.append("[Gate] MFA not passed -> cap trust at 59 (risky ceiling)")

    else:
        debug.append("[OK] MFA passed -> eligible for safe tier")

    # -------------------------------------------------
    # 4) MFA FAILURE HISTORY (repeat failures => degrade)
    # -------------------------------------------------
    if mfa_fail_count >= 1:
        penalty = 10 * min(mfa_fail_count, 3)   # max -30
        score -= penalty
        debug.append(f"[Penalty] MFA failures (count={mfa_fail_count}) -> -{penalty}")

    # -------------------------------------------------
    # 5) OPTIONAL POLICY RISK FLAGS (soft penalties)
    # -------------------------------------------------
    if policy_flags.get("high_risk"):
        score -= 25
        debug.append("[Penalty] high_risk policy -> -25")
    elif policy_flags.get("medium_risk"):
        score -= 15
        debug.append("[Penalty] medium_risk policy -> -15")
    elif policy_flags.get("low_risk"):
        score -= 5
        debug.append("[Penalty] low_risk policy -> -5")

    # -------------------------------------------------
    # 6) FINAL CLAMP + DEVICE CAP
    # -------------------------------------------------
    score = max(0, min(100, score))
    score = min(score, cap)

    debug.append(f"[Final Score] Dashboard Trust = {score}")
    print("\n".join(debug))
    return score
