def calculate_dashboard_trust(ip_reputation, device_score, mfa_passed, policy_flags):
    """
    Modern Zero Trust dashboard trust computation.
    Clean, explainable scoring with optional debug output.

    Weighting model (industry aligned):
      - MFA = strongest trust factor
      - Device Score = medium trust factor
      - IP reputation = high risk factor
      - Policy flags = absolute override
    """

    debug = []
    score = 100

    debug.append("----- DASHBOARD TRUST DEBUG REPORT -----")

    # =====================================================
    # 1) DEVICE POSTURE
    # =====================================================
    debug.append(f"[Device] Device score reported = {device_score}")

    if device_score < 20:
        score -= 50
        debug.append("[Penalty] Device score <20 (critical risk) → -50")
    elif device_score < 40:
        score -= 35
        debug.append("[Penalty] Device score <40 (high risk) → -35")
    elif device_score < 60:
        score -= 20
        debug.append("[Penalty] Device score <60 (medium risk) → -20")
    elif device_score < 75:
        score -= 10
        debug.append("[Penalty] Device score <75 (light risk) → -10")
    else:
        debug.append("[OK] Device score ≥75 (healthy posture)")

    # =====================================================
    # 2) IP REPUTATION
    # =====================================================
    debug.append(f"[IP] Reputation = {ip_reputation}")

    if ip_reputation == "bad":
        score -= 40
        debug.append("[Penalty] IP flagged as BAD → -40")
    elif ip_reputation == "unknown":
        score -= 15
        debug.append("[Penalty] IP UNKNOWN → -15")
    else:
        debug.append("[OK] Clean IP")

    # =====================================================
    # 3) MFA STATUS
    # =====================================================
    if mfa_passed:
        score += 20
        debug.append("[Bonus] MFA completed this session → +20")
    else:
        score -= 40
        debug.append("[Penalty] MFA not passed → -40")

    # =====================================================
    # 4) POLICY FLAGS
    # =====================================================
    if policy_flags.get("blocked"):
        debug.append("[HARD BLOCK] Policy system flagged BLOCK → score = 0")
        print(*debug, sep="\n")
        return 0

    if policy_flags.get("high_risk"):
        score -= 25
        debug.append("[Penalty] High-risk policy triggered → -25")

    if policy_flags.get("medium_risk"):
        score -= 15
        debug.append("[Penalty] Medium-risk policy triggered → -15")

    if policy_flags.get("low_risk"):
        score -= 5
        debug.append("[Penalty] Low-risk policy triggered → -5")

    # =====================================================
    # 5) FINAL CLAMP + DEBUG OUTPUT
    # =====================================================
    score = max(0, min(100, score))
    debug.append(f"[Final Score] Dashboard Trust = {score}")

    print("\n".join(debug))  # remove in production if needed

    return score
