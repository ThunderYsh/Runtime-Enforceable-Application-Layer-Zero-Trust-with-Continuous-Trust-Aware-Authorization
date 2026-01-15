def calculate_device_score(fp_hash, debug_mode=False):
    """
    Zero Trust Device Score (0–100)
    Hash-based, registry-driven, ZTNA-correct.
    """

    score = 50
    debug = []

    # ------------------------------
    # 1) Fingerprint presence
    # ------------------------------
    if not fp_hash:
        debug.append("[CRITICAL] No device fingerprint → Score = 20")
        if debug_mode:
            print("\n".join(debug))
        return 20

    debug.append("[OK] Device fingerprint present")
    score += 30  # trusted identifier exists

    # ------------------------------
    # 2) Stability bonus (hash length)
    # ------------------------------
    if len(fp_hash) >= 64:
        score += 10
        debug.append("[OK] Strong fingerprint hash length → +10")
    else:
        score -= 10
        debug.append("[Penalty] Weak fingerprint hash length → -10")

    # ------------------------------
    # 3) Final clamp
    # ------------------------------
    score = max(20, min(score, 100))
    debug.append(f"[FINAL DEVICE SCORE] = {score}")

    if debug_mode:
        print("\n====== DEVICE SCORE DEBUG ======")
        for line in debug:
            print(line)
        print("================================\n")

    return score
