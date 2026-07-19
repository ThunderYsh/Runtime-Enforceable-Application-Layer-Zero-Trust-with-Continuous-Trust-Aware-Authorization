def calculate_device_score(fp_hash, is_known_device=False, debug_mode=False):
    """
    Zero Trust Device Score (0-100)
    Hash-based, registry-driven, ZTNA-correct.

    is_known_device: True if DeviceFingerprintRecord already has this
    fingerprint on file for the current user (see
    ztna/device_fingerprint_middleware.py).

    A first-seen fingerprint is deliberately kept in the low-trust band
    (<40) regardless of hash quality -- this is what makes "New Device
    Login" (Table VIII) an actual enforcement signal rather than cosmetic:
    require_stepup_mfa_if_low_trust() gates sensitive actions on this score,
    so an unrecognized device is held to step-up MFA until it is verified
    and recorded in DeviceFingerprintRecord (at which point it scores in the
    known-device band on every subsequent request).
    """

    debug = []

    # ------------------------------
    # 1) Fingerprint presence
    # ------------------------------
    if not fp_hash:
        debug.append("[CRITICAL] No device fingerprint -> Score = 20")
        if debug_mode:
            print("\n".join(debug))
        return 20

    debug.append("[OK] Device fingerprint present")

    # ------------------------------
    # 2) Known vs unrecognized device
    # ------------------------------
    if not is_known_device:
        score = 35
        debug.append(
            "[Caution] Fingerprint not previously verified for this user "
            "-> Score = 35 (new-device band, below step-up threshold)"
        )
        if debug_mode:
            print("\n".join(debug))
        return score

    score = 50 + 30  # base + verified identifier
    debug.append("[OK] Fingerprint matches a previously-verified device -> base 80")

    # ------------------------------
    # 3) Stability bonus (hash length)
    # ------------------------------
    if len(fp_hash) >= 64:
        score += 20
        debug.append("[OK] Strong fingerprint hash length -> +20")
    else:
        score += 5
        debug.append("[Penalty] Weak fingerprint hash length -> +5 only")

    # ------------------------------
    # 4) Final clamp
    # ------------------------------
    score = max(20, min(score, 100))
    debug.append(f"[FINAL DEVICE SCORE] = {score}")

    if debug_mode:
        print("\n====== DEVICE SCORE DEBUG ======")
        for line in debug:
            print(line)
        print("================================\n")

    return score
