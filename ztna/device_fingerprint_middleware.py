# ztna/device_fingerprint_middleware.py

from ztna.device_score import calculate_device_score


class DeviceFingerprintMiddleware:
    """
    Sets two global request attributes:

    request.device_fingerprint = {"hash": <fp_hash>} or None
    request.device_score       = 0-100 device trust score

    Must run after AuthenticationMiddleware: the known-device check below
    looks up DeviceFingerprintRecord for the resolved request.user.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        fp_hash = request.COOKIES.get("device_fp")

        # 1) Attach fingerprint
        if fp_hash:
            request.device_fingerprint = {"hash": fp_hash}
        else:
            request.device_fingerprint = None

        # 2) Is this fingerprint already on record for this user?
        is_known_device = False
        if fp_hash and getattr(request, "user", None) and request.user.is_authenticated:
            from policy.models import DeviceFingerprintRecord
            from idp.models import UserProfile

            profile = UserProfile.objects.filter(user=request.user).first()
            if profile:
                is_known_device = DeviceFingerprintRecord.objects.filter(
                    user_profile=profile, fingerprint=fp_hash
                ).exists()

        # 3) Attach consistent device score for ALL views
        if fp_hash:
            request.device_score = calculate_device_score(
                fp_hash, is_known_device=is_known_device, debug_mode=False
            )
        else:
            request.device_score = 20  # unknown device baseline

        return self.get_response(request)
