# ztna/device_fingerprint_middleware.py
class DeviceFingerprintMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        fp_hash = request.COOKIES.get("device_fp")

        if fp_hash:
            request.device_fingerprint = {"hash": fp_hash}
        else:
            request.device_fingerprint = None

        return self.get_response(request)
