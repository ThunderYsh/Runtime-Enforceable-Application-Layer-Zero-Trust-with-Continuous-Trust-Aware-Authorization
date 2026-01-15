from django.contrib import admin
from .models import ZTNARequest
from policy.models import DeviceFingerprintRecord



# ================================
# ZTNA REQUEST LOG ADMIN
# ================================
@admin.register(ZTNARequest)
class ZTNARequestAdmin(admin.ModelAdmin):
    list_display = ("user_profile", "app_resource", "status", "timestamp")
    search_fields = ("user_profile__user__username", "app_resource__name")
    list_filter = ("status", "timestamp")
    readonly_fields = ("timestamp",)


# ================================
# DEVICE FINGERPRINT ADMIN PANEL
# ================================
@admin.register(DeviceFingerprintRecord)
class DeviceFingerprintRecordAdmin(admin.ModelAdmin):
    list_display = (
        "user_profile",
        "fingerprint_short",
        "last_ip",
        "first_seen",
        "last_seen",
    )

    search_fields = (
        "user_profile__user__username",
        "fingerprint",
        "last_ip",
    )

    list_filter = ("first_seen", "last_seen")

    # Fingerprints should NEVER be editable
    readonly_fields = ("fingerprint", "raw", "first_seen", "last_seen", "last_ip")

    # -------------------------
    # ADMIN UI GROUPING
    # -------------------------
    fieldsets = (
        ("Device Identity", {
            "fields": ("user_profile", "fingerprint", "raw"),
        }),
        ("Network Info", {
            "fields": ("last_ip",),
        }),
        ("Timestamps", {
            "fields": ("first_seen", "last_seen"),
        }),
    )

    # Preview short fingerprint
    def fingerprint_short(self, obj):
        if not obj.fingerprint:
            return "(none)"
        return obj.fingerprint[:18] + "..."

    fingerprint_short.short_description = "Fingerprint"
