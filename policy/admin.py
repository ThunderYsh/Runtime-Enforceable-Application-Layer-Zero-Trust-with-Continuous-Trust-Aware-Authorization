# policy/admin.py
from django.contrib import admin
from .models import (
    Policy,
    PolicyRule,
    DeviceRecord,
    ProtectedLink,
    LinkAccessAttempt,
    UserTemporaryBlock,
)

@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "sensitivity", "status", "created_by", "last_modified")
    search_fields = ("name",)

@admin.register(PolicyRule)
class PolicyRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "policy", "action", "priority", "enabled")
    list_filter = ("policy", "action", "enabled")

@admin.register(DeviceRecord)
class DeviceRecordAdmin(admin.ModelAdmin):
    list_display = ("user", "fingerprint", "device_score", "last_seen")

@admin.register(ProtectedLink)
class ProtectedLinkAdmin(admin.ModelAdmin):
    list_display = ("name", "resource_path", "owner", "is_active", "created_at")

@admin.register(LinkAccessAttempt)
class AttemptAdmin(admin.ModelAdmin):
    list_display = ("protected_link", "user", "ip", "success", "failure_reason", "timestamp")
    list_filter = ("success", "failure_reason")

@admin.register(UserTemporaryBlock)
class BlockAdmin(admin.ModelAdmin):
    list_display = ("user", "ip", "blocked_until")
