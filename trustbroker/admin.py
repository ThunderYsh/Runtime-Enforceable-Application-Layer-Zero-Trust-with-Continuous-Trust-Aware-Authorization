from django.contrib import admin
from .models import TrustScore, TrustEvent

@admin.register(TrustScore)
class TrustScoreAdmin(admin.ModelAdmin):
    list_display = (
        "user_profile",
        "overall_trust",
        "last_recovery",
    )
    list_filter = ("last_recovery",)
    search_fields = ("user_profile__user__username",)
    actions = ["reset_trust", "set_low_trust"]

@admin.register(TrustEvent)
class TrustEventAdmin(admin.ModelAdmin):
    list_display = (
        "user_profile",
        "event_type",
        "delta",
        "new_score",
        "timestamp",
    )
    list_filter = ("event_type", "timestamp")
    search_fields = ("user_profile__user__username",)

def reset_trust(self, request, queryset):
    for score in queryset:
        score.overall_trust = 1.0
        score.save()
    self.message_user(request, "Selected users' trust has been reset to 1.0")

def set_low_trust(self, request, queryset):
    for score in queryset:
        score.overall_trust = 0.2
        score.save()
    self.message_user(request, "Selected users' trust set to LOW")

actions = ["reset_trust", "set_low_trust"]
