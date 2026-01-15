# siem/models.py
from django.db import models
from idp.models import UserProfile

class AuditLog(models.Model):
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    action = models.CharField(max_length=200)

    ip = models.GenericIPAddressField(null=True, blank=True)
    latency_ms = models.FloatField(null=True, blank=True)

    policy_rule_id = models.IntegerField(null=True, blank=True)

    status = models.CharField(
        max_length=50,
        choices=[
            ("SUCCESS", "SUCCESS"),
            ("FAILURE", "FAILURE"),
            ("BLOCKED", "BLOCKED"),
            ("ADMIN_UNBLOCK", "ADMIN_UNBLOCK"),
        ],
        default="SUCCESS",
    )

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user_profile.user.username} — {self.action} [{self.status}]"
