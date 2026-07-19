# policy/models.py
from django.db import models
from django.contrib.auth.models import User

POLICY_STATUS = (
    ("active", "Active"),
    ("disabled", "Disabled")
)

class Policy(models.Model):
    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    sensitivity = models.IntegerField(default=1)  # risk scoring 1–10
    status = models.CharField(max_length=20, choices=POLICY_STATUS, default="active")
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.sensitivity})"


class PolicyRule(models.Model):
    policy = models.ForeignKey(Policy, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=150)
    condition = models.JSONField(default=dict)

    ACTIONS = [
        ("allow", "Allow"),
        ("deny", "Deny"),
        ("require_mfa", "Require MFA"),
        ("escalate", "Escalate"),
        ("block_1h", "Block 1h"),
        ("mark_critical", "Mark Critical"),
    ]

    action = models.CharField(max_length=50, choices=ACTIONS)
    priority = models.IntegerField(default=100)
    enabled = models.BooleanField(default=True)

    class Meta:
        ordering = ["priority"]

    def __str__(self):
        return f"{self.policy.name} - {self.name}"


class ProtectedLink(models.Model):
    name = models.CharField(max_length=200)
    resource_path = models.CharField(max_length=500)
    password_hash = models.CharField(max_length=256, blank=True)
    token_hash = models.CharField(max_length=256, blank=True)
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def set_password(self, raw):
        from django.contrib.auth.hashers import make_password
        self.password_hash = make_password(raw)

    def check_password(self, raw):
        from django.contrib.auth.hashers import check_password
        return check_password(raw, self.password_hash)

    def set_token(self, raw):
        from django.contrib.auth.hashers import make_password
        self.token_hash = make_password(raw)

    def check_token(self, raw):
        from django.contrib.auth.hashers import check_password
        return check_password(raw, self.token_hash)

    def __str__(self):
        return self.name


class LinkAccessAttempt(models.Model):
    protected_link = models.ForeignKey(ProtectedLink, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=200)
    user_agent = models.TextField(blank=True)

    def __str__(self):
        return f"{self.protected_link.name} - {self.ip}"


class UserTemporaryBlock(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    blocked_until = models.DateTimeField()
    block_level = models.IntegerField(default=1)

    def is_active(self):
        from django.utils import timezone
        return timezone.now() < self.blocked_until

    def __str__(self):
        who = self.user.username if self.user else self.ip
        return f"{who} blocked until {self.blocked_until}"

from django.db import models
from django.utils import timezone
from idp.models import UserProfile


class DeviceFingerprintRecord(models.Model):
    """
    Stores each known device for a user.
    Fingerprint = SHA-256 stable identifier from browser.
    """

    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    fingerprint = models.CharField(max_length=128, db_index=True)
    raw = models.TextField()  # full raw JSON
    last_ip = models.GenericIPAddressField(null=True, blank=True)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-last_seen"]

    def __str__(self):
        return f"{self.user_profile.user.username} | {self.fingerprint[:16]}..."

    @property
    def short_fp(self):
        return self.fingerprint[:18] + "..."
