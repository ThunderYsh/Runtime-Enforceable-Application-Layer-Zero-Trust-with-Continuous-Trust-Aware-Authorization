from django.db import models
from django.utils import timezone
from idp.models import UserProfile
from appsrv.models import ApplicationResource
from trustbroker.models import TrustScore
from siem.utils import audit_log
from datetime import datetime
from django.contrib.auth.models import User
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password




class ZTNARequest(models.Model):
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("APPROVED", "Approved"),
        ("DENIED", "Denied"),
        ("BLOCKED", "Blocked"),
    ]

    user_profile = models.ForeignKey("idp.UserProfile", on_delete=models.CASCADE)
    app_resource = models.ForeignKey(ApplicationResource, on_delete=models.CASCADE)

    policy = models.ForeignKey(
        "policy.Policy",
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    trust_score = models.ForeignKey(
        TrustScore,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    location = models.CharField(max_length=200, blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="PENDING")
    decision_reason = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now)

    policy_rule_id = models.IntegerField(null=True, blank=True)

    def evaluate_request(self, device_score=50, mfa_passed=False):
        """
        Core logic for Zero Trust evaluation.

        - Uses lazy imports to avoid circular dependencies.
        - Stores policy_rule_id for causal traceability.
        """

        #  lazy imports (prevents circular import crash)
        from policy.enforcer import enforce_access
        from siem.utils import audit_log

        trust_obj = (
            self.trust_score
            or TrustScore.objects.filter(user_profile=self.user_profile).first()
        )

        if not trust_obj:
            self.status = "BLOCKED"
            self.decision_reason = "No trust score found"
            self.policy_rule_id = None
            self.save(update_fields=["status", "decision_reason", "policy_rule_id"])
            return

        policy = self.policy or getattr(self.app_resource, "assigned_policy", None)
        if not policy:
            self.status = "DENIED"
            self.decision_reason = "No policy assigned"
            self.policy_rule_id = None
            self.save(update_fields=["status", "decision_reason", "policy_rule_id"])
            return

        ip = self.ip_address or "127.0.0.1"
        user = self.user_profile.user

        decision = enforce_access(
            user=user,
            ip=ip,
            protected_link=None,
            device_score=device_score,
            mfa_passed=mfa_passed,
        )

        self.policy_rule_id = decision.get("policy_rule_id")

        action = decision.get("action", "allow")
        if action == "allow":
            self.status = "APPROVED"
        elif action == "blocked":
            self.status = "BLOCKED"
        else:
            self.status = "DENIED"

        self.decision_reason = decision.get("reason", "policy_decision")

        # map to SIEM allowed statuses
        if self.status == "APPROVED":
            siem_status = "SUCCESS"
        elif self.status == "BLOCKED":
            siem_status = "BLOCKED"
        else:
            siem_status = "FAILURE"

        audit_log(
            user_profile=self.user_profile,
            action=f"Access {self.app_resource.name}",
            ip=self.ip_address,
            status=siem_status,
            policy_rule_id=self.policy_rule_id,
        )

        self.save(update_fields=["status", "decision_reason", "policy_rule_id"])

    def __str__(self):
        return f"{self.user_profile.user.username} -> {self.app_resource.name} [{self.status}]"




from django.contrib.auth.hashers import make_password, check_password

class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    content = models.TextField()

    share_mode = models.CharField(
        max_length=10,
        choices=[
            ("open", "Open Access"),
            ("strict", "Strict Access"),
            ("expire", "Temporary Access"),
        ],
        default="open"
    )
    allowed_users = models.TextField(blank=True, null=True)
    expire_at = models.DateTimeField(blank=True, null=True)

    # 🔐 PASSWORD PROTECTION FIELDS
    is_protected = models.BooleanField(default=False)
    password_hash = models.CharField(max_length=256, blank=True)

    updated_at = models.DateTimeField(auto_now=True)

    def set_password(self, raw_pwd):
        self.password_hash = make_password(raw_pwd)
        self.is_protected = True

    def check_password(self, raw_pwd):
        return check_password(raw_pwd, self.password_hash)

    def __str__(self):
        return self.name




