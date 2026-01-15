# trustbroker/models.py
from django.db import models
from django.utils import timezone
from idp.models import UserProfile


EVENT_TYPES = [
    ("bad_password", "Bad Password Attempt"),
    ("mfa_fail", "MFA Failure"),
    ("blocked", "Blocked by Policy/Admin Restriction"),
    ("link_fail", "Unauthorized Link Access"),
    ("login_success", "Successful Login"),

    # recovery events
    ("trust_recovery_hourly", "Hourly Trust Recovery"),
    ("trust_recovery_safe", "Safe Action Trust Recovery"),
    ("trust_recovery_mfa", "MFA Trust Recovery"),
]


class TrustScore(models.Model):
    """
    Analytical / behavioral trust for a user on a 0.0 – 1.0 scale.
    1.0 = fully trusted, 0.0 = fully untrusted.
    """
    user_profile = models.OneToOneField(UserProfile, on_delete=models.CASCADE)
    overall_trust = models.FloatField(default=1.0)
    last_recovery = models.DateTimeField(default=timezone.now)

    # penalties in 0–1 scale
    PENALTY_MAP = {
        "bad_password": 0.08,
        "mfa_fail": 0.06,
        "blocked": 0.10,
        "link_fail": 0.07,
    }

    def _clamp(self, value: float) -> float:
        """Clamp trust to [0.0, 1.0] and round for nicer logs."""
        return max(0.0, min(1.0, round(float(value), 4)))

    def apply_penalty(self, amount: float):
        """
        Subtract 'amount' from trust. Returns (old, new).
        """
        old = self._clamp(self.overall_trust)
        amount = float(amount)

        new = self._clamp(old - amount)
        self.overall_trust = new
        self.save(update_fields=["overall_trust"])
        return old, new

    def _log_recovery(self, event_type: str, increment: float, ip: str = "system"):
        """
        Shared helper: add positive trust only if it actually increases,
        and log a TrustEvent.
        """
        from .models import TrustEvent  # safe runtime import

        old = self._clamp(self.overall_trust)

        # Already maxed out -> nothing to do, no log
        if old >= 1.0:
            return

        increment = float(increment)
        new = self._clamp(old + increment)

        # Safety: if increment resulted in no change, don't log noise
        if new <= old:
            return

        self.overall_trust = new
        self.last_recovery = timezone.now()
        self.save(update_fields=["overall_trust", "last_recovery"])

        TrustEvent.objects.create(
            user_profile=self.user_profile,
            event_type=event_type,
            delta=new - old,
            old_score=old,
            new_score=new,
            ip=ip,
        )

    def hourly_recovery(self):
       
        self._log_recovery("trust_recovery_hourly", 0.02)

    def recovery_after_safe_action(self):
      
        self._log_recovery("trust_recovery_safe", 0.02)

    def recovery_after_mfa(self):
      
        self._log_recovery("trust_recovery_mfa", 0.10)

    def daily_recovery(self):
        
        now = timezone.now()
        hours_passed = (now - self.last_recovery).total_seconds() / 3600
        if hours_passed >= 24:
            new = self._clamp(self.overall_trust + 0.05)
            if new > self.overall_trust:
                self.overall_trust = new
                self.last_recovery = now
                self.save(update_fields=["overall_trust", "last_recovery"])

    def __str__(self):
        return f"{self.user_profile.user.username} — Trust {self.overall_trust:.2f}"


class TrustEvent(models.Model):
    """
    Single trust-impacting event for a user.
    delta: negative = penalty, positive = recovery
    """
    user_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    delta = models.FloatField(default=0.0)
    old_score = models.FloatField(default=1.0)
    new_score = models.FloatField(default=1.0)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"{self.user_profile.user.username} | {self.event_type} | {self.new_score:.2f}"
