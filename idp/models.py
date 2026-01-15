from django.db import models
from django.contrib.auth.models import User
import pyotp


class UserProfile(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="idp_profile"
    )

    is_device_registered = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=64, blank=True, null=True)

    def ensure_totp(self):
        """
        Create TOTP secret only once and return it.
    
        """
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            self.save()

        return self.totp_secret

    def verify_totp(self, token):
        """
        Verify the 6-digit code.
        """
        secret = self.ensure_totp()
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)

    def reset_totp(self):
        """Generate a fresh secret and force re-registration."""
        self.totp_secret = pyotp.random_base32()
        self.is_device_registered = False
        self.save()

    def __str__(self):
        return self.user.username
