from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from idp.models import UserProfile
from trustbroker.models import TrustEvent, TrustScore
from trustbroker.utils import event_penalty


class RecoveryAuditabilityTests(TestCase):
    def setUp(self):
        user = User.objects.create_user("u1", password="pw-123456")
        self.profile, _ = UserProfile.objects.get_or_create(user=user)
        self.ts, _ = TrustScore.objects.get_or_create(user_profile=self.profile)
        self.ts.overall_trust = 0.5
        self.ts.save()

    def _trust(self):
        self.ts.refresh_from_db()
        return self.ts.overall_trust

    def test_hourly_recovery_applies_once_per_hour(self):
        self.ts.hourly_recovery()
        self.ts.hourly_recovery()
        self.ts.hourly_recovery()
        self.assertAlmostEqual(self._trust(), 0.52)
        self.assertEqual(
            TrustEvent.objects.filter(event_type="trust_recovery_hourly").count(), 1
        )

    def test_hourly_recovery_applies_again_after_an_hour(self):
        self.ts.hourly_recovery()
        TrustEvent.objects.filter(event_type="trust_recovery_hourly").update(
            timestamp=timezone.now() - timedelta(hours=1, seconds=1)
        )
        self.ts.hourly_recovery()
        self.assertAlmostEqual(self._trust(), 0.54)

    def test_safe_action_recovery_is_not_gated(self):
        self.ts.recovery_after_safe_action()
        self.ts.recovery_after_safe_action()
        self.assertAlmostEqual(self._trust(), 0.54)

    def test_daily_recovery_is_logged(self):
        self.ts.last_recovery = timezone.now() - timedelta(hours=25)
        self.ts.save()
        self.ts.daily_recovery()
        ev = TrustEvent.objects.get(event_type="trust_recovery_daily")
        self.assertAlmostEqual(ev.delta, 0.05)
        self.assertAlmostEqual(self._trust(), 0.55)

    def test_daily_recovery_not_before_24h(self):
        self.ts.last_recovery = timezone.now() - timedelta(hours=23)
        self.ts.save()
        self.ts.daily_recovery()
        self.assertFalse(TrustEvent.objects.filter(event_type="trust_recovery_daily").exists())

    def test_event_chain_has_no_unlogged_gaps(self):
        """old_score of each event must equal new_score of the previous one."""
        self.ts.last_recovery = timezone.now() - timedelta(hours=25)
        self.ts.save()
        event_penalty(self.profile, "mfa_fail", "127.0.0.1")   # triggers daily recovery first
        self.ts.refresh_from_db()
        self.ts.hourly_recovery()
        event_penalty(self.profile, "link_fail", "127.0.0.1")
        evs = list(TrustEvent.objects.filter(user_profile=self.profile).order_by("timestamp", "id"))
        self.assertEqual([e.event_type for e in evs],
                         ["trust_recovery_daily", "mfa_fail", "trust_recovery_hourly", "link_fail"])
        for prev, cur in zip(evs, evs[1:]):
            self.assertAlmostEqual(prev.new_score, cur.old_score)
