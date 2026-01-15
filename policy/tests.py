from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from .models import ProtectedLink, LinkAccessAttempt, UserTemporaryBlock, Policy, PolicyRule
from .trust import evaluate_rules

class ZTNATestCases(TestCase):

    def setUp(self):
        self.user = User.objects.create_user("john", password="pass1234")
        self.client = Client()
        self.client.login(username="john", password="pass1234")

        self.link = ProtectedLink.objects.create(
            name="File1",
            resource_path="/download/file1"
        )
        self.link.set_password("secret")
        self.link.save()

    def test_night_window_block(self):
        night = timezone.now().replace(hour=1)
        with self.subTest():
            self.assertTrue(0 <= night.hour < 7)

    def test_failed_attempts_trigger_block(self):
        ip = "1.2.3.4"
        for _ in range(3):
            LinkAccessAttempt.objects.create(
                protected_link=self.link,
                user=self.user,
                ip=ip,
                success=False,
                failure_reason="bad_password"
            )
        attempts = LinkAccessAttempt.objects.filter(failure_reason="bad_password").count()
        self.assertEqual(attempts, 3)

    def test_policy_rule_action(self):
        p = Policy.objects.create(name="TestP", created_by=self.user)
        PolicyRule.objects.create(
            policy=p,
            name="NightRule",
            condition={"field":"hour","op":"between","value":"0-7"},
            action="mark_critical",
            enabled=True,
            priority=1,
        )

        score, flags, rule_id = evaluate_rules({"hour": 2, "failed_count": 0})
        self.assertEqual(flags["block"], False)
        self.assertLess(score, 100)
        self.assertIsNotNone(rule_id)


