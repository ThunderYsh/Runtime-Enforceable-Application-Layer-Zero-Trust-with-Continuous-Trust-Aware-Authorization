"""count_queries_r3.py -- number of SQL statements (and INSERT/UPDATE writes)
executed per request in each ZTNA_BENCH_MODE, via Django's
CaptureQueriesContext. Explains WHERE the enforcement cost comes from
(independently of wall-clock noise). Runs in-process on a throw-away copy of
the benchmark template DB. The local hour seen by NightAccessMiddleware and
the policy engine is pinned to 10:00 so that the count is not affected by the
time of day at which the script happens to run.
Usage: ZTNA_BENCH_MODE=<mode> ZTNA_DB_PATH=<copy> DJANGO_ALLOWED_HOSTS=testserver \
       python revision_r3/count_queries_r3.py
"""
import os, sys, json, datetime
from unittest import mock
sys.path.insert(0, os.getcwd()); os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ztna_proj.settings")
import django; django.setup()
from django.test import Client
from django.test.utils import CaptureQueriesContext
from django.db import connection
from django.utils import timezone
from django.contrib.auth.models import User

real_localtime = timezone.localtime
def fixed_localtime(value=None, tz=None):
    t = real_localtime(value, tz) if value is not None else real_localtime()
    return t.replace(hour=10) if value is None else t

with mock.patch("django.utils.timezone.localtime", fixed_localtime):
    c = Client(); c.force_login(User.objects.get(username="ztna_bench_user"))
    s = c.session; s["mfa_login_passed"] = True; s.save()
    c.cookies["device_fp"] = "a3f1c9e07b2d4c58e6f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"
    for _ in range(3): c.get("/ztna/dashboard/")
    out = {}
    for route in ("/ztna/dashboard/", "/ztna/trust/analytics/"):
        with CaptureQueriesContext(connection) as q:
            r = c.get(route)
        sql = [x["sql"].lstrip().split()[0].upper() for x in q.captured_queries]
        out[route] = {"status": r.status_code, "statements": len(sql),
                      "INSERT": sql.count("INSERT"), "UPDATE": sql.count("UPDATE"),
                      "SELECT": sql.count("SELECT")}
print(json.dumps({os.environ["ZTNA_BENCH_MODE"]: out}))
