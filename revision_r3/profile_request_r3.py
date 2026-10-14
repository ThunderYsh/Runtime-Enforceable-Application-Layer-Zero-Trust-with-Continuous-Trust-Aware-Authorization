"""cProfile breakdown of the dashboard request: cumulative time in the
project's enforcement functions and in Django's ORM/DB layer."""
import os, sys, cProfile, pstats
sys.path.insert(0, os.getcwd())
os.environ["DJANGO_SETTINGS_MODULE"] = "ztna_proj.settings"
import django
django.setup()
from django.test import Client
from django.contrib.auth.models import User

c = Client(HTTP_HOST="127.0.0.1")
c.force_login(User.objects.get(username="ztna_bench_user"))
s = c.session
s["mfa_login_passed"] = True
s.save()
c.cookies["device_fp"] = "a3f1c9e07b2d4c58e6f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"
for _ in range(5):
    c.get("/ztna/dashboard/")
N = 40
pr = cProfile.Profile()
pr.enable()
for _ in range(N):
    c.get("/ztna/dashboard/")
pr.disable()
st = pstats.Stats(pr)
total = max(v[3] for v in st.stats.values()) / N * 1000
print(f"mode={os.environ['ZTNA_BENCH_MODE']} total per request ~{total:.1f} ms")
proj = os.getcwd().replace("/", "\\").lower()
rows = []
for (fn, line, name), (cc, nc, tt, ct, callers) in st.stats.items():
    f = fn.replace("/", "\\").lower()
    if f.startswith(proj) and "\\site-packages\\" not in f:
        rows.append((ct / N * 1000, os.path.relpath(fn, os.getcwd()), name, nc // N))
rows.sort(reverse=True)
print("project functions by cumulative ms/request:")
for r in rows[:18]:
    print(f"  {r[0]:6.1f}  {r[1]}:{r[2]}  calls/req={r[3]}")
# Django DB layer
dbc = 0.0
for (fn, line, name), (cc, nc, tt, ct, callers) in st.stats.items():
    if fn.endswith(("backends\\utils.py", "backends/utils.py")) and name in ("execute", "_execute"):
        dbc = max(dbc, ct / N * 1000)
comp = 0.0
for (fn, line, name), (cc, nc, tt, ct, callers) in st.stats.items():
    if fn.endswith(("sql\\compiler.py", "sql/compiler.py")) and name == "execute_sql":
        comp = max(comp, ct / N * 1000)
print(f"django CursorWrapper.execute cumulative ~{dbc:.1f} ms/request; SQLCompiler.execute_sql cumulative ~{comp:.1f} ms/request")
