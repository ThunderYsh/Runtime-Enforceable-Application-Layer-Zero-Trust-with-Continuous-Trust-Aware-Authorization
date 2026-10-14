"""
bench_latency_r3.py -- JISA R3 latency re-run (Reviewer #1/#4/#6; audit D7, D8, D13).

Three server configurations (settings.ZTNA_BENCH_MODE):
  none          true no-enforcement baseline (authentication + login MFA only)
  no_middleware the R2 "baseline" (ZTNA middlewares removed, view-level
                enforce_access()/log_ztna()/trust recovery still active)
  full          complete ZTNA stack
Design
  * every run uses a fresh `manage.py runserver --noreload` process against
    bench_r3/bench.sqlite3, restored before EVERY run from one prepared copy
    of the frozen snapshot (db.sqlite3 and the snapshot are never written)
  * the bench user presents a 64-hex device_fp cookie that is registered in
    DeviceFingerprintRecord, so the device-familiarity lookup is exercised
  * sequential phase: 3 configs x 3 repetitions, interleaved order, 30 warm-up
    requests discarded, then 500 measured requests over dashboard /
    trust-analytics / logs with a seeded route sequence and think time
    (identical across configs for a given repetition)
  * concurrent phase: 8 client threads (one session each) x 150 requests,
    3 configs x 2 repetitions
  * client-side wall time per request (perf_counter around requests.get) is
    the primary metric; server-side time from RequestLatencyMiddleware (now
    the outermost middleware) is recorded per run as a cross-check
Outputs: bench_r3/raw_sequential.csv, bench_r3/raw_concurrent.csv,
         bench_r3/server_side.csv, bench_r3/run_log.json
Run (client venv needs requests + pyotp):
    python bench_latency_r3.py
"""
import csv, json, os, pathlib, random, re, shutil, sqlite3, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone

import pyotp
import requests

HERE = pathlib.Path(__file__).resolve().parent
PROJ = HERE.parent
SERVER_PY = PROJ.parent / ".venv" / "Scripts" / "python.exe"
OUT = HERE / "bench_r3"                                   # results (CSV/JSON) for the paper
# Database and server logs live OUTSIDE the OneDrive-synced project folder: a
# synced SQLite file / log file adds sync I/O to every commit (seen in a first,
# discarded attempt, kept in bench_r3_discarded_attempt1/).
WORK = pathlib.Path(os.environ.get("ZTNA_BENCH_WORKDIR", pathlib.Path(tempfile.gettempdir()) / "ztna_bench_r3"))
BENCH_DB = WORK / "bench.sqlite3"
TEMPLATE_DB = WORK / "bench_template.sqlite3"   # prepared once; restored before every run
SNAPSHOT = HERE / "snapshot_r2_20260719.sqlite3"
PORT = 8765
HOST = f"http://127.0.0.1:{PORT}"
USER, PASSWORD, TOTP_SECRET = "ztna_bench_user", "BenchmarkOnly!2026", "JBSWY3DPEHPK3PXP"
DEVICE_FP = "a3f1c9e07b2d4c58e6f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"   # 64 hex
# /ztna/logs/ is excluded: it renders every AuditLog row unpaginated, so its
# cost grows with each request of the run (5-7 s/request under load in the
# discarded attempt) and would dominate any configuration difference.
ROUTES = ["/ztna/dashboard/", "/ztna/trust/analytics/"]
STALL_MS = 10_000                      # any request slower than this is flagged
WARMUP, N_SEQ = 30, 500
CONC_THREADS, N_CONC = 8, 150
SEQ_ORDER = [("none", 0), ("no_middleware", 0), ("full", 0),
             ("full", 1), ("none", 1), ("no_middleware", 1),
             ("no_middleware", 2), ("full", 2), ("none", 2)]
CONC_ORDER = [("full", 0), ("none", 0), ("no_middleware", 0),
              ("none", 1), ("no_middleware", 1), ("full", 1)]


def server_env(mode):
    e = dict(os.environ)
    e.update(ZTNA_BENCH_MODE=mode, ZTNA_DB_PATH=str(BENCH_DB), DJANGO_DEBUG="false",
             PYTHONIOENCODING="utf-8")
    e.pop("ZTNA_ENFORCEMENT_ENABLED", None)
    return e


def manage(args, mode="full"):
    subprocess.run([str(SERVER_PY), "manage.py", *args], cwd=PROJ, env=server_env(mode),
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def prepare_db():
    OUT.mkdir(exist_ok=True); WORK.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SNAPSHOT, BENCH_DB)
    manage(["migrate", "--noinput"])
    subprocess.run([str(SERVER_PY), "seed_bench_user.py"], cwd=PROJ, env=server_env("full"),
                   check=True, stdout=subprocess.DEVNULL)
    c = sqlite3.connect(BENCH_DB)
    pid = c.execute("select p.id from idp_userprofile p join auth_user u on u.id=p.user_id "
                    "where u.username=?", (USER,)).fetchone()[0]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    c.execute("delete from policy_devicefingerprintrecord where user_profile_id=? and fingerprint=?", (pid, DEVICE_FP))
    c.execute("insert into policy_devicefingerprintrecord(fingerprint, raw, last_ip, first_seen, last_seen, user_profile_id) "
              "values (?, '{}', '127.0.0.1', ?, ?, ?)", (DEVICE_FP, now, now, pid))
    c.execute("delete from policy_usertemporaryblock")          # no carried-over blocks
    c.commit(); c.close()
    shutil.copyfile(BENCH_DB, TEMPLATE_DB)


def reset_trust():
    """Restore the prepared template so every run starts from an identical
    database (the logs page renders all AuditLog rows, so a growing DB would
    otherwise slow later runs regardless of configuration)."""
    shutil.copyfile(TEMPLATE_DB, BENCH_DB)
    c = sqlite3.connect(BENCH_DB)
    c.execute("update trustbroker_trustscore set overall_trust=1.0 where user_profile_id="
              "(select p.id from idp_userprofile p join auth_user u on u.id=p.user_id where u.username=?)", (USER,))
    c.commit(); c.close()


def start_server(mode):
    log = open(WORK / f"server_{mode}.log", "a", encoding="utf-8")
    p = subprocess.Popen([str(SERVER_PY), "manage.py", "runserver", "--noreload", f"127.0.0.1:{PORT}"],
                         cwd=PROJ, env=server_env(mode), stdout=log, stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            requests.get(f"{HOST}/ztna/login/", timeout=1); return p, log
        except requests.RequestException:
            time.sleep(0.25)
    p.kill(); raise RuntimeError("server did not start")


def stop_server(p, log):
    p.terminate()
    try: p.wait(10)
    except subprocess.TimeoutExpired: p.kill()
    log.close()


def csrf(html):
    return re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html).group(1)


def login():
    s = requests.Session()
    s.cookies.set("device_fp", DEVICE_FP, domain="127.0.0.1")
    r = s.get(f"{HOST}/ztna/login/")
    r = s.post(f"{HOST}/ztna/login/", data={"username": USER, "password": PASSWORD,
               "csrfmiddlewaretoken": csrf(r.text)}, headers={"Referer": f"{HOST}/ztna/login/"})
    assert "/ztna/mfa/" in r.url, r.url
    r = s.post(f"{HOST}/ztna/mfa/", data={"token": pyotp.TOTP(TOTP_SECRET).now(),
               "csrfmiddlewaretoken": csrf(r.text)}, headers={"Referer": f"{HOST}/ztna/mfa/"})
    assert "/ztna/dashboard/" in r.url, r.url
    return s


def plan(seed, n):
    rng = random.Random(seed)
    return [(rng.choice(ROUTES), rng.uniform(0.05, 0.3)) for _ in range(n)]


def drive(s, steps, sink, tag):
    for i, (route, think) in enumerate(steps):
        t0 = time.perf_counter()
        r = s.get(f"{HOST}{route}", timeout=120, allow_redirects=False)
        dt = (time.perf_counter() - t0) * 1000
        if sink is not None:
            sink.append({**tag, "i": i, "route": route, "status": r.status_code, "client_ms": round(dt, 3)})
        time.sleep(think)


def server_side(since, until, mode, phase, rep):
    c = sqlite3.connect(f"file:{BENCH_DB}?mode=ro", uri=True)
    rows = c.execute("select latency_ms from siem_auditlog where action='request_latency' "
                     "and timestamp>=? and timestamp<?", (since, until)).fetchall()
    c.close()
    return [{"phase": phase, "mode": mode, "rep": rep, "server_ms": r[0]} for r in rows]


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def keep_awake():
    """Windows: keep the system AND the display awake for the duration of the
    benchmark. System-only (ES_SYSTEM_REQUIRED) did not stop Modern Standby
    when the display timed out: the second attempt entered Modern Standby at
    20:45:07 (Kernel-Power event 506), the same second the server log stops.
    ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED."""
    try:
        import ctypes
        return bool(ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001 | 0x00000002))
    except Exception:
        return False


def run_sequential(mode, rep):
    rows = []
    reset_trust(); p, log = start_server(mode)
    try:
        s = login()
        drive(s, plan(1000 + rep, WARMUP), None, {})
        since = utcnow()
        drive(s, plan(2000 + rep, N_SEQ), rows, {"phase": "sequential", "mode": mode, "rep": rep})
        until = utcnow()
    finally:
        stop_server(p, log)
    return rows, server_side(since, until, mode, "sequential", rep), \
        {"phase": "sequential", "mode": mode, "rep": rep, "start": since, "end": until}


def run_concurrent(mode, rep):
    reset_trust(); p, log = start_server(mode)
    errors = []

    def worker(s, steps, sink, tag):
        try:
            drive(s, steps, sink, tag)
        except Exception as e:          # surface thread failures to the retry logic
            errors.append(repr(e))
    try:
        sessions = [login() for _ in range(CONC_THREADS)]
        for s in sessions:
            drive(s, plan(1000 + rep, 5), None, {})
        since = utcnow(); buf = [[] for _ in sessions]
        ths = [threading.Thread(target=worker, args=(s, plan(3000 + 10 * rep + k, N_CONC), buf[k],
               {"phase": "concurrent", "mode": mode, "rep": rep, "thread": k}))
               for k, s in enumerate(sessions)]
        t0 = time.perf_counter(); [t.start() for t in ths]; [t.join() for t in ths]
        wall = time.perf_counter() - t0; until = utcnow()
    finally:
        stop_server(p, log)
    if errors:
        raise RuntimeError(f"{len(errors)} client thread(s) failed: {errors[0]}")
    rows = [r for b in buf for r in b]
    return rows, server_side(since, until, mode, "concurrent", rep), \
        {"phase": "concurrent", "mode": mode, "rep": rep, "start": since, "end": until,
         "wall_s": wall, "requests": len(rows)}


def with_retry(fn, mode, rep, discarded, attempts=2):
    """A run is repeated in full (fresh DB, fresh server) if any request fails;
    the failed attempt is recorded, never merged into the results."""
    for a in range(1, attempts + 1):
        try:
            return fn(mode, rep)
        except Exception as e:
            discarded.append({"run": fn.__name__, "mode": mode, "rep": rep, "attempt": a,
                              "at": utcnow(), "error": repr(e)[:300]})
            print(f"[retry] {fn.__name__} {mode} rep{rep} attempt {a} failed: {e!r}"[:200], flush=True)
    raise RuntimeError(f"{fn.__name__} {mode} rep{rep} failed {attempts} times")


def main():
    hour = datetime.now().hour
    if 0 <= hour < 8:   # NightAccessMiddleware denies 00:00-07:00 local; leave margin for the ~30 min run
        sys.exit(f"Refusing to start at {hour:02d}h local: the night-access policy (00-07h) would turn "
                 "full-mode requests into HTTP 403. Run between 08:00 and 23:00 with the laptop open.")
    awake = keep_awake()
    prepare_db()
    seq, conc, srv, runs, discarded = [], [], [], [], []
    for mode, rep in SEQ_ORDER:
        rows, srows, meta = with_retry(run_sequential, mode, rep, discarded)
        seq += rows; srv += srows; runs.append(meta)
        print(f"[seq] {mode:<14} rep{rep} done ({meta['end']})", flush=True)
    for mode, rep in CONC_ORDER:
        rows, srows, meta = with_retry(run_concurrent, mode, rep, discarded)
        conc += rows; srv += srows; runs.append(meta)
        print(f"[conc] {mode:<14} rep{rep} done wall={meta['wall_s']:.1f}s", flush=True)
    for name, rows in (("raw_sequential.csv", seq), ("raw_concurrent.csv", conc), ("server_side.csv", srv)):
        with open(OUT / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r})); w.writeheader(); w.writerows(rows)
    meta = {"runs": runs, "design": {"warmup": WARMUP, "n_seq": N_SEQ, "threads": CONC_THREADS, "n_conc": N_CONC,
            "routes": ROUTES, "server": "django runserver --noreload, DJANGO_DEBUG=false, SQLite",
            "python": sys.version, "device_fp_registered": True, "keep_awake": awake,
            "workdir_outside_onedrive": str(WORK), "stall_threshold_ms": STALL_MS,
            "stalls": [r for r in seq + conc if r["client_ms"] > STALL_MS],
            "discarded_attempts": discarded}}
    (OUT / "run_log.json").write_text(json.dumps(meta, indent=1))
    print("done")


if __name__ == "__main__":
    main()
