"""
freeze_and_extract.py -- R3 revision, Reviewer #6 comments 3 and 4.

1. FREEZE: copies ../db.sqlite3 (never modified) to snapshot_r2_20260719.sqlite3
   and deletes, IN THE COPY ONLY, every row timestamped at or after CUTOFF.
   CUTOFF is the instant after which the R2 manuscript counts (647 requests,
   643 audit rows, 308 trust events) stop matching the live DB; it is
   verified below, not assumed.  SHA-256 of both files goes to the manifest.
2. EXTRACT: every number used in Tables VII/VIII and Figs. 10/12/13/14 is
   computed from the snapshot by the queries below, with an explicit
   counting unit per store.  Output: snapshot_manifest.json, metrics_r3.json,
   and regenerated figures fig_trust_events_r3, fig_ztnarequest_r3,
   fig_stepup_r3 (.png/.pdf).

Run:  python freeze_and_extract.py
"""
import hashlib, json, pathlib, shutil, sqlite3, re
from collections import Counter, OrderedDict

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent / "db.sqlite3"
SNAP = HERE / "snapshot_r2_20260719.sqlite3"
CUTOFF = "2026-07-19 07:17:15"          # UTC; last R2 row 07:17:14.96, next row 2026-09-10
DEVICE_FIX_MARKER = r"\((low behavioral trust|unrecognized device|low behavioral trust and unrecognized device)\)$"
TS_TABLES = {"ztna_ztnarequest": "timestamp", "siem_auditlog": "timestamp",
             "trustbroker_trustevent": "timestamp", "policy_devicefingerprintrecord": "first_seen",
             "policy_linkaccessattempt": "timestamp"}


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def freeze():
    src = sqlite3.connect(f"file:{SRC}?mode=ro", uri=True)
    if SNAP.exists():
        SNAP.unlink()
    dst = sqlite3.connect(SNAP)
    src.backup(dst)                       # consistent copy; source opened read-only
    src.close()
    removed = {}
    for t, col in TS_TABLES.items():
        try:
            n = dst.execute(f"select count(*) from {t} where {col} >= ?", (CUTOFF,)).fetchone()[0]
            dst.execute(f"delete from {t} where {col} >= ?", (CUTOFF,))
            removed[t] = n
        except sqlite3.OperationalError:
            pass
    dst.commit(); dst.execute("vacuum"); dst.close()
    return removed


def q(c, s, *a):
    return c.execute(s, a).fetchall()


def extract():
    c = sqlite3.connect(f"file:{SNAP}?mode=ro", uri=True)
    M = OrderedDict()
    span = lambda t, col="timestamp": q(c, f"select min({col}), max({col}) from {t}")[0]
    M["window"] = {"ztnarequest": span("ztna_ztnarequest"), "auditlog": span("siem_auditlog"),
                   "trustevent": span("trustbroker_trustevent")}

    # ---------------- users ----------------
    users = q(c, "select u.username, u.is_superuser, p.id from auth_user u join idp_userprofile p on p.user_id=u.id")
    M["users"] = {"total": len(users), "superuser": sum(u[1] for u in users),
                  "names": [u[0] for u in users]}

    # ---------------- ZTNARequest: one row per log_ztna() call --------------
    rows = q(c, """select r.status, r.decision_reason, a.name, u.is_superuser
                   from ztna_ztnarequest r join appsrv_applicationresource a on a.id=r.app_resource_id
                   join idp_userprofile p on p.id=r.user_profile_id join auth_user u on u.id=p.user_id""")
    # rows written with decision=... carry enforce_access() reasons
    DECISION_REASONS = {"ok", "policy_block", "admin_override", "existing_block", "trust_below_threshold"}
    def is_decision(reason):
        return reason in DECISION_REASONS or reason.startswith("dashboard_trust=") or reason.startswith("behavioral_trust=")
    dec = [r for r in rows if is_decision(r[1])]
    acc = [r for r in rows if not is_decision(r[1])]
    M["ztnarequest"] = {
        "total_rows": len(rows),
        "by_status": dict(Counter(r[0] for r in rows)),
        "policy_decision_rows": len(dec),
        "policy_decision_rows_by_status": dict(Counter(r[0] for r in dec)),
        "policy_decision_rows_admin_override": sum(r[1] == "admin_override" for r in dec),
        "policy_decision_rows_non_admin_by_status": dict(Counter(r[0] for r in dec if r[1] != "admin_override")),
        "access_log_rows": len(acc),
        "access_log_rows_by_status_reason": {f"{s}|{a}|{rs}": n for (s, rs, a), n in
                                             Counter((r[0], r[1], r[2]) for r in acc).items()},
    }

    # ---------------- AuditLog: one row per audit_log()/AuditLog.create() ---
    al = q(c, "select action, status from siem_auditlog")
    def cat(a):
        if a == "request_latency": return "latency telemetry"
        if a.startswith("Step-up MFA required"): return "step-up challenge issued"
        if a.startswith("Step-up MFA"): return "step-up outcome"
        if a.lower().startswith("mfa verification"): return "login MFA outcome"
        if a == "Unauthorized admin access attempt": return "admin-path block (middleware)"
        if a == "Night access attempt": return "night-access block (middleware)"
        if "blocked" in a.lower() or a.startswith("Denied"): return "view-level enforcement denial"
        if a.lower().startswith("dashboard access"): return "dashboard view"
        return "feature action / other"
    M["auditlog"] = {"total_rows": len(al), "by_status": dict(Counter(s for _, s in al)),
                     "by_category": dict(Counter(cat(a) for a, _ in al)),
                     "admin_path_blocks": sum(a == "Unauthorized admin access attempt" for a, _ in al)}

    # ---------------- TrustEvent: one row per logged trust change ----------
    te = q(c, "select event_type, delta from trustbroker_trustevent")
    M["trustevent"] = {"total_rows": len(te),
                       "by_type": dict(Counter(e for e, _ in te)),
                       "sum_delta_by_type": {k: round(sum(d for e, d in te if e == k), 4) for k in set(e for e, _ in te)}}
    ev = q(c, "select user_profile_id, old_score, new_score from trustbroker_trustevent order by user_profile_id, timestamp, id")
    prev, gaps = {}, []
    for u, o, n in ev:
        if u in prev and abs(prev[u] - o) > 1e-6:
            gaps.append(round(o - prev[u], 4))
        prev[u] = n
    M["trustevent"]["unlogged_changes_between_events"] = dict(Counter(gaps))

    # ---------------- step-up MFA, pre/post device-scoring fix -------------
    su = q(c, "select action, status, timestamp from siem_auditlog where action like 'Step-up MFA%' order by timestamp")
    trig = [s for s in su if s[0].startswith("Step-up MFA required")]
    post = [s for s in trig if re.search(DEVICE_FIX_MARKER, s[0])]
    M["stepup"] = {"triggers_total": len(trig), "triggers_pre_fix_unlabelled": len(trig) - len(post),
                   "triggers_post_fix": len(post),
                   "post_fix_by_reason": dict(Counter(re.search(DEVICE_FIX_MARKER, s[0]).group(1) for s in post)),
                   "post_fix_time_span": [post[0][2], post[-1][2]] if post else None,
                   "successes": sum(s[0] == "Step-up MFA Success" for s in su),
                   "failures": sum(s[0] == "Step-up MFA Failed" for s in su),
                   "pre_fix_time_span": [trig[0][2], [s for s in trig if s not in post][-1][2]]}

    # ---------------- devices / policies ----------------
    M["devices"] = {"records": q(c, "select count(*) from policy_devicefingerprintrecord")[0][0],
                    "records_created_by_post_fix_stepup_path":
                        q(c, "select count(*) from policy_devicefingerprintrecord where first_seen >= '2026-07-19'")[0][0]}
    M["policies"] = {"policies_active": q(c, "select count(*) from policy_policy where status='active'")[0][0],
                     "rules_enabled": q(c, "select count(*) from policy_policyrule where enabled=1")[0][0]}
    c.close()
    return M


def figures(M):
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    def save(name):
        plt.tight_layout()
        for ext in ("png", "pdf"):
            plt.savefig(HERE / f"{name}.{ext}", dpi=300)
        plt.close()
    # Figures are drawn at their printed size (one IEEE column, 3.5 in) so that
    # 7-8 pt text stays 7-8 pt in the paper; titles are left to the captions.
    plt.rcParams.update({"font.size": 7, "axes.labelsize": 7, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5})
    # Trust-log records by event type (sums to the trust-log total)
    bt = M["trustevent"]["by_type"]
    order = [("blocked", "Policy block"), ("night_access", "Night access"), ("mfa_fail", "MFA failure"),
             ("bad_password", "Bad password"), ("link_fail", "Unauthorised link"),
             ("trust_recovery_hourly", "Hourly recovery"), ("trust_recovery_safe", "Safe-action recovery"),
             ("trust_recovery_mfa", "MFA recovery")]
    ks = [(k, lab) for k, lab in order if k in bt]
    plt.figure(figsize=(3.5, 2.5))
    bars = plt.bar([lab for _, lab in ks], [bt[k] for k, _ in ks], color=["#C44E52"] * 5 + ["#55A868"] * 3)
    for b, (k, _) in zip(bars, ks):
        plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, str(bt[k]), ha="center", fontsize=6.5)
    plt.ylabel("Trust-log records"); plt.xticks(fontsize=6, rotation=35, ha="right"); plt.ylim(0, max(bt.values()) * 1.15)
    save("fig_trust_events_r3")
    # Request-log records: dashboard policy decisions vs page-access records
    z = M["ztnarequest"]
    labels = ["Allowed", "Admin (exempt)", "Blocked", "Denied", "Dashboard before MFA", "Other page opened"]
    nd = z["policy_decision_rows_non_admin_by_status"]
    vals = [nd.get("APPROVED", 0), z["policy_decision_rows_admin_override"], nd.get("BLOCKED", 0), nd.get("DENIED", 0),
            z["by_status"].get("ATTEMPT", 0), z["access_log_rows"] - z["by_status"].get("ATTEMPT", 0)]
    plt.figure(figsize=(3.5, 2.6))
    bars = plt.bar(labels, vals, color=["#4C72B0"] * 4 + ["#8C8C8C"] * 2)
    for b, v in zip(bars, vals):
        plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 3, str(v), ha="center", fontsize=6.5)
    plt.ylabel("Request-log records"); plt.xticks(fontsize=6, rotation=35, ha="right"); plt.ylim(0, max(vals) * 1.3)
    ax = plt.gca()
    ax.text(1.5, max(vals) * 1.18, "policy decisions", ha="center", fontsize=6.5, color="#4C72B0")
    ax.text(4.5, max(vals) * 1.18, "page-access records", ha="center", fontsize=6.5, color="#555555")
    save("fig_ztnarequest_r3")
    # Step-up challenges: earlier gate vs corrected gate, and outcomes
    s = M["stepup"]
    short = {"unrecognized device": "Corrected:\nunknown\nbrowser", "low behavioral trust": "Corrected:\nlow\ntrust",
             "low behavioral trust and unrecognized device": "Corrected:\nboth"}
    labels = (["Earlier gate\n(trust only)"] + [short.get(k, k) for k in s["post_fix_by_reason"]]
              + ["Passed", "Failed"])
    vals = [s["triggers_pre_fix_unlabelled"]] + list(s["post_fix_by_reason"].values()) + [s["successes"], s["failures"]]
    plt.figure(figsize=(3.5, 2.3))
    bars = plt.bar(labels, vals, color=["#8C8C8C"] + ["#DD8452"] * len(s["post_fix_by_reason"]) + ["#55A868", "#C44E52"])
    for b, v in zip(bars, vals):
        plt.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.15, str(v), ha="center", fontsize=6.5)
    plt.ylabel("Audit-log records"); plt.xticks(fontsize=5.8); plt.ylim(0, max(vals) * 1.18)
    save("fig_stepup_r3")


def main():
    import sys
    if "--figures-only" in sys.argv:      # regenerate figures from metrics_r3.json; snapshot untouched
        figures(json.loads((HERE / "metrics_r3.json").read_text(encoding="utf-8")))
        return
    removed = freeze()
    M = extract()
    # verify the cutoff reproduces the R2 manuscript totals
    check = {"ztnarequest==647": M["ztnarequest"]["total_rows"] == 647,
             "auditlog==643": M["auditlog"]["total_rows"] == 643,
             "trustevent==308": M["trustevent"]["total_rows"] == 308}
    manifest = {"source_db": str(SRC), "source_sha256": sha256(SRC), "snapshot": SNAP.name,
                "snapshot_sha256": sha256(SNAP), "cutoff_utc_exclusive": CUTOFF,
                "rows_removed_from_copy": removed, "reproduces_r2_totals": check}
    (HERE / "snapshot_manifest.json").write_text(json.dumps(manifest, indent=1))
    (HERE / "metrics_r3.json").write_text(json.dumps(M, indent=1, ensure_ascii=False))
    figures(M)
    print(json.dumps(manifest, indent=1)); print(json.dumps(M, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
