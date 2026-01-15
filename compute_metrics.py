# compute_metrics.py
# Usage:
#   python compute_metrics.py
#
# Works with SQLite db.sqlite3 (auto-detects table/column names).
# Prints LaTeX-ready baseline comparison table.

import sqlite3
from pathlib import Path
import re
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "db.sqlite3"

# -----------------------------
# Helpers
# -----------------------------
def q(conn, sql, params=None):
    cur = conn.cursor()
    cur.execute(sql, params or [])
    cols = [d[0] for d in cur.description] if cur.description else []
    rows = cur.fetchall()
    return cols, rows

def list_tables(conn):
    cols, rows = q(conn, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    return [r[0] for r in rows]

def list_columns(conn, table):
    cols, rows = q(conn, f"PRAGMA table_info({table});")
    # PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
    return [r[1] for r in rows]

def find_table(tables, contains_any=None, regex_any=None):
    contains_any = contains_any or []
    regex_any = regex_any or []
    candidates = []
    for t in tables:
        ok = True
        for c in contains_any:
            if c.lower() not in t.lower():
                ok = False
                break
        if ok and regex_any:
            if not any(re.search(rx, t, flags=re.I) for rx in regex_any):
                ok = False
        if ok:
            candidates.append(t)
    return candidates

def pick_first(candidates, label):
    if not candidates:
        raise RuntimeError(f"[ERROR] Could not auto-detect table for {label}.")
    # Prefer shorter / canonical names
    candidates = sorted(candidates, key=len)
    return candidates[0]

def safe_col(cols, preferred):
    """Return first existing column from preferred list."""
    for c in preferred:
        if c in cols:
            return c
    return None

def ratio(a, b):
    return (a * 100.0 / b) if b else 0.0

def format_pct(x):
    return f"{x:.1f}"

def latex_escape(s):
    if s is None:
        return ""
    s = str(s)
    s = s.replace("_", r"\_")
    return s


# -----------------------------
# Main
# -----------------------------
def main():
    if not DB_PATH.exists():
        raise FileNotFoundError(f"[ERROR] db.sqlite3 not found at: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    tables = list_tables(conn)

    # ---- auto-detect tables ----
    ztna_candidates = find_table(tables, contains_any=["ztna"], regex_any=[r"request"])
    audit_candidates = find_table(tables, contains_any=["siem"], regex_any=[r"audit"])
    trustevent_candidates = find_table(tables, contains_any=["trustbroker"], regex_any=[r"trustevent"])
    trustscore_candidates = find_table(tables, contains_any=["trustbroker"], regex_any=[r"trustscore"])

    # fallback patterns
    if not ztna_candidates:
        ztna_candidates = find_table(tables, regex_any=[r"ztna.*request", r"request.*ztna"])
    if not audit_candidates:
        audit_candidates = find_table(tables, regex_any=[r"auditlog"])
    if not trustevent_candidates:
        trustevent_candidates = find_table(tables, regex_any=[r"trustevent"])
    if not trustscore_candidates:
        trustscore_candidates = find_table(tables, regex_any=[r"trustscore"])

    ztna_table = pick_first(ztna_candidates, "ZTNARequest")
    audit_table = pick_first(audit_candidates, "AuditLog")
    trustevent_table = pick_first(trustevent_candidates, "TrustEvent")
    trustscore_table = pick_first(trustscore_candidates, "TrustScore")

    print("=== Auto-detected tables ===")
    print("ZTNARequest:", ztna_table)
    print("AuditLog  :", audit_table)
    print("TrustEvent:", trustevent_table)
    print("TrustScore:", trustscore_table)
    print()

    # ---- auto-detect columns ----
    z_cols = list_columns(conn, ztna_table)
    a_cols = list_columns(conn, audit_table)
    te_cols = list_columns(conn, trustevent_table)

    # ZTNARequest columns
    z_status = safe_col(z_cols, ["status"])
    z_reason = safe_col(z_cols, ["decision_reason", "reason"])
    z_ts = safe_col(z_cols, ["timestamp", "created_at", "time"])
    z_policy_rule = safe_col(z_cols, ["policy_rule_id"])
    z_app_fk = safe_col(z_cols, ["app_resource_id", "app_id"])

    if not z_status:
        raise RuntimeError(f"[ERROR] No status column detected in {ztna_table}. Columns: {z_cols}")

    # AuditLog columns
    a_action = safe_col(a_cols, ["action"])
    a_status = safe_col(a_cols, ["status"])
    a_ts = safe_col(a_cols, ["timestamp", "created_at", "time"])
    a_policy_rule = safe_col(a_cols, ["policy_rule_id"])
    a_latency = safe_col(a_cols, ["latency_ms"])

    # TrustEvent columns (best-effort)
    te_type = safe_col(te_cols, ["event_type", "type"])
    te_delta = safe_col(te_cols, ["delta", "trust_delta", "score_delta"])
    te_ts = safe_col(te_cols, ["timestamp", "created_at", "time"])

    # -----------------------------
    # Metric 1: Sensitive actions permitted (%)
    #
    # We do not have a clean "endpoint" column in ZTNARequest.
    # So we approximate sensitive actions using AuditLog action keywords.
    #
    # Sensitive actions = file create/edit/delete, command exec, share, download protected.
    # -----------------------------
    sensitive_keywords = [
        "Created file",
        "Updated file",
        "Edited file",
        "Deleted file",
        "Shared file",
        "Downloaded PROTECTED",
        "fire commands",
        "Started Docker",
        "Stopped Docker",
        "Restarted Docker",
    ]

    # Build SQL WHERE for action keywords
    sensitive_where = " OR ".join([f"{a_action} LIKE ?" for _ in sensitive_keywords]) if a_action else None

    sensitive_total = 0
    sensitive_allowed = 0

    if a_action and a_status:
        _, rows_total = q(conn,
            f"SELECT COUNT(*) FROM {audit_table} WHERE ({sensitive_where})",
            [f"%{k}%" for k in sensitive_keywords]
        )
        sensitive_total = rows_total[0][0] if rows_total else 0

        # "SUCCESS" indicates permitted action happened
        _, rows_allowed = q(conn,
            f"SELECT COUNT(*) FROM {audit_table} WHERE ({sensitive_where}) AND {a_status}='SUCCESS'",
            [f"%{k}%" for k in sensitive_keywords]
        )
        sensitive_allowed = rows_allowed[0][0] if rows_allowed else 0

    sensitive_allowed_pct = ratio(sensitive_allowed, sensitive_total)

    # -----------------------------
    # Metric 2: MFA prompts triggered (#)
    #
    # MFA prompt can be detected by:
    # - ZTNARequest.decision_reason == "require_mfa" (if logged)
    # - AuditLog action = "MFA Verification Failed"/"MFA Verification Success" (actual MFA flow)
    # We'll compute both.
    # -----------------------------
    mfa_required = 0
    if z_reason:
        _, rows = q(conn, f"SELECT COUNT(*) FROM {ztna_table} WHERE {z_reason}='require_mfa';")
        mfa_required = rows[0][0] if rows else 0

    mfa_failed = 0
    mfa_success = 0
    if a_action:
        _, rows = q(conn, f"SELECT COUNT(*) FROM {audit_table} WHERE {a_action}='MFA Verification Failed';")
        mfa_failed = rows[0][0] if rows else 0
        _, rows = q(conn, f"SELECT COUNT(*) FROM {audit_table} WHERE {a_action}='MFA Verification Success';")
        mfa_success = rows[0][0] if rows else 0

    # This is the "MFA prompts triggered" number for paper:
    # Choose the stronger interpretation:
    # - mfa_required is policy-triggered MFA
    # - mfa_failed + mfa_success are executed MFA attempts
    mfa_prompts = mfa_required if mfa_required > 0 else (mfa_failed + mfa_success)

    # -----------------------------
    # Metric 3: Hard blocks triggered (#)
    # Use ZTNARequest.status == BLOCKED
    # -----------------------------
    blocked_count = 0
    _, rows = q(conn, f"SELECT COUNT(*) FROM {ztna_table} WHERE {z_status}='BLOCKED';")
    blocked_count = rows[0][0] if rows else 0

    # -----------------------------
    # Metric 4: Recovery effort after degradation (requests)
    #
    # Hard to compute precisely without a request_id link in TrustEvent.
    # We'll approximate using TrustEvent counts after "penalty" events.
    #
    # If you have event_type and delta -> compute average number of requests between
    # first negative event and next recovery event.
    #
    # If not possible, report N/A and add that you compute it manually.
    # -----------------------------
    recovery_effort = None

    if te_type:
        # Count recovery events as proxy (safe_action/hourly/daily/mfa recovery)
        recovery_markers = ["recovery", "hourly", "daily", "safe", "mfa"]
        rec_where = " OR ".join([f"LOWER({te_type}) LIKE ?" for _ in recovery_markers])
        _, rows = q(conn, f"SELECT COUNT(*) FROM {trustevent_table} WHERE ({rec_where});",
                    [f"%{r}%" for r in recovery_markers])
        recovery_events = rows[0][0] if rows else 0

        # This isn't "requests until full access", but gives usable proxy.
        # Keep it as N/A unless you add request_id in TrustEvent later.
        recovery_effort = "N/A (requires request-linked TrustEvent)"

    else:
        recovery_effort = "N/A"

    # -----------------------------
    # Policy traceability health check
    # -----------------------------
    policy_rule_logged_requests = 0
    if z_policy_rule:
        _, rows = q(conn, f"SELECT COUNT(*) FROM {ztna_table} WHERE {z_policy_rule} IS NOT NULL;")
        policy_rule_logged_requests = rows[0][0] if rows else 0

    # -----------------------------
    # Print metrics
    # -----------------------------
    print("=== Proposed System Metrics (computed from logs) ===")
    print("Sensitive actions total:", sensitive_total)
    print("Sensitive actions allowed:", sensitive_allowed)
    print("Sensitive actions allowed (%):", format_pct(sensitive_allowed_pct))
    print("MFA required decisions (ZTNARequest):", mfa_required)
    print("MFA success logs (AuditLog):", mfa_success)
    print("MFA failure logs (AuditLog):", mfa_failed)
    print("MFA prompts triggered (chosen):", mfa_prompts)
    print("Hard blocks triggered:", blocked_count)
    print("Policy_rule_id logged requests:", policy_rule_logged_requests)
    print()

    # -----------------------------
    # LaTeX-ready baseline table
    #
    # NOTE: Session-Based / RBAC columns cannot be computed unless you executed them.
    # We keep them as N/A placeholders.
    # -----------------------------
    session_sensitive_pct = "N/A"
    session_mfa = "0"
    session_block = "0"
    session_recovery = "N/A"

    rbac_sensitive_pct = "N/A"
    rbac_mfa = "0"
    rbac_block = "N/A"
    rbac_recovery = "N/A"

    proposed_sensitive_pct = format_pct(sensitive_allowed_pct)
    proposed_mfa = str(mfa_prompts)
    proposed_block = str(blocked_count)
    proposed_recovery = str(recovery_effort)

    print("=== LaTeX Table (copy into paper) ===")
    print(r"\begin{table}[htbp]")
    print(r"\centering")
    print(r"\caption{Baseline Comparisons: Security and Usability Outcomes}")
    print(r"\label{tab:baseline_comparison}")
    print(r"\renewcommand{\arraystretch}{1.25}")
    print(r"\setlength{\tabcolsep}{5pt}")
    print(r"\begin{tabular}{|p{3.1cm}|c|c|c|}")
    print(r"\hline")
    print(r"\textbf{Metric} & \textbf{Session-Based} & \textbf{RBAC-Only} & \textbf{Proposed System} \\ \hline")
    print(rf"Sensitive actions permitted (\%) & {session_sensitive_pct} & {rbac_sensitive_pct} & {proposed_sensitive_pct} \\ \hline")
    print(rf"MFA prompts triggered (\#) & {session_mfa} & {rbac_mfa} & {proposed_mfa} \\ \hline")
    print(rf"Hard blocks triggered (\#) & {session_block} & {rbac_block} & {proposed_block} \\ \hline")
    print(rf"Recovery effort after degradation (requests) & {session_recovery} & {rbac_recovery} & {proposed_recovery} \\ \hline")
    print(r"\end{tabular}")
    print(r"\end{table}")
    print()

    print("=== Notes ===")
    print("1) Session-Based and RBAC-Only values show N/A unless you run those baselines.")
    print("2) Sensitive actions are approximated using AuditLog.action keyword matching.")
    print("3) For journal-grade recovery effort, add TrustEvent.request_id and compute precisely.")
    print("4) If policy_rule_id is mostly NULL, your traceability claim is still weak.")

    conn.close()


if __name__ == "__main__":
    main()
