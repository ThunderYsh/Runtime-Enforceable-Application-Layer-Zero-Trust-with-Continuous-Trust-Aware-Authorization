"""
replicate_v1.py -- R3 revision, Reviewer #6 comments 1 and 2.

(1) Re-runs the ORIGINAL sensitivity simulation (../run_sensitivity_analysis.py,
    seed 42) unchanged, to confirm the published Table IV numbers are
    reproducible from the shipped code.
(2) Re-runs the same model with common random numbers (identical event
    sequences for every alpha) and decomposes each post-event state into the
    three bands the original code uses:  T > 0.60 (normal),
    0.30 < T <= 0.60 (counted as "MFA trigger" == "restrict hit"),
    T <= 0.30 (counted as "block").  This tests Reviewer #6's explanation that
    the fall in "MFA triggers" at alpha = 0.15 is band conversion, not lower
    detection sensitivity.
(3) Proves comment 1 analytically: benign event mix has no negative delta.
No files are written except v1_replication.json.
"""
import json, random, importlib.util, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("v1", ROOT / "run_sensitivity_analysis.py")
v1 = importlib.util.module_from_spec(spec); spec.loader.exec_module(v1)

# ---- (1) exact reproduction of published table ----------------------------
random.seed(42)
_, summary = v1.run_analysis()
published = {0.03: (545, 122), 0.06: (610, 156), 0.10: (588, 342), 0.15: (579, 526)}
repro = []
for s in summary:
    a = s["mfa_fail_penalty"]
    repro.append(dict(alpha=a, mfa_triggers=s["total_mfa_triggers"],
                      restrict_hits=s["total_restrict_hits"], block=s["total_block_hits"],
                      fp=s["fp_rate"], matches_published=(s["total_mfa_triggers"], s["total_block_hits"]) == published[a],
                      triggers_identical_to_restrict_hits=s["total_mfa_triggers"] == s["total_restrict_hits"]))

# ---- (3) benign mix contains no penalty event ------------------------------
benign_events = set(v1.BENIGN_EVENT_DIST)
benign_has_penalty = any(e in ("mfa_fail", "bad_password", "link_fail", "blocked") for e in benign_events)

# ---- (2) common-random-numbers band decomposition --------------------------
def sessions(seed=42):
    rng = random.Random(seed); out = []
    n_adv = int(v1.N_SESSIONS * v1.ADVERSARIAL_RATIO)
    for i in range(v1.N_SESSIONS):
        dist = v1.ADV_EVENT_DIST if i < n_adv else v1.BENIGN_EVENT_DIST
        out.append((i < n_adv, [rng.choice(dist) for _ in range(v1.EVENTS_PER_SESSION)]))
    return out

def bands(alpha, seqs):
    pen = {"mfa_fail": alpha, "bad_password": 0.08, "blocked": 0.10, "link_fail": 0.07}
    c = dict(normal=0, restrict_band=0, block_band=0, adv_sessions_reaching_block=0,
             adv_sessions_below_060=0, benign_sessions_below_060=0)
    for adv, seq in seqs:
        t = v1.TRUST_INIT; hit_b = hit_r = False
        for e in seq:
            if e in pen: t = v1.clamp(t - pen[e])
            elif e == "safe_action": t = v1.clamp(t + v1.RECOVERY_SAFE)
            elif e == "mfa_success": t = v1.clamp(t + v1.RECOVERY_MFA)
            if t <= v1.BLOCK_THRESH: c["block_band"] += 1; hit_b = True
            elif t <= v1.RESTRICT_THRESH: c["restrict_band"] += 1; hit_r = True
            else: c["normal"] += 1
        if adv:
            c["adv_sessions_reaching_block"] += hit_b
            c["adv_sessions_below_060"] += (hit_b or hit_r)
        else:
            c["benign_sessions_below_060"] += (hit_b or hit_r)
    c["below_060_total"] = c["restrict_band"] + c["block_band"]
    return c

crn = {}
for seed in range(42, 42 + 50):
    seqs = sessions(seed)
    for a in (0.03, 0.06, 0.10, 0.15):
        r = bands(a, seqs)
        acc = crn.setdefault(a, {k: [] for k in r})
        for k, v in r.items(): acc[k].append(v)
crn_mean = {a: {k: sum(v) / len(v) for k, v in d.items()} for a, d in crn.items()}
seed42 = {a: bands(a, sessions(42)) for a in (0.03, 0.06, 0.10, 0.15)}

out = dict(reproduction=repro, benign_event_types=sorted(benign_events),
           benign_has_penalty_event=benign_has_penalty,
           crn_seed42=seed42, crn_mean_over_50_seeds=crn_mean)
json.dump(out, open(pathlib.Path(__file__).with_name("v1_replication.json"), "w"), indent=2)
print(json.dumps(out, indent=1))
