#!/usr/bin/env python3
# ======================================================================================
#  phase5_evaluate.py
#
#  Phase 5 - Comparative Evaluation
#
#  Membandingkan 4 pendekatan mitigasi sesuai Experimental Matrix (Tabel 4.1):
#      1. Baseline       : tanpa mitigasi (semua paket diterima)
#      2. Static         : rule-based statis (dup>0.1 -> drop dup; spoof -> drop; unauth -> rate-limit)
#      3. ML Adaptive    : kebijakan Phase 3 (risk threshold -> action)
#      4. ML + RL        : kebijakan Phase 4 (Q-learning policy)
#
#  Metrik dievaluasi (sesuai Tabel 3.1 laporan):
#      Network : throughput, PDR, PLR, end-to-end delay, completion time
#      Security: detection rate, false positive rate, mitigation time,
#                 unauthorized packet acceptance
#
#  Output:
#      comparison.csv          : tabel perbandingan metrik x metode
#      comparison_charts.png   : bar chart perbandingan
#
#  Cara pakai:
#      python3 phase5_evaluate.py --trace security-*.csv --rl-policy rl_policy.json
# ======================================================================================

import argparse
import glob
import json
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SENDER_NODE = 0
N_ACTIONS = 4
ACTION_NAMES = ["ALLOW", "RATE_LIMIT", "RE_AUTH", "ISOLATE"]


# ---------- Simulasi efek aksi per paket ----------
def apply_action(action, is_unauth, is_spoof, rng, rl_drop_prob=0.5):
    """Kembalikan (accepted, blocked_unauth, blocked_legit)."""
    if action == 0:   # ALLOW
        return True, False, False
    if action == 1:    # RATE_LIMIT
        if is_unauth and rng.random() < rl_drop_prob:
            return False, True, False
        return True, False, False
    if action == 2:    # RE_AUTH (drop spoof)
        if is_spoof:
            return False, False, False
        return True, False, False
    if action == 3:    # ISOLATE
        if is_unauth:
            return False, True, False
        return True, False, False
    return True, False, False


# ---------- Baseline: tanpa mitigasi ----------
def policy_baseline(row, rng):
    return 0  # ALLOW semua


# ---------- Static: rule-based statis ----------
def policy_static(row, rng):
    if row["spoof_ratio"] > 0 or row["dup_ratio"] > 0.1:
        return 3  # ISOLATE
    if row["unauth_ratio"] > 0.3:
        return 1  # RATE_LIMIT
    return 0


# ---------- ML Adaptive (Phase 3: risk threshold) ----------
def policy_ml_adaptive(row, rng, th_allow=0.3, th_isolate=0.7):
    if row["risk_score"] < th_allow:
        return 0
    elif row["risk_score"] < th_isolate:
        return 1
    return 3


# ---------- ML + RL (Phase 4: Q-learning policy) ----------
def make_policy_rl(rl_bundle):
    bins = rl_bundle["bins"]
    state_cols = rl_bundle["state_cols"]
    n_bins = rl_bundle["n_bins"]
    policy = rl_bundle["policy"]

    def disc(v, cuts):
        idx = 0
        for c in cuts:
            if v >= c:
                idx += 1
            else:
                break
        return idx

    def policy_fn(row, rng):
        s = 0
        for c in state_cols:
            s = s * n_bins[c] + disc(row[c], bins[c])
        s = min(s, len(policy) - 1)
        return int(policy[s])
    return policy_fn


# ---------- Evaluasi satu metode pada trace ----------
def evaluate_method(trace_df, policy_fn, rng, window_sec=1.0):
    """trace_df sudah punya kolom window + risk_score (dari merge)."""
    accepted = []; blk_u = []; blk_l = []
    for _, r in trace_df.iterrows():
        a = policy_fn(r, rng)
        acc, bu, bl = apply_action(a, r["actual_src_node"] != SENDER_NODE,
                                   r["is_spoof"], rng)
        accepted.append(acc); blk_u.append(bu); blk_l.append(bl)
    out = trace_df.copy()
    out["accepted"] = accepted
    out["blocked_unauth"] = blk_u
    out["blocked_legit"] = blk_l
    return out


def compute_metrics(df, sim_start=0.5):
    tot_unauth = (df["actual_src_node"] != SENDER_NODE).sum()
    tot_legit  = (df["actual_src_node"] == SENDER_NODE).sum()
    blk_unauth = df["blocked_unauth"].sum()
    blk_legit  = df["blocked_legit"].sum()

    # Network metrics (hanya pada paket yang diterima)
    acc = df[df["accepted"]]
    legit_acc = acc[acc["actual_src_node"] == SENDER_NODE]
    # PDR = legit diterima / legit total
    pdr = len(legit_acc) / tot_legit if tot_legit else 0
    plr = 1 - pdr
    # Throughput (kbps) berdasarkan byte legit diterima
    dur = max((acc["time"].max() - sim_start), 1e-6)
    thrput = (legit_acc["payload_size"].sum() * 8 / 1000.0) / dur if len(legit_acc) else 0
    # Mean delay (legit diterima)
    mean_delay = legit_acc["delay_ms"].mean() if len(legit_acc) else 0
    # Completion time = waktu paket legit terakhir diterima - start
    comp_time = (legit_acc["time"].max() - sim_start) if len(legit_acc) else 0
    # Security
    dr  = blk_unauth / tot_unauth if tot_unauth else 0
    fpr = blk_legit / tot_legit if tot_legit else 0
    una = 1 - dr
    return {
        "throughput_kbps": round(thrput, 2),
        "pdr": round(pdr, 4),
        "plr": round(plr, 4),
        "mean_delay_ms": round(mean_delay, 3),
        "completion_time_s": round(comp_time, 3),
        "detection_rate": round(dr, 4),
        "false_positive_rate": round(fpr, 4),
        "unauthorized_acceptance": round(una, 4),
    }


def main():
    ap = argparse.ArgumentParser(description="Phase 5 - Comparative Evaluation")
    ap.add_argument("--trace", nargs="*", default=glob.glob("security-*.csv"))
    ap.add_argument("--windows", default="adaptive_results.csv",
                    help="window df dengan risk_score (untuk merge ke trace)")
    ap.add_argument("--rl-policy", default="rl_policy.json")
    ap.add_argument("--out", default=".")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)

    # Muat windows (untuk risk_score per window)
    win = pd.read_csv(args.windows)
    win_map = win.set_index(["rx_node", "window"])[["risk_score"]]

    # Muat RL policy
    rl_bundle = None
    if os.path.exists(args.rl_policy):
        with open(args.rl_policy) as f:
            rl_bundle = json.load(f)

    # Muat & merge semua trace
    frames = []
    for tf in args.trace:
        if not os.path.exists(tf):
            continue
        df = pd.read_csv(tf)
        df["scenario"] = os.path.basename(tf).replace("security-", "").replace(".csv", "")
        df["window"] = (df["time"] / 1.0).astype(int)
        df = df.merge(win_map, left_on=["rx_node", "window"],
                      right_index=True, how="left")
        # Untuk RL, butuh kolom state lain
        if rl_bundle:
            for c in rl_bundle["state_cols"]:
                if c not in df.columns:
                    df[c] = 0
        frames.append(df)
    if not frames:
        import sys; sys.exit("Tidak ada trace. Jalankan Phase 1-4 dulu.")
    all_df = pd.concat(frames, ignore_index=True)

    # Definisi 4 metode
    methods = {
        "Baseline":    policy_baseline,
        "Static":       policy_static,
        "ML_Adaptive":  policy_ml_adaptive,
    }
    if rl_bundle:
        methods["ML+RL"] = make_policy_rl(rl_bundle)

    # Evaluasi tiap metode
    results = {}
    for name, fn in methods.items():
        res = evaluate_method(all_df, fn, rng)
        m = compute_metrics(res)
        m["method"] = name
        results[name] = m
        print(f"\n--- {name} ---")
        for k, v in m.items():
            if k != "method":
                print(f"  {k:25s}: {v}")

    # Simpan tabel perbandingan
    comp = pd.DataFrame(list(results.values())).set_index("method")
    comp.to_csv(os.path.join(args.out, "comparison.csv"))

    # Plot bar chart perbandingan (4 metrik kunci)
    fig, axes = plt.subplots(2, 2, figsize=(11, 8))
    metrics_to_plot = [("detection_rate", "Detection Rate (lebih tinggi lebih baik)"),
                      ("false_positive_rate", "False Positive Rate (lebih rendah lebih baik)"),
                      ("throughput_kbps", "Throughput (kbps, lebih tinggi lebih baik)"),
                      ("mean_delay_ms", "Mean Delay (ms, lebih rendah lebih baik)")]
    for ax, (m_key, title) in zip(axes.flat, metrics_to_plot):
        vals = [results[n][m_key] for n in methods]
        colors = ["#888", "#4c72b0", "#55a868", "#c44e52"]
        ax.bar(list(methods.keys()), vals, color=colors[:len(methods)])
        ax.set_title(title, fontsize=10)
        ax.tick_params(axis="x", rotation=20)
    fig.suptitle("Perbandingan Metode Mitigasi (Phase 5)", fontsize=13)
    plt.tight_layout()
    plt.savefig(os.path.join(args.out, "comparison_charts.png"), dpi=120)
    plt.close()

    print(f"\nTabel disimpan : {args.out}/comparison.csv")
    print(f"Chart disimpan : {args.out}/comparison_charts.png")
    print("\n===== RINGKASAN PERBANDINGAN =====")
    print(comp.to_string())


if __name__ == "__main__":
    main()
