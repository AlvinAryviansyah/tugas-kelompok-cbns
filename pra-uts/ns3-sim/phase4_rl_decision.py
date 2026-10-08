#!/usr/bin/env python3
# ======================================================================================
#  phase4_rl_decision.py
#
#  Phase 4 - RL Decision Engine (Q-learning)
#
#  Melatih agent Q-learning yang mengambil keputusan mitigasi berbasis state jaringan
#  + risk score. Berbeda dengan Phase 3 (threshold statis), agent RL belajar policy
#  optimal yang memaksimalkan trade-off security vs performance.
#
#  State  (diskret)  : binning dari [risk, pkt_rate, unauth_ratio, mean_delay]
#  Action            : 0=ALLOW, 1=RATE_LIMIT, 2=RE_AUTH, 3=ISOLATE
#  Reward            :  security_gain - performance_cost
#      security_gain  = unauth_blocked / (unauth_total + 1e-6)     (lebih tinggi lebih baik)
#      performance_cost = legit_blocked / (legit_total + 1e-6)     (false positive)
#
#  Pelatihan dilakukan offline pada window dataset (windows.csv + risk score dari Phase 2/3).
#  Pada penelitian lanjutan, hal yang sama dapat dijalankan online via NS3-Gym.
#
#  Output:
#      rl_policy.json       : Q-table + konfigurasi state/action
#      rl_rewards.csv       : reward per episode (untuk plot convergence)
#      rl_evaluation.csv    : evaluasi policy pada data window
#
#  Cara pakai:
#      python3 phase4_rl_decision.py --data adaptive_results.csv
# ======================================================================================

import argparse
import json
import os
import numpy as np
import pandas as pd

ACTIONS = ["ALLOW", "RATE_LIMIT", "RE_AUTH", "ISOLATE"]
N_ACTIONS = len(ACTIONS)
SENDER_NODE = 0

# Bins untuk diskritisasi state (quantile-based sederhana)
def make_bins(series, n=4):
    qs = np.linspace(0, 1, n + 1)[1:-1]
    cuts = series.quantile(qs).tolist()
    return cuts

def discretize(value, cuts):
    # kembalikan index bin 0..len(cuts)
    idx = 0
    for c in cuts:
        if value >= c:
            idx += 1
        else:
            break
    return idx

def simulate_action_effect(action, window_row, rng,
                            rate_limit_drop_prob=0.5):
    """
    Estimasi efek aksi pada satu window.
    Mengembalikan (unauth_blocked, legit_blocked) berdasarkan komposisi window.
    Pakai rasio unauth_ratio & asumsi paket legit = pkt_count - unauth_count.
    """
    n = window_row["pkt_count"]
    unauth_n = int(round(window_row["unauth_ratio"] * n))
    legit_n = n - unauth_n
    spoof_n = int(round(window_row["spoof_ratio"] * n))

    if action == 0:   # ALLOW
        return 0, 0
    if action == 1:    # RATE_LIMIT
        return int(unauth_n * rate_limit_drop_prob), 0
    if action == 2:    # RE_AUTH (drop spoof)
        return min(spoof_n, unauth_n), 0
    if action == 3:    # ISOLATE
        return unauth_n, 0
    return 0, 0


def main():
    ap = argparse.ArgumentParser(description="Phase 4 - RL Decision (Q-learning)")
    ap.add_argument("--data", default="adaptive_results.csv",
                    help="window dataset dengan risk_score (dari Phase 3)")
    ap.add_argument("--out",  default=".")
    ap.add_argument("--episodes", type=int, default=500)
    ap.add_argument("--alpha",   type=float, default=0.1)   # learning rate
    ap.add_argument("--gamma",   type=float, default=0.9)   # discount factor
    ap.add_argument("--eps",     type=float, default=1.0)   # exploration awal
    ap.add_argument("--eps_min", type=float, default=0.05)
    ap.add_argument("--eps_decay",type=float, default=0.995)
    ap.add_argument("--seed",    type=int, default=42)
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    df = pd.read_csv(args.data)

    # --- Bangun bins diskret untuk 4 dimensi state ---
    state_cols = ["risk_score", "pkt_rate", "unauth_ratio", "mean_delay_ms"]
    bins = {c: make_bins(df[c], n=4) for c in state_cols}
    n_bins = {c: len(bins[c]) + 1 for c in state_cols}
    # Total state = produk kartesian
    n_states = int(np.prod(list(n_bins.values())))

    def state_index(row):
        idxs = [discretize(row[c], bins[c]) for c in state_cols]
        # encode ke index flat: base-4 encoding
        s = 0
        for c in state_cols:
            s = s * n_bins[c] + discretize(row[c], bins[c])
        return s

    # --- Q-learning ---
    Q = np.zeros((n_states, N_ACTIONS))
    rewards_log = []

    for ep in range(args.episodes):
        # Iterasi window sebagai satu episode
        total_reward = 0
        order = rng.permutation(len(df))
        for i in order:
            row = df.iloc[i]
            s = state_index(row)
            # epsilon-greedy
            if rng.random() < args.eps:
                a = rng.integers(0, N_ACTIONS)
            else:
                a = int(np.argmax(Q[s]))
            # Eksekusi aksi -> reward
            unauth_blk, legit_blk = simulate_action_effect(a, row, rng)
            unauth_n = int(round(row["unauth_ratio"] * row["pkt_count"]))
            legit_n = row["pkt_count"] - unauth_n
            sec_gain = unauth_blk / (unauth_n + 1e-6)
            perf_cost = legit_blk / (legit_n + 1e-6)
            # Reward: security gain diberi bobot lebih besar
            reward = 1.5 * sec_gain - 1.0 * perf_cost
            # Next state = state window berikutnya (asumsi transisi sekuensial)
            total_reward += reward
            # Q update (terminal sederhana, gamma=0 untuk next karena window independen)
            Q[s, a] += args.alpha * (reward - Q[s, a])

        # Decay epsilon
        args.eps = max(args.eps_min, args.eps * args.eps_decay)
        rewards_log.append(total_reward / max(1, len(df)))

    # --- Ekstrak policy ---
    policy = np.argmax(Q, axis=1)
    # Simpan
    out = {
        "actions": ACTIONS,
        "state_cols": state_cols,
        "bins": {k: [float(x) for x in v] for k, v in bins.items()},
        "n_bins": n_bins,
        "Q_table": Q.tolist(),
        "policy": policy.tolist(),
        "hyperparams": {
            "episodes": args.episodes, "alpha": args.alpha,
            "gamma": args.gamma, "eps_init": 1.0,
            "eps_min": args.eps_min, "eps_decay": args.eps_decay,
        },
    }
    with open(os.path.join(args.out, "rl_policy.json"), "w") as f:
        json.dump(out, f, indent=2)
    pd.DataFrame({"episode": range(len(rewards_log)),
                  "avg_reward": rewards_log}).to_csv(
        os.path.join(args.out, "rl_rewards.csv"), index=False)

    # --- Evaluasi policy pada data ---
    eval_rows = []
    for _, row in df.iterrows():
        s = state_index(row)
        a = int(policy[s])
        unauth_blk, legit_blk = simulate_action_effect(a, row, rng)
        unauth_n = int(round(row["unauth_ratio"] * row["pkt_count"]))
        legit_n = row["pkt_count"] - unauth_n
        eval_rows.append({
            "rx_node": row["rx_node"], "window": row["window"],
            "scenario": row.get("scenario", ""),
            "risk_score": row["risk_score"],
            "rl_action": ACTIONS[a],
            "unauth_blocked": unauth_blk, "legit_blocked": legit_blk,
            "unauth_total": unauth_n, "legit_total": legit_n,
        })
    ev = pd.DataFrame(eval_rows)
    ev.to_csv(os.path.join(args.out, "rl_evaluation.csv"), index=False)

    # Ringkasan
    tot_unauth = ev["unauth_total"].sum()
    tot_blk_unauth = ev["unauth_blocked"].sum()
    tot_legit = ev["legit_total"].sum()
    tot_blk_legit = ev["legit_blocked"].sum()
    dr = tot_blk_unauth / tot_unauth if tot_unauth else 0
    fpr = tot_blk_legit / tot_legit if tot_legit else 0
    print("=============== PHASE 4 - RL DECISION (Q-learning) ===============")
    print(f"Episodes        : {args.episodes}")
    print(f"States          : {n_states}")
    print(f"Final epsilon   : {args.eps:.4f}")
    print(f"Final avg reward: {rewards_log[-1]:.4f}")
    print(f"Distribusi aksi :")
    print(ev["rl_action"].value_counts().to_frame("count"))
    print(f"\nDetection rate      : {dr:.4f}")
    print(f"False positive rate : {fpr:.4f}")
    print(f"\nOutput: rl_policy.json, rl_rewards.csv, rl_evaluation.csv")


if __name__ == "__main__":
    main()
