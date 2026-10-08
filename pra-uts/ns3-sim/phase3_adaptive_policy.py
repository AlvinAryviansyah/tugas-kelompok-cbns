#!/usr/bin/env python3
# ======================================================================================
#  phase3_adaptive_policy.py
#
#  Phase 3 - Adaptive Policy (Risk threshold -> Action)
#
#  Memakai model Random Forest dari Phase 2 untuk menghitung risk score per window,
#  lalu menerapkan kebijakan adaptif berbasis threshold:
#      risk < 0.3  -> ALLOW      (biarkan traffic lewat)
#      0.3 .. 0.7 -> RATE_LIMIT (batasi throughput attacker)
#      risk >= 0.7 -> ISOLATE   (drop semua paket dari sumber bukan sender resmi)
#
#  Efek aksi disimulasikan pada trace data:
#      - ALLOW     : semua paket diterima
#      - RATE_LIMIT: 50% paket bukan-sender di-drop
#      - ISOLATE   : 100% paket bukan-sender di-drop
#      - RE_AUTH   : (opsi) drop paket yang is_spoof=1
#
#  Output:
#      adaptive_results.csv  : per window -> risk, action, metrik post-mitigasi
#      action_distribution.csv: distribusi aksi
#
#  Cara pakai:
#      python3 phase3_adaptive_policy.py --model risk_model.joblib --data windows.csv
# ======================================================================================

import argparse
import os
import numpy as np
import pandas as pd
import joblib

SENDER_NODE = 0
# Threshold kebijakan (dapat di-tune)
TH_ALLOW, TH_RATE_LIMIT = 0.3, 0.7
RATE_LIMIT_DROP_PROB = 0.5  # probabilitas drop saat RATE_LIMIT


def decide_action(risk):
    """Pilih aksi berdasarkan risk score."""
    if risk < TH_ALLOW:
        return "ALLOW"
    elif risk < TH_RATE_LIMIT:
        return "RATE_LIMIT"
    else:
        return "ISOLATE"


def simulate_action(action, is_unauth, is_spoof, rng):
    """
    Simulasikan efek aksi pada satu paket.
    Mengembalikan (accepted, blocked_unauth, blocked_legit).
    """
    if action == "ALLOW":
        return True, False, False
    if action == "RATE_LIMIT":
        if is_unauth and rng.random() < RATE_LIMIT_DROP_PROB:
            return False, True, False   # drop paket attacker
        return True, False, False
    if action == "ISOLATE":
        if is_unauth:
            return False, True, False     # drop semua paket bukan sender
        return True, False, False
    if action == "RE_AUTH":
        if is_spoof:
            return False, False, False   # drop paket spoof
        return True, False, False
    return True, False, False


def main():
    ap = argparse.ArgumentParser(description="Phase 3 - Adaptive Policy")
    ap.add_argument("--model", default="risk_model.joblib")
    ap.add_argument("--data",  default="windows.csv")
    ap.add_argument("--trace", nargs="*", default=None,
                    help="file security-*.csv untuk evaluasi per-paket (opsional)")
    ap.add_argument("--out",   default=".")
    ap.add_argument("--seed",   type=int, default=42)
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)

    # --- Muat model + data window ---
    bundle = joblib.load(args.model)
    clf, feature_cols = bundle["model"], bundle["features"]
    windows = pd.read_csv(args.data)

    X = windows[feature_cols].values
    windows["risk_score"] = clf.predict_proba(X)[:, 1]
    windows["action"] = windows["risk_score"].apply(decide_action)

    # Distribusi aksi
    dist = windows["action"].value_counts().to_frame("count")
    dist["fraction"] = dist["count"] / len(windows)
    dist.to_csv(os.path.join(args.out, "action_distribution.csv"))

    print("=============== PHASE 3 - ADAPTIVE POLICY ===============")
    print("Distribusi aksi:")
    print(dist)
    print(f"Threshold: ALLOW<{TH_ALLOW}  RATE_LIMIT<{TH_RATE_LIMIT}  ISOLATE>={TH_RATE_LIMIT}")

    # --- Evaluasi per-paket jika trace disediakan ---
    if args.trace:
        all_rows = []
        for tf in args.trace:
            if not os.path.exists(tf):
                continue
            df = pd.read_csv(tf)
            df["scenario"] = os.path.basename(tf).replace("security-", "").replace(".csv", "")
            # Tempel risk/action per window ke tiap paket
            wmap = windows.set_index(["rx_node", "window"])
            df["window"] = (df["time"] / 1.0).astype(int)
            # Ambil risk/action dari window terdekat per rx_node
            df = df.merge(wmap[["risk_score", "action"]],
                          left_on=["rx_node", "window"], right_index=True, how="left")
            # Simulasikan efek aksi per paket
            accepted = []; blk_unauth = []; blk_legit = []
            for _, r in df.iterrows():
                acc, bu, bl = simulate_action(r["action"],
                                              r["actual_src_node"] != SENDER_NODE,
                                              r["is_spoof"], rng)
                accepted.append(acc); blk_unauth.append(bu); blk_legit.append(bl)
            df["accepted"] = accepted
            df["blocked_unauth"] = blk_unauth
            df["blocked_legit"] = blk_legit
            all_rows.append(df)
        if all_rows:
            ev = pd.concat(all_rows, ignore_index=True)
            # Metrik post-mitigasi
            total_unauth = (ev["actual_src_node"] != SENDER_NODE).sum()
            blocked_unauth = ev["blocked_unauth"].sum()
            total_legit = (ev["actual_src_node"] == SENDER_NODE).sum()
            blocked_legit = ev["blocked_legit"].sum()

            detection_rate = blocked_unauth / total_unauth if total_unauth else 0
            false_pos_rate = blocked_legit / total_legit if total_legit else 0
            unauth_acceptance = 1 - detection_rate

            print("\n--- Evaluasi post-mitigasi (per-paket) ---")
            print(f"Total paket attacker : {total_unauth}")
            print(f"Blocked attacker     : {blocked_unauth}")
            print(f"Total paket legit    : {total_legit}")
            print(f"Blocked legit (FP)   : {blocked_legit}")
            print(f"Detection rate       : {detection_rate:.4f}")
            print(f"False positive rate  : {false_pos_rate:.4f}")
            print(f"Unauthorized acceptance: {unauth_acceptance:.4f}")

            ev.to_csv(os.path.join(args.out, "adaptive_trace.csv"), index=False)
            summary = pd.DataFrame([{
                "phase": "ML_adaptive", "detection_rate": detection_rate,
                "false_positive_rate": false_pos_rate,
                "unauthorized_acceptance": unauth_acceptance,
                "blocked_unauth": int(blocked_unauth), "blocked_legit": int(blocked_legit),
            }])
            summary.to_csv(os.path.join(args.out, "adaptive_summary.csv"), index=False)

    windows.to_csv(os.path.join(args.out, "adaptive_results.csv"), index=False)
    print(f"\nHasil disimpan: adaptive_results.csv, action_distribution.csv")


if __name__ == "__main__":
    main()
