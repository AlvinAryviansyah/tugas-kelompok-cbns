#!/usr/bin/env python3
# ======================================================================================
#  phase2_ml_risk.py
#
#  Phase 2 - ML Risk Prediction (Random Forest)
#
#  Membaca file security-<scenario>.csv hasil simulasi NS-3 (Phase 1), melakukan
#  feature engineering berbasis time-window per receiver, melatih model Random
#  Forest sebagai risk predictor, lalu mengevaluasi (accuracy, precision, recall,
#  F1, ROC-AUC, confusion matrix).
#
#  Dataset input  : security-<scenario>.csv  (satu per skenario)
#  Dataset output : windows.csv             (fitur + label per window, untuk Phase 3-5)
#  Model output   : risk_model.joblib       (model RF tersimpan)
#  Metrik output  : ml_metrics.csv          + classification_report ke konsol
#  Plot output    : feature_importance.png, confusion_matrix.png
#
#  Cara pakai:
#      python3 phase2_ml_risk.py --inputs security-normal.csv security-flooding.csv \
#                                security-replay.csv security-spoofing.csv
# ======================================================================================

import argparse
import os
import sys
import glob

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")  # simpan ke file (tanpa display)
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, roc_auc_score, confusion_matrix,
                              classification_report)

SENDER_NODE = 0  # node 0 = sender resmi (lihat adaptive-security-sim.cc)


# --------------------------------------------------------------------------------------
# STEP 1. Feature engineering berbasis time-window
#
# Alih-alih mengklasifikasi tiap paket, kita agregasi paket per receiver per window
# waktu (default 1 detik). Ini lebih realistis untuk IDS karena keputusan diambil
# berdasarkan pola traffic, bukan satu paket tunggal.
#
# Fitur per window:
#   pkt_count        : jumlah paket
#   byte_count       : total byte
#   mean_payload     : rata-rata payload size
#   mean_delay_ms    : rata-rata end-to-end delay
#   dup_ratio        : fraction is_duplicate
#   spoof_ratio      : fraction is_spoof
#   unauth_ratio     : fraction is_unauthorized
#   pkt_rate         : pkt_count / window_sec (paket per detik)
#
# Label:
#   is_attack = 1 jika ada paket di window tsb yang actual_src_node != 0 (ground truth
#   dari IP sumber sebenarnya). Pada detektor nyata, ground truth ini tidak tersedia.
# --------------------------------------------------------------------------------------
def build_windows(df, window_sec=1.0):
    df = df.copy()
    # Nomor window = floor(time / window_sec)
    df["window"] = (df["time"] / window_sec).astype(int)
    # Label per (rx_node, window): 1 jika ada paket dari node != sender resmi
    df["is_attack_pkt"] = (df["actual_src_node"] != SENDER_NODE).astype(int)

    grouped = df.groupby(["rx_node", "window"])
    rows = []
    for (rx, win), g in grouped:
        n = len(g)
        rows.append({
            "rx_node":      rx,
            "window":       win,
            "pkt_count":    n,
            "byte_count":   g["payload_size"].sum(),
            "mean_payload": g["payload_size"].mean(),
            "mean_delay_ms": g["delay_ms"].mean(),
            "dup_ratio":    g["is_duplicate"].mean(),
            "spoof_ratio":  g["is_spoof"].mean(),
            "unauth_ratio": g["is_unauthorized"].mean(),
            "pkt_rate":     n / window_sec,
            # Label ground-truth: window dianggap "attack" jika mengandung paket
            # dari sumber bukan sender resmi.
            "is_attack":    int(g["is_attack_pkt"].max()),
        })
    return pd.DataFrame(rows)


# --------------------------------------------------------------------------------------
# STEP 2. Muat semua CSV skenario, beri label skenario, gabungkan
# --------------------------------------------------------------------------------------
def load_datasets(paths, window_sec):
    frames = []
    for p in paths:
        if not os.path.exists(p):
            print(f"  [warn] file tidak ditemukan, dilewati: {p}")
            continue
        df = pd.read_csv(p)
        df["scenario"] = os.path.basename(p).replace("security-", "").replace(".csv", "")
        win = build_windows(df, window_sec)
        win["scenario"] = df["scenario"].iloc[0]
        frames.append(win)
        print(f"  [ok] {p}: {len(df)} paket -> {len(win)} window")
    if not frames:
        sys.exit("Tidak ada data yang berhasil dimuat. Jalankan simulasi NS-3 dulu.")
    return pd.concat(frames, ignore_index=True)


# --------------------------------------------------------------------------------------
# STEP 3. Latih Random Forest + evaluasi
# --------------------------------------------------------------------------------------
def train_and_evaluate(windows_df, out_dir, seed):
    # Fitur yang dipakai model (tanpa ground-truth & metadata)
    feature_cols = ["pkt_count", "byte_count", "mean_payload", "mean_delay_ms",
                     "dup_ratio", "spoof_ratio", "unauth_ratio", "pkt_rate"]
    X = windows_df[feature_cols].values
    y = windows_df["is_attack"].values

    # Split train/test stratified berdasarkan label
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=seed, stratify=y)

    # Random Forest: 200 pohon, seimbangkan kelas (attack biasanya minoritas)
    clf = RandomForestClassifier(n_estimators=200, random_state=seed,
                                 class_weight="balanced", n_jobs=-1)
    clf.fit(X_train, y_train)

    # Prediksi
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]  # probabilitas kelas "attack" = risk score

    # Metrik
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)        # = detection rate
    f1   = f1_score(y_test, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_test, y_prob)
    except ValueError:
        auc = float("nan")
    cm = confusion_matrix(y_test, y_pred)

    # Cross-validation 5-fold untuk estimasi yang lebih robust
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    cv_f1 = cross_val_score(clf, X, y, cv=cv, scoring="f1").mean()

    # Cetak laporan
    print("\n================ LAPORAN KLASIFIKASI (Phase 2) ================")
    print(classification_report(y_test, y_pred,
                                target_names=["normal", "attack"]))
    print(f"Accuracy    : {acc:.4f}")
    print(f"Precision    : {prec:.4f}")
    print(f"Recall (DR)  : {rec:.4f}")
    print(f"F1-Score     : {f1:.4f}")
    print(f"ROC-AUC      : {auc:.4f}")
    print(f"CV F1 (5-fold): {cv_f1:.4f}")
    print("Confusion matrix (rows=actual, cols=pred):")
    print(cm)

    # Simpan metrik ke CSV
    metrics = pd.DataFrame([{
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
        "roc_auc": auc, "cv_f1": cv_f1,
        "tn": cm[0,0], "fp": cm[0,1], "fn": cm[1,0], "tp": cm[1,1],
    }])
    metrics.to_csv(os.path.join(out_dir, "ml_metrics.csv"), index=False)

    # Simpan model
    joblib.dump({"model": clf, "features": feature_cols}, os.path.join(out_dir, "risk_model.joblib"))

    # Plot feature importance
    importances = clf.feature_importances_
    order = np.argsort(importances)[::-1]
    plt.figure(figsize=(8, 5))
    plt.bar(range(len(feature_cols)), importances[order], color="steelblue")
    plt.xticks(range(len(feature_cols)), [feature_cols[i] for i in order], rotation=45, ha="right")
    plt.title("Feature Importance (Random Forest)")
    plt.ylabel("Importance")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "feature_importance.png"), dpi=120)
    plt.close()

    # Plot confusion matrix
    plt.figure(figsize=(4, 4))
    plt.imshow(cm, cmap="Blues")
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted"); plt.ylabel("Actual")
    plt.xticks([0, 1], ["normal", "attack"])
    plt.yticks([0, 1], ["normal", "attack"])
    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(cm[i, j]), ha="center", va="center",
                     color="white" if cm[i, j] > cm.max()/2 else "black")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "confusion_matrix.png"), dpi=120)
    plt.close()

    print(f"\nModel disimpan    : {out_dir}/risk_model.joblib")
    print(f"Metrik disimpan   : {out_dir}/ml_metrics.csv")
    print(f"Plot disimpan     : feature_importance.png, confusion_matrix.png")
    return clf, feature_cols


# --------------------------------------------------------------------------------------
# main()
# --------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Phase 2 - ML Risk Prediction (Random Forest)")
    ap.add_argument("--inputs", nargs="+", default=glob.glob("security-*.csv"),
                    help="file security-<scenario>.csv (default: semua security-*.csv)")
    ap.add_argument("--window", type=float, default=1.0,
                    help="ukuran window agregasi (detik, default 1.0)")
    ap.add_argument("--out", default=".", help="direktori output")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    print(f"Phase 2 - ML Risk Prediction")
    print(f"  Window    : {args.window} detik")
    print(f"  Input     : {args.inputs}")
    print(f"  Output dir: {args.out}")

    windows_df = load_datasets(args.inputs, args.window)
    windows_df.to_csv(os.path.join(args.out, "windows.csv"), index=False)
    print(f"Total window: {len(windows_df)} "
          f"(normal={int((windows_df.is_attack==0).sum())}, "
          f"attack={int((windows_df.is_attack==1).sum())})")
    train_and_evaluate(windows_df, args.out, args.seed)


if __name__ == "__main__":
    main()
