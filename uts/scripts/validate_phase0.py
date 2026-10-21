#!/usr/bin/env python3
"""Cek dataset Fase 0.

Tiap run dicetak PASS atau FAIL per kriteria, lalu ada ringkasan.
Keluar dengan kode 1 jika ada yang gagal, supaya skrip shell berhenti.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


RECEIVERS = (1, 2, 3, 4)


def discover_runs(out_dir):
    runs = []
    for run_dir in sorted(path for path in out_dir.iterdir() if path.is_dir()):
        meta_path = run_dir / "meta.json"
        tx_path = run_dir / "packets_tx.csv"
        rx_path = run_dir / "packets_rx.csv"
        if not (meta_path.is_file() and tx_path.is_file() and rx_path.is_file()):
            continue
        with meta_path.open(encoding="utf-8") as handle:
            meta = json.load(handle)
        runs.append(
            {
                "dir": run_dir,
                "meta": meta,
                "tx": pd.read_csv(tx_path),
                "rx": pd.read_csv(rx_path),
            }
        )
    return runs


def report(run_id, name, ok, detail, failures):
    status = "PASS" if ok else "FAIL"
    print(f"[{run_id}] {name} {status} {detail}".rstrip())
    if not ok:
        failures.append(f"{run_id} {name}: {detail}")


def check_run(run, windows, failures):
    meta = run["meta"]
    run_id = meta["run_id"]
    rx = run["rx"]
    run_windows = windows[windows["run_id"] == run_id]

    present = set(int(node) for node in rx["node_id"].unique()) if len(rx) else set()
    missing = [node for node in RECEIVERS if node not in present]
    extra = sorted(node for node in present if node not in RECEIVERS)
    receivers_ok = not missing and not extra and len(rx) > 0
    detail = "penerima 1-4 ada, node lain tidak menulis"
    if missing:
        detail = f"penerima yang hilang: {missing}"
    elif extra:
        detail = f"node yang tidak seharusnya menerima: {extra}"
    report(run_id, "receivers", receivers_ok, detail, failures)

    pdr = run_windows["pdr"].to_numpy(dtype=float)
    pdr = pdr[~np.isnan(pdr)]
    if len(pdr) == 0:
        mean_pdr = float("nan")
        pdr_ok = False
    else:
        mean_pdr = float(np.mean(pdr))
        pdr_ok = mean_pdr >= 0.999
    report(run_id, "mean_pdr", pdr_ok, f"mean={mean_pdr:.6f} batas=0.999", failures)

    duration = float(meta["sim_time_s"]) - float(meta["app_start_s"])
    rate = float(meta["rate_mbps"])
    per_node = []
    for node_id in RECEIVERS:
        uniq = rx[(rx["node_id"] == node_id) & (rx["is_duplicate"] == 0)]
        if duration <= 0:
            per_node.append(float("nan"))
        else:
            per_node.append(float(uniq["size_bytes"].sum()) * 8.0 / duration / 1e6)
    mean_thr = float(np.nanmean(per_node)) if per_node else float("nan")
    if rate <= 0 or math_isnan(mean_thr):
        thr_ok = False
        rel = float("nan")
    else:
        rel = abs(mean_thr - rate) / rate
        thr_ok = rel <= 0.03
    report(
        run_id,
        "throughput",
        thr_ok,
        f"mean_unique={mean_thr:.4f} Mbps ditawarkan={rate:.4f} selisih={rel:.4%}",
        failures,
    )

    if len(run_windows) == 0:
        clean_ok = False
        clean_detail = "tidak ada jendela"
    else:
        dup = int(run_windows["duplicate_count"].sum())
        auth = int(run_windows["auth_fail_count"].sum())
        clean_ok = dup == 0 and auth == 0
        clean_detail = f"duplicate_count={dup} auth_fail_count={auth}"
    report(run_id, "no_dup_no_auth_fail", clean_ok, clean_detail, failures)

    seq_ok = True
    seq_detail = "seq naik ketat di tiap penerima"
    if len(rx) == 0:
        seq_ok = False
        seq_detail = "tidak ada paket diterima"
    else:
        for node_id, group in rx.groupby("node_id"):
            ordered = group.sort_values(["rx_time_s", "seq"])
            seq = ordered["seq"].to_numpy()
            if len(seq) >= 2 and np.any(np.diff(seq.astype(np.int64)) <= 0):
                seq_ok = False
                seq_detail = f"seq tidak naik ketat di node {int(node_id)}"
                break
    report(run_id, "seq_increasing", seq_ok, seq_detail, failures)

    if len(run_windows) == 0:
        delay_ok = False
        delay_detail = "tidak ada jendela"
    else:
        means = run_windows["delay_mean_s"].to_numpy(dtype=float)
        p95 = run_windows["delay_p95_s"].to_numpy(dtype=float)
        finite_means = means[~np.isnan(means)]
        finite_p95 = p95[~np.isnan(p95)]
        too_fast = len(finite_means) == 0 or np.any(finite_means <= 0)
        too_slow = len(finite_means) and np.any(finite_means >= 0.1)
        reaches_seconds = len(finite_p95) and np.any(finite_p95 >= 1.0)
        delay_ok = not too_fast and not too_slow and not reaches_seconds
        delay_detail = (
            f"mean_min={np.nanmin(means):.6e} mean_max={np.nanmax(means):.6e} "
            f"p95_max={np.nanmax(p95):.6e}"
        )
    report(run_id, "delay_plausible", delay_ok, delay_detail, failures)


def math_isnan(value):
    return isinstance(value, float) and np.isnan(value)


def check_seeds(runs, failures):
    """Seed berbeda pada payload dan rate yang sama harus menghasilkan waktu kirim berbeda."""
    groups = {}
    for run in runs:
        meta = run["meta"]
        if str(meta.get("tag")) != "normal":
            continue
        key = (int(meta["payload"]), float(meta["rate_mbps"]))
        signature = tuple(run["tx"]["tx_time_s"].astype(str).tolist())
        groups.setdefault(key, {})[int(meta["seed"])] = signature

    if not groups:
        print("[semua] seeds FAIL tidak ada run tag normal")
        failures.append("seeds: tidak ada run")
        return

    for key, traces in sorted(groups.items()):
        payload, rate = key
        label = f"p{payload}_r{rate:g}"
        if len(traces) < 2:
            print(f"[{label}] seeds FAIL butuh minimal dua seed, ada {len(traces)}")
            failures.append(f"{label} seeds kurang")
            continue
        unique = {value for value in traces.values()}
        ok = len(unique) == len(traces)
        status = "PASS" if ok else "FAIL"
        print(f"[{label}] seeds {status} jumlah_seed={len(traces)} jejak_unik={len(unique)}")
        if not ok:
            failures.append(f"{label} seed menghasilkan jejak tx yang sama")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_repro(binary, work_dir, ns3_version, sim_time, failures):
    """Jalankan konfigurasi yang sama dua kali. packets_rx.csv harus identik."""
    work_dir = Path(work_dir)
    parent = work_dir / "out" / "phase0_repro"
    if parent.exists():
        shutil.rmtree(parent)
    hashes = []
    for name in ("a", "b"):
        rel_out = f"out/phase0_repro/{name}"
        (work_dir / rel_out).mkdir(parents=True, exist_ok=True)
        command = [
            str(binary),
            "--payload=800",
            "--rateMbps=5",
            "--seed=1",
            "--run=1",
            f"--simTime={sim_time}",
            "--appStart=2.0",
            "--tag=repro",
            "--anim=0",
            f"--outDir={rel_out}",
            f"--ns3Version={ns3_version}",
        ]
        print("[repro] menjalankan", " ".join(command))
        completed = subprocess.run(command, cwd=str(work_dir), check=False)
        if completed.returncode != 0:
            print(f"[repro] FAIL proses {name} keluar dengan kode {completed.returncode}")
            failures.append("repro proses gagal")
            return
        matches = list((work_dir / rel_out).glob("*/packets_rx.csv"))
        if len(matches) != 1:
            print(f"[repro] FAIL menemukan {len(matches)} packets_rx.csv pada {name}")
            failures.append("repro csv tidak ditemukan")
            return
        hashes.append(sha256_file(matches[0]))

    ok = hashes[0] == hashes[1]
    status = "PASS" if ok else "FAIL"
    print(f"[repro] hash {status} a={hashes[0][:12]} b={hashes[1][:12]}")
    if not ok:
        failures.append("repro hash packets_rx.csv berbeda")


def save_plot(out_dir, windows):
    preferred = "normal_p800_r5_s1"
    if preferred in set(windows["run_id"]):
        sample_id = preferred
    else:
        sample_id = sorted(windows["run_id"].unique())[0]
    sample = windows[windows["run_id"] == sample_id]
    figure, axes = plt.subplots(2, 1, sharex=True, figsize=(8, 6))
    for node_id, group in sample.groupby("node_id"):
        group = group.sort_values("window_start_s")
        axes[0].plot(group["window_start_s"], group["throughput_mbps"], label=f"node {int(node_id)}")
        axes[1].plot(group["window_start_s"], group["delay_mean_s"], label=f"node {int(node_id)}")
    axes[0].set_ylabel("throughput (Mbps)")
    axes[1].set_ylabel("delay rata-rata (detik)")
    axes[1].set_xlabel("awal jendela (detik)")
    axes[0].set_title(sample_id)
    axes[0].legend(loc="best")
    axes[1].legend(loc="best")
    figure.tight_layout()
    png = Path(out_dir) / "sample_throughput_delay.png"
    figure.savefig(png)
    plt.close(figure)
    print(f"[plot] PASS {png}")


def main():
    parser = argparse.ArgumentParser(description="Validasi dataset Fase 0.")
    parser.add_argument("--outDir", default="out/phase0")
    parser.add_argument("--windows", default="", help="Path windows.csv. Kosong = <outDir>/windows.csv")
    parser.add_argument("--phase0-bin", default="", help="Binary NS-3 untuk uji ulang reproducibility.")
    parser.add_argument("--work-dir", default=".", help="Folder kerja saat menjalankan binary.")
    parser.add_argument("--ns3-version", default="unrecorded")
    parser.add_argument("--repro-sim-time", type=float, default=10.0)
    parser.add_argument("--skip-repro", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.outDir)
    windows_path = Path(args.windows) if args.windows else out_dir / "windows.csv"
    if not windows_path.is_file():
        print(f"FAIL tidak menemukan {windows_path}")
        return 1

    windows = pd.read_csv(windows_path)
    runs = discover_runs(out_dir)
    if not runs:
        print(f"FAIL tidak ada run di {out_dir}")
        return 1

    failures = []
    for run in runs:
        check_run(run, windows, failures)
    check_seeds(runs, failures)

    if args.skip_repro:
        print("[repro] FAIL diminta dilewati")
        failures.append("repro dilewati")
    elif not args.phase0_bin:
        print("[repro] FAIL --phase0-bin kosong, jadi uji dua kali tidak dijalankan")
        failures.append("repro tidak dijalankan")
    else:
        check_repro(
            args.phase0_bin,
            args.work_dir,
            args.ns3_version,
            args.repro_sim_time,
            failures,
        )

    try:
        save_plot(out_dir, windows)
    except Exception as exc:  # gambar gagal tetap membuat validasi gagal
        print(f"[plot] FAIL {exc}")
        failures.append(f"plot: {exc}")

    print("")
    print(f"RINGKASAN run={len(runs)} gagal={len(failures)}")
    for item in failures:
        print(f"  - {item}")
    if failures:
        print("HASIL FAIL")
        return 1
    print("HASIL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
