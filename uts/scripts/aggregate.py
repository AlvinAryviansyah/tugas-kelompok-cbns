#!/usr/bin/env python3
"""Gabungkan CSV tiap run menjadi windows.csv.

Satu baris = satu penerima, pada satu jendela waktu.
Jendela sebelum appStart dibuang. Jendela terakhir yang terpotong juga dibuang.
"""

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd


COLUMNS = [
    "run_id",
    "tag",
    "payload",
    "rate_mbps",
    "seed",
    "node_id",
    "window_start_s",
    "tx_packets",
    "rx_packets",
    "pkt_rate_pps",
    "throughput_mbps",
    "pdr",
    "plr",
    "delay_mean_s",
    "delay_p95_s",
    "delay_max_s",
    "jitter_s",
    "duplicate_count",
    "duplicate_ratio",
    "auth_fail_count",
    "label",
]


def window_starts(app_start, sim_time, width):
    """Mulai di appStart. Jendela [mulai, mulai+lebar) harus muat utuh sebelum simTime."""
    starts = []
    start = float(app_start)
    while start + width <= float(sim_time) + 1e-9:
        starts.append(start)
        start += width
    return starts


def load_run(run_dir):
    meta_path = run_dir / "meta.json"
    tx_path = run_dir / "packets_tx.csv"
    rx_path = run_dir / "packets_rx.csv"
    if not (meta_path.is_file() and tx_path.is_file() and rx_path.is_file()):
        return None
    with meta_path.open(encoding="utf-8") as handle:
        meta = json.load(handle)
    tx = pd.read_csv(tx_path)
    rx = pd.read_csv(rx_path)
    return meta, tx, rx


def summarize_window(tx, node_rx, start, width):
    end = start + width
    tx_packets = int(((tx["tx_time_s"] >= start) & (tx["tx_time_s"] < end)).sum())

    in_window = node_rx[(node_rx["rx_time_s"] >= start) & (node_rx["rx_time_s"] < end)]
    in_window = in_window.sort_values(["rx_time_s", "seq"])

    duplicate_count = int((in_window["is_duplicate"] == 1).sum())
    rx_packets = int((in_window["is_duplicate"] == 0).sum())
    auth_fail_count = int((in_window["auth_ok"] == 0).sum())
    # Throughput memakai semua byte yang sampai, termasuk duplikat.
    # Satuan Mbps = bit / detik / 1e6.
    byte_count = float(in_window["size_bytes"].sum()) if len(in_window) else 0.0
    throughput_mbps = (byte_count * 8.0) / width / 1e6
    pkt_rate_pps = (rx_packets + duplicate_count) / width

    if tx_packets == 0:
        pdr = math.nan
        plr = math.nan
    else:
        pdr = rx_packets / tx_packets
        plr = 1.0 - pdr

    received = rx_packets + duplicate_count
    if received == 0:
        duplicate_ratio = 0.0
    else:
        duplicate_ratio = duplicate_count / received

    if len(in_window) == 0:
        delay_mean = math.nan
        delay_p95 = math.nan
        delay_max = math.nan
        jitter = math.nan
    else:
        delays = in_window["delay_s"].to_numpy(dtype=float)
        delay_mean = float(np.mean(delays))
        delay_p95 = float(np.quantile(delays, 0.95))
        delay_max = float(np.max(delays))
        if len(delays) >= 2:
            jitter = float(np.mean(np.abs(np.diff(delays))))
        else:
            # Kurang dari dua paket: tidak ada jeda antar delay.
            jitter = 0.0

    return {
        "tx_packets": tx_packets,
        "rx_packets": rx_packets,
        "pkt_rate_pps": pkt_rate_pps,
        "throughput_mbps": throughput_mbps,
        "pdr": pdr,
        "plr": plr,
        "delay_mean_s": delay_mean,
        "delay_p95_s": delay_p95,
        "delay_max_s": delay_max,
        "jitter_s": jitter,
        "duplicate_count": duplicate_count,
        "duplicate_ratio": duplicate_ratio,
        "auth_fail_count": auth_fail_count,
    }


def aggregate(out_dir, width):
    rows = []
    run_dirs = sorted(path for path in out_dir.iterdir() if path.is_dir())
    if not run_dirs:
        raise SystemExit(f"Tidak ada folder run di {out_dir}")

    for run_dir in run_dirs:
        loaded = load_run(run_dir)
        if loaded is None:
            continue
        meta, tx, rx = loaded
        tag = str(meta["tag"])
        label = 0 if tag == "normal" else 1
        starts = window_starts(meta["app_start_s"], meta["sim_time_s"], width)
        for node_id in (1, 2, 3, 4):
            node_rx = rx[rx["node_id"] == node_id]
            for start in starts:
                row = summarize_window(tx, node_rx, start, width)
                row.update(
                    {
                        "run_id": meta["run_id"],
                        "tag": tag,
                        "payload": int(meta["payload"]),
                        "rate_mbps": float(meta["rate_mbps"]),
                        "seed": int(meta["seed"]),
                        "node_id": node_id,
                        "window_start_s": start,
                        "label": label,
                    }
                )
                rows.append(row)

    if not rows:
        raise SystemExit(f"Tidak ada run lengkap (meta + csv) di {out_dir}")

    frame = pd.DataFrame(rows, columns=COLUMNS)
    destination = out_dir / "windows.csv"
    frame.to_csv(destination, index=False)
    print(f"menulis {destination} ({len(frame)} baris, {frame['run_id'].nunique()} run)")
    return destination


def main():
    parser = argparse.ArgumentParser(description="Agregasi jejak Fase 0 menjadi jendela waktu.")
    parser.add_argument("--outDir", default="out/phase0", help="Folder yang berisi subfolder run.")
    parser.add_argument("--window", type=float, default=1.0, help="Lebar jendela, detik.")
    args = parser.parse_args()
    if args.window <= 0:
        raise SystemExit("--window harus lebih dari 0")
    aggregate(Path(args.outDir), args.window)


if __name__ == "__main__":
    main()
