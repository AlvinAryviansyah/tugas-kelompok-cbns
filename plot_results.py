#!/usr/bin/env python3
"""
plot_results.py

Membaca CSV hasil run-experiments.sh dan membuat tiga grafik perbandingan
AI vs Static routing, menyerupai Fig 2, Fig 3, dan Fig 4 di paper:

    fig2-throughput.png   Throughput Comparison: AI vs Static Routing
    fig3-latency.png      Latency Comparison: AI vs Static Routing
    fig4-packet-loss.png  Packet Loss Comparison: AI vs Static Routing

Pemakaian:
    python3 plot_results.py dc-routing-results.csv

Kebutuhan:
    pip install matplotlib
"""

import csv
import sys
from collections import defaultdict

import matplotlib

# Backend non-interaktif supaya tetap jalan di server tanpa display (SSH/WSL).
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (harus setelah matplotlib.use)

# Urutan level beban mengikuti paper: low -> medium -> high.
TRAFFIC_ORDER = ["low", "medium", "high"]
TRAFFIC_LABEL = {"low": "Low Traffic", "medium": "Medium Traffic", "high": "High Traffic"}

# Satu entri per gambar: (nama kolom CSV, judul, label sumbu Y, nama file)
CHARTS = [
    ("throughput_mbps", "Throughput Comparison: AI vs Static Routing",
     "Throughput (Mbps)", "fig2-throughput.png"),
    ("latency_ms", "Latency Comparison: AI vs Static Routing",
     "Average latency (ms)", "fig3-latency.png"),
    ("loss_percent", "Packet Loss Comparison: AI vs Static Routing",
     "Packet loss (%)", "fig4-packet-loss.png"),
]


def load(path):
    """Baca CSV menjadi struktur data[mode][traffic] = baris."""
    data = defaultdict(dict)
    # utf-8-sig membuang BOM kalau CSV-nya pernah dibuka dan disimpan ulang
    # lewat Excel; tanpa ini nama kolom pertama menjadi "\ufeffmode".
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            data[row["mode"]][row["traffic"]] = row
    return data


def value(data, mode, traffic, column):
    """Ambil satu angka; kembalikan 0 kalau kombinasi itu tidak ada di CSV."""
    row = data.get(mode, {}).get(traffic)
    return float(row[column]) if row else 0.0


def bar_chart(data, column, title, ylabel, filename):
    """Gambar satu grafik batang berpasangan: static di kiri, AI di kanan."""
    static_vals = [value(data, "static", t, column) for t in TRAFFIC_ORDER]
    ai_vals = [value(data, "ai", t, column) for t in TRAFFIC_ORDER]

    x = range(len(TRAFFIC_ORDER))
    width = 0.35

    fig, ax = plt.subplots(figsize=(7, 4.5))
    bars_static = ax.bar([i - width / 2 for i in x], static_vals, width,
                         label="Static Routing", color="#c0504d")
    bars_ai = ax.bar([i + width / 2 for i in x], ai_vals, width,
                     label="AI Adaptive Routing", color="#4f81bd")

    # Angka di atas tiap batang supaya grafik bisa dibaca tanpa melihat CSV.
    for bars in (bars_static, bars_ai):
        ax.bar_label(bars, fmt="%.2f", fontsize=8, padding=2)

    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(list(x))
    ax.set_xticklabels([TRAFFIC_LABEL[t] for t in TRAFFIC_ORDER])
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)
    ax.legend()
    fig.tight_layout()
    fig.savefig(filename, dpi=150)
    plt.close(fig)
    print(f"  tersimpan: {filename}")


def print_table(data):
    """Tabel ringkas di terminal, berguna untuk ditempel ke laporan."""
    header = f"{'Mode':<8}{'Traffic':<9}{'Thr(Mbps)':>11}{'Lat(ms)':>10}{'Loss(%)':>10}{'Spine0(%)':>11}"
    print("\n" + header)
    print("-" * len(header))
    for mode in ("static", "ai"):
        for traffic in TRAFFIC_ORDER:
            row = data.get(mode, {}).get(traffic)
            if not row:
                continue
            print(f"{mode:<8}{traffic:<9}"
                  f"{float(row['throughput_mbps']):>11.2f}"
                  f"{float(row['latency_ms']):>10.3f}"
                  f"{float(row['loss_percent']):>10.2f}"
                  f"{float(row['spine0_share']):>11.1f}")
    print()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "dc-routing-results.csv"
    data = load(path)

    if not data:
        print(f"CSV {path} kosong atau tidak terbaca.", file=sys.stderr)
        return 1

    print_table(data)
    print("Membuat grafik:")
    for column, title, ylabel, filename in CHARTS:
        bar_chart(data, column, title, ylabel, filename)
    return 0


if __name__ == "__main__":
    sys.exit(main())
