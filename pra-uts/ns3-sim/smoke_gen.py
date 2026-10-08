#!/usr/bin/env python3
"""Generator data sintetik untuk smoke test pipeline Phase 2-5.
Menghasilkan security-<scenario>.csv dengan skema yang sama dengan NS-3."""
import os, numpy as np, pandas as pd

os.makedirs("smoke", exist_ok=True)
rng = np.random.default_rng(42)
SENDER = 0

def gen(scenario, n=2000):
    rows = []
    t = 0.0
    for i in range(n):
        rx = int(rng.integers(1, 5))
        if scenario == "normal":
            src_node, claimed, dup, spoof = SENDER, SENDER, 0, 0
            delay = rng.normal(2.0, 0.5)
        elif scenario == "flooding":
            src_node = int(rng.choice([SENDER, 5], p=[0.3, 0.7]))
            claimed = src_node; dup = 0; spoof = 0
            delay = rng.normal(5.0, 2.0)
        elif scenario == "replay":
            src_node = int(rng.choice([SENDER, 5], p=[0.5, 0.5]))
            claimed = SENDER; dup = 1 if src_node == 5 else 0; spoof = 0
            delay = rng.normal(8.0, 3.0)
        else:  # spoofing
            src_node = int(rng.choice([SENDER, 5], p=[0.5, 0.5]))
            claimed = SENDER if src_node == 5 else SENDER  # klaim sebagai sender
            spoof = 1 if src_node == 5 else 0; dup = 0
            delay = rng.normal(4.0, 1.5)
        unauth = 1 if src_node != SENDER else 0
        rows.append({
            "time": t, "rx_node": rx, "seq": i,
            "claimed_src": claimed,
            "actual_src_ip": f"10.1.1.{src_node+1}",
            "actual_src_node": src_node,
            "payload_size": int(rng.choice([400, 800, 1200])),
            "delay_ms": max(0.1, delay),
            "is_duplicate": dup, "is_spoof": spoof,
            "is_unauthorized": unauth,
        })
        t += 0.01
    return pd.DataFrame(rows)

for sc in ["normal", "flooding", "replay", "spoofing"]:
    df = gen(sc)
    out = f"smoke/security-{sc}.csv"
    df.to_csv(out, index=False)
    print(f"{out}: {len(df)} baris")
print("Done. Jalankan pipeline di direktori smoke/")
