# Adaptive Security Simulation - NS-3 + NetAnim

Simulasi NS-3 untuk penelitian **"AI-Driven Adaptive Routing based on Performance &
Security Traffic Framework for Dynamic Network Traffic using NS-3"**.

Script `adaptive-security-sim.cc` mengimplementasikan **Phase 0 (Validation)** dan
**Phase 1 (Attack Simulation)** dari Experimental Design, sekaligus menghasilkan
dataset trace yang akan dipakai pada Phase 2-5 (ML / RL / evaluasi).

## Topologi (sesuai laporan, Tabel 2.1)

```
                +-----------------------------+
                |        CSMA LAN 100 Mbps    |
                +-----------------------------+
   Node 0  ----+  Sender   (hijau)            |
   Node 1  ----+  RX1      (biru)            |
   Node 2  ----+  RX2      (biru)            |
   Node 3  ----+  RX3      (biru)            |
   Node 4  ----+  RX4      (biru)            |
   Node 5  ----+  Attacker (merah)           |
                +-----------------------------+
```

- Transport: **UDP port 9000** (broadcast `10.1.1.255`)
- Payload: `400 / 800 / 1200` byte (parameter `--payload`)
- Skenario: `normal | flooding | replay | spoofing` (parameter `--scenario`)

## Prasyarat (Ubuntu)

```bash
# Build tools & dependensi NS-3
sudo apt update
sudo apt install -y build-essential cmake ninja-build git python3 python3-dev \
    qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libxml2-dev libsqlite3-dev
```

## Install NS-3

```bash
# Clone ns-3-dev (versi stabil, mis. ns-3.40+)
git clone https://gitlab.com/nsnam/ns-3-dev.git
cd ns-3-dev

# Konfigurasi (dengan NetAnim)
./ns3 configure --enable-examples --enable-tests --with-netanim
```

> Jika `--with-netanim` tidak dikenali, build NetAnim secara terpisah (lihat bawah)
> dan abaikan flag tersebut — `AnimationInterface` tetap tersedia selama modul
> `netanim` ter-include di script.

## Build NetAnim (jika belum ter-build)

```bash
# Dari luar direktori ns-3-dev
cd ..
git clone https://gitlab.com/nsnam/netanim.git
cd netanim
make clean
qmake NetAnim.pro   # atau: qmake6 NetAnim.pro
make -j$(nproc)
# Hasil: executable ./NetAnim
```

## Pasang script simulasi

```bash
# Salin file simulasi ke direktori scratch ns-3
cp /path/ke/adaptive-security-sim.cc  ns-3-dev/scratch/adaptive-security-sim.cc
```

## Menjalankan simulasi

```bash
cd ns-3-dev

# Skenario normal (baseline)
./ns3 run "scratch/adaptive-security-sim --scenario=normal --payload=800"

# Skenario flooding
./ns3 run "scratch/adaptive-security-sim --scenario=flooding --payload=800 --attackRate=20"

# Skenario replay
./ns3 run "scratch/adaptive-security-sim --scenario=replay --payload=800 --attackRate=10"

# Skenario spoofing
./ns3 run "scratch/adaptive-security-sim --scenario=spoofing --payload=800 --attackRate=10"
```

## Parameter baris perintah

| Parameter       | Default | Keterangan                                  |
|-----------------|---------|---------------------------------------------|
| `--scenario`   | normal  | `normal \| flooding \| replay \| spoofing` |
| `--payload`     | 800     | Ukuran payload (byte): 400/800/1200         |
| `--legitRate`   | 5.0     | Rate traffic legitimate (Mbps)             |
| `--attackRate`  | 20.0    | Rate traffic serangan (Mbps)               |
| `--simTime`     | 20.0    | Durasi simulasi (detik)                    |
| `--attackStart` | 2.0     | Waktu mulai serangan (detik)               |
| `--attackStop`  | 0.0     | Waktu berhenti serangan, 0=sampai akhir     |
| `--seed`        | 1       | Seed RNG (untuk variasi antar run)        |
| `--enableAnim`  | 1       | Hasilkan file XML NetAnim (1/0)            |
| `--verbose`     | 1       | Cetak log progres (1/0)                    |
| `--outPrefix`   | adaptive-security | Prefix nama file output XML NetAnim |

## File output

Setiap run menghasilkan (di direktori kerja `ns-3-dev/`):

1. **`adaptive-security-<scenario>-anim.xml`** — buka di NetAnim untuk visualisasi.
2. **`security-<scenario>.csv`** — fitur per-paket di sisi receiver:
   `time, rx_node, seq, claimed_src, actual_src_ip, actual_src_node,
   payload_size, delay_ms, is_duplicate, is_spoof, is_unauthorized`
3. **`flowmon-<scenario>.csv`** & **`.xml`** — statistik FlowMonitor per flow.
4. **`summary-<scenario>.csv`** — ringkasan per receiver:
   PDR, throughput, mean delay, duplicate ratio, spoof count, unauthorized count,
   completion time.

> **Catatan FlowMonitor & broadcast:** pada traffic UDP broadcast, FlowMonitor
> hanya menghitung reception *pertama* per paket, jadi statistik PDR-nya tidak
> akurat untuk satu-ke-banyak. Karena itu perhitungan PDR/throughput utama
> diambil dari `ReceiverApp` (lihat `summary-<scenario>.csv` dan
> `security-<scenario>.csv`), bukan dari FlowMonitor.

## Visualisasi di NetAnim

```bash
cd ../netanim
./NetAnim
```

Klik **File → Load XML** lalu pilih `adaptive-security-<scenario>-anim.xml`
(di dalam `ns-3-dev/`). Anda akan melihat:

- Node hijau  = **SENDER** (node 0)
- Node biru   = **RX1..RX4** (node 1-4)
- Node merah = **ATTACKER** (node 5)
- Animasi paket mengalir sepanjang bus CSMA.

## Batch run (menghasilkan dataset lengkap untuk ML)

```bash
# Contoh: loop semua skenario x payload x seed
for sc in normal flooding replay spoofing; do
  for pl in 400 800 1200; do
    for seed in 1 2 3; do
      ./ns3 run "scratch/adaptive-security-sim \
        --scenario=$sc --payload=$pl --seed=$seed \
        --enableAnim=0 --outPrefix=run_${sc}_p${pl}_s${seed}"
    done
  done
done
```

> Untuk batch dataset, set `--enableAnim=0` agar XML NetAnim tidak menulis file
> besar. Gunakan `--enableAnim=1` hanya saat ingin visualisasi.

## Pemetaan ke Experimental Design

| Phase | Fokus                      | Status di script ini                          |
|-------|----------------------------|-----------------------------------------------|
| 0     | Validation topology        | ✅ Topologi + traffic normal                  |
| 1     | Attack simulation          | ✅ Flooding / Replay / Spoofing               |
| 2     | ML Risk (Random Forest)    | ✅ `phase2_ml_risk.py`                         |
| 3     | Adaptive Policy            | ✅ `phase3_adaptive_policy.py`                |
| 4     | RL Decision (Q-learning)   | ✅ `phase4_rl_decision.py`                    |
| 5     | Comparative evaluation     | ✅ `phase5_evaluate.py`                       |

---

# Phase 2-5: Pipeline ML / RL / Evaluasi (Python)

Pipeline post-simulation yang mengonsumsi CSV dari Phase 1. Semua script Python
berada di direktori `ns3-sim/` dan dijalankan **setelah** simulasi NS-3 selesai.

## Alur data

```
NS-3 (Phase 1)                Phase 2                Phase 3            Phase 4          Phase 5
security-*.csv  ───────────►  windows.csv  ──────►  adaptive_results  ──────►  rl_policy.json  ──────►  comparison.csv
                               risk_model.joblib     .csv                                  comparison_charts.png
                               ml_metrics.csv        action_distribution.csv
```

## Prasyarat Python

```bash
cd ns3-sim
pip install -r requirements.txt
```

## Step-by-step

### Phase 2 — ML Risk Prediction (Random Forest)

```bash
# Pastikan semua security-*.csv sudah ada dari Phase 1
python3 phase2_ml_risk.py \
    --inputs security-normal.csv security-flooding.csv security-replay.csv security-spoofing.csv \
    --window 1.0
```

Output:
- `windows.csv` — fitur + label per window (input Phase 3-5)
- `risk_model.joblib` — model RF tersimpan
- `ml_metrics.csv` — accuracy, precision, recall, F1, ROC-AUC, CV-F1
- `feature_importance.png`, `confusion_matrix.png`

### Phase 3 — Adaptive Policy (Risk threshold → Action)

```bash
python3 phase3_adaptive_policy.py \
    --model risk_model.joblib \
    --data windows.csv \
    --trace security-normal.csv security-flooding.csv security-replay.csv security-spoofing.csv
```

Kebijakan threshold:
- `risk < 0.3` → **ALLOW**
- `0.3 ≤ risk < 0.7` → **RATE_LIMIT** (drop 50% paket attacker)
- `risk ≥ 0.7` → **ISOLATE** (drop semua paket attacker)

Output: `adaptive_results.csv`, `action_distribution.csv`, `adaptive_summary.csv`

### Phase 4 — RL Decision (Q-learning)

```bash
python3 phase4_rl_decision.py --data adaptive_results.csv --episodes 500
```

State (diskret): `[risk_score, pkt_rate, unauth_ratio, mean_delay_ms]`
Actions: `ALLOW / RATE_LIMIT / RE_AUTH / ISOLATE`
Reward: `1.5 × security_gain − 1.0 × performance_cost`

Output: `rl_policy.json` (Q-table + policy), `rl_rewards.csv` (convergence),
`rl_evaluation.csv`

### Phase 5 — Comparative Evaluation

```bash
python3 phase5_evaluate.py \
    --trace security-normal.csv security-flooding.csv security-replay.csv security-spoofing.csv \
    --windows adaptive_results.csv \
    --rl-policy rl_policy.json
```

Membandingkan 4 metode (sesuai Experimental Matrix Tabel 4.1):
1. **Baseline** — tanpa mitigasi
2. **Static** — rule-based statis
3. **ML_Adaptive** — Phase 3 (risk threshold)
4. **ML+RL** — Phase 4 (Q-learning policy)

Metrik (sesuai Tabel 3.1 laporan):
- Network: throughput, PDR, PLR, mean delay, completion time
- Security: detection rate, false positive rate, unauthorized acceptance

Output: `comparison.csv`, `comparison_charts.png`

## Run semua sekaligus (contoh)

```bash
# 1. Jalankan NS-3 untuk semua skenario (di direktori ns-3-dev)
for sc in normal flooding replay spoofing; do
  ./ns3 run "scratch/adaptive-security-sim --scenario=$sc --payload=800 --enableAnim=0"
done

# 2. Pindahkan CSV ke direktori ns3-sim (atau jalankan di sana)
# 3. Pipeline ML/RL/Evaluasi
cd ../ns3-sim
python3 phase2_ml_risk.py
python3 phase3_adaptive_policy.py --trace security-*.csv
python3 phase4_rl_decision.py
python3 phase5_evaluate.py --trace security-*.csv
```

## Catatan RL & NS3-Gym

Phase 4 di sini menggunakan **offline Q-learning** pada window dataset — pendekatan
yang portabel dan tidak butuh setup NS3-Gym. Pada penelitian lanjutan, agent yang
sama dapat dijalankan **online** via [NS3-Gym](https://github.com/ns-3/ns3-gym) yang
menghubungkan environment NS-3 dengan OpenAI Gym, sehingga state/action/reward
dipertukarkan langsung selama simulasi berjalan (sesuai arah future work di laporan).

## Catatan teknis

- **Spoofing** dimodelkan di *application-identity layer* (sesuai definisi
  "claimed identity" pada laporan), bukan IP-header spoofing L3, sehingga script
  tetap self-contained dan portabel tanpa raw socket.
- **Replay**: attacker menyadap broadcast LAN (bind port 9000) sejak awal
  simulasi, menyimpan ≤256 paket legit, lalu mengirim ulang saat `--attackStart`.
- Kolom `actual_src_node` di CSV adalah **ground-truth** (dari IP sumber) untuk
  keperluan pelabelan supervised learning. Pada detektor nyata, kolom ini tidak
  tersedia dan harus diprediksi dari fitur lain.

## Referensi (dari laporan)

- [1] Mahajan et al., "Adaptive Routing in Wireless Mesh Networks Using Hybrid
      Reinforcement Learning Algorithm," IEEE Access, 2022.
- [2] Bel et al., "Co-Simulation Framework for Network Attack Generation and
      Monitoring," IEEE Access, 2024.
- [3] Zhang et al., "Predictive-Proactive Congestion Avoidance for Cross-Domain
      Data Center Interconnect," IEEE TNSE, 2026.
