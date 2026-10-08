# Simulasi ns-3: AI-Optimized Adaptive Routing untuk Data Center

Implementasi ns-3 dari paper **"AI-Optimized Adaptive Routing for High-Performance Data Centers:
A Predictive Framework for Dynamic Network Optimization"** (V. Hiremath, IEEE AIC 2025).

Simulasi membandingkan dua algoritma routing pada topologi data center leaf-spine:

| Mode | Perilaku |
|---|---|
| `static` | Semua jalur remote dipaku ke Spine0 (shortest-path dengan tie-break tetap). Spine1 menganggur. |
| `ai` | Controller memprediksi kongesti tiap 100 ms, lalu memindahkan tujuan ke spine yang paling lengang. |

Metrik yang diukur sama dengan Fig 2, 3, dan 4 di paper: **throughput**, **latency**, dan **packet loss**,
masing-masing pada beban **low / medium / high**.

## Isi folder

| File | Keterangan |
|---|---|
| `ai-adaptive-routing-dc.cc` | Program simulasi utama (ns-3, C++) |
| `run-experiments.sh` | Menjalankan 6 run pengukuran + 2 run animasi |
| `plot_results.py` | Membuat grafik Fig 2/3/4 dari CSV hasil run |

## Topologi

```
        Spine0            Spine1          <- 2 spine
       /  |  |  \        /  |  |  \
   Leaf0 Leaf1 Leaf2 Leaf3 ...            <- 4 leaf, tiap leaf ke SEMUA spine
     |     |     |     |
   2 host per leaf                        <- 8 host total
```

- LAN host-leaf: CSMA 1 Gbps (sengaja lebar, supaya bukan ini yang jadi bottleneck)
- Uplink leaf-spine: point-to-point **50 Mbps**, buffer FIFO 100 paket -> **ini titik kongesti**
- Trafik: UDP CBR, host `h` mengirim ke host `(h+2) mod 8` sehingga semua flow harus melewati spine

Karena tiap leaf punya 2 host pengirim, beban agregat per leaf adalah 2x laju per flow:

| Level | Per flow | Agregat per leaf | Static (1 uplink 50 Mbps) | AI (2 uplink) |
|---|---|---|---|---|
| low | 5 Mbps | 10 Mbps | 20% utilisasi | 10% + 10% |
| medium | 20 Mbps | 40 Mbps | 80% utilisasi, antrian menumpuk | 40% + 40% |
| high | 40 Mbps | 80 Mbps | **kelebihan beban, drop berat** | 80% + 80% kapasitas terpakai, tanpa drop |

Inilah sebabnya hasilnya mengikuti pola di paper: pada beban rendah kedua mode mirip,
pada beban tinggi AI routing jauh lebih baik.

## Setup di Ubuntu

### 1. Install dependency

```bash
sudo apt update
sudo apt install -y g++ cmake ninja-build python3 python3-pip git \
                    qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools \
                    libxml2 libxml2-dev
pip3 install matplotlib
```

Paket `qt*` hanya dibutuhkan untuk membangun NetAnim.

### 2. Ambil dan build ns-3

Kalau belum punya ns-3:

```bash
cd ~
git clone https://gitlab.com/nsnam/ns-3-dev.git
cd ns-3-dev
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

> Build pertama memakan waktu cukup lama (bisa 20-40 menit).
> Kalau nanti ingin run lebih cepat, pakai `./ns3 configure -d optimized` lalu `./ns3 build` ulang.

### 3. Copy file simulasi ke ns-3

```bash
cp ai-adaptive-routing-dc.cc  ~/ns-3-dev/scratch/
cp run-experiments.sh         ~/ns-3-dev/
cp plot_results.py            ~/ns-3-dev/
cd ~/ns-3-dev
chmod +x run-experiments.sh
```

File `.cc` **harus** berada di `scratch/` agar otomatis dikenali `./ns3` tanpa mengubah `CMakeLists.txt`.

## Menjalankan simulasi

### Opsi A: satu perintah untuk semua eksperimen

```bash
cd ~/ns-3-dev
./run-experiments.sh
```

Skrip ini menghasilkan:
- `dc-routing-results.csv` - 6 baris hasil (2 mode x 3 level beban)
- `anim-static.xml` dan `anim-ai.xml` - file animasi NetAnim

Lalu buat grafiknya:

```bash
python3 plot_results.py dc-routing-results.csv
```

Output: `fig2-throughput.png`, `fig3-latency.png`, `fig4-packet-loss.png`.

### Opsi B: run manual satu per satu

```bash
# Baseline static routing, beban tinggi
./ns3 run "ai-adaptive-routing-dc --mode=static --traffic=high"

# AI adaptive routing, beban tinggi
./ns3 run "ai-adaptive-routing-dc --mode=ai --traffic=high"

# Lihat keputusan controller secara detail (rute mana dipindah ke spine mana)
./ns3 run "ai-adaptive-routing-dc --mode=ai --traffic=high --verbose=1"
```

### Parameter command line

| Parameter | Default | Keterangan |
|---|---|---|
| `--mode` | `ai` | `static` atau `ai` |
| `--traffic` | `high` | `low`, `medium`, atau `high` |
| `--simTime` | `20` | Durasi simulasi (detik) |
| `--anim` | `0` | `1` untuk menghasilkan XML NetAnim |
| `--animFile` | otomatis | Nama file XML, default `anim-<mode>-<traffic>.xml` |
| `--csv` | `dc-routing-results.csv` | File CSV hasil; kosongkan (`--csv=`) untuk tidak menyimpan |
| `--seed` | `1` | Seed RNG |
| `--verbose` | `0` | `1` untuk menampilkan log keputusan controller |

## Menampilkan di NetAnim

### 1. Build NetAnim (sekali saja)

NetAnim sudah ikut di dalam repo ns-3-dev, tapi harus dibangun sendiri:

```bash
cd ~/ns-3-dev/netanim
make clean
qmake NetAnim.pro
make
```

Kalau `qmake` tidak ditemukan, pilih dulu versi Qt-nya:

```bash
export QT_SELECT=qt5
qmake NetAnim.pro && make
```

### 2. Hasilkan file animasi

```bash
cd ~/ns-3-dev
./ns3 run "ai-adaptive-routing-dc --mode=ai --traffic=medium --simTime=6 --anim=1 --csv="
```

> **Penting soal ukuran file.** Animasi merekam setiap paket, jadi XML-nya membengkak cepat.
> Gunakan `--simTime=6` (bukan 20) dan `--traffic=medium` untuk animasi.
> Dengan `--traffic=high --simTime=20`, XML bisa mencapai beberapa GB.

File XML ditulis di **direktori root ns-3** (tempat `./ns3 run` dijalankan), bukan di `scratch/`.

### 3. Buka di NetAnim

```bash
cd ~/ns-3-dev/netanim
./NetAnim
```

Di jendela NetAnim:
1. Klik ikon folder (**Open an XML trace file**) di kiri atas.
2. Pilih `~/ns-3-dev/anim-ai.xml`.
3. Tekan tombol **Play**. Atur **Sim time slider** / kecepatan playback kalau animasinya terlalu cepat.
4. Kalau node terlihat terlalu kecil atau berdempetan, geser slider **Node size** di toolbar.

### Apa yang harus dilihat di animasi

Node sudah diberi nama (`Spine0`, `Leaf2`, `Host5`) dan **warnanya berubah mengikuti kongesti**
(hijau = lengang, kuning = mulai padat, merah = jenuh). Label di setiap link menampilkan
utilisasi uplink dalam persen, diperbarui tiap 100 ms.

- Pada `anim-static.xml`: **Spine0 memerah** sementara **Spine1 tetap hijau** dan nyaris tanpa paket.
  Ini visualisasi langsung dari masalah yang dikritik paper, yaitu jalur alternatif tidak terpakai.
- Pada `anim-ai.xml`: beberapa detik pertama mirip static (controller masih mengumpulkan data),
  lalu paket mulai mengalir lewat **kedua spine** dan warna keduanya menjadi seimbang.

## Bagaimana bagian "AI" diimplementasikan

Empat layer arsitektur di Section III.A paper dipetakan langsung ke kode:

| Layer di paper | Fungsi di kode | Cara kerja |
|---|---|---|
| 1. Data Collection | `AiRoutingController::CollectMetrics()` | Tiap 100 ms membaca byte terkirim, panjang antrian, dan jumlah drop dari queue disc setiap uplink. Demand per tujuan diukur lewat trace `UnicastForward` di tiap leaf. |
| 2. Traffic Prediction | `class CongestionPredictor` | EWMA untuk meredam noise + slope antar interval untuk ekstrapolasi satu langkah ke depan. Keputusan dibuat atas beban yang **diprediksi**, bukan yang sudah terjadi. |
| 3. Routing Optimization | `AiRoutingController::AssignRoutes()` | Tujuan diurutkan dari demand terbesar, lalu ditempatkan greedy ke uplink dengan biaya prediksi terendah. Rute ditulis ulang via `Ipv4StaticRouting::AddHostRouteTo()`. |
| 4. Feedback & Adjustment | `AiRoutingController::ApplyFeedback()` | Total drop dipakai sebagai reward negatif. Kalau drop naik setelah rute diubah, histeresis dan penalti loss diperbesar (controller jadi konservatif); kalau jaringan bersih, keduanya dikendurkan. |

Beberapa keputusan desain yang perlu dicatat kalau ditanya saat presentasi:

- **Kenapa UDP, bukan TCP?** TCP akan menurunkan laju kirimnya sendiri saat kongesti,
  sehingga packet loss tersembunyi dan tidak terukur. Paper mengukur throughput, latency,
  *dan* packet loss pada beban tetap, jadi beban yang ditawarkan harus konstan.
- **Kenapa tidak pakai `Ipv4GlobalRouting`?** Global routing menghitung rute sendiri,
  sehingga keputusan controller akan ditimpa. Semua rute di sini diisi manual sebagai static route.
- **Kenapa ada histeresis?** Tanpa ambang minimal perbaikan, rute akan bolak-balik setiap
  100 ms (*route flapping*) dan justru memperburuk latency.
- **Kenapa rute per-host (`/32`), bukan per-subnet (`/24`)?** Granularitas per host membuat
  beban bisa dibagi rata ke dua spine. Dengan `/24`, satu keputusan memindahkan semua trafik
  sekaligus dan hasilnya berosilasi, bukan seimbang.

## Membaca output

Setiap run mencetak ringkasan seperti ini:

```
==================== HASIL SIMULASI ====================
  Mode routing      : ai
  Level trafik      : high
  --------------------------------------------------
  Throughput        : ... Mbps
  Latency rata-rata : ... ms
  Packet loss       : ... %
  --------------------------------------------------
  Paket dikirim     : ...
  Paket diterima    : ...
  Beban via Spine0  : ... %
  Beban via Spine1  : ... %
  Perubahan rute    : ...
========================================================
```

Dua baris **"Beban via SpineN"** adalah bukti kuantitatif bahwa AI routing bekerja:
pada mode `static` angkanya sekitar 100% / 0%, sedangkan pada mode `ai` mendekati 50% / 50%.

## Troubleshooting

| Gejala | Penyebab dan solusi |
|---|---|
| `./run-experiments.sh: bad interpreter` | File terbawa line ending Windows. Jalankan `sed -i 's/\r$//' run-experiments.sh`. |
| `Permission denied` saat menjalankan skrip | `chmod +x run-experiments.sh` |
| `ns3: command not found` | Skrip harus dijalankan dari direktori root ns-3, bukan dari `scratch/`. |
| `qmake: could not find a Qt installation` | `export QT_SELECT=qt5` lalu ulangi `qmake NetAnim.pro`. |
| File XML terlalu besar / NetAnim lambat | Kecilkan `--simTime` dan pakai `--traffic=low` atau `medium`. |
| Error kompilasi terkait `UpdateNodeSize`/API NetAnim | Beda versi ns-3. Kirimkan pesan error lengkapnya; penyesuaiannya biasanya hanya satu-dua baris. |

Diuji menargetkan **ns-3.40 sampai 3.44**. Kode hanya memakai API yang stabil
(`Ipv4StaticRouting`, `TrafficControlHelper`, `FlowMonitor`, `AnimationInterface`),
jadi versi lain di rentang itu seharusnya ikut jalan.
