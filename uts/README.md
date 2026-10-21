# Fase 0 — trafik normal di NS-3

Simulasi ini membangun jaringan bintang, mengirim data yang sah, dan menyimpan catatannya. Belum ada serangan, belum ada machine learning, dan belum ada reinforcement learning.

## Hubungan dengan paper

Tiga paper di folder ini adalah rujukan. Fase 0 tidak menyalin percobaan mereka.

- **Mahajan dkk., 2022, Adaptive Routing in Wireless Mesh Networks.** Mereka mengukur throughput, packet delivery ratio, dan delay. Fase 0 memakai ketiga ukuran itu. Topologinya berbeda: mereka memakai Wi-Fi mesh 50 node, kita memakai LAN CSMA berbentuk bintang. Q-learning mereka belum dipasang. Di akhir paper mereka, menyambungkan agent ke NS-3 disebut sebagai kerja berikutnya. Itu baru masuk di fase yang lebih belakang, lewat NS3-Gym.
- **Bel dkk., 2024, Co-Simulation Framework for Network Attack Generation and Monitoring.** Mereka memakai NS-3 untuk membuat skenario, merekam jejak, dan menyimpan dataset. Fase 0 mengambil cara kerja itu: simulasi dulu, simpan CSV, baru nanti dilihat. Sistem mereka (GridLAB-D, HELICS, serangan pada power grid) tidak dipakai. Node penyerang sudah duduk di jaringan, tetapi di fase ini tidak mengirim apa pun.
- **Zhang dkk., 2026, Predictive-Proactive Congestion Avoidance.** Mereka meramal kemacetan di jaringan data-center dengan Mininet, bukan NS-3. Fase 0 belum memakai model mereka. Jendela 1 detik di `windows.csv` disiapkan supaya data ini nanti bisa dilatih.

Desain jaringan (1 pengirim, 4 penerima, 1 penyerang, switch, UDP port 9000) mengikuti dokumen proposal, bukan skenario salah satu paper.

## Isi folder

```
scratch/phase0/phase0.cc    program NS-3
scripts/run_phase0.sh       build, 45 run, agregasi, validasi
scripts/aggregate.py        CSV mentah -> windows.csv
scripts/validate_phase0.py  PASS/FAIL dan satu gambar PNG
BELAJAR.md                  penjelasan dengan bahasa yang sangat sederhana
```

## Menyalin ke laptop Ubuntu

Di laptop itu NS-3 sudah ter-build, atau setidaknya folder sumbernya ada (`./ns3` atau `./waf`).

```bash
# contoh. Sesuaikan keduanya.
export NS3_ROOT="$HOME/ns-allinone-3.45/ns-3.45"
cd /path/ke/folder/uts
chmod +x scripts/run_phase0.sh
./scripts/run_phase0.sh smoke
```

`smoke` menjalankan dua simulasi 10 detik (seed 1 dan seed 2, payload 800 byte, 5 Mbps). Seed 1 juga menulis file NetAnim.

Kalau smoke lolos, jalankan matriks lengkap. Ini 45 simulasi, masing-masing 60 detik:

```bash
./scripts/run_phase0.sh full
```

Jumlah pekerjaan bersamaan bisa diubah:

```bash
MAX_JOBS=2 ./scripts/run_phase0.sh full
```

Skrip menyalin `phase0.cc` ke `$NS3_ROOT/scratch/phase0/`, membangun NS-3, lalu menjalankan binary-nya. Hasil ditulis di `$NS3_ROOT/out/phase0/`. Folder itu dikosongkan setiap kali skrip mulai, supaya hasil smoke dan full tidak tercampur.

Kalau `pandas`, `numpy`, atau `matplotlib` belum ada, skrip membuat venv di `$NS3_ROOT/.venv-phase0` dan memasangnya di sana.

## NetAnim

Simulasi hanya menulis XML. Kartunnya dibuka dengan program NetAnim (Qt), bukan dengan ns-3 itu sendiri.

Setelah `smoke`:

`$NS3_ROOT/out/phase0/normal_p800_r5_s1/animation.xml`

Cari `NetAnim.pro` di dalam folder NS-3 (sering di `netanim/` atau `src/netanim/`). Lalu:

```bash
cd /path/ke/folder/yang/berisi/NetAnim.pro
qmake NetAnim.pro
make
./NetAnim
```

Di jendela itu, buka `animation.xml`. Switch abu-abu di tengah, pengirim hijau, penerima biru, penyerang merah. Pada Fase 0 garis paket keluar dari pengirim. Penyerang tidak mengirim.

`--anim=1` pada run 60 detik membuat XML yang besar. Matriks `full` memakai `--anim=0`. Untuk satu kartun singkat di luar smoke:

```bash
cd "$NS3_ROOT"
./build/...phase0... \
  --payload=800 --rateMbps=5 --seed=1 --simTime=10 \
  --anim=1 --outDir=out/phase0 --tag=normal --ns3Version=manual
```

Ganti `./build/...phase0...` dengan binary yang dicetak skrip.

## Keluaran

Setiap run ada di `out/phase0/<tag>_p<payload>_r<rate>_s<seed>/`:

- `packets_tx.csv` — setiap paket yang dikirim
- `packets_rx.csv` — setiap paket yang diterima, lengkap dengan delay, cap, dan duplikat
- `meta.json` — parameter run
- `animation.xml` — hanya jika `--anim=1`

Setelah semua run:

- `out/phase0/windows.csv` — satu baris per penerima per detik
- `out/phase0/sample_throughput_delay.png` — throughput dan delay dari run contoh

`label` di `windows.csv` adalah 0 untuk tag `normal`. Tag lain nanti diisi 1.

## Arti kolom jendela

- `tx_packets`: paket yang waktu kirimnya jatuh di jendela itu. Angkanya sama untuk setiap penerima.
- `rx_packets`: paket yang diterima di jendela itu dan bukan duplikat.
- `pkt_rate_pps`: semua paket yang diterima (termasuk duplikat) dibagi lebar jendela.
- `throughput_mbps`: byte yang diterima, termasuk duplikat, diubah ke megabit per detik.
- `pdr` / `plr`: `rx_packets / tx_packets`, dan satu dikurangi angka itu. Kosong jika tidak ada paket kirim.
- `jitter_s`: rata-rata selisih delay paket yang berurutan menurut waktu terima. Bernilai 0 jika paket di jendela itu kurang dari dua.
- `duplicate_ratio`: 0 jika tidak ada paket diterima.

Cek throughput di validator memakai byte unik (bukan duplikat) selama `simTime - appStart`, dirata-ratakan pada empat penerima, lalu dibandingkan dengan laju yang diminta. Batasnya ±3%.

## Cek yang harus PASS

1. Penerima 1 sampai 4 mendapat paket. Node lain tidak menulis CSV terima.
2. Rata-rata PDR per jendela `>= 0.999`.
3. Throughput unik berada dalam ±3% dari laju yang diminta.
4. Setiap jendela: `duplicate_count == 0` dan `auth_fail_count == 0`.
5. `seq` naik ketat pada tiap penerima.
6. Delay rata-rata lebih dari 0 dan di bawah 100 ms. P95 tidak mencapai 1 detik.
7. Seed dan run yang sama, dijalankan dua kali selama 10 detik, menghasilkan `packets_rx.csv` yang identik.
8. Seed yang berbeda menghasilkan daftar waktu kirim yang berbeda.

Delay virtual tidak bergantung pada kecepatan CPU laptop. Kalau kriteria 6 gagal, yang salah adalah model jaringannya, bukan laptop yang lambat.

## Asumsi

- Kepala paket 18 byte: `seq` (4), waktu kirim dalam nanodetik (8, ditulis sebagai dua uint32), `claimedId` (2), `authTag` (4). Sisa payload adalah bantalan nol.
- Cap adalah FNV-1a 32-bit atas byte big-endian `seq`, `claimedId`, dan rahasia `0x5EC0DE01`. Ini bukan kriptografi.
- Jeda antar paket = `(payload * 8 / laju) * angka acak [0.9, 1.1]`. Variabel acak memakai stream nomor 10, di-set setelah seed, supaya jejak tidak bergeser hanya karena versi NS-3.
- Paket pertama keluar pada `appStart`. Tidak ada paket pada waktu `>= simTime`.
- Versi NS-3 di `meta.json` diisi skrip dari `./ns3 --version` atau `./waf --version`, karena tidak ada satu fungsi versi yang stabil di semua rilis.
- Modul `netanim` dan `mobility` ikut dikompilasi. Dokumen tugas semula hanya menyebut core, network, internet, csma, bridge, dan applications. NetAnim ditambahkan karena kartun simulasi diminta. Posisi diam dipasang dengan `ConstantPositionMobilityModel` sebelum `AnimationInterface` dibuat, supaya NetAnim tidak memperingatkan bahwa node belum punya model posisi.
- Kalau compiler menolak `CommandLine cmd(__FILE__);`, ganti baris itu di `phase0.cc` menjadi `CommandLine cmd;`. Constructor dengan `__FILE__` adalah gaya NS-3 3.36 ke atas.

## Kalau gagal di laptop

- `permission denied` pada skrip: `chmod +x scripts/run_phase0.sh`. Kalau muncul `bad interpreter` atau `$'\r'`, file masih berakhiran baris Windows. Di Ubuntu: `sed -i 's/\r$//' scripts/run_phase0.sh`.
- `netanim-module.h` tidak ketemu: build NS-3 tanpa `--disable-netanim`, lalu `./ns3 build` lagi.
- Binary `phase0` tidak ketemu: lihat pesan build. Target scratch yang diharapkan adalah `scratch/phase0/phase0.cc`.
- Tidak ada paket diterima: jangan ubah topologi dulu. Kirim cuplikan log build dan 20 baris pertama `packets_tx.csv` serta `packets_rx.csv`.
- Python tidak punya pandas: biarkan skrip membuat `.venv-phase0`, atau `python3 -m pip install pandas numpy matplotlib`.

## Yang sengaja belum ada

Kelas `AttackerApp` belum ditulis. Node 5 hanya punya alamat IP. Flooding, replay, spoofing, Random Forest, dan RL ada di fase berikutnya. `DisseminationSender` dan `DisseminationReceiver` tidak perlu diubah untuk menambah aplikasi penyerang; cap bersama sudah berupa fungsi `ComputeAuthTag()` di luar kedua kelas.
