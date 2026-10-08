#!/usr/bin/env bash
# =============================================================================
#  run-experiments.sh
#
#  Menjalankan seluruh set eksperimen paper dalam satu perintah:
#    - 6 run pengukuran  : {static, ai} x {low, medium, high}  -> CSV
#    - 2 run animasi     : {static, ai} pada beban medium      -> XML NetAnim
#
#  Jalankan dari DIREKTORI ROOT ns-3 (tempat skrip ./ns3 berada), contoh:
#    cp ai-adaptive-routing-dc.cc  ~/ns-3-dev/scratch/
#    cp run-experiments.sh         ~/ns-3-dev/
#    cd ~/ns-3-dev && ./run-experiments.sh
# =============================================================================

set -euo pipefail

PROGRAM="ai-adaptive-routing-dc"
CSV="dc-routing-results.csv"
SIM_TIME=20          # durasi run pengukuran (detik)
ANIM_SIM_TIME=6      # durasi run animasi: pendek, karena XML cepat membengkak
ANIM_TRAFFIC="medium"

# --- 0. Pastikan kita benar-benar berada di root ns-3 ------------------------
if [[ ! -x ./ns3 ]]; then
    echo "ERROR: skrip ./ns3 tidak ditemukan." >&2
    echo "Jalankan skrip ini dari direktori root ns-3, bukan dari folder lain." >&2
    exit 1
fi

if [[ ! -f "scratch/${PROGRAM}.cc" ]]; then
    echo "ERROR: scratch/${PROGRAM}.cc tidak ditemukan." >&2
    echo "Copy dulu: cp ai-adaptive-routing-dc.cc scratch/" >&2
    exit 1
fi

# --- 1. Build sekali di awal -------------------------------------------------
echo ">>> Build ns-3 ..."
./ns3 build "${PROGRAM}"

# --- 2. CSV lama dihapus agar hasilnya tidak tercampur run sebelumnya -------
rm -f "${CSV}"

# --- 3. Run pengukuran: 2 mode x 3 level beban ------------------------------
for mode in static ai; do
    for traffic in low medium high; do
        echo ""
        echo ">>> Run: mode=${mode} traffic=${traffic} simTime=${SIM_TIME}s"
        ./ns3 run "${PROGRAM} --mode=${mode} --traffic=${traffic} \
            --simTime=${SIM_TIME} --csv=${CSV}"
    done
done

# --- 4. Run animasi NetAnim --------------------------------------------------
# Hasil run ini TIDAK ditambahkan ke CSV (--csv dikosongkan) karena durasinya
# berbeda, jadi angkanya tidak sebanding dengan run pengukuran di atas.
for mode in static ai; do
    echo ""
    echo ">>> Run animasi: mode=${mode} traffic=${ANIM_TRAFFIC} simTime=${ANIM_SIM_TIME}s"
    ./ns3 run "${PROGRAM} --mode=${mode} --traffic=${ANIM_TRAFFIC} \
        --simTime=${ANIM_SIM_TIME} --anim=1 --animFile=anim-${mode}.xml --csv="
done

# --- 5. Ringkasan ------------------------------------------------------------
echo ""
echo "============================================================"
echo "Selesai."
echo "  Hasil numerik : ${CSV}"
echo "  Animasi       : anim-static.xml, anim-ai.xml"
echo ""
echo "Langkah berikutnya:"
echo "  1. Buat grafik  : python3 plot_results.py ${CSV}"
echo "  2. Lihat animasi: cd netanim && ./NetAnim"
echo "                    lalu buka file anim-static.xml / anim-ai.xml"
echo "============================================================"
