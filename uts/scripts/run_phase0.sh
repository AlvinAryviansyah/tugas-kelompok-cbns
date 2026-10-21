#!/usr/bin/env bash
# Menjalankan Fase 0 di laptop Ubuntu, dari mana saja.
#
#   export NS3_ROOT="$HOME/ns-allinone-3.xx/ns-3.xx"
#   ./scripts/run_phase0.sh smoke     # 2 run, 10 detik, satu file NetAnim
#   ./scripts/run_phase0.sh full      # 45 run, 60 detik, tanpa NetAnim
#
# Variabel opsional: MAX_JOBS (default 4).

set -euo pipefail

MODE="${1:-full}"
MAX_JOBS="${MAX_JOBS:-4}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_CC="$REPO_DIR/scratch/phase0/phase0.cc"

if [[ "$MODE" != "smoke" && "$MODE" != "full" ]]; then
    echo "Pakai: $0 [smoke|full]"
    exit 1
fi

if [[ ! -f "$SRC_CC" ]]; then
    echo "Tidak menemukan $SRC_CC"
    exit 1
fi

if [[ -n "${NS3_ROOT:-}" ]]; then
    ROOT="$NS3_ROOT"
elif [[ -f "./ns3" || -f "./waf" ]]; then
    ROOT="$(pwd)"
else
    echo "Set NS3_ROOT ke folder ns-3 (yang berisi ./ns3 atau ./waf), atau jalankan skrip ini dari folder itu."
    exit 1
fi
ROOT="$(cd "$ROOT" && pwd)"

if [[ ! -f "$ROOT/ns3" && ! -f "$ROOT/waf" ]]; then
    echo "Di $ROOT tidak ada ./ns3 maupun ./waf"
    exit 1
fi

mkdir -p "$ROOT/scratch/phase0"
if [[ "$SRC_CC" != "$ROOT/scratch/phase0/phase0.cc" ]]; then
    cp "$SRC_CC" "$ROOT/scratch/phase0/phase0.cc"
fi

ver_file="$(mktemp)"
if [[ -f "$ROOT/ns3" ]]; then
    (cd "$ROOT" && ./ns3 --version >"$ver_file" 2>&1 || true)
else
    (cd "$ROOT" && ./waf --version >"$ver_file" 2>&1 || true)
fi
NS3_VER="$(head -n 1 "$ver_file" | tr -cd 'A-Za-z0-9._-')"
rm -f "$ver_file"
NS3_VER="${NS3_VER:-unknown}"
echo "Versi NS-3 yang terbaca: $NS3_VER"

echo "Membangun ns-3. Ini bisa lama pada build pertama."
if [[ -f "$ROOT/ns3" ]]; then
    (cd "$ROOT" && ./ns3 build)
else
    (cd "$ROOT" && ./waf build)
fi

BIN=""
while IFS= read -r candidate; do
    case "$candidate" in
        *CMakeFiles*|*.o|*.cmake|*.py|*.sh) continue ;;
    esac
    BIN="$candidate"
done < <(find "$ROOT/build" -type f -name '*phase0*' -executable | sort)

if [[ -z "$BIN" ]]; then
    echo "Build selesai, tetapi binary *phase0* tidak ketemu di $ROOT/build"
    echo "Coba jalankan sendiri: cd \"$ROOT\" && ./ns3 run 'phase0 --anim=1 --simTime=10'"
    exit 1
fi
echo "Binary: $BIN"

PY="python3"
if ! python3 -c "import pandas, numpy, matplotlib" >/dev/null 2>&1; then
    echo "pandas/numpy/matplotlib belum ada. Membuat venv di $ROOT/.venv-phase0"
    python3 -m venv "$ROOT/.venv-phase0"
    "$ROOT/.venv-phase0/bin/pip" install pandas numpy matplotlib
    PY="$ROOT/.venv-phase0/bin/python"
fi

OUT_REL="out/phase0"
# Smoke dan full memakai run-id yang sama. Hapus hasil lama supaya tidak tercampur.
echo "Menghapus hasil lama di $ROOT/$OUT_REL"
rm -rf "$ROOT/$OUT_REL"
mkdir -p "$ROOT/$OUT_REL"

fail=0
running=0

wait_slot() {
    while [[ "$running" -ge "$MAX_JOBS" ]]; do
        if ! wait -n; then
            fail=1
        fi
        running=$((running - 1))
    done
}

launch() {
    (
        cd "$ROOT"
        "$BIN" "$@"
    ) &
    running=$((running + 1))
}

common=(
    --run=1
    --appStart=2.0
    --linkRate=100Mbps
    --linkDelay=2us
    --outDir="$OUT_REL"
    --tag=normal
    --ns3Version="$NS3_VER"
)

if [[ "$MODE" == "smoke" ]]; then
    echo "Smoke test: payload 800, rate 5 Mbps, seed 1 dan 2, 10 detik. Seed 1 menulis NetAnim."
    wait_slot
    launch "${common[@]}" --payload=800 --rateMbps=5 --seed=1 --simTime=10 --anim=1
    wait_slot
    launch "${common[@]}" --payload=800 --rateMbps=5 --seed=2 --simTime=10 --anim=0
else
    echo "Matriks penuh: 3 payload x 3 rate x 5 seed = 45 run, masing-masing 60 detik."
    for payload in 400 800 1200; do
        for rate in 2 5 10; do
            for seed in 1 2 3 4 5; do
                wait_slot
                launch "${common[@]}" \
                    --payload="$payload" \
                    --rateMbps="$rate" \
                    --seed="$seed" \
                    --simTime=60 \
                    --anim=0
            done
        done
    done
fi

while [[ "$running" -gt 0 ]]; do
    if ! wait -n; then
        fail=1
    fi
    running=$((running - 1))
done

if [[ "$fail" -ne 0 ]]; then
    echo "Ada run yang gagal. Agregasi tidak dijalankan."
    exit 1
fi

"$PY" "$REPO_DIR/scripts/aggregate.py" --outDir "$ROOT/$OUT_REL" --window 1.0
"$PY" "$REPO_DIR/scripts/validate_phase0.py" \
    --outDir "$ROOT/$OUT_REL" \
    --phase0-bin "$BIN" \
    --work-dir "$ROOT" \
    --ns3-version "$NS3_VER" \
    --repro-sim-time 10

echo ""
echo "Selesai. CSV ada di $ROOT/$OUT_REL"
if [[ "$MODE" == "smoke" ]]; then
    echo "NetAnim: buka $ROOT/$OUT_REL/normal_p800_r5_s1/animation.xml"
fi
