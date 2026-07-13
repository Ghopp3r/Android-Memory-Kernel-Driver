#!/usr/bin/env bash
# Host-side orchestrator for the drv_probe verification harness.
#
# 1. Builds drv_probe with the Android NDK if a fresh binary is needed.
# 2. Pushes my-driver-android15-6.6.ko + drv_probe to /data/local/tmp/test/.
# 3. insmods the driver.
# 4. Runs drv_probe with timing and pulls JSON + CSV results.
# 5. Captures kernel-side dmesg slice for the run.
#
# Usage:
#   release/scripts/verify-on-device.sh [--ndk PATH] [--ko PATH] [--iters N] [--tests A,B]
#
# Defaults: $ANDROID_NDK for NDK, release/my-driver-android15-6.6.ko for driver,
# 1000 iterations for the timing pass, all tests selected.
set -euo pipefail

ADB="${ADB:-/e/Programs/AndroidStudioSdk/platform-tools/adb.exe}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK:-}"
KO="${KO:-$ROOT/my-driver-android15-6.6.ko}"
ITERS=1000
TESTS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --ndk)    NDK="$2"; shift 2 ;;
        --ko)     KO="$2"; shift 2 ;;
        --iters)  ITERS="$2"; shift 2 ;;
        --tests)  TESTS="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$NDK" ]; then
    echo "ANDROID_NDK not set and --ndk not provided" >&2
    exit 2
fi
if [ ! -f "$KO" ]; then
    echo "driver .ko not found: $KO" >&2
    exit 2
fi

OUT_DIR="$ROOT/diagnostics"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
JSON="$OUT_DIR/results-$TS.json"
CSV="$OUT_DIR/timing-$TS.csv"
DMESG="$OUT_DIR/dmesg-$TS.txt"

# ---------------------------------------------------------------------------
# 1) Build drv_probe (skip if up-to-date)
# ---------------------------------------------------------------------------
BUILD="$ROOT/scripts/build-probe"
PROBE="$BUILD/drv_probe"
if [ ! -x "$PROBE" ] \
    || [ "$ROOT/scripts/src/drv_probe.c" -nt "$PROBE" ] \
    || [ "$ROOT/scripts/CMakeLists.txt" -nt "$PROBE" ] \
    || [ "$ROOT/driver/include/driver/uapi.h" -nt "$PROBE" ]; then
    echo "=== building drv_probe with NDK at $NDK"
    cmake -S "$ROOT/scripts" -B "$BUILD" \
        -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 \
        -DCMAKE_BUILD_TYPE=Release >/dev/null
    cmake --build "$BUILD" -j >/dev/null
fi

# ---------------------------------------------------------------------------
# 2) Push artefacts
# ---------------------------------------------------------------------------
echo "=== pushing artefacts"
"$ADB" shell 'su -c "mkdir -p /data/local/tmp/test"' >/dev/null
"$ADB" push "$KO"    //data/local/tmp/test/ >/dev/null
"$ADB" push "$PROBE" //data/local/tmp/test/ >/dev/null
"$ADB" shell 'su -c "chmod 755 /data/local/tmp/test/drv_probe; rm -f /data/local/tmp/test/results.json /data/local/tmp/test/timing.csv"'

# ---------------------------------------------------------------------------
# 3) insmod. The module stays registered and is intentionally non-unloadable;
# reboot the device before loading a replacement artifact.
# ---------------------------------------------------------------------------
echo "=== insmod"
"$ADB" shell 'su -c "dmesg -C 2>/dev/null || true; insmod /data/local/tmp/test/my-driver-android15-6.6.ko"'

# ---------------------------------------------------------------------------
# 4) run drv_probe
# ---------------------------------------------------------------------------
echo "=== running drv_probe (iters=$ITERS)"
SEL_ARG=""
[ -n "$TESTS" ] && SEL_ARG="--tests=$TESTS"
"$ADB" shell "cd /data/local/tmp/test && ./drv_probe $SEL_ARG --iters=$ITERS --json=/data/local/tmp/test/results.json --csv=/data/local/tmp/test/timing.csv 2>&1"
RC=$?

# ---------------------------------------------------------------------------
# 5) pull results
# ---------------------------------------------------------------------------
echo "=== pulling results"
"$ADB" pull //data/local/tmp/test/results.json "$JSON" >/dev/null 2>&1 || true
"$ADB" pull //data/local/tmp/test/timing.csv  "$CSV"  >/dev/null 2>&1 || true
"$ADB" shell 'su -c "dmesg | grep memory-driver"' > "$DMESG" 2>/dev/null || true

echo
echo "JSON:  $JSON"
echo "CSV:   $CSV"
echo "DMESG: $DMESG"
echo "drv_probe rc=$RC"
exit "$RC"
