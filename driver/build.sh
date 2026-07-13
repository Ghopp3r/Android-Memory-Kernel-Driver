#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Convenience local-build script.
#
# Pulls the matching ghcr.io/ylarod/ddk:<kmi>-<release> Docker image and
# runs `make` inside it against the current driver/ source tree.
#
# Usage:
#   ./build.sh <kmi> [ddk_release]
#
# Examples:
#   ./build.sh android15-6.6
#   HIDE_SELF_MODULE=0 HIDE_KGSL=1 ./build.sh android16-6.12
#   ./build.sh android14-6.1 20251104
#   ./build.sh android13-5.10 20250825
#
#   # Build all matrix KMIs in sequence:
#   for k in android12-5.10 android13-5.10 android13-5.15 \
#            android14-5.15 android14-6.1 android15-6.6 android16-6.12; do
#       ./build.sh "$k" || exit 1
#   done
#
# Output: $(pwd)/my-driver.ko (overwritten each run) plus
#         $(pwd)/out/my-driver-<kmi>.ko (kept across runs).
#
# Exit code: the underlying `make` exit code.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults & arg parsing
# ---------------------------------------------------------------------------
DEFAULT_KMI="android15-6.6"
DEFAULT_RELEASE="20251104"
DRIVER_NAME="${DRIVER_NAME:-my-driver}"
HIDE_SELF_MODULE="${HIDE_SELF_MODULE:-1}"
HIDE_KGSL="${HIDE_KGSL:-0}"

KMI="${1:-$DEFAULT_KMI}"
RELEASE="${2:-$DEFAULT_RELEASE}"
REQUIRE_6_12_KCFI=0
if [[ "${KMI}" == "android16-6.12" ]]; then
    REQUIRE_6_12_KCFI=1
fi

case "${HIDE_SELF_MODULE}" in
    0|1) ;;
    *) echo "ERROR: HIDE_SELF_MODULE must be 0 or 1." >&2; exit 2 ;;
esac
case "${HIDE_KGSL}" in
    0|1) ;;
    *) echo "ERROR: HIDE_KGSL must be 0 or 1." >&2; exit 2 ;;
esac

if [[ "${KMI}" == "-h" || "${KMI}" == "--help" ]]; then
    sed -n '2,30p' "$0"
    exit 0
fi

IMAGE="ghcr.io/ylarod/ddk:${KMI}-${RELEASE}"

# Resolve the absolute path of the driver/ directory (i.e. where this script lives).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Build configuration ===================================="
echo "  KMI:           ${KMI}"
echo "  DDK release:   ${RELEASE}"
echo "  Image:         ${IMAGE}"
echo "  Driver name:   ${DRIVER_NAME}"
echo "  LKM hide:      ${HIDE_SELF_MODULE}"
echo "  KGSL hide:     ${HIDE_KGSL}"
echo "  Source dir:    ${SCRIPT_DIR}"
echo "============================================================"

# ---------------------------------------------------------------------------
# Sanity check: docker must be available.
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not installed or not in PATH." >&2
    exit 127
fi

# ---------------------------------------------------------------------------
# Pull the per-KMI DDK image (no-op if up-to-date).
# ---------------------------------------------------------------------------
echo "=== docker pull ${IMAGE}"
docker pull "${IMAGE}"

# ---------------------------------------------------------------------------
# Run `make` inside the container with the driver/ tree bind-mounted at /work.
#
# The image sets $KERNEL_SRC to its pre-extracted kernel tree; our Makefile
# picks that up as KDIR automatically.
# ---------------------------------------------------------------------------
echo "=== docker run make"
set +e
docker run --rm \
    --privileged \
    -v "${SCRIPT_DIR}:/work" \
    -w /work \
    -e "DRIVER_NAME=${DRIVER_NAME}" \
    -e "HIDE_SELF_MODULE=${HIDE_SELF_MODULE}" \
    -e "HIDE_KGSL=${HIDE_KGSL}" \
    -e "REQUIRE_6_12_KCFI=${REQUIRE_6_12_KCFI}" \
    "${IMAGE}" \
    bash -c '
        set -euo pipefail
        if [[ "${REQUIRE_6_12_KCFI}" == "1" ]]; then
            config="${KERNEL_SRC:?}/.config"
            test -r "${config}"
            grep -Fxq "CONFIG_CFI_CLANG=y" "${config}"
            grep -Fxq "CONFIG_CFI_ICALL_NORMALIZE_INTEGERS=y" "${config}"
        fi
        make -j"$(nproc)"
        if [[ "${REQUIRE_6_12_KCFI}" == "1" ]]; then
            grep -R -F -q --include="*.cmd" -- \
                "-fsanitize-cfi-icall-experimental-normalize-integers" .
        fi
    '
MAKE_RC=$?
set -e

if [[ ${MAKE_RC} -ne 0 ]]; then
    echo "make failed (exit ${MAKE_RC})" >&2
    exit ${MAKE_RC}
fi

# ---------------------------------------------------------------------------
# Stage the artefact under out/ with a KMI-tagged filename.
# ---------------------------------------------------------------------------
mkdir -p "${SCRIPT_DIR}/out"
OUT_KO="${SCRIPT_DIR}/out/${DRIVER_NAME}-${KMI}.ko"
cp "${SCRIPT_DIR}/${DRIVER_NAME}.ko" "${OUT_KO}"

echo ""
echo "=== Build OK ==============================================="
echo "  ${OUT_KO}"
echo "  size: $(du -h "${OUT_KO}" | cut -f1)"
echo "============================================================"

exit 0
