#!/system/bin/sh
# Synchronous /dev/kmsg capture for crash investigations.
#
# Designed to lose as few pre-panic lines as possible:
#   - dd with bs=64 + oflag=sync forces an fsync per 64-byte block, so no
#     write sits in the userspace stdio buffer or page cache between
#     pr_drv() landing in the kernel ring and the bytes reaching /data.
#   - iflag=fullblock prevents short reads from /dev/kmsg producing under-
#     filled blocks (which would still be written, just smaller).
#
# Usage:
#   su -c "nohup /data/local/tmp/test/capture-kmsg.sh </dev/null >/dev/null 2>&1 &"
#
# Output file is recreated on every invocation (no append) so we always know
# the trail belongs to the current test run.

set -e

DST=/data/local/tmp/test/kmsg.log
: > "$DST"

# Kill any prior cat/dd capture so we don't have two readers tearing /dev/kmsg.
for proc in cat dd; do
    pkill -f "$proc /dev/kmsg" 2>/dev/null || true
done

exec dd if=/dev/kmsg of="$DST" bs=64 oflag=sync iflag=fullblock conv=notrunc status=none
