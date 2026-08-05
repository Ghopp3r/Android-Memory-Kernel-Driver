#!/system/bin/sh
# Capture /dev/kmsg into a fresh per-run log with Android Toybox.
# Usage: su -c "nohup /data/local/tmp/test/capture-kmsg.sh </dev/null >/dev/null 2>&1 &"

set -e

DST=/data/local/tmp/test/kmsg.log
: > "$DST"

# Stop older readers before starting the only capture process.
pkill -f "cat /dev/kmsg" 2>/dev/null || true
pkill -f "dd if=/dev/kmsg" 2>/dev/null || true

exec dd if=/dev/kmsg of="$DST" bs=64 status=none
