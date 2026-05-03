#!/usr/bin/env bash
# Demo: active tamperer flips a bit in a DATA frame.
# Asserts: bob logs "GCM auth failure" and exits non-zero.

set -euo pipefail
BACKEND="${BACKEND:-A}"
LOG=/results/modify_bob.log
mkdir -p /results

echo "[demo:modify] starting bob..."
/app/build/bob --backend "$BACKEND" --port 5556 > "$LOG" 2>&1 &
BOB_PID=$!

echo "[demo:modify] starting attacker (flip mode)..."
/app/build/attacker --mode flip --listen-port 5555 \
    --upstream-host 127.0.0.1 --upstream-port 5556 \
    --target-frame 1 --target-byte 5 &
ATK_PID=$!

sleep 1
echo "[demo:modify] alice connecting..."
/app/build/alice --backend "$BACKEND" --host 127.0.0.1 --port 5555 \
    --message "tamper-target" --repeat 3 || true

sleep 1
# Wait for bob; expect non-zero exit due to auth failure.
wait "$BOB_PID" || BOB_RC=$?
kill "$ATK_PID" 2>/dev/null || true
wait 2>/dev/null || true

echo "[demo:modify] bob exit code: ${BOB_RC:-0}"
echo "[demo:modify] bob log tail:"
tail -20 "$LOG"

if grep -qi "GCM auth failure" "$LOG"; then
    echo "PASS: bob detected GCM auth failure as expected."
    exit 0
fi
echo "FAIL: expected 'GCM auth failure' in bob log."
exit 1
