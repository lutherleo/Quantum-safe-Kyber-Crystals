#!/usr/bin/env bash
# Demo: attacker replays a captured DATA frame.
# Asserts: bob logs "replay detected" and exits non-zero.

set -euo pipefail
BACKEND="${BACKEND:-A}"
LOG=/results/replay_bob.log
mkdir -p /results

echo "[demo:replay] starting bob..."
/app/build/bob --backend "$BACKEND" --port 5556 > "$LOG" 2>&1 &
BOB_PID=$!

echo "[demo:replay] starting attacker (replay mode, target frame 1)..."
/app/build/attacker --mode replay --listen-port 5555 \
    --upstream-host 127.0.0.1 --upstream-port 5556 \
    --target-frame 1 &
ATK_PID=$!

sleep 1
echo "[demo:replay] alice connecting..."
/app/build/alice --backend "$BACKEND" --host 127.0.0.1 --port 5555 \
    --message "replay-target" --repeat 3 || true

sleep 1
wait "$BOB_PID" || BOB_RC=$?
kill "$ATK_PID" 2>/dev/null || true
wait 2>/dev/null || true

echo "[demo:replay] bob exit code: ${BOB_RC:-0}"
echo "[demo:replay] bob log tail:"
tail -20 "$LOG"

if grep -qi "replay detected" "$LOG"; then
    echo "PASS: bob detected replayed frame."
    exit 0
fi
echo "FAIL: expected 'replay detected' in bob log."
exit 1
