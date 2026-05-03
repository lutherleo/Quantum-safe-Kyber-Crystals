#!/usr/bin/env bash
# Demo: passive eavesdropper sees only ciphertext.
# Asserts that the plaintext message string never appears in the captured pcap.

set -euo pipefail
BACKEND="${BACKEND:-A}"
SECRET="banana-cantaloupe-pineapple"   # rare token; if it leaks, grep finds it
PCAP=/results/eavesdrop.pcap

mkdir -p /results
rm -f "$PCAP"

echo "[demo:eavesdrop] starting bob..."
/app/build/bob --backend "$BACKEND" --port 5556 &
BOB_PID=$!

echo "[demo:eavesdrop] starting attacker proxy (passthrough) on :5555 -> bob:5556..."
/app/build/attacker --mode passthrough --listen-port 5555 \
    --upstream-host 127.0.0.1 --upstream-port 5556 &
ATK_PID=$!

# tcpdump on loopback (or pqnet inside compose). Try common ifaces.
IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E 'eth|lo' | head -1)
echo "[demo:eavesdrop] tcpdump on $IFACE..."
tcpdump -i "$IFACE" -w "$PCAP" tcp port 5555 &
TD_PID=$!

sleep 1
echo "[demo:eavesdrop] alice sending secret '$SECRET'..."
/app/build/alice --backend "$BACKEND" --host 127.0.0.1 --port 5555 \
    --message "$SECRET" --repeat 3 || true

sleep 1
kill "$TD_PID" "$ATK_PID" "$BOB_PID" 2>/dev/null || true
wait 2>/dev/null || true

echo "[demo:eavesdrop] scanning pcap for plaintext..."
if strings "$PCAP" | grep -F "$SECRET" >/dev/null; then
    echo "FAIL: plaintext '$SECRET' found in capture!"
    exit 1
fi
echo "PASS: plaintext NOT found in captured ciphertext."
exit 0
