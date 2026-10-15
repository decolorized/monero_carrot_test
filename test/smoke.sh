#!/usr/bin/env bash
# Host smoke test (Linux): builds the signing code for the PC with random test
# keys, starts the device simulator on a pseudo-terminal and talks to it with
# the frontend (tools/mwlink/mwlink.py). Needs gcc, make, python3, pyserial.
#   test/smoke.sh
set -euo pipefail
cd "$(dirname "$0")"
WORK=$(mktemp -d)
trap 'kill $SIM 2>/dev/null || true; rm -rf "$WORK"' EXIT

# random keys (scalars below the group order), never the real ones
python3 - > "$WORK/secrets.h" <<'PY'
import os
def k():
    b = bytearray(os.urandom(32)); b[31] &= 0x0f; return b.hex()
print('#pragma once')
print('#define SPEND_SECRET_KEY_HEX "%s"' % k())
print('#define VIEW_SECRET_KEY_HEX "%s"' % k())
print('#define SPEND_PUBLIC_KEY_HEX ""\n#define VIEW_PUBLIC_KEY_HEX ""')
print('#define WALLET_NETWORK 1\n#define WALLET_NAME "smoke"')
PY
[ ! -f secrets.h ] || { echo "remove test/secrets.h first (it would shadow the test keys)"; exit 1; }

SRC=$(sed -n 's/^SRC := //p; s/^       //p' host.mk | tr -d '\\' | sed 's#\$(FW)#..#g')
gcc -O2 -w -Ihost -I"$WORK" -I.. -o "$WORK/cwsim" cwsim.c ../cw_link.c platform_host.c $SRC -lutil -lpthread
gcc -O2 -w -Ihost -I"$WORK" -I.. -o "$WORK/cwtool" cwtool.c host_store.c platform_host.c $SRC

"$WORK/cwsim" "$WORK/pty.txt" > "$WORK/sim.log" 2>&1 &
SIM=$!
for _ in $(seq 50); do [ -s "$WORK/pty.txt" ] && break; sleep 0.2; done
PORT=$(cat "$WORK/pty.txt")
sleep 2   # keys load (cn_slow_hash)

MW=../tools/mwlink/mwlink.py
python3 $MW --serial "$PORT" info | tee "$WORK/info.txt"
grep -q "protocol    3" "$WORK/info.txt"
echo "not a wallet file" > "$WORK/junk"
python3 $MW --serial "$PORT" send "$WORK/junk" --out "$WORK" 2>&1 | tee "$WORK/send.txt" || true
grep -q "unrecognised file" "$WORK/send.txt"
echo "smoke test passed"
