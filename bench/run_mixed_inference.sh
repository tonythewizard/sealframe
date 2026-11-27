#!/usr/bin/env bash
set -euo pipefail

# Pure-C11 Physical 2-Host Mixed-Inference Benchmark (Zero Python, Zero NumPy!)
# Edge Stage-1: Proxmox LXC 900 (192.168.1.12, Pentium P6100, C11 + libsealframe)
# PC   Stage-2: Localhost (Ryzen 7 7800X3D, C11 + libsealframe)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EDGE_HOST="${EDGE_HOST:-192.168.1.12}"
PORT="${MIXED_PORT:-17915}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_proxmox}"
SSH_OPTS=(-i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no)
REMOTE_DIR="/var/tmp/sf-mixed-c"
WORK="$(mktemp -d /tmp/sf-mixed-c-XXXXXX)"
SRV_PID=""

cleanup() {
  if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
  ssh "${SSH_OPTS[@]}" "root@${EDGE_HOST}" "rm -rf $REMOTE_DIR" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== SealFrame Pure-C11 Physical 2-Host Mixed Inference (Zero Python) ==="
make -C "$ROOT" build/mixed_infer_client bin/sf >/dev/null

"$ROOT/bin/sf" keygen "$WORK/cli.sk" "$WORK/cli.pk" >/dev/null
ssh "${SSH_OPTS[@]}" "root@${EDGE_HOST}" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
scp "${SSH_OPTS[@]}" "$ROOT/bench/edge_infer_stream.c" "$WORK/cli.pk" "root@${EDGE_HOST}:${REMOTE_DIR}/" >/dev/null

echo "[1/3] Compiling C11 Edge Stage-1 server on ${EDGE_HOST}..."
ssh "${SSH_OPTS[@]}" "root@${EDGE_HOST}" \
  "gcc -std=c11 -O3 -Wall -Wextra -Werror -I/usr/local/include ${REMOTE_DIR}/edge_infer_stream.c \
   -L/usr/local/lib -Wl,-rpath,/usr/local/lib -lsealframe -lsodium -lm -o ${REMOTE_DIR}/edge_infer_stream && \
   sf keygen ${REMOTE_DIR}/srv.sk ${REMOTE_DIR}/srv.pk >/dev/null"
scp "${SSH_OPTS[@]}" "root@${EDGE_HOST}:${REMOTE_DIR}/srv.pk" "$WORK/srv.pk" >/dev/null

echo "[2/3] Launching mutually-pinned C11 Edge server on ${EDGE_HOST}:${PORT}..."
ssh "${SSH_OPTS[@]}" "root@${EDGE_HOST}" \
  "${REMOTE_DIR}/edge_infer_stream 0.0.0.0 ${PORT} ${REMOTE_DIR}/srv.sk ${REMOTE_DIR}/cli.pk" >"$WORK/srv.out" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 40); do
  if grep -q "^READY " "$WORK/srv.out" 2>/dev/null; then break; fi
  sleep 0.1
done
grep -q "^READY " "$WORK/srv.out" || { echo "Edge server failed:"; cat "$WORK/srv.out"; exit 1; }
echo "  $(head -n1 "$WORK/srv.out")"

echo "[3/3] Running pure-C11 closed-loop mixed inference (native SFT1 FP32 + FP16)..."
"$ROOT/build/mixed_infer_client" "$EDGE_HOST" "$PORT" "$WORK/cli.sk" "$WORK/srv.pk"
wait "$SRV_PID" 2>/dev/null || true
SRV_PID=""
