#!/usr/bin/env bash
set -euo pipefail

# SealFrame 3-Device Physical Verifiable Mixed-Inference Campaign (100% Pure ISO C11)
#   Node 0 (Stage 0, L0..2): Proxmox LXC 900 (192.168.1.12, Pentium P6100, 256 MiB RAM, Debian)
#   Node 1 (Stage 1, L2..5): MacBook Air CachyOS (192.168.1.17, Core i5-5250U, 4 GiB RAM)
#   Node 2 (Stage 2, L5..8 + LM + Verifier): Workstation PC (localhost, Ryzen 7 7800X3D)
#   Byzantine Miner (Stage 0 corrupt step #5): Proxmox secondary worker port 17917
#
# Also supports --local mode (all 3 workers on 127.0.0.1 for CI / loopback verification).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-physical}"

make -C "$ROOT" bin/sf build/infer_node build/infer_3node_suite >/dev/null

WORK="$(mktemp -d /tmp/sf-infer3-XXXXXX)"
PIDS=()

PROX="${PROX_HOST:-192.168.1.12}"
MAC="${MAC_HOST:-192.168.1.17}"
SSH_P="ssh -i $HOME/.ssh/id_ed25519_proxmox -o BatchMode=yes root@$PROX"
SCP_P="scp -i $HOME/.ssh/id_ed25519_proxmox -o BatchMode=yes -q"
SSH_M="ssh -i $HOME/.ssh/id_ed25519_cachy -o BatchMode=yes cachy@$MAC"
SCP_M="scp -i $HOME/.ssh/id_ed25519_cachy -o BatchMode=yes -q"
PDIR="/var/tmp/sf-infer3"
MDIR="/tmp/sf-infer3"

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  if [ "$MODE" = "physical" ]; then
    $SSH_P "pkill -f '$PDIR' 2>/dev/null || true; rm -rf $PDIR" 2>/dev/null || true
    $SSH_M "pkill -f '$MDIR' 2>/dev/null || true; rm -rf $MDIR" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

"$ROOT/bin/sf" keygen "$WORK/cli.sk" "$WORK/cli.pk" >/dev/null
"$ROOT/bin/sf" keygen "$WORK/n0.sk"  "$WORK/n0.pk"  >/dev/null
"$ROOT/bin/sf" keygen "$WORK/n1.sk"  "$WORK/n1.pk"  >/dev/null
"$ROOT/bin/sf" keygen "$WORK/bz.sk"  "$WORK/bz.pk"  >/dev/null

wait_ready() {
  local f="$1"
  for _ in $(seq 1 60); do
    if grep -q "^READY " "$f" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "Worker failed to start ($f):"; cat "$f" 2>/dev/null || true; exit 1
}

if [ "$MODE" = "--local" ]; then
  echo "=== Running 7-Scenario 3-Node Verifiable Inference Suite (LOOPBACK MODE) ==="
  "$ROOT/build/infer_node" --bind 127.0.0.1 --port 17915 --layers 0:2 --key "$WORK/n0.sk" --allow-pub "$WORK/cli.pk" --max-sessions 2 >"$WORK/n0.log" 2>&1 & PIDS+=($!)
  "$ROOT/build/infer_node" --bind 127.0.0.1 --port 17916 --layers 2:5 --key "$WORK/n1.sk" --allow-pub "$WORK/cli.pk" --max-sessions 3 >"$WORK/n1.log" 2>&1 & PIDS+=($!)
  "$ROOT/build/infer_node" --bind 127.0.0.1 --port 17917 --layers 0:2 --key "$WORK/bz.sk" --allow-pub "$WORK/cli.pk" --max-sessions 1 --corrupt-step 5 >"$WORK/bz.log" 2>&1 & PIDS+=($!)
  wait_ready "$WORK/n0.log"; wait_ready "$WORK/n1.log"; wait_ready "$WORK/bz.log"

  "$ROOT/build/infer_3node_suite" \
    127.0.0.1 17915 "$WORK/n0.pk" \
    127.0.0.1 17916 "$WORK/n1.pk" \
    127.0.0.1 17917 "$WORK/bz.pk" \
    "$WORK/cli.sk"
  exit 0
fi

echo "=== Deploying Pure-C11 infer_node to Proxmox ($PROX) and MacBook Air ($MAC) ==="
$SSH_P "rm -rf $PDIR && mkdir -p $PDIR"
$SSH_M "rm -rf $MDIR && mkdir -p $MDIR"

$SCP_P "$ROOT/bench/infer_node.c" "$WORK/cli.pk" "$WORK/n0.sk" "$WORK/bz.sk" "root@$PROX:$PDIR/"
$SSH_P "gcc -std=c11 -O3 -Wall -Wextra -Werror -I/usr/local/include $PDIR/infer_node.c \
  -L/usr/local/lib -Wl,-rpath,/usr/local/lib -lsealframe -lsodium -lm -o $PDIR/infer_node"

# On MacBook Air, ship source & compile cleanly with vendored pure-C libsealframe.a
tar -C "$ROOT" --exclude='./build' --exclude='./bin' --exclude='./.git' -cf - . | \
  $SSH_M "tar -xf - -C $MDIR"
$SCP_M "$WORK/cli.pk" "$WORK/n1.sk" "cachy@$MAC:$MDIR/"
$SSH_M "cd $MDIR && make build/infer_node >/dev/null"

echo "=== Launching 3-Device Encrypted Inference Workers ==="
$SSH_P "$PDIR/infer_node --bind 0.0.0.0 --port 17915 --layers 0:2 --key $PDIR/n0.sk --allow-pub $PDIR/cli.pk --max-sessions 2" >"$WORK/n0.log" 2>&1 & PIDS+=($!)
$SSH_P "$PDIR/infer_node --bind 0.0.0.0 --port 17917 --layers 0:2 --key $PDIR/bz.sk --allow-pub $PDIR/cli.pk --max-sessions 1 --corrupt-step 5" >"$WORK/bz.log" 2>&1 & PIDS+=($!)
$SSH_M "$MDIR/build/infer_node --bind 0.0.0.0 --port 17916 --layers 2:5 --key $MDIR/n1.sk --allow-pub $MDIR/cli.pk --max-sessions 3" >"$WORK/n1.log" 2>&1 & PIDS+=($!)

wait_ready "$WORK/n0.log"; echo "  Proxmox Honest    : $(head -n1 "$WORK/n0.log")"
wait_ready "$WORK/bz.log"; echo "  Proxmox Byzantine : $(head -n1 "$WORK/bz.log")"
wait_ready "$WORK/n1.log"; echo "  MacBook Air Mid   : $(head -n1 "$WORK/n1.log")"

"$ROOT/build/infer_3node_suite" \
  "$PROX" 17915 "$WORK/n0.pk" \
  "$MAC"  17916 "$WORK/n1.pk" \
  "$PROX" 17917 "$WORK/bz.pk" \
  "$WORK/cli.sk"
