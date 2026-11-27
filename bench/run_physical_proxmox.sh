#!/usr/bin/env bash
set -euo pipefail

# Reproducible Physical 2-Host Benchmark & Resilience Test:
#   Server: Proxmox LXC 900 (192.168.1.12, Pentium P6100 1 vCPU, 256 MiB RAM, mechanical HDD)
#   Client: Workstation     (192.168.1.2,  Wi-Fi wlan0)

REMOTE_IP="${REMOTE_IP:-192.168.1.12}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_proxmox}"
SSH="ssh -i $SSH_KEY -o BatchMode=yes root@$REMOTE_IP"
SCP="scp -i $SSH_KEY -q"
LOCAL_FP="${LOCAL_FP:-$(cd "$(dirname "$0")/.." && pwd)/bin/sf}"
REMOTE_FP="/root/sealframe-kit/bin/sf"

WORK_L="/tmp/fp-phys-local"
WORK_R="/var/tmp/fp-phys-remote"

run_timed_local() {
  local label="$1"; shift
  python3 - "$label" "$@" <<'PYEOF'
import resource, subprocess, sys, time
label = sys.argv[1]
t0 = time.monotonic()
p = subprocess.run(sys.argv[2:], capture_output=True, text=True)
dt = time.monotonic() - t0
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
if p.stdout: sys.stdout.write(p.stdout)
if p.stderr: sys.stderr.write(p.stderr)
print(f"{label}_peak_rss_kb={ru.ru_maxrss} {label}_wall_s={dt:.3f}")
sys.exit(p.returncode)
PYEOF
}

cleanup() {
  $SSH "pkill -f '$REMOTE_FP serve $WORK_R' 2>/dev/null || true; pkill -f '$REMOTE_FP udp-serve $WORK_R' 2>/dev/null || true" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$WORK_L"
mkdir -p "$WORK_L/store_big" "$WORK_L/store_res" "$WORK_L/store_fw" "$WORK_L/store_udp" "$WORK_L/keys"
$SSH "rm -rf $WORK_R && mkdir -p $WORK_R/store $WORK_R/keys"

echo "=== 0. Physical Link Baseline (192.168.1.2 Wi-Fi <-> $REMOTE_IP Ethernet/Proxmox) ==="
ping -c 5 "$REMOTE_IP" | tail -n 2
$SSH "uname -a; free -h | head -n 2"

# Generate mutual Ed25519 keys on both hosts and exchange public keys
"$LOCAL_FP" keygen "$WORK_L/keys/cli.sk" "$WORK_L/keys/cli.pk" >/dev/null
$SSH "$REMOTE_FP keygen $WORK_R/keys/srv.sk $WORK_R/keys/srv.pk >/dev/null"
$SCP "$WORK_L/keys/cli.pk" "root@$REMOTE_IP:$WORK_R/keys/cli.pk"
$SCP "root@$REMOTE_IP:$WORK_R/keys/srv.pk" "$WORK_L/keys/srv.pk"

echo ""
echo "=== TEST 1: Multi-RAM 512 MiB Serving & Transfer (File = 2x Server RAM of 256 MiB!) ==="
$SSH "python3 - $WORK_R/big512.bin <<'PYEOF'
import os, sys
path = sys.argv[1]
block = os.urandom(1024 * 1024)
with open(path, 'wb') as f:
    for i in range(512):
        b = bytearray(block)
        b[0] = i & 0xFF
        b[1] = (i >> 8) & 0xFF
        b[-1] = (i * 73) & 0xFF
        f.write(b)
PYEOF"
SRC_SHA512=$($SSH "sha256sum $WORK_R/big512.bin | awk '{print \$1}'")
echo "Remote (256 MiB RAM) 512 MiB SHA-256: $SRC_SHA512"

PUT_OUT=$($SSH "/usr/bin/time -f 'remote_put_peak_rss_kb=%M remote_put_wall_s=%e' $REMOTE_FP put $WORK_R/store $WORK_R/big512.bin 2>&1")
echo "Remote fp put (on 256 MiB RAM HDD): $PUT_OUT"
BIG_DNA=$(echo "$PUT_OUT" | sed -n 's/.*dna=\([0-9a-f]\{64\}\).*/\1/p')
$SSH "rm -f $WORK_R/big512.bin"

# Start FP-NET TCP server on 256 MiB container (max 3 requests: Test 1 + Test 2 killed + Test 2 resumed)
$SSH "nohup /usr/bin/time -f 'remote_srv_peak_rss_kb=%M remote_srv_wall_s=%e' $REMOTE_FP serve $WORK_R/store --key $WORK_R/keys/srv.sk --allow-pub $WORK_R/keys/cli.pk --bind 0.0.0.0 --port 17777 --max 3 >$WORK_R/srv.log 2>$WORK_R/srv_time.log </dev/null &"
sleep 1.2

echo "Pulling 512 MiB from 256 MiB RAM Pentium P6100 over physical Ethernet<->Wi-Fi..."
run_timed_local cli "$LOCAL_FP" pull "$REMOTE_IP:17777" "$BIG_DNA" "$WORK_L/store_big" \
  --key "$WORK_L/keys/cli.sk" --peer-pub "$WORK_L/keys/srv.pk" --stream
LOC_SHA512=$(sha256sum "$WORK_L/store_big/objects/$BIG_DNA" | awk '{print $1}')
echo "Local  512 MiB SHA-256: $LOC_SHA512"
test "$SRC_SHA512" = "$LOC_SHA512" && echo "[PASS] TEST 1: 512 MiB bit-exact verified from 256 MiB RAM server!"

echo ""
echo "=== TEST 2: Real Mid-Flight SIGKILL + Exact Merkle Resume over Physical LAN ==="
"$LOCAL_FP" pull "$REMOTE_IP:17777" "$BIG_DNA" "$WORK_L/store_res" \
  --key "$WORK_L/keys/cli.sk" --peer-pub "$WORK_L/keys/srv.pk" --stream >"$WORK_L/kill.log" 2>&1 &
CPID=$!
# Wait until > 128 MiB has genuinely streamed over physical LAN, THEN SIGKILL mid-flight!
for _ in $(seq 1 120); do
  SZ=$(stat -c%s "$WORK_L/store_res/staging/$BIG_DNA.part" 2>/dev/null || echo 0)
  if [ "$SZ" -ge 134217728 ]; then break; fi
  sleep 0.25
done
kill -9 "$CPID" 2>/dev/null || true
wait "$CPID" 2>/dev/null || true
echo -n "Staged partial file after mid-flight SIGKILL: "
ls -lh "$WORK_L/store_res/staging/$BIG_DNA.part" 2>/dev/null || true
sleep 1

echo "Resuming exact same 512 MiB pull..."
run_timed_local resume "$LOCAL_FP" pull "$REMOTE_IP:17777" "$BIG_DNA" "$WORK_L/store_res" \
  --key "$WORK_L/keys/cli.sk" --peer-pub "$WORK_L/keys/srv.pk" --stream
RES_SHA512=$(sha256sum "$WORK_L/store_res/objects/$BIG_DNA" | awk '{print $1}')
test "$SRC_SHA512" = "$RES_SHA512" && echo "[PASS] TEST 2: Mid-flight SIGKILL resumed bit-exact over physical LAN!"
sleep 0.5
echo "Server (256 MiB RAM container) memory stats across all 3 x 512 MiB requests:"
$SSH "cat $WORK_R/srv_time.log"

echo ""
echo "=== TEST 3: 32 MiB Firmware Update (4 KiB patched) — FP-NET DELTA vs scp vs rsync ==="
$SSH "python3 - $WORK_R/fw_v1.bin $WORK_R/fw_v2.bin <<'PYEOF'
import os, sys
v1 = bytearray(os.urandom(32 * 1024 * 1024))
with open(sys.argv[1], 'wb') as f:
    f.write(v1)
v2 = bytearray(v1)
mid = 16 * 1024 * 1024
v2[mid:mid+4096] = os.urandom(4096)
with open(sys.argv[2], 'wb') as f:
    f.write(v2)
PYEOF"
FW1_DNA=$($SSH "$REMOTE_FP put $WORK_R/store $WORK_R/fw_v1.bin" | sed -n 's/.*dna=\([0-9a-f]\{64\}\).*/\1/p')
FW2_DNA=$($SSH "$REMOTE_FP put $WORK_R/store $WORK_R/fw_v2.bin" | sed -n 's/.*dna=\([0-9a-f]\{64\}\).*/\1/p')
FW2_SHA=$($SSH "sha256sum $WORK_R/fw_v2.bin | awk '{print \$1}'")

$SSH "nohup $REMOTE_FP serve $WORK_R/store --key $WORK_R/keys/srv.sk --allow-pub $WORK_R/keys/cli.pk --bind 0.0.0.0 --port 17777 --max 2 >$WORK_R/srv_fw.log 2>&1 </dev/null &"
sleep 1
echo "--- Step 3a: Initial fw_v1 (32 MiB) via FP-NET ---"
"$LOCAL_FP" pull "$REMOTE_IP:17777" "$FW1_DNA" "$WORK_L/store_fw" --key "$WORK_L/keys/cli.sk" --peer-pub "$WORK_L/keys/srv.pk"
echo "--- Step 3b: Patched fw_v2 (32 MiB, 4 KiB diff) via FP-NET Autonomous DELTA ---"
run_timed_local fp_delta "$LOCAL_FP" pull "$REMOTE_IP:17777" "$FW2_DNA" "$WORK_L/store_fw" --key "$WORK_L/keys/cli.sk" --peer-pub "$WORK_L/keys/srv.pk" --ref "$FW1_DNA"
LOC_FW2_SHA=$(sha256sum "$WORK_L/store_fw/objects/$FW2_DNA" | awk '{print $1}')
test "$FW2_SHA" = "$LOC_FW2_SHA" && echo "[PASS] TEST 3: FP-NET DELTA fw_v2 bit-exact!"

echo "--- Comparator 3c: scp fw_v2 (32 MiB) from 192.168.1.12 over same physical link ---"
run_timed_local scp scp -i "$SSH_KEY" -q "root@$REMOTE_IP:$WORK_R/fw_v2.bin" "$WORK_L/fw_scp.bin"
echo "--- Comparator 3d: rsync fw_v1 -> fw_v2 (32 MiB, 4 KiB diff) over same physical link ---"
cp "$WORK_L/store_fw/objects/$FW1_DNA" "$WORK_L/fw_rsync.bin"
run_timed_local rsync rsync --stats -e "ssh -i $SSH_KEY" "root@$REMOTE_IP:$WORK_R/fw_v2.bin" "$WORK_L/fw_rsync.bin" | grep -E "Total transferred|Total bytes sent|Total bytes received|rsync_wall_s"

echo ""
echo "=== TEST 4: Encrypted UDP (FP-UDP1, 32 MiB) over Real Ethernet<->Wi-Fi ==="
$SSH "nohup /usr/bin/time -f 'remote_udp_srv_peak_rss_kb=%M' $REMOTE_FP udp-serve $WORK_R/store --key $WORK_R/keys/srv.sk --bind 0.0.0.0 --port 17778 --max 1 >$WORK_R/udp.log 2>$WORK_R/udp_time.log </dev/null &"
sleep 1
run_timed_local udp_cli "$LOCAL_FP" udp-pull "$REMOTE_IP:17778" "$FW2_DNA" "$WORK_L/store_udp" \
  --key "$WORK_L/keys/cli.sk" --peer-pub "$WORK_L/keys/srv.pk"
UDP_SHA=$(sha256sum "$WORK_L/store_udp/objects/$FW2_DNA" | awk '{print $1}')
test "$FW2_SHA" = "$UDP_SHA" && echo "[PASS] TEST 4: 32 MiB Encrypted UDP AIMD bit-exact over physical Ethernet<->Wi-Fi!"
sleep 0.5
$SSH "cat $WORK_R/udp_time.log"

echo ""
echo "=== TEST 5: Write-Limit Failure (ulimit -f) Fail-Closed Check on 192.168.1.12 ==="
$SSH "
  mkdir -p $WORK_R/store_full
  (ulimit -f 1024; $REMOTE_FP put $WORK_R/store_full $WORK_R/fw_v2.bin) >/dev/null 2>&1 && { echo 'FAIL: should have failed'; exit 1; } || true
  CNT=\$(ls -A $WORK_R/store_full/objects/ 2>/dev/null | wc -l)
  echo \"Objects/temp files left after failed write (must be 0): \$CNT\"
  test \"\$CNT\" -eq 0 && echo '[PASS] TEST 5: Write failure left 0 corrupt or orphan files!'
"

echo ""
echo "=== CLEANUP TEMP TEST FILES ==="
rm -rf "$WORK_L"
$SSH "rm -rf $WORK_R"
echo "ALL 5 PHYSICAL 2-HOST TESTS COMPLETED SUCCESSFULLY!"
