#!/usr/bin/env bash
set -euo pipefail

# Head-to-Head Reproducible Benchmark: SealFrame (v0.5.1) vs Standard Linux Tools
# Measures BOTH local (x86_64 NVMe) and physical 2-host (Proxmox Pentium P6100 256MiB RAM HDD <-> Workstation Wi-Fi).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FP_L="$ROOT/bin/sf"
FP_R="/usr/local/bin/sf"
REMOTE_IP="${REMOTE_IP:-192.168.1.12}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_proxmox}"
SSH="ssh -i $SSH_KEY -o BatchMode=yes root@$REMOTE_IP"
SCP="scp -i $SSH_KEY -q"

WL="/tmp/fp-vs-local"
WR="/var/tmp/fp-vs-remote"

cleanup() {
  $SSH "python3 -c '
import os, signal
for p in os.listdir(\"/proc\"):
    if not p.isdigit(): continue
    try:
        c = open(f\"/proc/{p}/cmdline\", \"rb\").read()
        if b\"/var/tmp/fp-vs-remote\" in c and (b\"/usr/local/bin/sf\" in c or b\"http.server\" in c):
            os.kill(int(p), signal.SIGTERM)
    except Exception: pass
'" 2>/dev/null || true
  rm -rf "$WL"
  $SSH "rm -rf $WR" 2>/dev/null || true
}
trap cleanup EXIT

measure() {
  local label="$1"; shift
  python3 - "$label" "$@" <<'PYEOF'
import resource, subprocess, sys, time
label = sys.argv[1]
t0 = time.monotonic()
p = subprocess.run(sys.argv[2:], capture_output=True, text=True)
dt = time.monotonic() - t0
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
if p.returncode != 0:
    sys.stderr.write(f"FAILED {label}: rc={p.returncode}\n{p.stdout}\n{p.stderr}\n")
    sys.exit(p.returncode)
print(f"{label} | wall={dt:.3f}s | peak_rss={ru.ru_maxrss/1024.0:.2f}MiB | out={(p.stdout.strip().splitlines()[-1] if p.stdout.strip() else '')[:120]}")
PYEOF
}

rm -rf "$WL"
mkdir -p "$WL/store" "$WL/store_fp" "$WL/store_udp" "$WL/store_fw" "$WL/keys"
$SSH "rm -rf $WR && mkdir -p $WR/store $WR/keys"

echo "================================================================================"
echo "  BENCHMARK 1: Integrity Hashing (128 MiB) — fp dna (BLAKE3 Merkle) vs sha256sum"
echo "================================================================================"
python3 - "$WL/hash128.bin" <<'PYEOF'
import os, sys
blk = os.urandom(1024 * 1024)
with open(sys.argv[1], "wb") as f:
    for i in range(128):
        b = bytearray(blk); b[0] = i; f.write(b)
PYEOF
measure "LOCAL  fp dna (128 MiB)  " "$FP_L" dna "$WL/hash128.bin"
measure "LOCAL  sha256sum (128MiB)" sha256sum "$WL/hash128.bin"
$SSH "python3 - $WR/hash64.bin <<'PYEOF'
import os, sys
blk = os.urandom(1024 * 1024)
with open(sys.argv[1], 'wb') as f:
    for i in range(64):
        b = bytearray(blk); b[0] = i; f.write(b)
PYEOF
/usr/bin/time -f 'REMOTE fp dna (64 MiB, P6100)    | wall=%es | peak_rss=%MKB' $FP_R dna $WR/hash64.bin 2>&1 | tail -n 2
/usr/bin/time -f 'REMOTE sha256sum (64 MiB, P6100) | wall=%es | peak_rss=%MKB' sha256sum $WR/hash64.bin 2>&1 | tail -n 2
"

echo ""
echo "================================================================================"
echo "  BENCHMARK 2: Binary Patch & Shift Dedup (32 MiB Structured Firmware)"
echo "================================================================================"
python3 - "$WL/fw_v1.bin" "$WL/fw_v2.bin" "$WL/fw_shifted.bin" <<'PYEOF'
import os, sys
# Realistic compressible+structured firmware (code + weights mix)
rng = os.urandom(1024 * 1024)
v1 = bytearray()
for i in range(32):
    blk = bytearray(rng)
    # 50% structured repetitive tables, 50% high-entropy weights
    for j in range(0, 524288, 64):
        blk[j:j+32] = bytes([(i + (j >> 6)) & 0xFF] * 32)
    blk[524288] = i
    v1.extend(blk)
open(sys.argv[1], "wb").write(v1)
v2 = bytearray(v1)
v2[16*1024*1024 : 16*1024*1024 + 4096] = os.urandom(4096)
open(sys.argv[2], "wb").write(v2)
# Shifted: prepend 137 bytes (breaks fixed-block deduplication!)
shifted = os.urandom(137) + v1[:-137]
open(sys.argv[3], "wb").write(shifted)
PYEOF

measure "fp morph delta (32MiB->v2)" "$FP_L" morph delta "$WL/fw_v2.bin" "$WL/v2.fp" "$WL/fw_v1.bin"
measure "zstd -3 (32MiB full)      " zstd -3 -f -q "$WL/fw_v2.bin" -o "$WL/v2.zst"
measure "gzip -6 (32MiB full)      " gzip -6 -c "$WL/fw_v2.bin" > "$WL/v2.gz" || true
python3 - "$WL/fw_v2.bin" "$WL/v2.gz" <<'PYEOF'
import subprocess, sys, time
t0 = time.monotonic()
with open(sys.argv[2], "wb") as f:
    subprocess.run(["gzip", "-6", "-c", sys.argv[1]], stdout=f, check=True)
dt = time.monotonic() - t0
print(f"gzip -6 (32MiB full)       | wall={dt:.3f}s | out_size={open(sys.argv[2],'rb').seek(0,2)} B")
PYEOF
echo "Sizes: fp_delta=$(stat -c%s "$WL/v2.fp") B | zstd=$(stat -c%s "$WL/v2.zst") B | gzip=$(stat -c%s "$WL/v2.gz") B"

echo "--- Shift Resilience (+137 B prepended to 32 MiB) ---"
measure "fp ingest v1 (FastCDC)     " "$FP_L" ingest "$WL/cdc_store" "$WL/fw_v1.bin"
measure "fp ingest +137B shifted    " "$FP_L" ingest "$WL/cdc_store" "$WL/fw_shifted.bin"

echo ""
echo "================================================================================"
echo "  BENCHMARK 3: Physical 2-Host Cold Transfer (64 MiB Incompressible)"
echo "  Server: Proxmox LXC 900 (Pentium P6100, NO AES-NI, 256MiB RAM, HDD)"
echo "  Client: Workstation (Wi-Fi wlan0)"
echo "================================================================================"
"$FP_L" keygen "$WL/keys/cli.sk" "$WL/keys/cli.pk" >/dev/null
$SSH "$FP_R keygen $WR/keys/srv.sk $WR/keys/srv.pk >/dev/null"
$SCP "$WL/keys/cli.pk" "root@$REMOTE_IP:$WR/keys/cli.pk"
$SCP "root@$REMOTE_IP:$WR/keys/srv.pk" "$WL/keys/srv.pk"

DNA64=$($SSH "$FP_R put $WR/store $WR/hash64.bin" | sed -n 's/.*dna=\([0-9a-f]\{64\}\).*/\1/p')
SHA64=$($SSH "sha256sum $WR/hash64.bin | awk '{print \$1}'")

# 3a. FP-NET TCP Merkle Stream (X25519 + XChaCha20-Poly1305 + 16KiB Merkle)
$SSH "nohup /usr/bin/time -f 'srv_rss_kb=%M' $FP_R serve $WR/store --key $WR/keys/srv.sk --allow-pub $WR/keys/cli.pk --bind 0.0.0.0 --port 17801 --max 1 >$WR/s1.log 2>$WR/s1.t </dev/null &"
sleep 0.8
measure "FP-NET TCP (enc+Merkle)   " "$FP_L" pull "$REMOTE_IP:17801" "$DNA64" "$WL/store_fp" --key "$WL/keys/cli.sk" --peer-pub "$WL/keys/srv.pk" --stream
test "$(sha256sum "$WL/store_fp/objects/$DNA64" | awk '{print $1}')" = "$SHA64"
echo "  -> Remote 256MiB Server: $($SSH cat $WR/s1.t)"

# 3b. FP-UDP1 Encrypted UDP (X25519 + XChaCha20-Poly1305 + AIMD/SRTT)
$SSH "nohup /usr/bin/time -f 'srv_rss_kb=%M' $FP_R udp-serve $WR/store --key $WR/keys/srv.sk --bind 0.0.0.0 --port 17802 --max 1 >$WR/u1.log 2>$WR/u1.t </dev/null &"
sleep 0.8
measure "FP-UDP1 (enc+AIMD+Merkle) " "$FP_L" udp-pull "$REMOTE_IP:17802" "$DNA64" "$WL/store_udp" --key "$WL/keys/cli.sk" --peer-pub "$WL/keys/srv.pk"
test "$(sha256sum "$WL/store_udp/objects/$DNA64" | awk '{print $1}')" = "$SHA64"
echo "  -> Remote 256MiB Server: $($SSH cat $WR/u1.t)"

# 3c. scp (OpenSSH encrypted)
measure "scp (OpenSSH TCP)         " scp -i "$SSH_KEY" -q "root@$REMOTE_IP:$WR/hash64.bin" "$WL/scp64.bin"
test "$(sha256sum "$WL/scp64.bin" | awk '{print $1}')" = "$SHA64"

# 3d. rsync over SSH (cold transfer)
measure "rsync -e ssh (cold)       " rsync -e "ssh -i $SSH_KEY" "root@$REMOTE_IP:$WR/hash64.bin" "$WL/rsync64.bin"
test "$(sha256sum "$WL/rsync64.bin" | awk '{print $1}')" = "$SHA64"

# 3e. curl plain HTTP (unencrypted, unverified baseline)
$SSH "nohup python3 -m http.server 17803 --directory $WR >/dev/null 2>&1 </dev/null &"
sleep 0.8
measure "curl HTTP (PLAIN, no auth)" curl -sS -o "$WL/http64.bin" "http://$REMOTE_IP:17803/hash64.bin"
test "$(sha256sum "$WL/http64.bin" | awk '{print $1}')" = "$SHA64"

echo ""
echo "================================================================================"
echo "  BENCHMARK 4: Physical 2-Host Incremental Update (32 MiB, 4 KiB patched & No-Op)"
echo "================================================================================"
$SCP "$WL/fw_v1.bin" "$WL/fw_v2.bin" "$WL/fw_shifted.bin" "root@$REMOTE_IP:$WR/"
FW1_DNA=$($SSH "$FP_R put $WR/store $WR/fw_v1.bin" | sed -n 's/.*dna=\([0-9a-f]\{64\}\).*/\1/p')
FW2_DNA=$($SSH "$FP_R put $WR/store $WR/fw_v2.bin" | sed -n 's/.*dna=\([0-9a-f]\{64\}\).*/\1/p')
FWS_DNA=$($SSH "$FP_R put $WR/store $WR/fw_shifted.bin" | sed -n 's/.*dna=\([0-9a-f]\{64\}\).*/\1/p')

# Pre-seed local store with fw_v1
"$FP_L" put "$WL/store_fw" "$WL/fw_v1.bin" >/dev/null

$SSH "nohup $FP_R serve $WR/store --key $WR/keys/srv.sk --allow-pub $WR/keys/cli.pk --bind 0.0.0.0 --port 17804 --max 3 >$WR/s4.log 2>&1 </dev/null &"
sleep 0.8

echo "--- 4A: 4 KiB in-place patch (32 MiB) ---"
measure "FP-NET DELTA (32MiB 4K)   " "$FP_L" pull "$REMOTE_IP:17804" "$FW2_DNA" "$WL/store_fw" --key "$WL/keys/cli.sk" --peer-pub "$WL/keys/srv.pk" --ref "$FW1_DNA"
cp "$WL/fw_v1.bin" "$WL/r_v2.bin"
measure "rsync 4K patch (32MiB)    " rsync --stats -e "ssh -i $SSH_KEY" "root@$REMOTE_IP:$WR/fw_v2.bin" "$WL/r_v2.bin"
rsync --stats -e "ssh -i $SSH_KEY" "root@$REMOTE_IP:$WR/fw_v2.bin" "$WL/fw_v1.bin" >/dev/null 2>&1 || true

echo "--- 4B: +137 B shifted binary (32 MiB) ---"
measure "FP-NET DELTA (+137B shift)" "$FP_L" pull "$REMOTE_IP:17804" "$FWS_DNA" "$WL/store_fw" --key "$WL/keys/cli.sk" --peer-pub "$WL/keys/srv.pk" --ref "$FW1_DNA"
cp "$WL/fw_v1.bin" "$WL/r_shift.bin"
python3 - "$SSH_KEY" "$REMOTE_IP" "$WR/fw_shifted.bin" "$WL/r_shift.bin" <<'PYEOF'
import subprocess, sys, time
t0 = time.monotonic()
p = subprocess.run(["rsync", "--stats", "-e", f"ssh -i {sys.argv[1]}", f"root@{sys.argv[2]}:{sys.argv[3]}", sys.argv[4]], capture_output=True, text=True, check=True)
dt = time.monotonic() - t0
sent = [l for l in p.stdout.splitlines() if "Total bytes sent" in l or "Total bytes received" in l]
print(f"rsync +137B shift (32MiB)  | wall={dt:.3f}s | {' ; '.join(sent)}")
PYEOF

echo "--- 4C: Identical file / No-Op sync (32 MiB) ---"
measure "FP-NET REF (0-byte body!) " "$FP_L" pull "$REMOTE_IP:17804" "$FW1_DNA" "$WL/store_fw" --key "$WL/keys/cli.sk" --peer-pub "$WL/keys/srv.pk" --ref "$FW1_DNA"
python3 - "$SSH_KEY" "$REMOTE_IP" "$WR/fw_v1.bin" "$WL/fw_v1.bin" <<'PYEOF'
import subprocess, sys, time
t0 = time.monotonic()
p = subprocess.run(["rsync", "--checksum", "--stats", "-e", f"ssh -i {sys.argv[1]}", f"root@{sys.argv[2]}:{sys.argv[3]}", sys.argv[4]], capture_output=True, text=True, check=True)
dt = time.monotonic() - t0
sent = [l for l in p.stdout.splitlines() if "Total bytes sent" in l or "Total bytes received" in l]
print(f"rsync --checksum No-Op     | wall={dt:.3f}s | {' ; '.join(sent)}")
PYEOF

echo ""
echo "ALL HEAD-TO-HEAD BENCHMARKS COMPLETED!"
