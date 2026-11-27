#!/usr/bin/env bash
set -euo pipefail

# Honest comparative benchmark: SealFrame (`bin/sf`) vs native system tools
# (`sha256sum`, `zstd`, `zstd --patch-from`, `rsync --checksum`).
# Scope: single-host Linux x86_64 CPU + loopback (NOT physical WAN!).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FP="$ROOT/bin/sf"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "========================================================================"
echo " SealFrame (fp) — Honest Comparative Benchmark (Single-Host x86_64)"
echo " Comparators: sha256sum, zstd $(zstd --version | awk '{print $5}' | tr -d ','), rsync $(rsync --version | head -n1 | awk '{print $3}')"
echo "========================================================================"

python3 - "$TMP" <<'PY'
import os, sys, random
d = sys.argv[1]
rng = random.Random(2026)

# Workload A: 8 MiB structured binary (v1 -> v2 with 4 KiB modified in the middle)
block = bytearray(8 << 20)
for i in range(len(block)):
    block[i] = (65 + (i % 26)) if (i & 63) < 40 else rng.randrange(256)
open(f"{d}/a_v1.bin", "wb").write(block)
v2 = bytearray(block)
mid = len(v2) // 2
for i in range(4096):
    v2[mid + i] ^= (i * 31 + 7) & 0xFF
open(f"{d}/a_v2.bin", "wb").write(v2)

# Workload B: 8 MiB incompressible random shifted by +251 bytes at byte 0
rnd = rng.randbytes(8 << 20)
open(f"{d}/b_v1.bin", "wb").write(rnd)
open(f"{d}/b_v2.bin", "wb").write(rng.randbytes(251) + rnd)
PY

time_ms() {
    python3 - "$@" <<'PY'
import subprocess, sys, time
t0 = time.perf_counter()
subprocess.run(sys.argv[1:], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"{(time.perf_counter() - t0)*1000:.2f}")
PY
}

echo ""
echo "--- 1. Integrity Identity (8 MiB file) ---"
T_SHA=$(time_ms sha256sum "$TMP/a_v2.bin")
T_FP=$(time_ms "$FP" dna "$TMP/a_v2.bin")
printf "  sha256sum (flat SHA-256)          : %7s ms\n" "$T_SHA"
printf "  fp dna    (BLAKE3 16KiB Merkle)   : %7s ms  (includes chunk Merkle tree!)\n" "$T_FP"

echo ""
echo "--- 2. Standalone Compression (8 MiB structured binary) ---"
T_ZSTD=$(time_ms zstd -q -3 -f "$TMP/a_v2.bin" -o "$TMP/a_v2.zst")
SZ_ZSTD=$(stat -c%s "$TMP/a_v2.zst")
T_FPZ=$(time_ms "$FP" morph zstd "$TMP/a_v2.bin" "$TMP/a_v2.fp")
SZ_FPZ=$(stat -c%s "$TMP/a_v2.fp")
printf "  zstd -3                           : %7s ms | size = %9d B\n" "$T_ZSTD" "$SZ_ZSTD"
printf "  fp morph zstd (+56B FP01 + DNA)   : %7s ms | size = %9d B\n" "$T_FPZ" "$SZ_FPZ"

echo ""
echo "--- 3. Delta Encoding (8 MiB v1 -> v2, 4 KiB modified) ---"
T_ZDELTA=$(time_ms zstd -q -3 -f --long=27 --patch-from="$TMP/a_v1.bin" "$TMP/a_v2.bin" -o "$TMP/a_delta.zst")
SZ_ZDELTA=$(stat -c%s "$TMP/a_delta.zst")
T_FPDELTA=$(time_ms "$FP" morph delta "$TMP/a_v2.bin" "$TMP/a_delta.fp" "$TMP/a_v1.bin")
SZ_FPDELTA=$(stat -c%s "$TMP/a_delta.fp")
printf "  zstd --patch-from (no DNA verify) : %7s ms | size = %9d B\n" "$T_ZDELTA" "$SZ_ZDELTA"
printf "  fp morph delta (+DNA+ref_dna)     : %7s ms | size = %9d B\n" "$T_FPDELTA" "$SZ_FPDELTA"

echo ""
echo "--- 4. Shifted Incompressible Update (8 MiB random + 251 B prepended at byte 0) ---"
T_ZRND=$(time_ms zstd -q -3 -f "$TMP/b_v2.bin" -o "$TMP/b_v2.zst")
SZ_ZRND=$(stat -c%s "$TMP/b_v2.zst")
"$FP" ingest "$TMP/cdc" "$TMP/b_v1.bin" >/dev/null
CDC_OUT=$("$FP" ingest "$TMP/cdc" "$TMP/b_v2.bin")
cp "$TMP/b_v1.bin" "$TMP/b_rsync_dst.bin"
RSYNC_STATS=$(rsync --no-whole-file --checksum --stats "$TMP/b_v2.bin" "$TMP/b_rsync_dst.bin")
RSYNC_MATCHED=$(echo "$RSYNC_STATS" | awk '/Matched data:/ {print $3}')
RSYNC_LITERAL=$(echo "$RSYNC_STATS" | awk '/Literal data:/ {print $3}')
printf "  zstd -3 (no shared memory)        : %7s ms | size = %9d B (incompressible)\n" "$T_ZRND" "$SZ_ZRND"
printf "  rsync --no-whole-file --checksum  : matched=%s B | literal=%s B\n" "$RSYNC_MATCHED" "$RSYNC_LITERAL"
printf "  sf ingest (FastCDC Cross-File)    : %s\n" "$CDC_OUT"

echo ""
echo "--- 5. Encrypted Loopback Sync (8 MiB v1 -> v2 delta over TCP) ---"
"$FP" keygen "$TMP/s.key" "$TMP/s.pub" >/dev/null
"$FP" keygen "$TMP/c.key" "$TMP/c.pub" >/dev/null
DNA1=$("$FP" put "$TMP/srv" "$TMP/a_v1.bin" | sed -n 's/.*dna=\([0-9a-f]*\).*/\1/p')
DNA2=$("$FP" put "$TMP/srv" "$TMP/a_v2.bin" | sed -n 's/.*dna=\([0-9a-f]*\).*/\1/p')
"$FP" put "$TMP/cli" "$TMP/a_v1.bin" >/dev/null
"$FP" serve "$TMP/srv" --key "$TMP/s.key" --port 0 --allow-pub "$TMP/c.pub" --max 1 --ready-file "$TMP/port" >/dev/null &
SRV_PID=$!
for _ in $(seq 1 50); do [ -s "$TMP/port" ] && break; sleep 0.02; done
PORT=$(cat "$TMP/port")
FP_PULL_OUT=$("$FP" pull "127.0.0.1:$PORT" "$DNA2" "$TMP/cli" --key "$TMP/c.key" --peer-pub "$TMP/s.pub" --ref "$DNA1")
wait "$SRV_PID"
printf "  fp pull (X25519+XChaCha20+DNA)    : %s\n" "$FP_PULL_OUT"
echo "========================================================================"
echo "Note: Single-host loopback only. Use PHYSICAL_TEST_GUIDE.md for real WAN/ARM64 tests."
