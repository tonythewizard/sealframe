# FPM1 disk-backed transfer benchmark

This Linux benchmark calls the public TCP and UDP pull APIs against a separate,
mutually pinned server process on loopback. A 2 GiB file crosses the runtime's
1 GiB disk-index threshold. Each client starts with an empty store. The first
download builds the index, and the second reuses it. These states describe
the FPM1 file only. The kernel page cache is uncontrolled.

## Build and run

From the repository root, build the benchmark against each reference checkout
using the same compiler and flags. GNU linker wrapping observes successful
verification and socket sends in the static library. Assertions must be enabled.
Use the same binary twice for A/A calibration.

```sh
make -j4 all build/bench_fpm_transfer
lab=$(mktemp -d)
cp build/bench_fpm_transfer "$lab/reference"
python3 - "$lab/object" <<'PY'
import hashlib, sys
block = hashlib.shake_256(b'SealFrame FPM1 transfer fixture v1').digest(1 << 20)
with open(sys.argv[1], 'wb') as out:
    for _ in range(2048):
        out.write(block)
PY
dna=$(bin/sf dna "$lab/object" | cut -d' ' -f1 | cut -d= -f2)
mv "$lab/object" "$lab/$dna"
python3 bench/run_fpm_transfer.py "$lab/$dna" "$lab/reference" "$lab/reference" \
  --pairs 2 > "$lab/aa.jsonl"
```

For A/B, replace the second executable with the candidate built against its
own headers and static library. The runner alternates AB and BA across pairs.
It needs space for the fixture, one destination and an index on the chosen
filesystem. A failed transfer exits with an error. Completed rows remain in
the JSONL stream.

## Measurements

- Wall time covers the pull call through publication of the received object.
  The independent final file DNA and size check runs outside that timer.
- Chunk p99 is the nearest-rank 99th percentile of the 131,071 gaps between
  successive successful receiver proof verifications. It measures the pace
  of verified delivery. The startup delay contributes to total wall time.
- Client CPU covers the pull. Server CPU covers its child process lifetime.
  Linux peak RSS is reported separately for each process in KiB.
- Socket bytes sum successful send/sendto return values on both endpoints.
  They include application framing and UDP retries. Kernel TCP retransmission
  and link/IP headers require independent packet capture.
- Each row includes the binary SHA-256, expected and validated object DNA,
  chunk count, protocol, pair, side and initial index state. A small pilot
  can expose trade-offs. A release decision requires independent repeated
  sessions, uncertainty estimates and coverage of production storage and links.
