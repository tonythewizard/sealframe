# Physical 2-Host Hardware Verification Report (`v0.2.1`)

> **Date**: 2026-11-26
> **Scope**: Real 2-host physical network (`Ethernet ↔ Wi-Fi`) and constrained legacy hardware validation (low RAM, mechanical HDD, no AVX / no AES-NI).
> **Reproducible Script**: [`bench/run_physical_proxmox.sh`](../bench/run_physical_proxmox.sh)

---

## 1. Physical Testbed

| Role | Host / Environment | CPU | RAM / Disk | OS / Link |
|---|---|---|---|---|
| **Edge Server (Constrained)** | Proxmox LXC `900` (`fp-test`, unprivileged, `192.168.1.12`) on `pve` (`192.168.1.30`) | **Intel Pentium P6100 @ 2.00 GHz** (1 vCPU allocated; 2010 architecture, **NO AVX, NO AES-NI**) | **256 MiB RAM** (+ 512 MiB swap), **8 GiB `ext4`** on mechanical HDD (`local-lvm`) | Debian 13 (Trixie) `amd64`, Gigabit Ethernet (`vmbr0`) |
| **Client Workstation** | Local Linux host (`192.168.1.2`) | Modern `x86_64` | NVMe | Arch Linux `x86_64`, Wi-Fi (`wlan0`) |
| **Physical Network Link** | Real LAN Ethernet ↔ Router/AP ↔ Wi-Fi | — | — | Measured ICMP RTT: `min=1.82 ms`, `avg=7.90 ms`, `max=18.02 ms`, `mdev=5.40 ms` |

---

## 2. Native Build, Hardening & Full Test Suite on Constrained Hardware (`192.168.1.12`)

Built from verified `sealframe-kit.tar.gz` (`SHA256SUMS` verified) directly inside the 256 MiB RAM container:
- **Compiler & Flags**: Debian GCC, `-std=c11 -O3 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wall -Wextra -Werror -pedantic` (**0 warnings**).
- **Binary Footprint**: `bin/sf` = **148 KB**, `build/libsealframe.so` = **131 KB**.
- **ELF Security Check (`make security-check`)**: **PASS** (`PIE/DYN + Full RELRO + NX Stack + Stack Canary`).
- **SBOM (`make sbom`)**: CycloneDX 1.5 JSON generated with exact container deps (`BLAKE3 1.8.2`, `libsodium 1.0.18`, `zstd 1.5.7`, `sqlite 3.46.1`).
- **All 7 Test Suites (`make test`)**: **PASS** — including 10× real `SIGKILL` crashes during composite bundle apply on mechanical HDD (`0` corrupt states), 25% UDP loss + live migration (`29.56 ms`), 4-peer untrusted swarm + poisoned-peer ban, 2-of-3 Root Multi-Sig, and bit-rot detection.
- **Single-Core Pentium P6100 Local Benchmarks (no AVX / no AES-NI)**:
  - BLAKE3 16 KiB Merkle DNA: **560.6 MiB/s**
  - FastCDC Cut (32 MiB): **746.0 MiB/s**
  - Atomic Bundle Apply (`fsync` on mechanical HDD): **0.368 ms / bundle**; Rollback: **0.440 ms**
  - Encrypted TCP Merkle Stream (XChaCha20-Poly1305): **62.0 MiB/s**

---

## 3. Physical 2-Host Real-Network Measurements (`192.168.1.12 ↔ 192.168.1.2`)

| Test | Workload & Condition | Measured Result | Peak RSS (256 MiB Server) | Integrity |
|---|---|---|---|---|
| **Test 1 — Multi-RAM 512 MiB Streaming** | **512 MiB** incompressible blob (**2× container RAM!**) stored via `fp put` and served via `FP-NET` TCP Merkle Stream (`pread()`, 32,768 chunks) | `fp put`: `17.32 s`<br>`fp pull --stream`: **`17.15 s` (29.8 MiB/s)** | `fp put`: **2.44 MiB** (`2496 KB`)<br>`fp serve` (3×512 MiB): **5.86 MiB** (`5996 KB`) | **SHA-256 bit-exact** |
| **Test 2 — Mid-Flight `SIGKILL` + Exact Resume** | `kill -9` client after **134 MiB** staged over physical LAN, then restart exact `fp pull --stream` | **`resumed_chunks=8529`**, `recv_chunks=24239`, `wire=410 MiB` (vs `554 MiB` full), **`12.89 s`** | **5.86 MiB** (same server) | **SHA-256 bit-exact** |
| **Test 3 — 32 MiB Firmware Update (4 KiB diff)** | `FP-NET` Autonomous `DELTA` vs `scp` vs `rsync` over identical Ethernet↔Wi-Fi link | **`FP-NET DELTA`**: **56,332 B wire** (`0.546 s`, **99.83% saved**)<br>`scp` (full 32 MiB): `2.005 s` (**3.67× slower**)<br>`rsync`: `75,442 B` total sent+recv (`0.337 s`) | — | **SHA-256 bit-exact** |
| **Test 4 — 32 MiB Encrypted UDP (`FP-UDP1`)** | 32 MiB (2,048 chunks) over real Ethernet↔Wi-Fi with X25519 + XChaCha20-Poly1305 + AIMD/SRTT | **`1.758 s` (18.2 MiB/s)** — *faster than `scp` over TCP (`2.005 s`)*; **`retrans=0`**, **`cwnd=32`**, **`srtt=4.21 ms`** | **3.30 MiB** (`3376 KB`) | **SHA-256 bit-exact** |
| **Test 5 — Write-Limit Failure (`EFBIG`)** | `ulimit -f 1024` during `fp put` on 4 MiB file (`SIGXFSZ` ignored → kernel returns `EFBIG`) | Fails closed with `FP_ERR_IO`; **0 orphan temp files and 0 corrupt objects** left in `objects/` | — | **Fail-closed** |

---

## 4. Real Production Bugs Caught & Fixed by Physical Hardware Testing

Testing on slow legacy hardware uncovered **4 real-world engineering issues** invisible on NVMe loopback — all fixed and verified in `v0.2.1`:
1. **`FP-UDP1` duplicate `U_HELLO` race on slow HDD**: When `fp_merkle_tree_build_file()` took > 200 ms on the mechanical HDD, the client retransmitted `U_HELLO` and the server destroyed the newly created session `S1` to create `S2`, stalling the transfer. **Fix**: Idempotent `U_HELLO` deduplication (`c_eph + c_nonce` → resend cached `U_WELCOME`) + 500 ms handshake retry (`src/udp.c`).
2. **1-in-128 Ed25519 pubkey first-byte collision in `U_HELLO` dispatch**: Checking `pkt[4] != U_REQ_FRAGS && pkt[4] != U_BYE` on 180-byte `U_HELLO` packets collided whenever a random Ed25519 public key started with byte `0x03` or `0x05`. **Fix**: Dispatch strictly by exact `UDP_HELLO_LEN` (180 B) + Ed25519 signature verification (`src/udp.c`).
3. **CLI streaming `fp put` & Multi-GB ceiling**: Added constant-RAM `fp_store_put_file()` (`64 KiB` buffer, zero file-size `malloc`) and raised CLI streaming pull ceiling to 64 GiB (`src/store.c`, `src/main.c`).
4. **POSIX `SIGXFSZ` / `SIGPIPE` hygiene**: Ignored `SIGPIPE` and `SIGXFSZ` in `src/main.c` so `write()` returns `EFBIG` and `fp_store_put_file()` cleanly `unlink()`s staging files on quota/limit failure.
5. **Packaging insight (Debian 13)**: `libblake3-dev` is not packaged in default Debian 13 apt repos (built cleanly from official BLAKE3 1.8.2 C source); future commercial B2B SDK builds should vendor the 4-file official BLAKE3 C source for zero-friction cross-distro deployment.

---

## 5. Honest Remaining Gaps (Not Yet Physically Executed)
- Physical **ARM64** hardware run (Raspberry Pi / NVIDIA Jetson) — this testbed validated `x86_64 ↔ x86_64` across two physical machines.
- Kernel-level **power-cut (`dm-flakey` / QEMU hard power-off)** across `ext4`, `Btrfs`, `XFS` (LXC shares host kernel; requires dedicated VM/hardware).
- **WAN NAT traversal** (UDP hole-punching / blind encrypted relay across symmetric NATs).
