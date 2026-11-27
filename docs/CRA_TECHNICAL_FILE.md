# EU Cyber Resilience Act (CRA) — Technical Documentation (Annex VII)

> **Product**: SealFrame (`sf` CLI + `libsealframe` C11 Core Library)
> **Version**: `0.2.0` (Phase 1 — Hardened Multi-GB Streaming & AIMD Transport Core)
> **Regulation**: Regulation (EU) 2024/2847 (Cyber Resilience Act — CRA)
> **Commercial Distribution Model**: Proprietary Closed-Source B2B SDK / Binary Component
> **Document Status**: Engineering Draft (Living Technical File — updated at every release gate; formal EU Declaration of Conformity issued at `v1.0` after external audit)

---

## 1. General Description & Intended Purpose (Annex VII, §1)

**SealFrame (`libsealframe` / `sf`)** is a compact, standalone C11 software engine designed for B2B integrators (Industrial IoT, Robotics, Edge AI, Automation, and Critical Infrastructure) to distribute, verify, transform, and atomically commit software artifacts, AI models, and structured SQLite state across untrusted or intermittent networks.

### 1.1 Architectural Boundaries
- **Core Footprint**: Pure ISO C11 (`-std=c11 -Wall -Wextra -Werror -pedantic`), ~3,700 LoC across 11 core modules (`src/*.c`) and 1 public header (`include/fp.h`).
- **Minimal Runtime Dependencies** (tracked automatically via `make sbom` → `build/sbom.cdx.json`):
  - `libblake3` — BLAKE3 cryptographic hashing for 16 KiB Merkle trees and Content DNA.
  - `libsodium` — Ed25519 digital signatures, X25519 ephemeral key exchange, XChaCha20-Poly1305 AEAD, and constant-time memory zeroing (`sodium_memzero`).
  - `libzstd` — Zstandard compression and reference-based `DELTA` morphing with long-distance matching.
  - `sqlite3` (with `SQLITE_ENABLE_SESSION`) — deterministic logical row-level SQLite changesets (`FPB1` atomic bundles).
- **Zero OpenSSL / Zero X.509 PKI Bloat**: Transport authentication uses pinned Ed25519 keys + X25519 ephemeral ECDH (WireGuard-style authenticated handshake), eliminating the ASN.1 / X.509 parser attack surface.
- **Zero Mandatory Cloud or Blockchain Dependency**: All operations function fully offline or on-premises; `src/anchor.c` exposes an optional, decoupled 32-byte commitment hook for external transparency logs without linking any consensus/network stack into the core.

### 1.2 CRA Product Classification Assessment
- **Primary Category**: Component/library integrated into products with digital elements (*Default* category when embedded as an OTA/sync library; *Important Product — Class I* if deployed standalone as a network management/update infrastructure service).
- **Target Conformity Path**: Internal Control (Module A) + voluntary third-party cryptographic/binary penetration test under NDA + future alignment with harmonized standard **IEC 62443-4-1 / 62443-4-2** at `v1.0`.

---

## 2. Design, Architecture & Binary Formats (Annex VII, §2)

All 8 binary formats specified in [`SPEC.md`](../SPEC.md) use explicit big-endian serialization, fixed 4-byte ASCII magic headers, strict bounds checking before allocation, and fail-closed verification:

| Format | Magic | Module(s) | Security Function |
|---|---|---|---|
| Morph Wire | `FP01` | `src/morph.c` | Encodes `RAW`, `ZSTD`, `DELTA`, `REF`, `COMPUTE`; target Content DNA verified *after* materialization |
| Lineage Event | `FPE1` | `src/lineage.c`, `src/store.c` | Ed25519-signed `INSTALL` / `ROLLBACK` / `REVOKE`, monotonic `serial`, `prev_event_hash`, anti-freeze `expires_unix` |
| Signed Derivation | `FPD1` | `src/lineage.c` | Ed25519-signed provenance `parent_dna + op_dna → result_dna` |
| FastCDC Recipe | `FPC1` | `src/cdc.c` | Content-defined chunking (64 KiB avg) manifest; canonical full-file DNA verified on reassembly |
| Atomic Bundle | `FPB1` | `src/bundle.c` | Atomic commit of Files + SQLite logical changesets; crash-safe via temp files + `fsync` + `rename` |
| Multi-Sig Root | `FPR1` | `src/trust.c` | $t$-of-$n$ Ed25519 Root threshold + delegated Release keys + monotonic key rotation & revocation |
| Auth TCP Stream | `FPN1` | `src/net.c`, `src/swarm.c` | X25519 + Ed25519 mutual handshake + XChaCha20-Poly1305 frames; streaming `pread()` + Merkle proof per 16 KiB chunk |
| Auth UDP Stream | `FPU1` | `src/udp.c` | X25519 + Ed25519 handshake + XChaCha20-Poly1305 datagrams; `session_id` migration + AIMD cwnd & Jacobson/Karels SRTT |

---

## 3. Formal STRIDE Threat Model & Mitigations (Annex VII, §3)

| Threat (STRIDE) | Attack Vector | Concrete Mitigation in `libsealframe` | Source Verification |
|---|---|---|---|
| **Spoofing** | Rogue server or MITM impersonates repository or peer | Mutual Ed25519 identity signature over ephemeral X25519 transcript hash (`FPN1/C_HELLO`, `FPN1/S_HELLO`, `FPU1/*`); optional key pinning | `src/net.c`, `src/udp.c` |
| **Spoofing (Key Compromise)** | Single compromised Release signing key pushes malicious update | Multi-Sig $t$-of-$n$ Root manifest (`FPR1`) separates offline Root keys from online Release keys; single key cannot forge Root or rotate trust | `src/trust.c` |
| **Tampering** | Poisoned peer or bit-flip in transit / at rest | Every 16 KiB chunk carries a BLAKE3 Merkle inclusion proof verified against `target_dna` before disk write; poisoned swarm peer is banned immediately on first bad chunk; server verifies `fp_merkle_tree_dna(tree) == target_dna` before serving | `src/dna.c`, `src/swarm.c`, `src/net.c`, `src/udp.c` |
| **Tampering (Downgrade / Freeze)** | Attacker replays old signed firmware or freezes updates indefinitely | Strictly monotonic `serial`, hash-chained `prev_event_hash`, mandatory `expires_unix` anti-freeze check, permanent `revoked` set (`FP_ERR_REVOKED`) | `src/lineage.c`, `src/store.c` |
| **Repudiation / Equivocation** | Compromised key signs two conflicting versions for the same `serial` | Signed derivation chain (`FPD1`) + optional 32B transparency commitment (`src/anchor.c`) detects split-view equivocation (`FP_ERR_CHAIN`) | `src/lineage.c`, `src/anchor.c` |
| **Information Disclosure** | Passive eavesdropping on LAN/WAN/4G or key residue in RAM | End-to-end XChaCha20-Poly1305 AEAD with fresh ephemeral X25519 keys per session (forward secrecy); immediate `sodium_memzero()` of ephemeral/shared/session secrets | `src/net.c`, `src/udp.c` |
| **Denial of Service (Memory Exhaustion)** | Malicious header declares huge size or server serves Multi-GB file into RAM | Strict `max_output_bytes` cap on decode/materialize; zero-`malloc(obj_len)` streaming server via `fp_merkle_tree_build_file()` + `fp_store_open_object_fd()` + `pread()` in fixed 16 KiB buffers | `src/dna.c`, `src/store.c`, `src/morph.c`, `src/net.c`, `src/udp.c` |
| **Denial of Service (Congestion / Packet Loss)** | Lossy wireless/4G links or spoofed UDP datagrams | AEAD tag verified before state mutation; AIMD congestion window (`cwnd`) + Jacobson/Karels SRTT/RTTVAR pacing prevents self-induced congestion collapse | `src/udp.c` |
| **Elevation of Privilege / Memory Corruption** | Buffer overflow, integer overflow, UB in untrusted binary parsers | ISO C11 `-Werror -pedantic`, stack canaries, `_FORTIFY_SOURCE=3`, Full RELRO, PIE, NX stack; 100k ASan/UBSan + 1M release fuzz iterations across all parsers | `Makefile`, `tests/fuzz_parsers.c` |
| **State Corruption (Crash)** | `SIGKILL` / process crash mid-update | Staging files + `fsync()` + atomic `rename()` + SQLite transactional changesets; verified under 10× repeated `SIGKILL` (`tests/test_chaos.c`) | `src/store.c`, `src/bundle.c`, `tests/test_chaos.c` |

---

## 4. CRA Annex I Essential Cybersecurity Requirements Traceability

| CRA Annex I Requirement | Implementation & Evidence in `v0.2.0` | Status |
|---|---|---|
| **I.1(1)** Appropriate level of cybersecurity based on risks | STRIDE threat model (§3), fail-closed cryptographic verification on every layer | Implemented |
| **I.1(2)(a)** No known exploitable vulnerabilities at release | Zero-warning GCC + Clang builds, ASan/UBSan clean, 1.1M fuzz clean, pinned SBOM deps | Verified (local) |
| **I.1(2)(b)** Secure by default configuration | Encryption and Ed25519/DNA verification mandatory (no plaintext/unsigned bypass mode) | Implemented |
| **I.1(2)(c)** Security updates & rollback protection | `FPE1` signed lineage + `FPR1` Multi-Sig + anti-freeze + permanent `REVOKE` | Implemented |
| **I.1(2)(d)** Protection against unauthorized access | Mutual Ed25519 authentication + X25519 ephemeral key exchange | Implemented |
| **I.1(2)(e)** Confidentiality of stored/transmitted data | XChaCha20-Poly1305 AEAD in transit + `sodium_memzero()` key hygiene | Implemented |
| **I.1(2)(f)** Integrity of data, commands, and configuration | BLAKE3 Content DNA + 16 KiB Merkle proofs + Ed25519 signatures | Implemented |
| **I.1(2)(g)** Data minimization | Minimal telemetry/metadata; only 32B DNA, signatures, and required state | Implemented |
| **I.1(2)(h)** Availability & resilience against DoS | Constant-memory `pread()` streaming, AIMD congestion control, swarm peer banning | Implemented |
| **I.1(2)(j)** Minimize attack surface | 148 KB binary, 4 audited C libraries, zero X.509/ASN.1, PIE + Full RELRO + NX + Canary | Verified (`make security-check`) |
| **I.1(2)(l)** Security audit logging | Immutable hash-chained event ledger (`FPE1`) & signed derivations (`FPD1`) | Implemented |
| **I.2(1)** Machine-readable SBOM | Automated CycloneDX 1.5 JSON (`make sbom` → `build/sbom.cdx.json`) | Implemented |
| **I.2(2–8)** Vulnerability handling, CVD & 24h ENISA reporting | Policy defined in §6 below (operationalized prior to commercial `v1.0` launch) | Drafted (Phase 3 gate) |

---

## 5. Secure Development Lifecycle (SDLC) & Verification Evidence (Annex VII, §4–5)

### 5.1 Compiler & Linker Hardening (`Makefile`)
Every release binary (`bin/sf`) and shared library (`build/libsealframe.so`) is compiled with:
- `-std=c11 -O3 -Wall -Wextra -Werror -pedantic`
- `-fstack-protector-strong` (Stack Canaries)
- `-D_FORTIFY_SOURCE=3` (Buffer bounds instrumentation)
- `-fPIE -pie` / `-fPIC` (Full ASLR / Position Independent Executable)
- `-Wl,-z,relro,-z,now` (Full RELRO — read-only GOT after startup)
- `-Wl,-z,noexecstack` (Non-executable stack / NX)

Automated verification command:
```bash
make security-check   # Verifies DYN/PIE, GNU_RELRO, BIND_NOW, NX GNU_STACK, __stack_chk_fail via readelf
```

### 5.2 Reproducible Test, Sanitizer & Fuzzing Gates
- `make test` — 8 unit & integration suites (`test_particle`, `test_net`, `test_cdc`, `test_bundle`, `test_trust`, `test_swarm`, `test_chaos`, `test_agent`).
- `make test-clang` — Independent compiler verification with Clang (`-Werror -pedantic`) + C/Python examples + `security-check`.
- `make test-asan` — AddressSanitizer + UndefinedBehaviorSanitizer across all 8 suites + 100,000 mutated parser inputs.
- `make fuzz` — 1,000,000 deterministic mutated/truncated/corrupted binary inputs across all decoders.
- `make libfuzzer` — Clang coverage-guided **`libFuzzer + ASan + UBSan`** (`tests/libfuzzer_all.c`) across all 7 parser/verifier entrypoints (`FP01`, `FPE1`, `FPD1`, `FPB1`, `FPR1`, `FPC1`, Merkle proofs). Measured baseline (`v0.5.1`): **10,263,534 coverage-guided executions in 16 s (`641,470 exec/s`, `cov=478`, `ft=799`, `0` crashes, `0` UB, `0` leaks)**.
- `make sbom` — Generates verified CycloneDX 1.5 JSON at `build/sbom.cdx.json`.

### 5.3 Honest Scope Disclosure (What Is Verified vs Pending)
- **Verified locally (`x86_64` Arch Linux)**: All 7 suites, GCC 16 + Clang 23 strict builds, ASan/UBSan, 1.1M fuzzing inputs, ELF hardening (`security-check`), CycloneDX 1.5 SBOM, 10× `SIGKILL` bundle crash tests, 25% UDP loss + live socket migration with AIMD/SRTT.
- **Verified physically on 2 real hosts (`Ethernet ↔ Wi-Fi`, see [`docs/PHYSICAL_TEST_REPORT_v0.2.md`](PHYSICAL_TEST_REPORT_v0.2.md))**:
  - Constrained legacy server (Proxmox LXC `900`, Intel Pentium P6100 1 vCPU without AVX/AES-NI, **256 MiB RAM**, Debian 13, mechanical HDD) ↔ workstation (`192.168.1.2`, Wi-Fi).
  - Served **512 MiB** (`2× container RAM`) at **29.8 MiB/s** using **5.86 MiB Peak RSS** (`fp put`: 2.44 MiB Peak RSS), mid-flight `SIGKILL` resume (`8,529` chunks skipped), 32 MiB `DELTA` in **56.3 KiB** wire, 32 MiB encrypted UDP `FPU1` at **18.2 MiB/s** (`0` retransmits, `srtt=4.21 ms`, **3.30 MiB Peak RSS**), and fail-closed `EFBIG` write-limit cleanup.
- **Pending physical / Phase 1–3 gates (NOT yet claimed)**:
  1. Physical **ARM64** target verification (`x86_64 ↔ ARM64` Raspberry Pi / Jetson) over LAN/4G/WAN.
  2. Real kernel power-cut testing (`dm-flakey` / QEMU hard power-off) across `ext4`, `Btrfs`, `XFS`.
  3. Continuous 24/7 `libFuzzer` / `AFL++` corpus campaign (> 1B executions) and external third-party cryptographic/pentest audit under NDA.

---

## 6. Vulnerability Handling, CVD & Support Lifecycle (CRA Annex I Part II)

1. **Support Period**: Minimum **5 years** of security maintenance from the commercial release date of each major `v1.x` LTS branch (aligned with CRA Art. 13(8)).
2. **Coordinated Vulnerability Disclosure (CVD)**:
   - Dedicated security contact (`tonyswagcard@gmail.com`) provided across all releases.
   - Triage SLA: acknowledgment within **24 hours**, severity scoring (CVSS v4.0) within **72 hours**.
3. **CRA Mandatory Reporting Workflow (Art. 14)**:
   - Upon awareness of an **actively exploited vulnerability** or **severe security incident** impacting `libsealframe`:
     - **Within 24 hours**: Early Warning to CSIRT (CSIRT Italia / ACN) and ENISA single reporting platform.
     - **Within 72 hours**: Formal Vulnerability/Incident Notification with initial severity assessment and mitigation guidance.
     - **Within 14 days** (after patch availability): Final Report with root cause, affected versions/DNA, and remediation verification.
4. **Dependency CVE Monitoring**: `build/sbom.cdx.json` is scanned on every build/release against NVD / OSV for `libblake3`, `libsodium`, `libzstd`, and `sqlite3`.

---

## 7. Integrator Security Instructions (CRA Annex II)

B2B integrators embedding `libsealframe` MUST enforce the following operational controls:
1. **Offline Root Key Custody**: Generate `FPR1` Root keys (`t-of-n`, recommended `2-of-3`) on air-gapped hardware or HSM/YubiKey. Never store Root private keys on build servers or edge devices.
2. **Pin Root Keys in Read-Only Storage**: Embed only the Root public keys (and initial `FPR1` manifest) in device firmware/read-only partitions.
3. **Enforce Tight `expires_unix` Windows**: Set realistic expiration windows on `FPE1` events and `FPR1` manifests to bound freeze attacks.
4. **Enforce `max_output_bytes`**: Always pass an application-appropriate ceiling to `fp_morph_materialize()` and `fp_store_get_object()`.
5. **Verify `make security-check` on Target Architecture**: When cross-compiling for ARM64/RISC-V targets, preserve all hardening flags from `Makefile` and re-run `readelf` verification on the target ELF binaries.
