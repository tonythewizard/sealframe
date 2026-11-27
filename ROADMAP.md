# SealFrame™ Engineering Roadmap

This roadmap tracks completed hardening milestones and planned work to develop methodically without sacrificing hot-path performance or introducing bloat.

---

## Completed Foundation (`v0.6.x → v0.7.0-rc`)

### P0 — Security & Transactional Correctness (Merged)
- [x] **Persistent Transactional Recovery Journal (`.sf_tx_journal`) & Immutable Generations** (`src/bundle.c`): deterministic recovery across all 3 `SIGKILL` commit boundaries (pre-COMMIT, post-COMMIT/pre-flip, post-flip).
- [x] **Fail-Closed Watchdog Semantics** (`src/agent.c`): explicit `FP_AGENT_ROLLBACK_FAILED` / `FP_AGENT_INITIAL_INSTALL_FAILED` non-OK returns and live target deactivation on failed initial install.
- [x] **Cryptographic 2-of-N Ed25519 Quorum Enforcement** (`src/cp_main.c`, `sf sign-approval`): `/api/v1/approvers`, Ed25519 signature verification on `/api/v1/approvals`, mandatory `403` promotion gate.
- [x] **Device Enrollment, Key Pinning & Anti-Replay** (`src/cp_main.c`, `src/agent.c`): `/api/v1/devices/enroll`, `--require-enrolled`, key-swap rejection (`401`), monotonic `hb_seq` replay rejection (`409`).
- [x] **Operational Revocation & Monotonic Emergency Rollback** (`src/agent.c`, `src/cp_main.c`): physical `current` symlink removal + `.sf_revoked` marker, monotonic `FP_ACTION_ROLLBACK` enforcement (`409`).
- [x] **CI Hardening**: all 11 test suites (including `test_agent`, `test_chaos`, `test_redteam`) verified under GCC ASan + UBSan and Clang `-Werror -pedantic`.

### P1 — Scalability, UDP Hardening & Normative Spec (Merged)
- [x] **Multi-GB `O(1)`-RAM Streaming Bundle Staging & Safe GC** (`src/bundle.c`, `sf bundle-gc`): 64 KiB streaming copy with inline BLAKE3 verification, `openat(..., O_DIRECTORY | O_NOFOLLOW)` path hardening, active-generation-safe GC.
- [x] **Historical Multi-Step Root Rotation & Offline Recovery** (`src/agent.c`, `src/cp_main.c`): walk `/repo/roots/<N>.fpr` from expired pinned roots across key rotations up to 4096-event gaps + monotonic root timestamps (`src/trust.c`).
- [x] **Persistent `FPM1` Merkle Index & `O(1)`-RAM Disk Proofs** (`src/dna.c`, `src/net.c`, `src/udp.c`): eliminates repeated full-file Merkle rebuilds; enables `O(log N)` proof extraction via `pread()`.
- [x] **UDP Anti-DoS & Path Validation** (`src/udp.c`): 16-slot multi-session table (no single-packet client eviction), stateless BLAKE3 retry cookie (`U_RETRY`), multi-key client ACL, and AEAD `U_PATH_CHALLENGE` / `U_PATH_RESPONSE` preventing ~500× migration amplification.
- [x] **`sf-llama-bridge` Compatibility Handshake & `--strict-lossless`**: 0-RTT `BR_TAG_HELLO` (`SFLB` v4) protocol check with 0 ms per-token overhead.
- [x] **Normative `SPEC.md` (`SF-001`..`SF-010`)** & **Honest Security/Licensing Calibration** (`LICENSE-COMMERCIAL.md`, `SECURITY.md`, `CONTRIBUTING.md`, `README.md`).

---

## Phase A — Empirical Validation & Benchmarks (`v0.8`, Low Risk)

1. **Vendored Pure-C/ASM BLAKE3 SIMD (AVX2 / SSE4.1 / NEON, Zero C++)**
   - Vendor the upstream C/assembly BLAKE3 SIMD kernels (`blake3_sse41`, `blake3_avx2`, `blake3_neon`) without C++/TBB dependencies for multi-GiB/s hashing out of the box.
2. **Full WAN Ablation Study (`sf-llama-bridge`)**
   - Add **`Stock TCP + local draft`** baseline alongside Stock TCP no-draft, `SF BF16` (pure transport), `SF INT8* + draft`, and `SF INT4o + draft` with `N >= 20` prompts, perplexity/output-drift reporting, and per-optimization isolation (pipelining vs Zstd vs SFT1 vs Top-K vs draft).
2. **Real Multi-Host Physical WAN Benchmark**
   - Validate `sf-llama-bridge` and `FP-UDP1` across >= 2 physically separated hosts over real residential/cloud WAN links (beyond single-host shaping).
3. **QUIC Comparative Baseline**
   - Benchmark `FP-UDP1` against a standard QUIC backend (e.g., `msquic` or `quiche`) on the same lossy/migrating object-transfer and tensor-RPC workloads to quantify where `FP-UDP1` wins and where QUIC is preferable.
4. **Expanded Fuzzing Corpus & Extended Coverage**
   - Add dedicated `libFuzzer` harnesses for the HTTP/JSON parser (`src/cp_main.c`), `FP-UDP1` packet state machine (`src/udp.c`), and `sf-llama-bridge` RPC framing (`sf_llama_bridge.c`), and commit minimal seed corpora + reproducible CI smoke runs.

---

## Phase B — Transport & Control Plane Hardening (`v0.9`)

1. **Control Plane TLS, Root-Signed Approvers & Signed Channel Promotions**
   - Provide built-in authenticated transport for `sf-cp` (either `FP-NET` encrypted reverse-proxy bridge or minimal mTLS integration) + short-lived scoped operator tokens replacing the single static `admin.token`.
   - Anchor approver key sets in root-signed manifests (separating approver management from CP admin Bearer compromise) and emit Ed25519-signed channel promotion receipts verified end-to-end by `sf-agent`.
2. **Strict Fail-Closed Peer Authentication Mode**
   - Add explicit `allow_any_peer` opt-in flag across `FP-NET` and `FP-UDP1` APIs so passing `NULL` peer keys fails closed by default unless explicitly authorized for public content mirrors.
3. **Handshake Formalization (Noise IK/XX Evaluation)**
   - Evaluate migrating the experimental `FPN1`/`FPU1` 1-RTT handshake to a standard **Noise_IK** / **Noise_XX** pattern with explicit key confirmation, server-identity binding in `C_HELLO`, and ProVerif/Tamarin symbolic analysis.
4. **Power-Loss & Disk-Full Fault Injection**
   - Add automated `dm-flakey` / loop-device `ENOSPC` and concurrent multi-agent target-lock stress tests to `tests/test_chaos.c`.
5. **Segmented / Checkpointed Multi-Window SQLite Catch-Up**
   - Extend single-window SQLite catch-up beyond the v0.7 rollback safety bounds (`<= 64` incremental `INSTALL` steps / `<= 32 MiB` cumulative changesets, no mixed `INSTALL+ROLLBACK` in one window) via persisted intermediate checkpoint windows or explicit snapshot-reprovisioning handshakes.

---

## Phase C — Modularization, Conformance & `v1.0`

1. **Source Modularization (Zero Behavior/Perf Change)**
   - Split monolithic translation units (`src/cp_main.c`, `src/udp.c`, `integrations/llama_cpp/sf_llama_bridge.c`) into clean internal modules (`storage/`, `transaction/`, `trust/`, `transport/`, `control_plane/`, `inference/`) while keeping the exact same C11 ABI and single `libsealframe` build.
2. **Product Packaging Split (Shared Core)**
   - Offer clean build targets / packages from one repository:
     - **SealFrame Edge** (`libsealframe-core` + `sf` + `sf-agent` + `sf-cp`): crash-safe OTA & fleet management without inference/blockchain surface.
     - **SealFrame AI** (`libsealframe-core` + `sf-llama-bridge` + `SFT1`): distributed split-model WAN acceleration.
3. **Conformance Golden Vectors & Independent Implementation**
   - Publish deterministic JSON/binary test vectors for `SF-001`..`SF-009` and verify interoperability with a clean-room reference decoder.
4. **Independent Third-Party Security Audit**
   - Commission external review of the cryptographic handshake, TUF trust rotation, bundle recovery state machine, and Control Plane HTTP/SQLite surface prior to declaring `v1.0` production-certified.
