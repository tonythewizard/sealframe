# SealFrame (`sf`) — Normative Wire, Storage & Security Specification (`SF-001`..`SF-010`)

> *"Universal by nature, materialized by context, verified by math."*

This specification defines the normative binary formats, state machines, cryptographic domain separations, crash-recovery contracts, and security boundaries of **SealFrame (`v0.6+`, C11 POSIX/Linux)**.

All multi-byte integers are **big-endian** unless explicitly noted (e.g., upstream `llama.cpp` `ggml-rpc` little-endian headers). All content hashes use **BLAKE3-256** with explicit null-terminated ASCII domain separation tags. All signatures use **Ed25519** (`libsodium`). All transport encryption uses **1-RTT X25519 + Ed25519 + XChaCha20-Poly1305 AEAD**.

---

## SF-001 — Canonical Identity (`DNA`, 32 B) & Persistent Merkle Index (`FPM1`)

### 1.1 Content DNA
Binary left-balanced Merkle tree (RFC 6962 split: `largest_pow2_lt(count)`) over fixed **16 KiB** chunks (`FP_CHUNK_SIZE = 16384`):
- Empty (`len == 0`): `root = BLAKE3("FP1/EMPTY\0")`
- Leaf `i` (`len ∈ [1..16384]`): `BLAKE3("FP1/LEAF\0" || u64_be(i) || u32_be(len) || chunk_bytes)`
- Internal node: `BLAKE3("FP1/NODE\0" || left_32 || right_32)`
- **DNA**: `BLAKE3("FP1/DNA\0" || u64_be(total_size) || root_32)`

### 1.2 Inclusion Proof Verification (`fp_merkle_verify`)
A chunk proof (`chunk_index`, `total_size`, `chunk_len`, `depth <= 64`, `siblings[depth][32]`, `is_right[depth]`) is accepted **if and only if**:
1. `total_size > 0`, `chunk_index < ceil(total_size / 16384)`, and `chunk_len` matches the exact expected chunk length (16384 for non-final chunks, remainder for the final chunk).
2. Folding `hash_leaf(chunk_index, chunk_data)` bottom-up across `siblings[0..depth-1]` yields `root` such that `BLAKE3("FP1/DNA\0" || u64_be(total_size) || root) == expected_dna`.

### 1.3 Persistent On-Disk Merkle Index (`FPM1`)
Stored atomically alongside CAS objects as `<obj_path>.fpm` to eliminate repeated full-file reads and enable `O(log N)` disk proofs in `O(1)` RAM (`fp_merkle_prove_from_index_file`):
- **Header (56 B):** `"FPM1"` (4) | `total_size` (u64) | `nchunks` (u64) | `used_nodes` (u32, MUST equal `2*nchunks - 1`) | `dna` (32 B).
- **Nodes (`used_nodes * 40 B`):** `hash` (32 B) | `left` (u32, `UINT32_MAX` for leaves) | `right` (u32, `UINT32_MAX` for leaves).
- **Validation:** Readers MUST reject files whose byte length != `56 + used_nodes * 40`, whose node indices are out of range, or where `hash_dna_root(total_size, nodes[0].hash) != expected_dna`.

---

## SF-002 — Morph Wire Format (`FP01`)

Separates canonical content identity (`DNA`) from wire representation:
- **Magic:** `"FP01"` (4 B) | `version` (u16 = 1) | `kind` (u8: `0=RAW`, `1=ZSTD`, `2=DELTA`, `3=REF`, `4=COMPUTE`) | `flags` (u8: bit 0 = `FP_WIRE_FLAG_REF`) | `canonical_size` (u64) | `payload_size` (u64) | `dna` (32 B) | `[ref_dna (32 B) if flag bit 0]` | `payload[payload_size]`.
- **Fail-Closed Rule:** Materialization MUST recompute `fp_dna_compute(output) == dna` before releasing bytes. `output_size` is bounded by caller `max_output`.

---

## SF-003 — Content-Addressed Storage (`CAS`) & FastCDC Composition (`FPC1`)

- **Object Layout:** `<store_dir>/objects/<64-hex-dna>` written via `mkstemp` + `fsync(fd)` + atomic `rename` + `fsync(dir)`.
- **FastCDC Recipe (`FPC1`):** Gear-hash content-defined chunking (4–64 KiB, avg ~20 KiB, chunk hash `BLAKE3("FP1/CHUNK\0" || bytes)`). Streams in `O(1)` chunker RAM and verifies reconstructed canonical `DNA` end-to-end before commit.

---

## SF-004 — Composite File + SQLite Transactions (`FPB1` + `.sf_tx_journal`)

### 4.1 Bundle Manifest (`FPB1`)
Binds `FP_ROLE_FILE (1)` (arbitrary multi-GB files/models, streamed in 64 KiB `O(1)` RAM via `openat(O_NOFOLLOW)`) and `FP_ROLE_SQLITE_CHANGESET (2)` (SQLite Session extension binary changesets, max 64 MiB) under one root `DNA`.
- Path validation rejects absolute paths, empty segments, `.` / `..`, control chars, and intermediate symlinks (`openat(..., O_DIRECTORY | O_NOFOLLOW)`).
- Table filter blocks modifications to internal `_fp_progress`.

### 4.2 Immutable Generations & Transactional Journal (`.sf_tx_journal`)
Generations live under `<target_dir>/gen/<dna_hex>/` and are **immutable once sealed** (`.sf_gen_sealed`). Staging happens in `<target_dir>/gen/.stage-<dna_hex>-<pid>` followed by atomic `rename()`.

Commit state machine (recorded atomically in `<target_dir>/.sf_tx_journal`: `SFTX1 <state> <seq> <dna_hex> <has_sql>`):
1. `STAGING`: stream-stage files with inline BLAKE3 verification, seal `.sf_gen_sealed`, publish `gen/<dna_hex>`.
2. `ACTIVATION_PENDING`: fsync journal BEFORE `SQLite COMMIT`.
3. `SQLite WAL COMMIT`: apply changesets + update `_fp_progress(seq, dna_hex)` in one `BEGIN IMMEDIATE ... COMMIT`.
4. `ATOMIC FLIP`: `symlink("gen/<dna_hex>", ".current-new-<pid>")` + `rename` → `current` + `fsync(target_dir)`.
5. `COMMITTED`: seal journal.

**Deterministic Crash Recovery (`fp_bundle_recover`):**
- If interrupted in `STAGING` or in `ACTIVATION_PENDING` *before* SQLite `COMMIT`: live `current` and DB remain at previous generation; journal is cleared.
- If interrupted in `ACTIVATION_PENDING` *after* SQLite `COMMIT` (before symlink flip): `fp_bundle_recover` detects `_fp_progress == (seq, dna_hex)` and deterministically completes forward symlink activation + seals `COMMITTED`.
- Garbage collection (`fp_bundle_gc`) removes `.stage-*` / `.stale-*` and old generations while strictly protecting `current` and the most recent `keep_last` inactive generations.

---

## SF-005 — Root Trust (`FPR1`), Lineage (`FPE1`), Derivation (`FPD1`) & Anchor

- **`FPR1` (TUF-Style k-of-n Root Multi-Sig):** Up to 8 root keys, threshold `k <= n`, `root_version` strictly monotonic (`vN -> vN+1`), dual-quorum rotation (valid `k_old` signatures from `prev` AND `k_new` signatures from `next`), monotonic key revocation list (`revoked_keys` never shrinks).
  - Historical offline recovery: agents walk `/repo/roots/<v+1>.fpr` (fallback `/repo/root.fpr`) cryptographically before enforcing wall-clock `expires_unix` freshness on the final active root.
- **`FPE1` (Signed Event Chain):** `INSTALL (1)`, `ROLLBACK (2, reason required)`, `REVOKE (3, target_size == 0)`, domain `"FP1/EVENT\0"`, strictly increasing `serial = prev + 1`, hash-linked via `prev_event_hash`.
- **`FPD1` (Derivation Attestation):** Signs `parent_dna + op_dna -> result_dna` (`parent != result`) under `"FP1/DERIVE\0"`.
- **Transparency Anchor:** `BLAKE3("FP1/ANCHOR\0" || repo_id || u64_be(serial) || event_hash || target_dna)`.

---

## SF-006 — Encrypted Transport (`FPN1` TCP & `FPU1` UDP)

- **1-RTT Handshake:** Ephemeral X25519 ECDH + static Ed25519 mutual authentication; keys derived via BLAKE3 transcript hash; optional `allowed_peer_pk` enforced **before** any disk I/O or Merkle lookup.
- **AEAD Framing:** XChaCha20-Poly1305 with monotonic 64-bit sequence nonces and 64-packet sliding anti-replay window on UDP.
- **`FP-UDP1` (`FPU1`):** MTU-safe (< 1280 B), selective fragment ARQ, adaptive 0-RTT XOR FEC, and 64-bit `session_id` routing enabling seamless live IP/port migration.

---

## SF-007 — Edge OTA Lifecycle & Control Plane Governance

- **Health Watchdog (`sf-agent`):** Executes `--health-cmd` in an isolated process group with `SIGKILL` timeout.
  - Failure with previous generation → automatic `fp_bundle_rollback()` (inverts SQLite changesets + flips `current` back). If rollback fails → returns non-`FP_OK` with `FP_AGENT_ROLLBACK_FAILED`.
  - Failure on initial install → unlinks `current`, returns non-`FP_OK` with `FP_AGENT_INITIAL_INSTALL_FAILED`.
- **Operational Revocation (`FP_ACTION_REVOKE`):** Advances store state, physically unlinks `<target_dir>/current`, and writes `<target_dir>/.sf_revoked`.
- **Monotonic Emergency Rollback:** Requires a new signed `FP_ACTION_ROLLBACK` event with `serial > active_channel_serial` (Control Plane rejects `serial <= active` with `409 Conflict`).
- **Control Plane Governance (`sf-cp`):**
  - **Device Identity & Anti-Replay:** `/api/v1/devices/enroll` + key-pinning (`401` on key-swap impersonation) + strictly monotonic `hb_seq` (`409` on replay).
  - **Cryptographic 2-of-N Approver Quorum:** `/api/v1/approvers` registers Ed25519 approver keys; `/api/v1/approvals` verifies Ed25519 signatures over `"SF_APPROVAL_V1|<channel>|<serial>|<event_hash_hex>"`; channel promotion blocks with `403 Forbidden` unless `>= 2` distinct verified approvals match `(channel, serial, event_hash)`.

---

## SF-008 & SF-009 — Verified Tensor Wire Format (`SFT1`) & Distributed Inference Bridge

- **`SFT1` (32 B Header):** `"SFT1"` | `version` | `dtype` (`FP32`, `FP16`, `BF16`, `INT8`, `INT4_G32`, `INT4_OUTLIER`) | `ndim` (1..4) | `flags` | `dims[4]` | `seq_id`. Per-tensor `INT8` automatically promotes frames with `crest_factor > 24` to `BF16`.
- **`sf-llama-bridge` Compatibility Handshake (`BR_TAG_HELLO = 13`):** 20-byte session preamble (`"SFLB"` | `proto_ver=4` | `ggml_tensor_hdr_len=296` | `ggml_cmd_max=16` | `cap_bitmap` | `wire_cast` | `strict_lossless` | `logits_topk` | `reserved`) verified fail-closed at connection setup (0 overhead on per-token decode).
- **Sparse FP32 Top-K Logits (`BR_TAG_RESP_TOPK`):** Transmits exact FP32 values for the top-`K` logits per row and fills excluded vocabulary entries with `-1e9f` (exact for greedy / top-k `<= K`; alters full-vocab sampling distributions when `K < vocab`). Use `--strict-lossless` to disable lossy codecs and Top-K completely.

---

## SF-010 — Threat Model & Security Boundaries

- **Protected against:** MITM tampering (AEAD + Merkle proofs), single-key compromise (k-of-n Root Multi-Sig), rollback/freeze attacks (monotonic serials + expiry), Byzantine swarm peers (chunk-level Merkle verification + ban on first bad chunk), symlink traversal (`openat` + `O_NOFOLLOW`), telemetry spoofing/replay (enrolled Ed25519 key-pinning + monotonic `hb_seq`), single-admin rollout bypass (Ed25519 2-of-N approver quorum), and OS `SIGKILL` crashes at any bundle commit boundary.
- **Explicit assumptions / out-of-scope:** Physical host kernel compromise, volatile disk write-cache lying about `fsync` on power loss, and plaintext HTTP Control Plane exposure without a TLS/mTLS reverse proxy or `FP-NET` tunnel.
