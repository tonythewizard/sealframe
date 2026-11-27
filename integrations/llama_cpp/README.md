# SealFrame × `llama.cpp` (`ggml-rpc`) Bridge & Native Integration Guide

`bin/sf-llama-bridge` is a **100% pure ISO C11** transparent accelerator and cryptographic tunnel for **`llama.cpp` distributed inference (`ggml-rpc`)** — usable **without modifying or recompiling `llama.cpp`**, or embedded directly via `libsealframe.so`.

## What It Replaces in `llama.cpp` `ggml-rpc`

| Feature | Stock `llama.cpp` `ggml-rpc` | With SealFrame (`sf-llama-bridge` / `libsealframe`) |
|---|---|---|
| Transport Security | Plaintext TCP (no auth, no encryption) | 1-RTT X25519+Ed25519 mutual auth + XChaCha20-Poly1305 AEAD |
| WAN Resilience | TCP HoL blocking on packet loss | `FP-UDP1` + proactive **0-RTT XOR FEC** + selective NACK |
| FP32 Activation Wire Size | 100% raw FP32 (`16 KiB/tok` @ `d=4096`) | `SFT1`: `BF16` (`-50%`), `INT8` (`-75%`), `INT4+Outlier FP16` (`-85%`) |
| Verifiability / Keryx | None | Inline rolling BLAKE3 `TraceCommitment` + Ed25519 `FPD1` + Keryx BlockDAG 76B receipt |

---

## Mode 1 — Zero-Modification Drop-In Bridge (`bin/sf-llama-bridge`)

### 1. Generate Ed25519 Node Identities
```bash
# On Remote GPU Worker (Stage 1)
./bin/sf-llama-bridge --keygen worker1.key
# Prints: PubKey (Ed25519): <WORKER1_PK_HEX>

# On Coordinator (where llama-cli / llama-server runs)
./bin/sf-llama-bridge --keygen coord.key
# Prints: PubKey (Ed25519): <COORD_PK_HEX>
```

### 2. Start `rpc-server` + `sf-llama-bridge` on Remote Worker
```bash
# Run standard llama.cpp rpc-server bound ONLY to loopback (never exposed to WAN!)
./rpc-server -H 127.0.0.1 -p 50053 &

# Wrap it with SealFrame FP-UDP1 + 0-RTT XOR FEC + SFT1 INT4+Outlier FP16
./bin/sf-llama-bridge \
  --role server --bind 0.0.0.0 --port 50062 \
  --backend-host 127.0.0.1 --backend-port 50053 \
  --key worker1.key --allow-pk <COORD_PK_HEX> \
  --transport udp --cast int4o
```

### 3. Start Local Bridge + Unmodified `llama-cli` / `llama-server` on Coordinator
```bash
./bin/sf-llama-bridge \
  --role client --listen 127.0.0.1 --listen-port 50052 \
  --remote-host <WORKER1_IP> --remote-port 50062 \
  --key coord.key --peer-pk <WORKER1_PK_HEX> \
  --transport udp --cast int4o &

# Point unmodified llama-cli / llama-server at local bridge!
./llama-cli -m model.gguf --rpc 127.0.0.1:50052 -p "Explain SealFrame:"
```

### 4. Built-In End-to-End Self-Test (including live `keryxd --simnet`)
```bash
./bin/sf-llama-bridge --selftest --transport udp --cast int4o --drop 2 --keryx-ws ws://127.0.0.1:26114
./bin/sf-llama-bridge --selftest --transport tcp --cast int8
```

---

## Mode 2 — Direct Native C/C++ Embedding inside `ggml/src/ggml-rpc/ggml-rpc.cpp`

If you build `llama.cpp` from source, link `-lsealframe` (`pkg-config --cflags --libs libsealframe`) and replace the raw `send_data`/`recv_data` calls inside `ggml_backend_rpc_set_tensor` / `ggml_backend_rpc_get_tensor` with two calls from [`include/sealframe_split.h`](../../include/sealframe_split.h):

```c
#include <sealframe_split.h>

// Sender side (replaces plaintext FP32 TCP send_data in ggml-rpc):
sf_ggml_boundary_send(
    SF_SPLIT_UDP, NULL, udp_sess,
    (sf_ggml_type_t)tensor->type,
    (uint32_t)tensor->ne[0], (uint32_t)tensor->ne[1], seq_pos,
    data, size, FP_WIRE_CAST_INT4_OUTLIER, &out_dna);

// Receiver side (replaces plaintext recv_data in rpc-server):
sf_ggml_boundary_recv(
    SF_SPLIT_UDP, NULL, udp_sess,
    64u << 20, /* upcast_f32 = */ 1,
    &ggml_type, &ne0, &ne1, &seq_pos,
    &out_data, &out_len, &out_dna);
```
