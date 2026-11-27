/*
 * SealFrame Split-Model & llama.cpp / Keryx Layer-Boundary Shim (Pure ISO C11)
 *
 * Drop-in pure-C11 library for accelerating distributed LLM split-model inference
 * (Keryx / llama.cpp ggml-rpc / homelab multi-device pipelines):
 *
 *   1. Dual Authenticated Encrypted Transport:
 *      - SF_SPLIT_TCP : persistent 1-RTT fp_session_t (X25519+Ed25519 + XChaCha20-Poly1305)
 *      - SF_SPLIT_UDP : persistent 1-RTT fp_udp_session_t (FP-UDP1, selective NACK, 0-HoL)
 *   2. Native SFT1 Layer-Boundary Wire Quantization:
 *      - FP32 (raw), FP16 (-50%), BF16 (-50%, full FP32 range), INT8 (-75% symmetric)
 *   3. Warm Persistent Pipeline Pool + Speculative Multi-Token Batch Forward (K tokens/RTT):
 *      - Amortizes WAN RTT across K draft tokens in a single verified forward pass
 *      - Inline zero-extra-RTT chained BLAKE3 TraceCommitment across all pipeline stages
 *   4. Direct Keryx Live BlockDAG Receipt Sealing:
 *      - Binds pipeline trace + live keryxd sink/virtualDaaScore via sf_keryx_wrpc_call
 *      - Produces Ed25519-signed FPD1 receipt + OPoI Phase-2 8B tag + 76B BlockDAG payload
 *   5. ggml_type Boundary Helpers for llama.cpp ggml-rpc drop-in integration.
 */
#ifndef SEALFRAME_SPLIT_H
#define SEALFRAME_SPLIT_H

#include "fp.h"
#include "sealframe_chain.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SF_SPLIT_MAX_STAGES 8u

typedef enum {
    SF_SPLIT_TCP = 1,
    SF_SPLIT_UDP = 2
} sf_split_transport_t;

/* Exact ggml_type numeric IDs from llama.cpp/ggml for zero-header C ABI compatibility */
typedef enum {
    SF_GGML_TYPE_F32  = 0,
    SF_GGML_TYPE_F16  = 1,
    SF_GGML_TYPE_I8   = 24,
    SF_GGML_TYPE_BF16 = 30
} sf_ggml_type_t;

/* User-provided layer forward callback (plug llama.cpp / ggml / custom kernel here).
 * Input and output buffers are row-major float32 [n_tokens, d_model]. */
typedef fp_err_t (*sf_layer_forward_fn)(
    void *model_ctx,
    uint32_t layer_start,
    uint32_t layer_end,
    uint64_t seq_pos,
    uint32_t n_tokens,
    uint32_t d_model,
    const float *in_act,
    float *out_act);

/* Optional KV-cache reset callback invoked on SF_SPLIT_OP_RESET (<0.2 ms warm reset). */
typedef void (*sf_layer_reset_fn)(void *model_ctx, uint64_t seq_id);

typedef struct {
    sf_split_transport_t transport;
    fp_wire_cast_t       wire_cast;      /* Wire quantization for outgoing activations */
    uint32_t             stage_index;
    uint32_t             layer_start;
    uint32_t             layer_end;
    uint32_t             d_model;
    const fp_keypair_t  *server_kp;
    const uint8_t       *allowed_peer_pk; /* Optional 32B client pubkey pin */
    int                  io_timeout_ms;   /* Default: 15000 ms */
    uint32_t             fault_drop_pct;  /* UDP test hook: drop N% outgoing packets */
    sf_layer_forward_fn  forward_fn;
    sf_layer_reset_fn    reset_fn;
    void                *model_ctx;
} sf_split_worker_cfg_t;

typedef struct {
    const char    *host;
    uint16_t       port;
    const uint8_t *expected_pk; /* Required 32B pinned stage Ed25519 pubkey */
    uint32_t       layer_start;
    uint32_t       layer_end;
} sf_split_stage_ep_t;

typedef struct {
    sf_split_transport_t       transport;
    fp_wire_cast_t             wire_cast;
    uint32_t                   d_model;
    uint32_t                   stage_count; /* 1..SF_SPLIT_MAX_STAGES */
    const sf_split_stage_ep_t *stages;
    const fp_keypair_t        *client_kp;
    int                        io_timeout_ms;
    uint32_t                   fault_drop_pct; /* UDP test hook */
} sf_split_pipe_cfg_t;

typedef struct {
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t udp_retransmits;
    uint64_t udp_fec_recoveries;
    uint64_t straggler_failovers;
    uint64_t forward_calls;
    uint64_t tokens_processed;
    fp_dna_t chain_trace; /* Rolling BLAKE3 commitment across every stage & step */
} sf_split_stats_t;

typedef struct {
    fp_derivation_t        derivation;
    fp_anchor_commitment_t anchor;
    uint8_t                keryx_payload[76];
    uint8_t                keryx_opoi_tag[8];
    uint64_t               keryx_daa_score;
    char                   keryx_sink[80];
    int                    keryx_live; /* 1 if bound to live keryxd node, 0 if offline */
} sf_split_keryx_receipt_t;

typedef struct sf_split_pipe sf_split_pipe_t;

/* Run a warm persistent split-model stage worker on a pre-bound TCP listen_fd or UDP udp_fd.
 * Serves RESET, FORWARD, and SPEC_VERIFY ops until the coordinator sends QUIT or disconnects. */
fp_err_t sf_split_worker_run(int bound_fd, const sf_split_worker_cfg_t *cfg);

/* Open warm persistent connections to all pipeline stages (1-RTT mutual auth per stage). */
fp_err_t sf_split_pipe_open(const sf_split_pipe_cfg_t *cfg, sf_split_pipe_t **out_pipe);

/* Arm a warm standby replica for a stage with a straggler latency budget (ms).
 * If the primary stage disconnects, times out, or exceeds straggler_budget_ms,
 * SealFrame automatically evicts the straggler and promotes the warm standby (0 ms handshake). */
fp_err_t sf_split_pipe_set_standby(sf_split_pipe_t *pipe, uint32_t stage_idx,
                                   const sf_split_stage_ep_t *standby_ep,
                                   int straggler_budget_ms);

/* Warm-reset KV-cache / sequence state across all stages without tearing down sessions. */
fp_err_t sf_split_pipe_reset(sf_split_pipe_t *pipe, uint64_t seq_id);

/* Forward [n_tokens, d_model] FP32 activations through all stages using SFT1 wire_cast.
 * Updates chained BLAKE3 TraceCommitment across every stage with zero extra RTT. */
fp_err_t sf_split_pipe_forward(sf_split_pipe_t *pipe,
                               uint64_t seq_pos, uint32_t n_tokens,
                               const float *in_act, float *out_act,
                               fp_dna_t *out_step_trace);

/* Speculative / Multi-Token Verification: sends [draft_k, d_model] draft token activations
 * through all stages in ONE single pipeline round-trip (amortizing WAN RTT by Kx).
 * If ref_draft_out != NULL, computes per-token cosine similarity against target verified_out
 * and sets *out_accepted_prefix to the longest contiguous accepted prefix (1..draft_k). */
fp_err_t sf_split_pipe_spec_verify(sf_split_pipe_t *pipe,
                                   uint64_t seq_pos, uint32_t draft_k,
                                   const float *draft_in,
                                   const float *ref_draft_out,
                                   float cos_threshold,
                                   float *verified_out,
                                   uint32_t *out_accepted_prefix,
                                   fp_dna_t *out_step_trace);

/* Seal the accumulated pipeline trace into a signed FPD1 derivation + Keryx 76B BlockDAG
 * payload, optionally querying a live keryxd wRPC-JSON endpoint (e.g. "ws://127.0.0.1:26114"). */
fp_err_t sf_split_pipe_seal_keryx(sf_split_pipe_t *pipe,
                                  const fp_keypair_t *signer_kp,
                                  const char *keryx_ws_url,
                                  sf_split_keryx_receipt_t *out_receipt);

void sf_split_pipe_stats(const sf_split_pipe_t *pipe, sf_split_stats_t *out_stats);
void sf_split_pipe_close(sf_split_pipe_t *pipe);

/* --- Direct llama.cpp / ggml-rpc Layer-Boundary Tensor Helpers --- */

fp_err_t sf_ggml_boundary_send(sf_split_transport_t transport,
                               fp_session_t *tcp_sess,
                               fp_udp_session_t *udp_sess,
                               sf_ggml_type_t ggml_type,
                               uint32_t ne0, uint32_t ne1, uint64_t seq_pos,
                               const void *data, size_t data_len,
                               fp_wire_cast_t wire_cast,
                               fp_dna_t *out_dna);

fp_err_t sf_ggml_boundary_recv(sf_split_transport_t transport,
                               fp_session_t *tcp_sess,
                               fp_udp_session_t *udp_sess,
                               size_t max_bytes, int upcast_f32,
                               sf_ggml_type_t *out_ggml_type,
                               uint32_t *out_ne0, uint32_t *out_ne1,
                               uint64_t *out_seq_pos,
                               uint8_t **out_data, size_t *out_data_len,
                               fp_dna_t *out_dna);

/* --- Ring / Daisy-Chain P2P Pipeline (Coord -> S0 -> S1 -> ... -> S(N-1) -> Coord) ---
 * Eliminates Coordinator hub-and-spoke bottleneck (-40%..-50% WAN RTT, N-fold less Coord BW)
 * while preserving per-hop XChaCha20-Poly1305 AEAD + chained BLAKE3 TraceCommitment
 * and Prefix KV-Cache DNA pinning (skips repeated system/RAG prompt prefill). */

#define SF_PREFIX_CACHE_SLOTS 16u

typedef struct {
    sf_split_transport_t transport;
    fp_wire_cast_t       wire_cast;
    uint32_t             stage_index;
    uint32_t             layer_start;
    uint32_t             layer_end;
    uint32_t             d_model;
    const fp_keypair_t  *stage_kp;
    const uint8_t       *prev_allowed_pk;   /* Optional pin for incoming predecessor */
    const char          *next_host;         /* Successor stage host (or Coord return host) */
    uint16_t             next_port;         /* Successor stage port (or Coord return port) */
    const uint8_t       *next_expected_pk;  /* Required 32B pubkey of successor / Coord */
    int                  io_timeout_ms;
    uint32_t             fault_drop_pct;    /* UDP test hook */
    sf_layer_forward_fn  forward_fn;
    sf_layer_reset_fn    reset_fn;
    void                *model_ctx;
} sf_split_ring_worker_cfg_t;

typedef struct {
    sf_split_transport_t transport;
    fp_wire_cast_t       wire_cast;
    uint32_t             d_model;
    uint32_t             stage_count;
    const char          *entry_host;        /* Stage 0 host */
    uint16_t             entry_port;        /* Stage 0 port */
    const uint8_t       *entry_expected_pk; /* Stage 0 Ed25519 pubkey */
    int                  return_fd;         /* Pre-bound Coord return TCP/UDP fd for Stage N-1 */
    const uint8_t       *tail_allowed_pk;   /* Optional pin for Stage N-1 pubkey */
    const fp_keypair_t  *coord_kp;
    int                  io_timeout_ms;
    uint32_t             fault_drop_pct;
} sf_split_ring_cfg_t;

typedef struct sf_split_ring sf_split_ring_t;

fp_err_t sf_split_ring_worker_run(int bound_in_fd, const sf_split_ring_worker_cfg_t *cfg);
fp_err_t sf_split_ring_open(const sf_split_ring_cfg_t *cfg, sf_split_ring_t **out_ring);
fp_err_t sf_split_ring_reset(sf_split_ring_t *ring, uint64_t seq_id);

/* Forward [n_tokens, d_model] around the entire P2P Ring in one single traversal. */
fp_err_t sf_split_ring_forward(sf_split_ring_t *ring,
                               uint64_t seq_pos, uint32_t n_tokens,
                               const float *in_act, float *out_act,
                               fp_dna_t *out_ring_trace);

/* Prefix KV-Cache DNA Pinning over the Ring:
 *   - On first turn (MISS): sends full [total_tokens, d_model], pins prefix_dna across all stages,
 *     writes [total_tokens, d_model] into out_act and sets *out_kv_hit = 0, *out_out_tokens = total_tokens.
 *   - On repeat turn (HIT): sends ONLY [delta_tokens = total_tokens - prefix_tokens, d_model],
 *     skips prefix prefill across all stages, writes [delta_tokens, d_model] into out_act and sets
 *     *out_kv_hit = 1, *out_out_tokens = delta_tokens! */
fp_err_t sf_split_ring_prefix_forward(sf_split_ring_t *ring,
                                      uint64_t seq_pos,
                                      const fp_dna_t *prefix_dna,
                                      uint32_t prefix_tokens,
                                      uint32_t total_tokens,
                                      const float *full_in_act,
                                      float *out_act,
                                      uint32_t *out_out_tokens,
                                      int *out_kv_hit,
                                      fp_dna_t *out_ring_trace);

void sf_split_ring_stats(const sf_split_ring_t *ring, sf_split_stats_t *out_stats);
void sf_split_ring_close(sf_split_ring_t *ring);

/* --- Adaptive Speculative Draft-K Controller (Pure ISO C11) --- */

typedef struct {
    uint32_t min_k;
    uint32_t max_k;
    uint32_t current_k;
    float    ema_accept_rate;
    uint64_t steps;
    uint64_t total_accepted;
} sf_spec_adapt_t;

void     sf_spec_adapt_init(sf_spec_adapt_t *ad, uint32_t min_k, uint32_t max_k, uint32_t init_k);
uint32_t sf_spec_adapt_update(sf_spec_adapt_t *ad, uint32_t proposed_k, uint32_t accepted_k);

#ifdef __cplusplus
}
#endif

#endif /* SEALFRAME_SPLIT_H */
