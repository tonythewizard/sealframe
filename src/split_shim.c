/*
 * SealFrame Split-Model & llama.cpp / Keryx Layer-Boundary Shim (Pure ISO C11)
 *
 * Implements warm persistent multi-stage activation transport over TCP (fp_session_t)
 * or FP-UDP1 (fp_udp_session_t), native SFT1 BF16/INT8 wire quantization, speculative
 * K-token batched verification, chained inline BLAKE3 TraceCommitment, live Keryx
 * BlockDAG receipt sealing, and ggml_type boundary helpers for llama.cpp ggml-rpc.
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe_split.h"

#include <blake3.h>
#include <math.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
    SF_SPLIT_OP_RESET       = 1,
    SF_SPLIT_OP_FORWARD     = 2,
    SF_SPLIT_OP_SPEC_VERIFY = 3,
    SF_SPLIT_OP_GGML_TENSOR = 4,
    SF_SPLIT_OP_RING_FWD    = 5,
    SF_SPLIT_OP_RING_PREFIX = 6,
    SF_SPLIT_OP_QUIT        = 99
};

#define SF_RING_HDR_LEN     76u /* chain(32) | prefix_dna(32) | prefix_tok(4) | total_tok(4) | flags(4) */
#define SF_RING_FLAG_KV_HIT 0x01u

struct sf_split_pipe {
    sf_split_transport_t transport;
    fp_wire_cast_t       wire_cast;
    uint32_t             d_model;
    uint32_t             stage_count;
    fp_keypair_t         client_kp;
    int                  io_timeout_ms;
    uint32_t             fault_drop_pct;
    fp_session_t        *tcp[SF_SPLIT_MAX_STAGES];
    fp_udp_session_t    *udp[SF_SPLIT_MAX_STAGES];
    fp_session_t        *standby_tcp[SF_SPLIT_MAX_STAGES];
    fp_udp_session_t    *standby_udp[SF_SPLIT_MAX_STAGES];
    int                  straggler_budget_ms[SF_SPLIT_MAX_STAGES];
    uint64_t             straggler_failovers;
    uint64_t             retired_tx;
    uint64_t             retired_rx;
    uint64_t             retired_retx;
    uint64_t             retired_fec;
    fp_dna_t             chain_trace;
    uint64_t             forward_calls;
    uint64_t             tokens_processed;
};

static uint64_t split_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void put_be64(uint8_t dst[8], uint64_t v) {
    dst[0] = (uint8_t)(v >> 56); dst[1] = (uint8_t)(v >> 48);
    dst[2] = (uint8_t)(v >> 40); dst[3] = (uint8_t)(v >> 32);
    dst[4] = (uint8_t)(v >> 24); dst[5] = (uint8_t)(v >> 16);
    dst[6] = (uint8_t)(v >> 8);  dst[7] = (uint8_t)(v);
}

static uint64_t get_be64(const uint8_t src[8]) {
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  | ((uint64_t)src[7]);
}

static void put_be32(uint8_t dst[4], uint32_t v) {
    dst[0] = (uint8_t)(v >> 24); dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);  dst[3] = (uint8_t)(v);
}

static void chain_trace_update(fp_dna_t *chain, uint32_t stage_idx,
                               uint64_t seq_pos, const fp_dna_t *stage_dna) {
    static const uint8_t dom[16] = "SF_SPLIT/TRACE1";
    uint8_t sb[4], pb[8];
    put_be32(sb, stage_idx);
    put_be64(pb, seq_pos);
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, dom, sizeof(dom));
    blake3_hasher_update(&h, chain->bytes, FP_DNA_LEN);
    blake3_hasher_update(&h, sb, 4);
    blake3_hasher_update(&h, pb, 8);
    blake3_hasher_update(&h, stage_dna->bytes, FP_DNA_LEN);
    blake3_hasher_finalize(&h, chain->bytes, FP_DNA_LEN);
}

static fp_err_t xport_send_raw(sf_split_transport_t tr, fp_session_t *ts,
                               fp_udp_session_t *us, uint8_t tag,
                               const uint8_t *data, size_t len, fp_dna_t *dna) {
    if (tr == SF_SPLIT_TCP) return fp_session_send_verified(ts, tag, data, len, dna);
    return fp_udp_session_send_verified(us, tag, data, len, dna);
}

static fp_err_t xport_recv_raw(sf_split_transport_t tr, fp_session_t *ts,
                               fp_udp_session_t *us, size_t max_bytes,
                               uint8_t *tag, uint8_t **data, size_t *len, fp_dna_t *dna) {
    if (tr == SF_SPLIT_TCP) return fp_session_recv_verified(ts, max_bytes, tag, data, len, dna);
    return fp_udp_session_recv_verified(us, max_bytes, tag, data, len, dna);
}

static fp_err_t xport_send_tensor(sf_split_transport_t tr, fp_session_t *ts,
                                  fp_udp_session_t *us, uint8_t tag,
                                  const fp_tensor_meta_t *meta,
                                  const void *data, size_t data_len,
                                  fp_wire_cast_t cast, fp_dna_t *dna) {
    if (tr == SF_SPLIT_TCP) {
        return fp_session_send_tensor_ex(ts, tag, meta, data, data_len, cast, dna);
    }
    return fp_udp_session_send_tensor(us, tag, meta, data, data_len, cast, dna);
}

static fp_err_t xport_recv_tensor(sf_split_transport_t tr, fp_session_t *ts,
                                  fp_udp_session_t *us, size_t max_bytes,
                                  int upcast_f32, uint8_t *tag,
                                  fp_tensor_meta_t *meta, uint8_t **data,
                                  size_t *data_len, fp_dna_t *dna) {
    if (tr == SF_SPLIT_TCP) {
        return fp_session_recv_tensor(ts, max_bytes, upcast_f32, tag, meta, data, data_len, dna);
    }
    return fp_udp_session_recv_tensor(us, max_bytes, upcast_f32, tag, meta, data, data_len, dna);
}

/* ==================== Stage Worker Loop ==================== */

fp_err_t sf_split_worker_run(int bound_fd, const sf_split_worker_cfg_t *cfg) {
    if (bound_fd < 0 || !cfg || !cfg->server_kp || !cfg->forward_fn || cfg->d_model == 0) {
        return FP_ERR_INVALID;
    }
    int timeout_ms = cfg->io_timeout_ms > 0 ? cfg->io_timeout_ms : 15000;
    fp_session_t *ts = NULL;
    fp_udp_session_t *us = NULL;
    fp_err_t err = FP_OK;

    if (cfg->transport == SF_SPLIT_TCP) {
        err = fp_session_accept(bound_fd, cfg->server_kp, cfg->allowed_peer_pk, timeout_ms, &ts);
    } else if (cfg->transport == SF_SPLIT_UDP) {
        err = fp_udp_session_accept(bound_fd, cfg->server_kp, cfg->allowed_peer_pk,
                                    timeout_ms, cfg->fault_drop_pct, &us);
    } else {
        return FP_ERR_INVALID;
    }
    if (err != FP_OK) return err;

    for (;;) {
        uint8_t tag = 0;
        uint8_t *wire = NULL;
        size_t wlen = 0;
        err = xport_recv_raw(cfg->transport, ts, us, 32u << 20, &tag, &wire, &wlen, NULL);
        if (err != FP_OK) break;

        if (tag == SF_SPLIT_OP_QUIT) {
            free(wire);
            err = FP_OK;
            break;
        }
        if (tag == SF_SPLIT_OP_RESET) {
            uint64_t seq_id = (wlen >= 8u) ? get_be64(wire) : 0u;
            free(wire);
            if (cfg->reset_fn) cfg->reset_fn(cfg->model_ctx, seq_id);
            uint8_t ok = 1u;
            err = xport_send_raw(cfg->transport, ts, us, SF_SPLIT_OP_RESET, &ok, 1u, NULL);
            if (err != FP_OK) break;
            continue;
        }
        if (tag == SF_SPLIT_OP_FORWARD || tag == SF_SPLIT_OP_SPEC_VERIFY) {
            fp_tensor_meta_t in_meta;
            uint8_t *in_bytes = NULL;
            size_t in_len = 0;
            err = fp_tensor_unpack(wire, wlen, 1, &in_meta, &in_bytes, &in_len);
            free(wire);
            if (err != FP_OK) break;
            if (in_meta.ndim != 2u || in_meta.dims[1] != cfg->d_model ||
                in_meta.dtype != FP_DTYPE_FP32) {
                free(in_bytes);
                err = FP_ERR_INVALID;
                break;
            }
            uint32_t n_tok = in_meta.dims[0];
            size_t elems = (size_t)n_tok * (size_t)cfg->d_model;
            float *out_act = malloc(elems * sizeof(float));
            if (!out_act) { free(in_bytes); err = FP_ERR_NOMEM; break; }

            err = cfg->forward_fn(cfg->model_ctx, cfg->layer_start, cfg->layer_end,
                                  in_meta.seq_id, n_tok, cfg->d_model,
                                  (const float *)in_bytes, out_act);
            free(in_bytes);
            if (err != FP_OK) { free(out_act); break; }

            /* Pack output activation into SFT1 (BF16/INT8/FP16/FP32) and send back.
             * The verified message DNA itself serves as the zero-extra-RTT TraceCommitment! */
            fp_tensor_meta_t out_meta;
            memset(&out_meta, 0, sizeof(out_meta));
            out_meta.dtype   = FP_DTYPE_FP32;
            out_meta.ndim    = 2u;
            out_meta.dims[0] = n_tok;
            out_meta.dims[1] = cfg->d_model;
            out_meta.seq_id  = in_meta.seq_id;

            err = xport_send_tensor(cfg->transport, ts, us, tag, &out_meta,
                                    out_act, elems * sizeof(float), cfg->wire_cast, NULL);
            free(out_act);
            if (err != FP_OK) break;
            continue;
        }

        free(wire);
        err = FP_ERR_INVALID;
        break;
    }

    if (ts) fp_session_close(ts);
    if (us) fp_udp_session_close(us);
    return err;
}

/* ==================== Pipeline Coordinator ==================== */

fp_err_t sf_split_pipe_open(const sf_split_pipe_cfg_t *cfg, sf_split_pipe_t **out_pipe) {
    if (!cfg || !out_pipe || !cfg->stages || !cfg->client_kp || cfg->d_model == 0 ||
        cfg->stage_count == 0 || cfg->stage_count > SF_SPLIT_MAX_STAGES) {
        return FP_ERR_INVALID;
    }
    *out_pipe = NULL;

    sf_split_pipe_t *p = calloc(1, sizeof(*p));
    if (!p) return FP_ERR_NOMEM;
    p->transport      = cfg->transport;
    p->wire_cast      = cfg->wire_cast;
    p->d_model        = cfg->d_model;
    p->stage_count    = cfg->stage_count;
    p->client_kp      = *cfg->client_kp;
    p->io_timeout_ms  = cfg->io_timeout_ms > 0 ? cfg->io_timeout_ms : 15000;
    p->fault_drop_pct = cfg->fault_drop_pct;

    int timeout_ms = p->io_timeout_ms;
    for (uint32_t s = 0; s < cfg->stage_count; s++) {
        const sf_split_stage_ep_t *ep = &cfg->stages[s];
        if (!ep->host || ep->port == 0 || !ep->expected_pk) {
            sf_split_pipe_close(p);
            return FP_ERR_INVALID;
        }
        fp_err_t err;
        if (cfg->transport == SF_SPLIT_TCP) {
            err = fp_session_connect(ep->host, ep->port, cfg->client_kp,
                                     ep->expected_pk, timeout_ms, &p->tcp[s]);
        } else if (cfg->transport == SF_SPLIT_UDP) {
            err = fp_udp_session_connect(ep->host, ep->port, cfg->client_kp,
                                         ep->expected_pk, timeout_ms,
                                         cfg->fault_drop_pct, &p->udp[s]);
        } else {
            err = FP_ERR_INVALID;
        }
        if (err != FP_OK) {
            sf_split_pipe_close(p);
            return err;
        }
    }

    *out_pipe = p;
    return FP_OK;
}

static void pipe_promote_standby(sf_split_pipe_t *pipe, uint32_t s) {
    uint64_t tx = 0, rx = 0, retx = 0;
    if (pipe->transport == SF_SPLIT_TCP) {
        if (pipe->tcp[s]) {
            fp_session_stats(pipe->tcp[s], &tx, &rx);
            pipe->retired_tx += tx; pipe->retired_rx += rx;
            (void)fp_session_send_verified(pipe->tcp[s], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
            fp_session_close(pipe->tcp[s]);
        }
        pipe->tcp[s] = pipe->standby_tcp[s];
        pipe->standby_tcp[s] = NULL;
    } else {
        if (pipe->udp[s]) {
            fp_udp_session_stats(pipe->udp[s], &tx, &rx, &retx);
            pipe->retired_tx += tx; pipe->retired_rx += rx;
            pipe->retired_retx += retx;
            pipe->retired_fec += fp_udp_session_fec_recoveries(pipe->udp[s]);
            (void)fp_udp_session_send_verified(pipe->udp[s], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
            fp_udp_session_close(pipe->udp[s]);
        }
        pipe->udp[s] = pipe->standby_udp[s];
        pipe->standby_udp[s] = NULL;
    }
    pipe->straggler_budget_ms[s] = 0;
    pipe->straggler_failovers++;
}

fp_err_t sf_split_pipe_set_standby(sf_split_pipe_t *pipe, uint32_t stage_idx,
                                   const sf_split_stage_ep_t *standby_ep,
                                   int straggler_budget_ms) {
    if (!pipe || stage_idx >= pipe->stage_count || !standby_ep ||
        !standby_ep->host || standby_ep->port == 0 || !standby_ep->expected_pk) {
        return FP_ERR_INVALID;
    }
    if (pipe->standby_tcp[stage_idx]) {
        (void)fp_session_send_verified(pipe->standby_tcp[stage_idx], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
        fp_session_close(pipe->standby_tcp[stage_idx]);
        pipe->standby_tcp[stage_idx] = NULL;
    }
    if (pipe->standby_udp[stage_idx]) {
        (void)fp_udp_session_send_verified(pipe->standby_udp[stage_idx], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
        fp_udp_session_close(pipe->standby_udp[stage_idx]);
        pipe->standby_udp[stage_idx] = NULL;
    }

    fp_err_t err;
    if (pipe->transport == SF_SPLIT_TCP) {
        err = fp_session_connect(standby_ep->host, standby_ep->port, &pipe->client_kp,
                                 standby_ep->expected_pk, pipe->io_timeout_ms,
                                 &pipe->standby_tcp[stage_idx]);
    } else {
        err = fp_udp_session_connect(standby_ep->host, standby_ep->port, &pipe->client_kp,
                                     standby_ep->expected_pk, pipe->io_timeout_ms,
                                     pipe->fault_drop_pct, &pipe->standby_udp[stage_idx]);
    }
    if (err != FP_OK) return err;
    pipe->straggler_budget_ms[stage_idx] = straggler_budget_ms;
    return FP_OK;
}

fp_err_t sf_split_pipe_reset(sf_split_pipe_t *pipe, uint64_t seq_id) {
    if (!pipe) return FP_ERR_INVALID;
    uint8_t sb[8];
    put_be64(sb, seq_id);
    for (uint32_t s = 0; s < pipe->stage_count; s++) {
        fp_err_t err = xport_send_raw(pipe->transport, pipe->tcp[s], pipe->udp[s],
                                      SF_SPLIT_OP_RESET, sb, 8u, NULL);
        if (err != FP_OK) return err;
        uint8_t rt = 0;
        uint8_t *rb = NULL;
        size_t rl = 0;
        err = xport_recv_raw(pipe->transport, pipe->tcp[s], pipe->udp[s],
                             1024u, &rt, &rb, &rl, NULL);
        free(rb);
        if (err != FP_OK || rt != SF_SPLIT_OP_RESET) return (err != FP_OK) ? err : FP_ERR_IO;
    }
    memset(&pipe->chain_trace, 0, sizeof(pipe->chain_trace));
    return FP_OK;
}

static fp_err_t pipe_run_op(sf_split_pipe_t *pipe, uint8_t op,
                            uint64_t seq_pos, uint32_t n_tokens,
                            const float *in_act, float *out_act,
                            fp_dna_t *out_step_trace) {
    if (!pipe || !in_act || !out_act || n_tokens == 0) return FP_ERR_INVALID;
    size_t elems = (size_t)n_tokens * (size_t)pipe->d_model;
    size_t fbytes = elems * sizeof(float);

    float *cur = malloc(fbytes);
    if (!cur) return FP_ERR_NOMEM;
    memcpy(cur, in_act, fbytes);

    fp_dna_t step_chain;
    memset(&step_chain, 0, sizeof(step_chain));

    fp_tensor_meta_t m;
    memset(&m, 0, sizeof(m));
    m.dtype   = FP_DTYPE_FP32;
    m.ndim    = 2u;
    m.dims[0] = n_tokens;
    m.dims[1] = pipe->d_model;
    m.seq_id  = seq_pos;

    for (uint32_t s = 0; s < pipe->stage_count; s++) {
        int has_standby = (pipe->transport == SF_SPLIT_TCP)
                              ? (pipe->standby_tcp[s] != NULL)
                              : (pipe->standby_udp[s] != NULL);
        uint64_t t_s0 = split_mono_ns();
        fp_err_t err = xport_send_tensor(pipe->transport, pipe->tcp[s], pipe->udp[s],
                                         op, &m, cur, fbytes, pipe->wire_cast, NULL);
        uint8_t rtag = 0;
        fp_tensor_meta_t rm;
        uint8_t *rdata = NULL;
        size_t rlen = 0;
        fp_dna_t stage_dna;
        if (err == FP_OK) {
            err = xport_recv_tensor(pipe->transport, pipe->tcp[s], pipe->udp[s],
                                    32u << 20, 1, &rtag, &rm, &rdata, &rlen, &stage_dna);
        }
        double stage_ms = (double)(split_mono_ns() - t_s0) / 1e6;

        /* Fail-over on primary I/O failure/disconnect immediately onto warm standby */
        if (err != FP_OK && has_standby) {
            free(rdata); rdata = NULL;
            pipe_promote_standby(pipe, s);
            err = xport_send_tensor(pipe->transport, pipe->tcp[s], pipe->udp[s],
                                    op, &m, cur, fbytes, pipe->wire_cast, NULL);
            if (err == FP_OK) {
                err = xport_recv_tensor(pipe->transport, pipe->tcp[s], pipe->udp[s],
                                        32u << 20, 1, &rtag, &rm, &rdata, &rlen, &stage_dna);
            }
        } else if (err == FP_OK && has_standby && pipe->straggler_budget_ms[s] > 0 &&
                   stage_ms > (double)pipe->straggler_budget_ms[s]) {
            /* Straggler evicted: promote warm standby so all following steps run at full speed */
            pipe_promote_standby(pipe, s);
        }

        if (err != FP_OK) { free(rdata); free(cur); return err; }
        if (rtag != op || rlen != fbytes || rm.dims[0] != n_tokens || rm.dims[1] != pipe->d_model) {
            free(rdata);
            free(cur);
            return FP_ERR_BOUNDS;
        }
        memcpy(cur, rdata, fbytes);
        free(rdata);

        chain_trace_update(&step_chain, s, seq_pos, &stage_dna);
        chain_trace_update(&pipe->chain_trace, s, seq_pos, &stage_dna);
    }

    memcpy(out_act, cur, fbytes);
    free(cur);
    pipe->forward_calls++;
    pipe->tokens_processed += n_tokens;
    if (out_step_trace) *out_step_trace = step_chain;
    return FP_OK;
}

fp_err_t sf_split_pipe_forward(sf_split_pipe_t *pipe,
                               uint64_t seq_pos, uint32_t n_tokens,
                               const float *in_act, float *out_act,
                               fp_dna_t *out_step_trace) {
    return pipe_run_op(pipe, SF_SPLIT_OP_FORWARD, seq_pos, n_tokens,
                       in_act, out_act, out_step_trace);
}

static float vec_cosine(const float *a, const float *b, uint32_t n) {
    double dot = 0.0, na = 0.0, nb = 0.0;
    for (uint32_t i = 0; i < n; i++) {
        dot += (double)a[i] * (double)b[i];
        na  += (double)a[i] * (double)a[i];
        nb  += (double)b[i] * (double)b[i];
    }
    if (na <= 1e-18 || nb <= 1e-18) return 0.0f;
    return (float)(dot / (sqrt(na) * sqrt(nb)));
}

fp_err_t sf_split_pipe_spec_verify(sf_split_pipe_t *pipe,
                                   uint64_t seq_pos, uint32_t draft_k,
                                   const float *draft_in,
                                   const float *ref_draft_out,
                                   float cos_threshold,
                                   float *verified_out,
                                   uint32_t *out_accepted_prefix,
                                   fp_dna_t *out_step_trace) {
    if (!pipe || draft_k == 0 || !draft_in || !verified_out) return FP_ERR_INVALID;
    fp_err_t err = pipe_run_op(pipe, SF_SPLIT_OP_SPEC_VERIFY, seq_pos, draft_k,
                               draft_in, verified_out, out_step_trace);
    if (err != FP_OK) return err;

    if (out_accepted_prefix) {
        if (!ref_draft_out) {
            *out_accepted_prefix = draft_k;
        } else {
            uint32_t acc = 0;
            for (uint32_t t = 0; t < draft_k; t++) {
                float c = vec_cosine(ref_draft_out + (size_t)t * pipe->d_model,
                                     verified_out  + (size_t)t * pipe->d_model,
                                     pipe->d_model);
                if (c >= cos_threshold) {
                    acc++;
                } else {
                    break; /* Speculative decoding stops at first mismatch + 1 bonus token */
                }
            }
            if (acc == 0) acc = 1u; /* Always emit at least 1 verified target token */
            *out_accepted_prefix = acc;
        }
    }
    return FP_OK;
}

static void json_get_field(const char *json, const char *key, char *out, size_t cap) {
    out[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i + 1u < cap) out[i++] = *p++;
        out[i] = '\0';
    } else {
        size_t i = 0;
        while (*p && *p != ',' && *p != '}' && *p != ' ' && i + 1u < cap) out[i++] = *p++;
        out[i] = '\0';
    }
}

fp_err_t sf_split_pipe_seal_keryx(sf_split_pipe_t *pipe,
                                  const fp_keypair_t *signer_kp,
                                  const char *keryx_ws_url,
                                  sf_split_keryx_receipt_t *out_receipt) {
    if (!pipe || !signer_kp || !out_receipt) return FP_ERR_INVALID;
    memset(out_receipt, 0, sizeof(*out_receipt));
    snprintf(out_receipt->keryx_sink, sizeof(out_receipt->keryx_sink), "offline");

    if (keryx_ws_url && keryx_ws_url[0] != '\0') {
        char resp[8192];
        if (sf_keryx_wrpc_call(keryx_ws_url, "getBlockDagInfo", "{}", 3000,
                               resp, sizeof(resp)) == FP_OK) {
            char daa[32];
            json_get_field(resp, "sink", out_receipt->keryx_sink, sizeof(out_receipt->keryx_sink));
            json_get_field(resp, "virtualDaaScore", daa, sizeof(daa));
            out_receipt->keryx_daa_score = (uint64_t)strtoull(daa, NULL, 10);
            out_receipt->keryx_live = 1;
        }
    }

    fp_dna_t parent_dna, op_dna;
    fp_err_t err = fp_dna_compute((const uint8_t *)out_receipt->keryx_sink,
                                  strlen(out_receipt->keryx_sink), &parent_dna);
    if (err != FP_OK) return err;
    err = fp_dna_compute((const uint8_t *)"SF_SPLIT_SHIM_V1", 16u, &op_dna);
    if (err != FP_OK) return err;

    out_receipt->derivation.version        = 1u;
    out_receipt->derivation.parent_dna     = parent_dna;
    out_receipt->derivation.op_dna         = op_dna;
    out_receipt->derivation.result_dna     = pipe->chain_trace;
    out_receipt->derivation.result_size    = pipe->tokens_processed * (uint64_t)pipe->d_model * 4u;
    out_receipt->derivation.timestamp_unix = (uint64_t)time(NULL);
    err = fp_derivation_sign(&out_receipt->derivation, signer_kp);
    if (err != FP_OK) return err;

    fp_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.version        = 1u;
    ev.action         = FP_ACTION_INSTALL;
    memcpy(ev.repo_id.bytes, signer_kp->pk, FP_PK_LEN);
    ev.serial         = pipe->forward_calls > 0 ? pipe->forward_calls : 1u;
    ev.timestamp_unix = out_receipt->derivation.timestamp_unix;
    ev.expires_unix   = ev.timestamp_unix + 3600u;
    ev.target_dna     = pipe->chain_trace;
    ev.target_size    = out_receipt->derivation.result_size;
    snprintf(ev.reason, sizeof(ev.reason), "sf-split-keryx");
    err = fp_event_sign(&ev, signer_kp);
    if (err != FP_OK) return err;

    err = fp_anchor_compute(&ev, &out_receipt->anchor);
    if (err != FP_OK) return err;

    sf_keryx_encode_payload(&out_receipt->anchor, out_receipt->keryx_daa_score,
                            out_receipt->keryx_payload, out_receipt->keryx_opoi_tag);
    return FP_OK;
}

void sf_split_pipe_stats(const sf_split_pipe_t *pipe, sf_split_stats_t *out_stats) {
    if (!pipe || !out_stats) return;
    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->forward_calls       = pipe->forward_calls;
    out_stats->tokens_processed    = pipe->tokens_processed;
    out_stats->straggler_failovers = pipe->straggler_failovers;
    out_stats->tx_bytes            = pipe->retired_tx;
    out_stats->rx_bytes            = pipe->retired_rx;
    out_stats->udp_retransmits     = pipe->retired_retx;
    out_stats->udp_fec_recoveries  = pipe->retired_fec;
    out_stats->chain_trace         = pipe->chain_trace;
    for (uint32_t s = 0; s < pipe->stage_count; s++) {
        uint64_t tx = 0, rx = 0, retx = 0;
        if (pipe->transport == SF_SPLIT_TCP && pipe->tcp[s]) {
            fp_session_stats(pipe->tcp[s], &tx, &rx);
        } else if (pipe->transport == SF_SPLIT_UDP && pipe->udp[s]) {
            fp_udp_session_stats(pipe->udp[s], &tx, &rx, &retx);
            out_stats->udp_fec_recoveries += fp_udp_session_fec_recoveries(pipe->udp[s]);
        }
        out_stats->tx_bytes        += tx;
        out_stats->rx_bytes        += rx;
        out_stats->udp_retransmits += retx;
    }
}

void sf_split_pipe_close(sf_split_pipe_t *pipe) {
    if (!pipe) return;
    for (uint32_t s = 0; s < pipe->stage_count; s++) {
        if (pipe->tcp[s]) {
            (void)fp_session_send_verified(pipe->tcp[s], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
            fp_session_close(pipe->tcp[s]);
            pipe->tcp[s] = NULL;
        }
        if (pipe->udp[s]) {
            (void)fp_udp_session_send_verified(pipe->udp[s], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
            fp_udp_session_close(pipe->udp[s]);
            pipe->udp[s] = NULL;
        }
        if (pipe->standby_tcp[s]) {
            (void)fp_session_send_verified(pipe->standby_tcp[s], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
            fp_session_close(pipe->standby_tcp[s]);
            pipe->standby_tcp[s] = NULL;
        }
        if (pipe->standby_udp[s]) {
            (void)fp_udp_session_send_verified(pipe->standby_udp[s], SF_SPLIT_OP_QUIT, NULL, 0, NULL);
            fp_udp_session_close(pipe->standby_udp[s]);
            pipe->standby_udp[s] = NULL;
        }
    }
    sodium_memzero(&pipe->client_kp, sizeof(pipe->client_kp));
    free(pipe);
}

/* ==================== llama.cpp / ggml-rpc Layer-Boundary Helpers ==================== */

static fp_dtype_t ggml_to_fp_dtype(sf_ggml_type_t gt) {
    switch (gt) {
        case SF_GGML_TYPE_F32:  return FP_DTYPE_FP32;
        case SF_GGML_TYPE_F16:  return FP_DTYPE_FP16;
        case SF_GGML_TYPE_BF16: return FP_DTYPE_BF16;
        case SF_GGML_TYPE_I8:   return FP_DTYPE_INT8;
        default:                return (fp_dtype_t)0;
    }
}

static sf_ggml_type_t fp_to_ggml_dtype(fp_dtype_t dt) {
    switch (dt) {
        case FP_DTYPE_FP32: return SF_GGML_TYPE_F32;
        case FP_DTYPE_FP16: return SF_GGML_TYPE_F16;
        case FP_DTYPE_BF16: return SF_GGML_TYPE_BF16;
        case FP_DTYPE_INT8: return SF_GGML_TYPE_I8;
        default:            return SF_GGML_TYPE_F32;
    }
}

fp_err_t sf_ggml_boundary_send(sf_split_transport_t transport,
                               fp_session_t *tcp_sess,
                               fp_udp_session_t *udp_sess,
                               sf_ggml_type_t ggml_type,
                               uint32_t ne0, uint32_t ne1, uint64_t seq_pos,
                               const void *data, size_t data_len,
                               fp_wire_cast_t wire_cast,
                               fp_dna_t *out_dna) {
    fp_dtype_t dt = ggml_to_fp_dtype(ggml_type);
    if (dt == 0 || ne0 == 0 || ne1 == 0 || !data) return FP_ERR_INVALID;
    fp_tensor_meta_t m;
    memset(&m, 0, sizeof(m));
    m.dtype   = dt;
    m.ndim    = 2u;
    m.dims[0] = ne1;
    m.dims[1] = ne0;
    m.seq_id  = seq_pos;
    return xport_send_tensor(transport, tcp_sess, udp_sess, SF_SPLIT_OP_GGML_TENSOR,
                             &m, data, data_len, wire_cast, out_dna);
}

fp_err_t sf_ggml_boundary_recv(sf_split_transport_t transport,
                               fp_session_t *tcp_sess,
                               fp_udp_session_t *udp_sess,
                               size_t max_bytes, int upcast_f32,
                               sf_ggml_type_t *out_ggml_type,
                               uint32_t *out_ne0, uint32_t *out_ne1,
                               uint64_t *out_seq_pos,
                               uint8_t **out_data, size_t *out_data_len,
                               fp_dna_t *out_dna) {
    uint8_t tag = 0;
    fp_tensor_meta_t m;
    fp_err_t err = xport_recv_tensor(transport, tcp_sess, udp_sess, max_bytes, upcast_f32,
                                     &tag, &m, out_data, out_data_len, out_dna);
    if (err != FP_OK) return err;
    if (tag != SF_SPLIT_OP_GGML_TENSOR || m.ndim != 2u) {
        free(*out_data);
        *out_data = NULL;
        *out_data_len = 0;
        return FP_ERR_INVALID;
    }
    if (out_ggml_type) *out_ggml_type = fp_to_ggml_dtype(m.dtype);
    if (out_ne0)       *out_ne0       = m.dims[1];
    if (out_ne1)       *out_ne1       = m.dims[0];
    if (out_seq_pos)   *out_seq_pos   = m.seq_id;
    return FP_OK;
}

/* ==================== Ring / Daisy-Chain P2P Pipeline + Prefix KV-Cache ==================== */

static uint32_t get_be32(const uint8_t src[4]) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  | ((uint32_t)src[3]);
}

typedef struct {
    fp_dna_t dna;
    uint32_t tokens;
    int      valid;
} prefix_slot_t;

static int prefix_cache_lookup(const prefix_slot_t slots[SF_PREFIX_CACHE_SLOTS],
                               const fp_dna_t *dna, uint32_t tokens) {
    if (!dna || tokens == 0 || fp_dna_is_zero(dna)) return 0;
    for (uint32_t i = 0; i < SF_PREFIX_CACHE_SLOTS; i++) {
        if (slots[i].valid && slots[i].tokens == tokens && fp_dna_equal(&slots[i].dna, dna)) {
            return 1;
        }
    }
    return 0;
}

static void prefix_cache_insert(prefix_slot_t slots[SF_PREFIX_CACHE_SLOTS], uint32_t *cursor,
                                const fp_dna_t *dna, uint32_t tokens) {
    if (!dna || tokens == 0 || fp_dna_is_zero(dna)) return;
    if (prefix_cache_lookup(slots, dna, tokens)) return;
    uint32_t idx = (*cursor) % SF_PREFIX_CACHE_SLOTS;
    slots[idx].dna    = *dna;
    slots[idx].tokens = tokens;
    slots[idx].valid  = 1;
    *cursor = idx + 1u;
}

static void ring_trace_update(fp_dna_t *chain, uint32_t stage_idx,
                              uint64_t seq_pos, const fp_dna_t *stage_dna) {
    static const uint8_t dom[16] = "SF_RING/TRACE1";
    uint8_t sb[4], pb[8];
    put_be32(sb, stage_idx);
    put_be64(pb, seq_pos);
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, dom, sizeof(dom));
    blake3_hasher_update(&h, chain->bytes, FP_DNA_LEN);
    blake3_hasher_update(&h, sb, 4);
    blake3_hasher_update(&h, pb, 8);
    blake3_hasher_update(&h, stage_dna->bytes, FP_DNA_LEN);
    blake3_hasher_finalize(&h, chain->bytes, FP_DNA_LEN);
}

fp_err_t sf_split_ring_worker_run(int bound_in_fd, const sf_split_ring_worker_cfg_t *cfg) {
    if (bound_in_fd < 0 || !cfg || !cfg->stage_kp || !cfg->next_host || cfg->next_port == 0 ||
        !cfg->next_expected_pk || !cfg->forward_fn || cfg->d_model == 0) {
        return FP_ERR_INVALID;
    }
    int timeout_ms = cfg->io_timeout_ms > 0 ? cfg->io_timeout_ms : 15000;
    fp_session_t *in_tcp = NULL, *out_tcp = NULL;
    fp_udp_session_t *in_udp = NULL, *out_udp = NULL;
    fp_err_t err = FP_OK;

    if (cfg->transport == SF_SPLIT_TCP) {
        err = fp_session_accept(bound_in_fd, cfg->stage_kp, cfg->prev_allowed_pk, timeout_ms, &in_tcp);
        if (err == FP_OK) {
            err = fp_session_connect(cfg->next_host, cfg->next_port, cfg->stage_kp,
                                     cfg->next_expected_pk, timeout_ms, &out_tcp);
        }
    } else if (cfg->transport == SF_SPLIT_UDP) {
        err = fp_udp_session_accept(bound_in_fd, cfg->stage_kp, cfg->prev_allowed_pk,
                                    timeout_ms, cfg->fault_drop_pct, &in_udp);
        if (err == FP_OK) {
            err = fp_udp_session_connect(cfg->next_host, cfg->next_port, cfg->stage_kp,
                                         cfg->next_expected_pk, timeout_ms,
                                         cfg->fault_drop_pct, &out_udp);
        }
    } else {
        return FP_ERR_INVALID;
    }

    if (err != FP_OK) {
        if (in_tcp)  fp_session_close(in_tcp);
        if (out_tcp) fp_session_close(out_tcp);
        if (in_udp)  fp_udp_session_close(in_udp);
        if (out_udp) fp_udp_session_close(out_udp);
        return err;
    }

    prefix_slot_t kv_cache[SF_PREFIX_CACHE_SLOTS];
    memset(kv_cache, 0, sizeof(kv_cache));
    uint32_t kv_cur = 0;

    for (;;) {
        uint8_t tag = 0;
        uint8_t *msg = NULL;
        size_t mlen = 0;
        err = xport_recv_raw(cfg->transport, in_tcp, in_udp, 32u << 20, &tag, &msg, &mlen, NULL);
        if (err != FP_OK) break;

        if (tag == SF_SPLIT_OP_QUIT) {
            (void)xport_send_raw(cfg->transport, out_tcp, out_udp, SF_SPLIT_OP_QUIT, NULL, 0, NULL);
            free(msg);
            err = FP_OK;
            break;
        }
        if (tag == SF_SPLIT_OP_RESET) {
            uint64_t seq_id = (mlen >= 8u) ? get_be64(msg) : 0u;
            if (cfg->reset_fn) cfg->reset_fn(cfg->model_ctx, seq_id);
            err = xport_send_raw(cfg->transport, out_tcp, out_udp, SF_SPLIT_OP_RESET,
                                 msg, mlen, NULL);
            free(msg);
            if (err != FP_OK) break;
            continue;
        }
        if (tag == SF_SPLIT_OP_RING_FWD || tag == SF_SPLIT_OP_RING_PREFIX) {
            if (mlen <= SF_RING_HDR_LEN) { free(msg); err = FP_ERR_INVALID; break; }
            fp_dna_t chain, prefix_dna;
            memcpy(chain.bytes, msg, 32);
            memcpy(prefix_dna.bytes, msg + 32, 32);
            uint32_t prefix_tok = get_be32(msg + 64);
            uint32_t total_tok  = get_be32(msg + 68);
            uint32_t flags      = get_be32(msg + 72);

            fp_tensor_meta_t in_meta;
            uint8_t *in_bytes = NULL;
            size_t in_len = 0;
            err = fp_tensor_unpack(msg + SF_RING_HDR_LEN, mlen - SF_RING_HDR_LEN, 1,
                                   &in_meta, &in_bytes, &in_len);
            free(msg);
            if (err != FP_OK) break;
            if (in_meta.ndim != 2u || in_meta.dims[1] != cfg->d_model ||
                in_meta.dtype != FP_DTYPE_FP32) {
                free(in_bytes);
                err = FP_ERR_INVALID;
                break;
            }

            uint32_t n_tok = in_meta.dims[0];
            if (tag == SF_SPLIT_OP_RING_PREFIX && prefix_tok > 0) {
                if (prefix_cache_lookup(kv_cache, &prefix_dna, prefix_tok)) {
                    flags |= SF_RING_FLAG_KV_HIT;
                } else {
                    prefix_cache_insert(kv_cache, &kv_cur, &prefix_dna, prefix_tok);
                    flags &= ~SF_RING_FLAG_KV_HIT;
                }
            }

            size_t elems = (size_t)n_tok * (size_t)cfg->d_model;
            float *out_act = malloc(elems * sizeof(float));
            if (!out_act) { free(in_bytes); err = FP_ERR_NOMEM; break; }

            err = cfg->forward_fn(cfg->model_ctx, cfg->layer_start, cfg->layer_end,
                                  in_meta.seq_id, n_tok, cfg->d_model,
                                  (const float *)in_bytes, out_act);
            free(in_bytes);
            if (err != FP_OK) { free(out_act); break; }

            fp_tensor_meta_t out_meta;
            memset(&out_meta, 0, sizeof(out_meta));
            out_meta.dtype   = FP_DTYPE_FP32;
            out_meta.ndim    = 2u;
            out_meta.dims[0] = n_tok;
            out_meta.dims[1] = cfg->d_model;
            out_meta.seq_id  = in_meta.seq_id;

            uint8_t *sft_buf = NULL;
            size_t sft_len = 0;
            err = fp_tensor_pack_ex(&out_meta, out_act, elems * sizeof(float),
                                    cfg->wire_cast, &sft_buf, &sft_len);
            free(out_act);
            if (err != FP_OK) break;

            fp_dna_t stage_dna;
            err = fp_dna_compute(sft_buf, sft_len, &stage_dna);
            if (err != FP_OK) { free(sft_buf); break; }
            ring_trace_update(&chain, cfg->stage_index, in_meta.seq_id, &stage_dna);

            uint8_t *fwd = malloc(SF_RING_HDR_LEN + sft_len);
            if (!fwd) { free(sft_buf); err = FP_ERR_NOMEM; break; }
            memcpy(fwd, chain.bytes, 32);
            memcpy(fwd + 32, prefix_dna.bytes, 32);
            put_be32(fwd + 64, prefix_tok);
            put_be32(fwd + 68, total_tok);
            put_be32(fwd + 72, flags);
            memcpy(fwd + SF_RING_HDR_LEN, sft_buf, sft_len);
            free(sft_buf);

            err = xport_send_raw(cfg->transport, out_tcp, out_udp, tag,
                                 fwd, SF_RING_HDR_LEN + sft_len, NULL);
            free(fwd);
            if (err != FP_OK) break;
            continue;
        }

        free(msg);
        err = FP_ERR_INVALID;
        break;
    }

    if (in_tcp)  fp_session_close(in_tcp);
    if (out_tcp) fp_session_close(out_tcp);
    if (in_udp)  fp_udp_session_close(in_udp);
    if (out_udp) fp_udp_session_close(out_udp);
    return err;
}

struct sf_split_ring {
    sf_split_transport_t transport;
    fp_wire_cast_t       wire_cast;
    uint32_t             d_model;
    uint32_t             stage_count;
    fp_session_t        *tx_tcp;
    fp_session_t        *rx_tcp;
    fp_udp_session_t    *tx_udp;
    fp_udp_session_t    *rx_udp;
    fp_dna_t             chain_trace;
    uint64_t             forward_calls;
    uint64_t             tokens_processed;
    prefix_slot_t        coord_prefixes[SF_PREFIX_CACHE_SLOTS];
    uint32_t             coord_prefix_cur;
};

fp_err_t sf_split_ring_open(const sf_split_ring_cfg_t *cfg, sf_split_ring_t **out_ring) {
    if (!cfg || !out_ring || !cfg->entry_host || cfg->entry_port == 0 ||
        !cfg->entry_expected_pk || cfg->return_fd < 0 || !cfg->coord_kp ||
        cfg->d_model == 0 || cfg->stage_count == 0 || cfg->stage_count > SF_SPLIT_MAX_STAGES) {
        return FP_ERR_INVALID;
    }
    *out_ring = NULL;

    sf_split_ring_t *r = calloc(1, sizeof(*r));
    if (!r) return FP_ERR_NOMEM;
    r->transport   = cfg->transport;
    r->wire_cast   = cfg->wire_cast;
    r->d_model     = cfg->d_model;
    r->stage_count = cfg->stage_count;

    int timeout_ms = cfg->io_timeout_ms > 0 ? cfg->io_timeout_ms : 15000;
    fp_err_t err = FP_OK;
    if (cfg->transport == SF_SPLIT_TCP) {
        err = fp_session_connect(cfg->entry_host, cfg->entry_port, cfg->coord_kp,
                                 cfg->entry_expected_pk, timeout_ms, &r->tx_tcp);
        if (err == FP_OK) {
            err = fp_session_accept(cfg->return_fd, cfg->coord_kp, cfg->tail_allowed_pk,
                                    timeout_ms, &r->rx_tcp);
        }
    } else if (cfg->transport == SF_SPLIT_UDP) {
        err = fp_udp_session_connect(cfg->entry_host, cfg->entry_port, cfg->coord_kp,
                                     cfg->entry_expected_pk, timeout_ms,
                                     cfg->fault_drop_pct, &r->tx_udp);
        if (err == FP_OK) {
            err = fp_udp_session_accept(cfg->return_fd, cfg->coord_kp, cfg->tail_allowed_pk,
                                        timeout_ms, cfg->fault_drop_pct, &r->rx_udp);
        }
    } else {
        err = FP_ERR_INVALID;
    }

    if (err != FP_OK) {
        sf_split_ring_close(r);
        return err;
    }
    *out_ring = r;
    return FP_OK;
}

fp_err_t sf_split_ring_reset(sf_split_ring_t *ring, uint64_t seq_id) {
    if (!ring) return FP_ERR_INVALID;
    uint8_t sb[8];
    put_be64(sb, seq_id);
    fp_err_t err = xport_send_raw(ring->transport, ring->tx_tcp, ring->tx_udp,
                                  SF_SPLIT_OP_RESET, sb, 8u, NULL);
    if (err != FP_OK) return err;
    uint8_t rt = 0; uint8_t *rb = NULL; size_t rl = 0;
    err = xport_recv_raw(ring->transport, ring->rx_tcp, ring->rx_udp,
                         1024u, &rt, &rb, &rl, NULL);
    free(rb);
    if (err != FP_OK || rt != SF_SPLIT_OP_RESET) return (err != FP_OK) ? err : FP_ERR_IO;
    memset(&ring->chain_trace, 0, sizeof(ring->chain_trace));
    return FP_OK;
}

static fp_err_t ring_send_and_collect(sf_split_ring_t *ring, uint8_t op,
                                      uint64_t seq_pos,
                                      const fp_dna_t *prefix_dna,
                                      uint32_t prefix_tokens, uint32_t total_tokens,
                                      uint32_t send_tokens, const float *send_act,
                                      float *out_act, uint32_t *out_flags,
                                      fp_dna_t *out_ring_trace) {
    fp_tensor_meta_t m;
    memset(&m, 0, sizeof(m));
    m.dtype   = FP_DTYPE_FP32;
    m.ndim    = 2u;
    m.dims[0] = send_tokens;
    m.dims[1] = ring->d_model;
    m.seq_id  = seq_pos;

    size_t fbytes = (size_t)send_tokens * (size_t)ring->d_model * sizeof(float);
    uint8_t *sft_buf = NULL;
    size_t sft_len = 0;
    fp_err_t err = fp_tensor_pack_ex(&m, send_act, fbytes, ring->wire_cast, &sft_buf, &sft_len);
    if (err != FP_OK) return err;

    uint8_t *pkt = malloc(SF_RING_HDR_LEN + sft_len);
    if (!pkt) { free(sft_buf); return FP_ERR_NOMEM; }
    memcpy(pkt, ring->chain_trace.bytes, 32);
    if (prefix_dna) memcpy(pkt + 32, prefix_dna->bytes, 32);
    else memset(pkt + 32, 0, 32);
    put_be32(pkt + 64, prefix_tokens);
    put_be32(pkt + 68, total_tokens);
    put_be32(pkt + 72, 0u);
    memcpy(pkt + SF_RING_HDR_LEN, sft_buf, sft_len);
    free(sft_buf);

    err = xport_send_raw(ring->transport, ring->tx_tcp, ring->tx_udp,
                         op, pkt, SF_RING_HDR_LEN + sft_len, NULL);
    free(pkt);
    if (err != FP_OK) return err;

    uint8_t rtag = 0;
    uint8_t *rmsg = NULL;
    size_t rmlen = 0;
    err = xport_recv_raw(ring->transport, ring->rx_tcp, ring->rx_udp,
                         32u << 20, &rtag, &rmsg, &rmlen, NULL);
    if (err != FP_OK) return err;
    if (rtag != op || rmlen <= SF_RING_HDR_LEN) {
        free(rmsg);
        return FP_ERR_INVALID;
    }

    fp_dna_t final_chain;
    memcpy(final_chain.bytes, rmsg, 32);
    uint32_t rflags = get_be32(rmsg + 72);

    fp_tensor_meta_t rm;
    uint8_t *rdata = NULL;
    size_t rlen = 0;
    err = fp_tensor_unpack(rmsg + SF_RING_HDR_LEN, rmlen - SF_RING_HDR_LEN, 1,
                           &rm, &rdata, &rlen);
    free(rmsg);
    if (err != FP_OK) return err;
    if (rlen != fbytes || rm.dims[0] != send_tokens || rm.dims[1] != ring->d_model) {
        free(rdata);
        return FP_ERR_BOUNDS;
    }
    memcpy(out_act, rdata, fbytes);
    free(rdata);

    ring->chain_trace = final_chain;
    ring->forward_calls++;
    ring->tokens_processed += send_tokens;
    if (out_flags) *out_flags = rflags;
    if (out_ring_trace) *out_ring_trace = final_chain;
    return FP_OK;
}

fp_err_t sf_split_ring_forward(sf_split_ring_t *ring,
                               uint64_t seq_pos, uint32_t n_tokens,
                               const float *in_act, float *out_act,
                               fp_dna_t *out_ring_trace) {
    if (!ring || n_tokens == 0 || !in_act || !out_act) return FP_ERR_INVALID;
    return ring_send_and_collect(ring, SF_SPLIT_OP_RING_FWD, seq_pos, NULL, 0u, n_tokens,
                                 n_tokens, in_act, out_act, NULL, out_ring_trace);
}

fp_err_t sf_split_ring_prefix_forward(sf_split_ring_t *ring,
                                      uint64_t seq_pos,
                                      const fp_dna_t *prefix_dna,
                                      uint32_t prefix_tokens,
                                      uint32_t total_tokens,
                                      const float *full_in_act,
                                      float *out_act,
                                      uint32_t *out_out_tokens,
                                      int *out_kv_hit,
                                      fp_dna_t *out_ring_trace) {
    if (!ring || !prefix_dna || !full_in_act || !out_act ||
        total_tokens == 0 || prefix_tokens >= total_tokens) {
        return FP_ERR_INVALID;
    }
    int known_pinned = prefix_cache_lookup(ring->coord_prefixes, prefix_dna, prefix_tokens);
    uint32_t send_tok = known_pinned ? (total_tokens - prefix_tokens) : total_tokens;
    const float *send_ptr = known_pinned
                                ? (full_in_act + (size_t)prefix_tokens * ring->d_model)
                                : full_in_act;
    uint32_t rflags = 0;
    fp_err_t err = ring_send_and_collect(ring, SF_SPLIT_OP_RING_PREFIX,
                                         known_pinned ? (seq_pos + prefix_tokens) : seq_pos,
                                         prefix_dna, prefix_tokens, total_tokens,
                                         send_tok, send_ptr, out_act, &rflags, out_ring_trace);
    if (err != FP_OK) return err;
    if (!known_pinned) {
        prefix_cache_insert(ring->coord_prefixes, &ring->coord_prefix_cur,
                            prefix_dna, prefix_tokens);
    }
    if (out_out_tokens) *out_out_tokens = send_tok;
    if (out_kv_hit)     *out_kv_hit     = (rflags & SF_RING_FLAG_KV_HIT) ? 1 : 0;
    return FP_OK;
}

void sf_split_ring_stats(const sf_split_ring_t *ring, sf_split_stats_t *out_stats) {
    if (!ring || !out_stats) return;
    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->forward_calls    = ring->forward_calls;
    out_stats->tokens_processed = ring->tokens_processed;
    out_stats->chain_trace      = ring->chain_trace;
    uint64_t tx1 = 0, rx1 = 0, tx2 = 0, rx2 = 0, rt1 = 0, rt2 = 0;
    if (ring->transport == SF_SPLIT_TCP) {
        if (ring->tx_tcp) fp_session_stats(ring->tx_tcp, &tx1, &rx1);
        if (ring->rx_tcp) fp_session_stats(ring->rx_tcp, &tx2, &rx2);
    } else {
        if (ring->tx_udp) fp_udp_session_stats(ring->tx_udp, &tx1, &rx1, &rt1);
        if (ring->rx_udp) fp_udp_session_stats(ring->rx_udp, &tx2, &rx2, &rt2);
        out_stats->udp_fec_recoveries =
            (ring->tx_udp ? fp_udp_session_fec_recoveries(ring->tx_udp) : 0u) +
            (ring->rx_udp ? fp_udp_session_fec_recoveries(ring->rx_udp) : 0u);
    }
    out_stats->tx_bytes        = tx1 + tx2;
    out_stats->rx_bytes        = rx1 + rx2;
    out_stats->udp_retransmits = rt1 + rt2;
}

void sf_split_ring_close(sf_split_ring_t *ring) {
    if (!ring) return;
    if (ring->tx_tcp) {
        (void)fp_session_send_verified(ring->tx_tcp, SF_SPLIT_OP_QUIT, NULL, 0, NULL);
        fp_session_close(ring->tx_tcp);
    }
    if (ring->rx_tcp) {
        uint8_t qt = 0; uint8_t *qb = NULL; size_t ql = 0;
        (void)fp_session_recv_verified(ring->rx_tcp, 256u, &qt, &qb, &ql, NULL);
        free(qb);
        fp_session_close(ring->rx_tcp);
    }
    if (ring->tx_udp) {
        (void)fp_udp_session_send_verified(ring->tx_udp, SF_SPLIT_OP_QUIT, NULL, 0, NULL);
        fp_udp_session_close(ring->tx_udp);
    }
    if (ring->rx_udp) {
        uint8_t qt = 0; uint8_t *qb = NULL; size_t ql = 0;
        (void)fp_udp_session_recv_verified(ring->rx_udp, 256u, &qt, &qb, &ql, NULL);
        free(qb);
        fp_udp_session_close(ring->rx_udp);
    }
    free(ring);
}

/* ==================== Adaptive Speculative Draft-K Controller ==================== */

void sf_spec_adapt_init(sf_spec_adapt_t *ad, uint32_t min_k, uint32_t max_k, uint32_t init_k) {
    if (!ad) return;
    if (min_k < 1u) min_k = 1u;
    if (max_k < min_k) max_k = min_k;
    if (init_k < min_k) init_k = min_k;
    if (init_k > max_k) init_k = max_k;
    ad->min_k           = min_k;
    ad->max_k           = max_k;
    ad->current_k       = init_k;
    ad->ema_accept_rate = 0.75f;
    ad->steps           = 0u;
    ad->total_accepted  = 0u;
}

uint32_t sf_spec_adapt_update(sf_spec_adapt_t *ad, uint32_t proposed_k, uint32_t accepted_k) {
    if (!ad || proposed_k == 0) return 1u;
    float rate = (float)accepted_k / (float)proposed_k;
    if (rate > 1.0f) rate = 1.0f;
    ad->ema_accept_rate = 0.7f * ad->ema_accept_rate + 0.3f * rate;
    ad->steps++;
    ad->total_accepted += accepted_k;
    if (ad->ema_accept_rate >= 0.78f && ad->current_k < ad->max_k) {
        ad->current_k++;
    } else if (ad->ema_accept_rate <= 0.45f && ad->current_k > ad->min_k) {
        ad->current_k--;
    }
    return ad->current_k;
}
