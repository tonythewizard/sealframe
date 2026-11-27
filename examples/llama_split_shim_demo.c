/*
 * SealFrame llama.cpp / Keryx Split-Model Shim Reference CLI (Pure ISO C11)
 *
 * Demonstrates how to plug a real Transformer / llama.cpp layer-slice forward pass
 * into SealFrame's pure-C11 split-model shim over encrypted TCP or FP-UDP1 with
 * SFT1 BF16/INT8 wire quantization, speculative K-token verification, and live
 * Keryx BlockDAG receipt sealing.
 *
 * Usage:
 *   ./build/sf_llama_split_demo [ws://127.0.0.1:26114] [udp|tcp] [int8|bf16|fp16|fp32]
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe.h"
#include "sealframe_split.h"

#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEMO_STAGES 3u
#define DEMO_DMODEL 1024u
#define DEMO_DRAFTK 4u

/* Deterministic Transformer-style residual block (RMSNorm + SwiGLU-like residual)
 * standing in for llama_decode / ggml_backend_graph_compute at each split stage. */
static fp_err_t transformer_stage_forward(void *ctx,
                                          uint32_t layer_start, uint32_t layer_end,
                                          uint64_t seq_pos, uint32_t n_tokens,
                                          uint32_t d_model,
                                          const float *in_act, float *out_act) {
    (void)ctx;
    for (uint32_t t = 0; t < n_tokens; t++) {
        const float *x = in_act + (size_t)t * d_model;
        float *y = out_act + (size_t)t * d_model;
        /* RMSNorm */
        double ss = 1e-6;
        for (uint32_t i = 0; i < d_model; i++) ss += (double)x[i] * (double)x[i];
        float inv_rms = (float)(1.0 / sqrt(ss / (double)d_model));
        /* Deterministic layer-dependent projection + SiLU + residual */
        float phase = 0.03f * (float)(layer_start + layer_end + 1u) + 0.005f * (float)(seq_pos + t);
        for (uint32_t i = 0; i < d_model; i++) {
            float xn = x[i] * inv_rms;
            float g  = xn * cosf(phase + 0.001f * (float)i);
            float silu = g / (1.0f + expf(-g));
            y[i] = x[i] + 0.125f * silu;
        }
    }
    return FP_OK;
}

typedef struct {
    int                   fd;
    sf_split_worker_cfg_t cfg;
} worker_arg_t;

static void *worker_thread(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    (void)sf_split_worker_run(wa->fd, &wa->cfg);
    close(wa->fd);
    return NULL;
}

static double cosine_sim(const float *a, const float *b, size_t n) {
    double dot = 0.0, na = 0.0, nb = 0.0;
    for (size_t i = 0; i < n; i++) {
        dot += (double)a[i] * (double)b[i];
        na  += (double)a[i] * (double)a[i];
        nb  += (double)b[i] * (double)b[i];
    }
    return dot / (sqrt(na) * sqrt(nb) + 1e-18);
}

static uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    assert(fp_init() == FP_OK);

    const char *ws_url = (argc >= 2) ? argv[1] : "ws://127.0.0.1:26114";
    sf_split_transport_t tr = (argc >= 3 && strcmp(argv[2], "tcp") == 0)
                                  ? SF_SPLIT_TCP : SF_SPLIT_UDP;
    fp_wire_cast_t cast = FP_WIRE_CAST_INT8;
    if (argc >= 4) {
        if (strcmp(argv[3], "bf16") == 0) cast = FP_WIRE_CAST_BF16;
        else if (strcmp(argv[3], "fp16") == 0) cast = FP_WIRE_CAST_FP16;
        else if (strcmp(argv[3], "fp32") == 0) cast = FP_WIRE_CAST_NONE;
    }

    fp_keypair_t ckp, skp[DEMO_STAGES];
    assert(fp_keygen(&ckp) == FP_OK);

    worker_arg_t warg[DEMO_STAGES];
    pthread_t wth[DEMO_STAGES];
    sf_split_stage_ep_t eps[DEMO_STAGES];

    for (uint32_t s = 0; s < DEMO_STAGES; s++) {
        assert(fp_keygen(&skp[s]) == FP_OK);
        uint16_t port = 0;
        int fd = (tr == SF_SPLIT_TCP) ? fp_net_listen("127.0.0.1", 0, &port)
                                      : fp_udp_bind("127.0.0.1", 0, &port);
        assert(fd >= 0);
        memset(&warg[s], 0, sizeof(warg[s]));
        warg[s].fd                  = fd;
        warg[s].cfg.transport       = tr;
        warg[s].cfg.wire_cast       = cast;
        warg[s].cfg.stage_index     = s;
        warg[s].cfg.layer_start     = s * 8u;
        warg[s].cfg.layer_end       = s * 8u + 7u;
        warg[s].cfg.d_model         = DEMO_DMODEL;
        warg[s].cfg.server_kp       = &skp[s];
        warg[s].cfg.allowed_peer_pk = ckp.pk;
        warg[s].cfg.io_timeout_ms   = 10000;
        warg[s].cfg.forward_fn      = transformer_stage_forward;
        assert(pthread_create(&wth[s], NULL, worker_thread, &warg[s]) == 0);

        eps[s].host        = "127.0.0.1";
        eps[s].port        = port;
        eps[s].expected_pk = skp[s].pk;
        eps[s].layer_start = s * 8u;
        eps[s].layer_end   = s * 8u + 7u;
    }

    sf_split_pipe_cfg_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.transport     = tr;
    pcfg.wire_cast     = cast;
    pcfg.d_model       = DEMO_DMODEL;
    pcfg.stage_count   = DEMO_STAGES;
    pcfg.stages        = eps;
    pcfg.client_kp     = &ckp;
    pcfg.io_timeout_ms = 10000;

    sf_split_pipe_t *pipe = NULL;
    uint64_t t0 = mono_ns();
    assert(sf_split_pipe_open(&pcfg, &pipe) == FP_OK);
    double open_ms = (double)(mono_ns() - t0) / 1e6;

    assert(sf_split_pipe_reset(pipe, 1u) == FP_OK);

    /* Build [K=4, d_model=1024] draft token activations + local FP32 reference */
    size_t elems = (size_t)DEMO_DRAFTK * DEMO_DMODEL;
    float *in_act  = malloc(elems * sizeof(float));
    float *ref_cur = malloc(elems * sizeof(float));
    float *ref_nxt = malloc(elems * sizeof(float));
    float *out_act = malloc(elems * sizeof(float));
    assert(in_act && ref_cur && ref_nxt && out_act);

    for (size_t i = 0; i < elems; i++) {
        in_act[i] = sinf(0.017f * (float)i) * 1.5f;
    }
    memcpy(ref_cur, in_act, elems * sizeof(float));
    for (uint32_t s = 0; s < DEMO_STAGES; s++) {
        assert(transformer_stage_forward(NULL, s * 8u, s * 8u + 7u, 10u,
                                         DEMO_DRAFTK, DEMO_DMODEL, ref_cur, ref_nxt) == FP_OK);
        memcpy(ref_cur, ref_nxt, elems * sizeof(float));
    }

    uint32_t accepted = 0;
    fp_dna_t step_trace;
    uint64_t ts0 = mono_ns();
    assert(sf_split_pipe_spec_verify(pipe, 10u, DEMO_DRAFTK, in_act, ref_cur,
                                     0.995f, out_act, &accepted, &step_trace) == FP_OK);
    double spec_ms = (double)(mono_ns() - ts0) / 1e6;
    double cos = cosine_sim(ref_cur, out_act, elems);

    sf_split_stats_t st;
    sf_split_pipe_stats(pipe, &st);
    sf_split_keryx_receipt_t rcpt;
    assert(sf_split_pipe_seal_keryx(pipe, &ckp, ws_url, &rcpt) == FP_OK);
    assert(fp_derivation_verify(&rcpt.derivation, ckp.pk) == FP_OK);

    char tag_hex[17], tr_hex[65];
    fp_hex_encode(rcpt.keryx_opoi_tag, 8, tag_hex);
    fp_hex_encode(st.chain_trace.bytes, 32, tr_hex);

    printf("SealFrame llama.cpp/Keryx Split-Model Shim Demo (%s, cast=%d):\n",
           tr == SF_SPLIT_UDP ? "FP-UDP1" : "TCP", (int)cast);
    printf("  3-stage warm open=%.2f ms | K=%u spec_verify=%.2f ms | accepted=%u/%u | cos=%.6f\n",
           open_ms, DEMO_DRAFTK, spec_ms, accepted, DEMO_DRAFTK, cos);
    printf("  wire tx=%llu B rx=%llu B udp_retx=%llu | chain=%.24s...\n",
           (unsigned long long)st.tx_bytes, (unsigned long long)st.rx_bytes,
           (unsigned long long)st.udp_retransmits, tr_hex);
    printf("  Keryx receipt: live=%d daa=%llu opoi_tag=%s sink=%.24s...\n",
           rcpt.keryx_live, (unsigned long long)rcpt.keryx_daa_score, tag_hex, rcpt.keryx_sink);

    sf_split_pipe_close(pipe);
    for (uint32_t s = 0; s < DEMO_STAGES; s++) {
        pthread_join(wth[s], NULL);
        sodium_memzero(&skp[s], sizeof(skp[s]));
    }
    sodium_memzero(&ckp, sizeof(ckp));
    free(in_act); free(ref_cur); free(ref_nxt); free(out_act);
    return 0;
}
