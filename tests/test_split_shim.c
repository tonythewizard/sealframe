/*
 * SealFrame FP-UDP1 Tensor Session & llama.cpp/Keryx Split-Model Shim Tests (Pure ISO C11)
 *
 * Verifies:
 *   1. Persistent encrypted FP-UDP1 tensor session (BF16 & INT8) with 0% AND 5% real packet loss
 *      (selective fragment NACK/retransmit + BLAKE3 DNA verification + cosine accuracy).
 *   2. 3-stage split-model pipeline (RMSNorm+SiLU residual blocks) over TCP & FP-UDP1 (2% loss)
 *      with warm KV-cache reset, SFT1 BF16/INT8, and rolling BLAKE3 TraceCommitment.
 *   3. Speculative K=4 multi-token verification (1 RTT across 3 stages):
 *      - Full acceptance (4/4) against local FP32 reference
 *      - Prefix cutoff (2/4) on controlled token-2 divergence
 *      - Signed FPD1 + 76-byte Keryx BlockDAG receipt sealing.
 *   4. llama.cpp ggml_type layer-boundary send/recv helpers (-50% BF16, -75% INT8 over FP-UDP1).
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe.h"
#include "sealframe_split.h"

#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static double cosine_sim(const float *a, const float *b, size_t n) {
    double dot = 0.0, na = 0.0, nb = 0.0;
    for (size_t i = 0; i < n; i++) {
        dot += (double)a[i] * (double)b[i];
        na  += (double)a[i] * (double)a[i];
        nb  += (double)b[i] * (double)b[i];
    }
    return dot / (sqrt(na) * sqrt(nb) + 1e-18);
}

/* ==================== Test 1: FP-UDP1 Persistent Tensor Session (0% & 5% Loss) ==================== */

typedef struct {
    int                 ufd;
    const fp_keypair_t *skp;
    const uint8_t      *allow_pk;
    uint32_t            drop_pct;
} udp_echo_t;

static void *udp_tensor_echo_thread(void *arg) {
    udp_echo_t *e = (udp_echo_t *)arg;
    fp_udp_session_t *us = NULL;
    if (fp_udp_session_accept(e->ufd, e->skp, e->allow_pk, 10000, e->drop_pct, &us) == FP_OK) {
        for (int i = 0; i < 4; i++) {
            uint8_t tag = 0;
            fp_tensor_meta_t m;
            uint8_t *data = NULL;
            size_t len = 0;
            if (fp_udp_session_recv_tensor(us, 8u << 20, 1, &tag, &m, &data, &len, NULL) != FP_OK) {
                break;
            }
            fp_wire_cast_t cast = (i % 2 == 0) ? FP_WIRE_CAST_BF16 : FP_WIRE_CAST_INT8;
            fp_err_t serr = fp_udp_session_send_tensor(us, tag, &m, data, len, cast, NULL);
            free(data);
            if (serr != FP_OK) break;
        }
        fp_udp_session_close(us);
    }
    close(e->ufd);
    return NULL;
}

static void test_udp_tensor_session(const fp_keypair_t *ckp, const fp_keypair_t *skp,
                                    uint32_t drop_pct) {
    uint16_t port = 0;
    int ufd = fp_udp_bind("127.0.0.1", 0, &port);
    assert(ufd >= 0);

    udp_echo_t ctx = { ufd, skp, ckp->pk, drop_pct };
    pthread_t th;
    assert(pthread_create(&th, NULL, udp_tensor_echo_thread, &ctx) == 0);

    fp_udp_session_t *cli = NULL;
    assert(fp_udp_session_connect("127.0.0.1", port, ckp, skp->pk, 10000, drop_pct, &cli) == FP_OK);

    /* [16, 4096] FP32 = 256 KiB -> 128 KiB BF16 (~114 UDP frags), 64 KiB INT8 (~57 UDP frags) */
    const uint32_t rows = 16u, cols = 4096u;
    size_t elems = (size_t)rows * cols;
    float *src = malloc(elems * sizeof(float));
    assert(src != NULL);
    for (size_t i = 0; i < elems; i++) src[i] = sinf(0.013f * (float)i) * 3.0f;

    fp_tensor_meta_t m;
    memset(&m, 0, sizeof(m));
    m.dtype = FP_DTYPE_FP32; m.ndim = 2u; m.dims[0] = rows; m.dims[1] = cols;

    for (int i = 0; i < 4; i++) {
        m.seq_id = (uint64_t)i;
        fp_wire_cast_t cast = (i % 2 == 0) ? FP_WIRE_CAST_BF16 : FP_WIRE_CAST_INT8;
        fp_dna_t tx_dna, rx_dna;
        assert(fp_udp_session_send_tensor(cli, 7u, &m, src, elems * 4u, cast, &tx_dna) == FP_OK);
        uint8_t rtag = 0;
        fp_tensor_meta_t rm;
        uint8_t *out = NULL;
        size_t olen = 0;
        assert(fp_udp_session_recv_tensor(cli, 8u << 20, 1, &rtag, &rm, &out, &olen, &rx_dna) == FP_OK);
        assert(rtag == 7u && olen == elems * 4u && rm.dims[0] == rows && rm.dims[1] == cols);
        double cos = cosine_sim(src, (const float *)out, elems);
        assert(cos > (cast == FP_WIRE_CAST_BF16 ? 0.9999 : 0.9990));
        free(out);
    }

    uint64_t tx_b = 0, rx_b = 0, retx = 0;
    fp_udp_session_stats(cli, &tx_b, &rx_b, &retx);
    uint64_t fec_rec = fp_udp_session_fec_recoveries(cli);
    assert(tx_b > 0 && rx_b > 0);
    if (drop_pct >= 5u) assert(fec_rec > 0 || retx > 0);
    fp_udp_session_close(cli);
    pthread_join(th, NULL);
    free(src);
    printf("  [PASS] FP-UDP1 persistent tensor session (drop=%u%%, tx=%llu B, fec_0rtt=%llu, retx=%llu)\n",
           drop_pct, (unsigned long long)tx_b, (unsigned long long)fec_rec, (unsigned long long)retx);
}

/* ==================== Test 2 & 3: 3-Stage Split Pipeline + Speculative Verify ==================== */

typedef struct {
    _Atomic uint32_t reset_calls;
} stage_model_t;

static void stage_reset_cb(void *ctx, uint64_t seq_id) {
    (void)seq_id;
    stage_model_t *sm = (stage_model_t *)ctx;
    atomic_fetch_add(&sm->reset_calls, 1u);
}

static fp_err_t stage_forward_cb(void *ctx,
                                 uint32_t layer_start, uint32_t layer_end,
                                 uint64_t seq_pos, uint32_t n_tokens,
                                 uint32_t d_model,
                                 const float *in_act, float *out_act) {
    (void)ctx;
    for (uint32_t t = 0; t < n_tokens; t++) {
        const float *x = in_act + (size_t)t * d_model;
        float *y = out_act + (size_t)t * d_model;
        double ss = 1e-6;
        for (uint32_t i = 0; i < d_model; i++) ss += (double)x[i] * (double)x[i];
        float inv = (float)(1.0 / sqrt(ss / (double)d_model));
        float ph = 0.04f * (float)(layer_start + layer_end + 1u) + 0.01f * (float)(seq_pos + t);
        for (uint32_t i = 0; i < d_model; i++) {
            float xn = x[i] * inv;
            float g  = xn * cosf(ph + 0.002f * (float)i);
            y[i] = x[i] + 0.15f * (g / (1.0f + expf(-g)));
        }
    }
    return FP_OK;
}

typedef struct {
    int                   fd;
    sf_split_worker_cfg_t cfg;
} split_w_arg_t;

static void *split_worker_fn(void *arg) {
    split_w_arg_t *w = (split_w_arg_t *)arg;
    (void)sf_split_worker_run(w->fd, &w->cfg);
    close(w->fd);
    return NULL;
}

static void test_split_pipeline(sf_split_transport_t tr, fp_wire_cast_t cast, uint32_t drop_pct) {
    enum { NST = 3, DMOD = 512, K = 4 };
    fp_keypair_t ckp, skp[NST];
    assert(fp_keygen(&ckp) == FP_OK);
    stage_model_t sm[NST];
    split_w_arg_t wa[NST];
    pthread_t th[NST];
    sf_split_stage_ep_t eps[NST];

    for (uint32_t s = 0; s < NST; s++) {
        assert(fp_keygen(&skp[s]) == FP_OK);
        atomic_init(&sm[s].reset_calls, 0u);
        uint16_t port = 0;
        int fd = (tr == SF_SPLIT_TCP) ? fp_net_listen("127.0.0.1", 0, &port)
                                      : fp_udp_bind("127.0.0.1", 0, &port);
        assert(fd >= 0);
        memset(&wa[s], 0, sizeof(wa[s]));
        wa[s].fd                  = fd;
        wa[s].cfg.transport       = tr;
        wa[s].cfg.wire_cast       = cast;
        wa[s].cfg.stage_index     = s;
        wa[s].cfg.layer_start     = s * 8u;
        wa[s].cfg.layer_end       = s * 8u + 7u;
        wa[s].cfg.d_model         = DMOD;
        wa[s].cfg.server_kp       = &skp[s];
        wa[s].cfg.allowed_peer_pk = ckp.pk;
        wa[s].cfg.io_timeout_ms   = 10000;
        wa[s].cfg.fault_drop_pct  = drop_pct;
        wa[s].cfg.forward_fn      = stage_forward_cb;
        wa[s].cfg.reset_fn        = stage_reset_cb;
        wa[s].cfg.model_ctx       = &sm[s];
        assert(pthread_create(&th[s], NULL, split_worker_fn, &wa[s]) == 0);

        eps[s].host        = "127.0.0.1";
        eps[s].port        = port;
        eps[s].expected_pk = skp[s].pk;
        eps[s].layer_start = s * 8u;
        eps[s].layer_end   = s * 8u + 7u;
    }

    sf_split_pipe_cfg_t pcfg;
    memset(&pcfg, 0, sizeof(pcfg));
    pcfg.transport      = tr;
    pcfg.wire_cast      = cast;
    pcfg.d_model        = DMOD;
    pcfg.stage_count    = NST;
    pcfg.stages         = eps;
    pcfg.client_kp      = &ckp;
    pcfg.io_timeout_ms  = 10000;
    pcfg.fault_drop_pct = drop_pct;

    sf_split_pipe_t *pipe = NULL;
    assert(sf_split_pipe_open(&pcfg, &pipe) == FP_OK);
    assert(sf_split_pipe_reset(pipe, 42u) == FP_OK);
    for (uint32_t s = 0; s < NST; s++) assert(atomic_load(&sm[s].reset_calls) == 1u);

    /* 1. Single-step forward pass & numerical parity vs local reference */
    size_t elems = (size_t)K * DMOD;
    float *in_act  = malloc(elems * sizeof(float));
    float *ref_a   = malloc(elems * sizeof(float));
    float *ref_b   = malloc(elems * sizeof(float));
    float *out_act = malloc(elems * sizeof(float));
    assert(in_act && ref_a && ref_b && out_act);
    for (size_t i = 0; i < elems; i++) in_act[i] = cosf(0.021f * (float)i) * 2.0f;

    memcpy(ref_a, in_act, elems * sizeof(float));
    for (uint32_t s = 0; s < NST; s++) {
        assert(stage_forward_cb(NULL, s * 8u, s * 8u + 7u, 100u, K, DMOD, ref_a, ref_b) == FP_OK);
        memcpy(ref_a, ref_b, elems * sizeof(float));
    }

    fp_dna_t tr1, tr2;
    assert(sf_split_pipe_forward(pipe, 100u, K, in_act, out_act, &tr1) == FP_OK);
    assert(!fp_dna_is_zero(&tr1));
    double cos1 = cosine_sim(ref_a, out_act, elems);
    assert(cos1 > (cast == FP_WIRE_CAST_BF16 ? 0.9998 : 0.9985));

    /* 2. Speculative K=4 verify: full accept (4/4) */
    uint32_t acc = 0;
    assert(sf_split_pipe_spec_verify(pipe, 100u, K, in_act, ref_a, 0.995f,
                                     out_act, &acc, &tr2) == FP_OK);
    assert(acc == K);
    assert(fp_dna_equal(&tr1, &tr2)); /* Deterministic trace commitment! */

    /* 3. Speculative K=4 verify: force mismatch at draft token #2 -> prefix accept must be 2 */
    for (uint32_t i = 0; i < DMOD; i++) ref_a[(size_t)2u * DMOD + i] *= -1.0f;
    assert(sf_split_pipe_spec_verify(pipe, 100u, K, in_act, ref_a, 0.995f,
                                     out_act, &acc, NULL) == FP_OK);
    assert(acc == 2u);

    /* 4. Seal Keryx offline receipt + verify Ed25519 FPD1 + 76B BlockDAG payload */
    sf_split_keryx_receipt_t rcpt;
    assert(sf_split_pipe_seal_keryx(pipe, &ckp, NULL, &rcpt) == FP_OK);
    assert(rcpt.keryx_live == 0);
    assert(fp_derivation_verify(&rcpt.derivation, ckp.pk) == FP_OK);
    assert(memcmp(rcpt.keryx_payload, "SF1\0", 4) == 0);

    sf_split_stats_t st;
    sf_split_pipe_stats(pipe, &st);
    assert(st.forward_calls == 3u && st.tokens_processed == 12u);
    assert(!fp_dna_is_zero(&st.chain_trace));

    sf_split_pipe_close(pipe);
    for (uint32_t s = 0; s < NST; s++) {
        pthread_join(th[s], NULL);
        sodium_memzero(&skp[s], sizeof(skp[s]));
    }
    sodium_memzero(&ckp, sizeof(ckp));
    free(in_act); free(ref_a); free(ref_b); free(out_act);
    printf("  [PASS] 3-stage split shim (%s, cast=%d, drop=%u%%, cos=%.6f, spec=4/4 & cutoff=2/4)\n",
           tr == SF_SPLIT_UDP ? "FP-UDP1" : "TCP", (int)cast, drop_pct, cos1);
}

/* ==================== Test 4: llama.cpp ggml_type Layer-Boundary Helpers ==================== */

typedef struct {
    int                 ufd;
    const fp_keypair_t *skp;
    const uint8_t      *allow_pk;
} ggml_srv_t;

static void *ggml_srv_thread(void *arg) {
    ggml_srv_t *g = (ggml_srv_t *)arg;
    fp_udp_session_t *us = NULL;
    if (fp_udp_session_accept(g->ufd, g->skp, g->allow_pk, 10000, 0, &us) == FP_OK) {
        for (int i = 0; i < 3; i++) {
            sf_ggml_type_t gt;
            uint32_t ne0 = 0, ne1 = 0;
            uint64_t pos = 0;
            uint8_t *buf = NULL;
            size_t len = 0;
            if (sf_ggml_boundary_recv(SF_SPLIT_UDP, NULL, us, 4u << 20, 1,
                                      &gt, &ne0, &ne1, &pos, &buf, &len, NULL) != FP_OK) break;
            assert(gt == SF_GGML_TYPE_F32 && ne0 == 2048u && ne1 == 4u && pos == (uint64_t)(50 + i));
            (void)fp_udp_session_send_verified(us, 1u, (const uint8_t *)"OK", 2u, NULL);
            free(buf);
        }
        fp_udp_session_close(us);
    }
    close(g->ufd);
    return NULL;
}

static void test_ggml_boundary_helpers(const fp_keypair_t *ckp, const fp_keypair_t *skp) {
    uint16_t port = 0;
    int ufd = fp_udp_bind("127.0.0.1", 0, &port);
    assert(ufd >= 0);
    ggml_srv_t gs = { ufd, skp, ckp->pk };
    pthread_t th;
    assert(pthread_create(&th, NULL, ggml_srv_thread, &gs) == 0);

    fp_udp_session_t *cli = NULL;
    assert(fp_udp_session_connect("127.0.0.1", port, ckp, skp->pk, 10000, 0, &cli) == FP_OK);

    const uint32_t ne0 = 2048u, ne1 = 4u;
    size_t fbytes = (size_t)ne0 * ne1 * sizeof(float);
    float *act = malloc(fbytes);
    assert(act != NULL);
    for (size_t i = 0; i < (size_t)ne0 * ne1; i++) act[i] = ((float)(i % 64) - 32.0f) * 0.05f;

    fp_wire_cast_t casts[3] = { FP_WIRE_CAST_NONE, FP_WIRE_CAST_BF16, FP_WIRE_CAST_INT8 };
    uint64_t bytes[3] = { 0, 0, 0 };
    for (int i = 0; i < 3; i++) {
        uint64_t btx = 0, brx = 0, atx = 0, arx = 0;
        fp_udp_session_stats(cli, &btx, &brx, NULL);
        assert(sf_ggml_boundary_send(SF_SPLIT_UDP, NULL, cli, SF_GGML_TYPE_F32,
                                     ne0, ne1, (uint64_t)(50 + i),
                                     act, fbytes, casts[i], NULL) == FP_OK);
        uint8_t rt = 0; uint8_t *rb = NULL; size_t rl = 0;
        assert(fp_udp_session_recv_verified(cli, 64, &rt, &rb, &rl, NULL) == FP_OK);
        free(rb);
        fp_udp_session_stats(cli, &atx, &arx, NULL);
        bytes[i] = atx - btx;
    }
    /* Verify BF16 cuts wire bytes ~50% and INT8 cuts wire bytes ~75% */
    assert(bytes[1] < (bytes[0] * 56u) / 100u);
    assert(bytes[2] < (bytes[0] * 30u) / 100u);

    fp_udp_session_close(cli);
    pthread_join(th, NULL);
    free(act);
    printf("  [PASS] llama.cpp ggml_type boundary shim over FP-UDP1 (FP32=%llu B -> BF16=%llu B -> INT8=%llu B)\n",
           (unsigned long long)bytes[0], (unsigned long long)bytes[1], (unsigned long long)bytes[2]);
}

/* ==================== Test 5: SFT1 INT4_G32 Codec & Edge Cases ==================== */

static void test_int4_g32_codec(void) {
    /* 1. Standard LLM hidden vector [4, 4096] -> exact -85.7% wire reduction */
    const uint32_t rows = 4u, cols = 4096u;
    size_t elems = (size_t)rows * cols;
    float *src = malloc(elems * sizeof(float));
    assert(src != NULL);
    for (size_t i = 0; i < elems; i++) src[i] = sinf(0.019f * (float)i) * 2.5f;

    fp_tensor_meta_t m;
    memset(&m, 0, sizeof(m));
    m.dtype = FP_DTYPE_FP32; m.ndim = 2u; m.dims[0] = rows; m.dims[1] = cols; m.seq_id = 99u;

    uint8_t *w_i4 = NULL, *dec = NULL;
    size_t l_i4 = 0, dlen = 0;
    assert(fp_tensor_pack_ex(&m, src, elems * 4u, FP_WIRE_CAST_INT4_G32, &w_i4, &l_i4) == FP_OK);
    /* 32B hdr + (16384/32)*18 = 32 + 9216 = 9248 B vs 65568 B FP32 */
    assert(l_i4 == 32u + (elems / 32u) * 18u);

    fp_tensor_meta_t dm;
    assert(fp_tensor_unpack(w_i4, l_i4, 1, &dm, &dec, &dlen) == FP_OK);
    assert(dm.dtype == FP_DTYPE_FP32 && dlen == elems * 4u && dm.seq_id == 99u);
    double cos = cosine_sim(src, (const float *)dec, elems);
    assert(cos > 0.992);

    /* Negative test: corrupt FP16 scale to NaN (0x7E00) -> fail-closed FP_ERR_INVALID */
    w_i4[32] = 0x00u; w_i4[33] = 0x7Eu;
    uint8_t *bad = NULL; size_t blen = 0;
    assert(fp_tensor_unpack(w_i4, l_i4, 1, &dm, &bad, &blen) == FP_ERR_INVALID && bad == NULL);

    free(w_i4); free(dec); free(src);

    /* 2. Non-multiple-of-32 dims (37 elements) + all-zero vector */
    float odd[37];
    memset(odd, 0, sizeof(odd));
    m.ndim = 1u; m.dims[0] = 37u; m.dims[1] = 0u;
    assert(fp_tensor_pack_ex(&m, odd, sizeof(odd), FP_WIRE_CAST_INT4_G32, &w_i4, &l_i4) == FP_OK);
    assert(l_i4 == 32u + 2u * 18u);
    assert(fp_tensor_unpack(w_i4, l_i4, 1, &dm, &dec, &dlen) == FP_OK && dlen == sizeof(odd));
    for (int i = 0; i < 37; i++) assert(((const float *)dec)[i] == 0.0f);
    free(w_i4); free(dec);
    printf("  [PASS] SFT1 INT4_G32 group-32 wire codec (-85.9%% wire, cos=%.6f, odd/zero/NaN checks)\n", cos);
}

/* ==================== Test 6: 4-Stage Ring P2P + Prefix KV-Cache DNA + Adaptive K ==================== */

typedef struct {
    int                        fd;
    sf_split_ring_worker_cfg_t cfg;
} ring_w_arg_t;

static void *ring_worker_fn(void *arg) {
    ring_w_arg_t *w = (ring_w_arg_t *)arg;
    (void)sf_split_ring_worker_run(w->fd, &w->cfg);
    close(w->fd);
    return NULL;
}

static void test_ring_p2p_and_prefix_kv(sf_split_transport_t tr, uint32_t drop_pct) {
    enum { NST = 4, DMOD = 256, TOT_P = 64, PIN_P = 56 };
    fp_keypair_t ckp, skp[NST];
    assert(fp_keygen(&ckp) == FP_OK);
    for (uint32_t s = 0; s < NST; s++) assert(fp_keygen(&skp[s]) == FP_OK);

    uint16_t ret_port = 0;
    int ret_fd = (tr == SF_SPLIT_TCP) ? fp_net_listen("127.0.0.1", 0, &ret_port)
                                      : fp_udp_bind("127.0.0.1", 0, &ret_port);
    assert(ret_fd >= 0);

    uint16_t sports[NST];
    int sfds[NST];
    for (uint32_t s = 0; s < NST; s++) {
        sfds[s] = (tr == SF_SPLIT_TCP) ? fp_net_listen("127.0.0.1", 0, &sports[s])
                                       : fp_udp_bind("127.0.0.1", 0, &sports[s]);
        assert(sfds[s] >= 0);
    }

    stage_model_t sm[NST];
    ring_w_arg_t rw[NST];
    pthread_t th[NST];
    for (uint32_t s = 0; s < NST; s++) {
        atomic_init(&sm[s].reset_calls, 0u);
        memset(&rw[s], 0, sizeof(rw[s]));
        rw[s].fd                   = sfds[s];
        rw[s].cfg.transport        = tr;
        rw[s].cfg.wire_cast        = FP_WIRE_CAST_INT4_G32;
        rw[s].cfg.stage_index      = s;
        rw[s].cfg.layer_start      = s * 8u;
        rw[s].cfg.layer_end        = s * 8u + 7u;
        rw[s].cfg.d_model          = DMOD;
        rw[s].cfg.stage_kp         = &skp[s];
        rw[s].cfg.prev_allowed_pk  = (s == 0) ? ckp.pk : skp[s - 1].pk;
        rw[s].cfg.next_host        = "127.0.0.1";
        rw[s].cfg.next_port        = (s + 1u < NST) ? sports[s + 1] : ret_port;
        rw[s].cfg.next_expected_pk = (s + 1u < NST) ? skp[s + 1].pk : ckp.pk;
        rw[s].cfg.io_timeout_ms    = 12000;
        rw[s].cfg.fault_drop_pct   = drop_pct;
        rw[s].cfg.forward_fn       = stage_forward_cb;
        rw[s].cfg.reset_fn         = stage_reset_cb;
        rw[s].cfg.model_ctx        = &sm[s];
        assert(pthread_create(&th[s], NULL, ring_worker_fn, &rw[s]) == 0);
    }

    sf_split_ring_cfg_t rcfg = {
        tr, FP_WIRE_CAST_INT4_G32, DMOD, NST,
        "127.0.0.1", sports[0], skp[0].pk,
        ret_fd, skp[NST - 1].pk, &ckp, 12000, drop_pct
    };
    sf_split_ring_t *ring = NULL;
    assert(sf_split_ring_open(&rcfg, &ring) == FP_OK);
    assert(sf_split_ring_reset(ring, 7u) == FP_OK);
    for (uint32_t s = 0; s < NST; s++) assert(atomic_load(&sm[s].reset_calls) == 1u);

    size_t elems = (size_t)TOT_P * DMOD;
    float *full_in = malloc(elems * sizeof(float));
    float *ref_a   = malloc(elems * sizeof(float));
    float *ref_b   = malloc(elems * sizeof(float));
    float *out_buf = malloc(elems * sizeof(float));
    assert(full_in && ref_a && ref_b && out_buf);
    for (size_t i = 0; i < elems; i++) full_in[i] = sinf(0.011f * (float)i) * 1.8f;

    memcpy(ref_a, full_in, elems * sizeof(float));
    for (uint32_t s = 0; s < NST; s++) {
        assert(stage_forward_cb(NULL, s * 8u, s * 8u + 7u, 0u, TOT_P, DMOD, ref_a, ref_b) == FP_OK);
        memcpy(ref_a, ref_b, elems * sizeof(float));
    }

    fp_dna_t p_dna, tr1, tr2;
    assert(fp_dna_compute((const uint8_t *)"SYS_PROMPT_56_TOKENS", 20, &p_dna) == FP_OK);

    /* Turn 1: MISS -> sends all 64 tokens, pins prefix_dna across all 4 stages */
    uint32_t ot1 = 0, ot2 = 0;
    int hit1 = -1, hit2 = -1;
    sf_split_stats_t sb, sa1, sa2;
    sf_split_ring_stats(ring, &sb);
    assert(sf_split_ring_prefix_forward(ring, 0u, &p_dna, PIN_P, TOT_P,
                                        full_in, out_buf, &ot1, &hit1, &tr1) == FP_OK);
    assert(hit1 == 0 && ot1 == TOT_P && !fp_dna_is_zero(&tr1));
    double cos_ring = cosine_sim(ref_a, out_buf, elems);
    assert(cos_ring > 0.985);
    sf_split_ring_stats(ring, &sa1);

    /* Turn 2: HIT -> sends ONLY 8 delta tokens (-87.5% wire!) */
    assert(sf_split_ring_prefix_forward(ring, 0u, &p_dna, PIN_P, TOT_P,
                                        full_in, out_buf, &ot2, &hit2, &tr2) == FP_OK);
    assert(hit2 == 1 && ot2 == (TOT_P - PIN_P) && !fp_dna_is_zero(&tr2));
    sf_split_ring_stats(ring, &sa2);
    uint64_t tx_miss = sa1.tx_bytes - sb.tx_bytes;
    uint64_t tx_hit  = sa2.tx_bytes - sa1.tx_bytes;
    assert(tx_hit < tx_miss / 4u); /* >4x wire savings on prefix KV-cache hit! */

    sf_split_ring_close(ring);
    close(ret_fd);
    for (uint32_t s = 0; s < NST; s++) {
        pthread_join(th[s], NULL);
        sodium_memzero(&skp[s], sizeof(skp[s]));
    }
    sodium_memzero(&ckp, sizeof(ckp));
    free(full_in); free(ref_a); free(ref_b); free(out_buf);
    printf("  [PASS] 4-stage Ring P2P (%s, INT4_G32, drop=%u%%, cos=%.5f, KV-hit TX %llu -> %llu B)\n",
           tr == SF_SPLIT_UDP ? "FP-UDP1" : "TCP", drop_pct, cos_ring,
           (unsigned long long)tx_miss, (unsigned long long)tx_hit);
}

static void test_adaptive_spec_k(void) {
    sf_spec_adapt_t ad;
    sf_spec_adapt_init(&ad, 2u, 8u, 4u);
    assert(ad.current_k == 4u);
    /* High acceptance -> scales K upward toward 8 */
    for (int i = 0; i < 6; i++) (void)sf_spec_adapt_update(&ad, ad.current_k, ad.current_k);
    assert(ad.current_k > 4u && ad.current_k <= 8u);
    /* Low acceptance -> backs off K downward toward 2 */
    for (int i = 0; i < 10; i++) (void)sf_spec_adapt_update(&ad, ad.current_k, 1u);
    assert(ad.current_k <= 3u && ad.current_k >= 2u);
    printf("  [PASS] Adaptive Speculative-K controller (scales up on hits, backs off on misses)\n");
}

/* ==================== Test 7: SFT1 INT4_G32 + Top-1% Outlier FP16 ==================== */

static double sqnr_db(const float *ref, const float *rec, size_t n) {
    double sig2 = 0.0, err2 = 0.0;
    for (size_t i = 0; i < n; i++) {
        double a = (double)ref[i], d = a - (double)rec[i];
        sig2 += a * a;
        err2 += d * d;
    }
    return 10.0 * log10(sig2 / (err2 + 1e-18));
}

static void test_int4_outlier_codec(void) {
    const uint32_t rows = 4u, cols = 4096u;
    size_t elems = (size_t)rows * cols;
    float *src = malloc(elems * sizeof(float));
    assert(src != NULL);
    for (size_t i = 0; i < elems; i++) {
        float v = sinf(0.031f * (float)i) * 0.8f;
        if ((i % 128u) == 7u) v *= 8.0f; /* 0.78% heavy LLM outlier channels */
        src[i] = v;
    }

    fp_tensor_meta_t m;
    memset(&m, 0, sizeof(m));
    m.dtype = FP_DTYPE_FP32; m.ndim = 2u; m.dims[0] = rows; m.dims[1] = cols; m.seq_id = 77u;

    uint8_t *w_i4 = NULL, *w_i4o = NULL, *d_i4 = NULL, *d_i4o = NULL;
    size_t l_i4 = 0, l_i4o = 0, dl1 = 0, dl2 = 0;
    fp_tensor_meta_t dm;
    assert(fp_tensor_pack_ex(&m, src, elems * 4u, FP_WIRE_CAST_INT4_G32, &w_i4, &l_i4) == FP_OK);
    assert(fp_tensor_pack_ex(&m, src, elems * 4u, FP_WIRE_CAST_INT4_OUTLIER, &w_i4o, &l_i4o) == FP_OK);
    assert(fp_tensor_unpack(w_i4, l_i4, 1, &dm, &d_i4, &dl1) == FP_OK);
    assert(fp_tensor_unpack(w_i4o, l_i4o, 1, &dm, &d_i4o, &dl2) == FP_OK && dl2 == elems * 4u);

    double sqnr_plain = sqnr_db(src, (const float *)d_i4, elems);
    double sqnr_out   = sqnr_db(src, (const float *)d_i4o, elems);
    double cos_out    = cosine_sim(src, (const float *)d_i4o, elems);
    /* Must keep >82% wire reduction vs FP32 AND jump SQNR by > +6 dB! */
    assert(l_i4o < (elems * 4u * 18u) / 100u);
    assert(sqnr_out > sqnr_plain + 6.0 && cos_out > 0.9985);

    /* Negative test 1: duplicate outlier index -> fail-closed FP_ERR_INVALID (AI-04) */
    uint8_t saved_idx[4];
    memcpy(saved_idx, w_i4o + 42, 4);
    memcpy(w_i4o + 42, w_i4o + 36, 4); /* duplicate index 0 into entry 1 */
    uint8_t *bad = NULL; size_t blen = 0;
    assert(fp_tensor_unpack(w_i4o, l_i4o, 1, &dm, &bad, &blen) == FP_ERR_INVALID && bad == NULL);
    memcpy(w_i4o + 42, saved_idx, 4);

    /* Negative test 2: out-of-bounds outlier index -> fail-closed FP_ERR_BOUNDS */
    w_i4o[36] = 0xFFu; w_i4o[37] = 0xFFu; w_i4o[38] = 0xFFu; w_i4o[39] = 0x0Fu;
    assert(fp_tensor_unpack(w_i4o, l_i4o, 1, &dm, &bad, &blen) == FP_ERR_BOUNDS && bad == NULL);

    /* Negative test 3 (AI-04): FP16 scale overflow (>65504*7) -> fail-closed FP_ERR_BOUNDS */
    float huge_vals[64];
    for (int i = 0; i < 64; i++) huge_vals[i] = 1e6f;
    fp_tensor_meta_t hm;
    memset(&hm, 0, sizeof(hm));
    hm.dtype = FP_DTYPE_FP32; hm.ndim = 1u; hm.dims[0] = 64u;
    uint8_t *hw = NULL; size_t hlen = 0;
    assert(fp_tensor_pack_ex(&hm, huge_vals, sizeof(huge_vals), FP_WIRE_CAST_INT4_G32, &hw, &hlen) == FP_ERR_BOUNDS && hw == NULL);
    assert(fp_tensor_pack_ex(&hm, huge_vals, sizeof(huge_vals), FP_WIRE_CAST_INT4_OUTLIER, &hw, &hlen) == FP_ERR_BOUNDS && hw == NULL);

    free(w_i4); free(w_i4o); free(d_i4); free(d_i4o); free(src);
    printf("  [PASS] SFT1 INT4+Outlier FP16 (%zu B vs %zu B FP32, SQNR %.2f -> %.2f dB, cos=%.6f, AI-04 guards OK)\n",
           l_i4o, elems * 4u, sqnr_plain, sqnr_out, cos_out);
}

/* ==================== Test 8: Straggler Watchdog & Hot-Standby Failover ==================== */

static fp_err_t slow_straggler_forward_cb(void *ctx,
                                          uint32_t layer_start, uint32_t layer_end,
                                          uint64_t seq_pos, uint32_t n_tokens,
                                          uint32_t d_model,
                                          const float *in_act, float *out_act) {
    struct timespec ts = { 0, 40000000L }; /* 40 ms straggler stall */
    nanosleep(&ts, NULL);
    return stage_forward_cb(ctx, layer_start, layer_end, seq_pos, n_tokens, d_model, in_act, out_act);
}

static void test_straggler_failover(void) {
    enum { NST = 3, DMOD = 256 };
    fp_keypair_t ckp, skp[NST], sb_kp;
    assert(fp_keygen(&ckp) == FP_OK && fp_keygen(&sb_kp) == FP_OK);
    split_w_arg_t wa[NST], sb_wa;
    pthread_t th[NST], sb_th;
    sf_split_stage_ep_t eps[NST], sb_ep;

    for (uint32_t s = 0; s < NST; s++) {
        assert(fp_keygen(&skp[s]) == FP_OK);
        uint16_t port = 0;
        int fd = fp_net_listen("127.0.0.1", 0, &port);
        assert(fd >= 0);
        memset(&wa[s], 0, sizeof(wa[s]));
        wa[s].fd = fd;
        wa[s].cfg.transport = SF_SPLIT_TCP; wa[s].cfg.wire_cast = FP_WIRE_CAST_INT8;
        wa[s].cfg.stage_index = s; wa[s].cfg.layer_start = s * 8u; wa[s].cfg.layer_end = s * 8u + 7u;
        wa[s].cfg.d_model = DMOD; wa[s].cfg.server_kp = &skp[s]; wa[s].cfg.allowed_peer_pk = ckp.pk;
        /* Inject a 40 ms straggler on Stage 1! */
        wa[s].cfg.forward_fn = (s == 1u) ? slow_straggler_forward_cb : stage_forward_cb;
        assert(pthread_create(&th[s], NULL, split_worker_fn, &wa[s]) == 0);
        eps[s].host = "127.0.0.1"; eps[s].port = port; eps[s].expected_pk = skp[s].pk;
    }

    /* Healthy warm standby for Stage 1 (0 ms stall) */
    uint16_t sb_port = 0;
    int sb_fd = fp_net_listen("127.0.0.1", 0, &sb_port);
    assert(sb_fd >= 0);
    memset(&sb_wa, 0, sizeof(sb_wa));
    sb_wa.fd = sb_fd;
    sb_wa.cfg.transport = SF_SPLIT_TCP; sb_wa.cfg.wire_cast = FP_WIRE_CAST_INT8;
    sb_wa.cfg.stage_index = 1u; sb_wa.cfg.layer_start = 8u; sb_wa.cfg.layer_end = 15u;
    sb_wa.cfg.d_model = DMOD; sb_wa.cfg.server_kp = &sb_kp; sb_wa.cfg.allowed_peer_pk = ckp.pk;
    sb_wa.cfg.forward_fn = stage_forward_cb;
    assert(pthread_create(&sb_th, NULL, split_worker_fn, &sb_wa) == 0);
    sb_ep.host = "127.0.0.1"; sb_ep.port = sb_port; sb_ep.expected_pk = sb_kp.pk;

    sf_split_pipe_cfg_t pcfg = { SF_SPLIT_TCP, FP_WIRE_CAST_INT8, DMOD, NST, eps, &ckp, 10000, 0 };
    sf_split_pipe_t *pipe = NULL;
    assert(sf_split_pipe_open(&pcfg, &pipe) == FP_OK);
    assert(sf_split_pipe_set_standby(pipe, 1u, &sb_ep, 15) == FP_OK);

    float in_v[DMOD], out1[DMOD], out2[DMOD];
    for (uint32_t i = 0; i < DMOD; i++) in_v[i] = sinf(0.05f * (float)i);

    /* Step 1 hits slow primary (40 ms > 15 ms budget) -> evicts straggler & promotes standby! */
    assert(sf_split_pipe_forward(pipe, 1u, 1u, in_v, out1, NULL) == FP_OK);
    sf_split_stats_t st;
    sf_split_pipe_stats(pipe, &st);
    assert(st.straggler_failovers == 1u);

    /* Step 2 runs on fast warm standby (< 10 ms!) with identical deterministic output */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    assert(sf_split_pipe_forward(pipe, 1u, 1u, in_v, out2, NULL) == FP_OK);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double fast_ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
    assert(fast_ms < 20.0);
    assert(cosine_sim(out1, out2, DMOD) > 0.9999);

    sf_split_pipe_close(pipe);
    for (uint32_t s = 0; s < NST; s++) {
        pthread_join(th[s], NULL);
        sodium_memzero(&skp[s], sizeof(skp[s]));
    }
    pthread_join(sb_th, NULL);
    sodium_memzero(&sb_kp, sizeof(sb_kp));
    sodium_memzero(&ckp, sizeof(ckp));
    printf("  [PASS] Straggler Watchdog & Hot-Standby Failover (40 ms straggler evicted -> %.2f ms standby!)\n",
           fast_ms);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    assert(fp_init() == FP_OK);

    fp_keypair_t ckp, skp;
    assert(fp_keygen(&ckp) == FP_OK);
    assert(fp_keygen(&skp) == FP_OK);

    printf("Running SealFrame FP-UDP1 + Split-Model/llama.cpp Shim Tests...\n");
    test_udp_tensor_session(&ckp, &skp, 0u);
    test_udp_tensor_session(&ckp, &skp, 5u);
    test_split_pipeline(SF_SPLIT_TCP, FP_WIRE_CAST_BF16, 0u);
    test_split_pipeline(SF_SPLIT_UDP, FP_WIRE_CAST_INT8, 2u);
    test_ggml_boundary_helpers(&ckp, &skp);
    test_int4_g32_codec();
    test_int4_outlier_codec();
    test_ring_p2p_and_prefix_kv(SF_SPLIT_TCP, 0u);
    test_ring_p2p_and_prefix_kv(SF_SPLIT_UDP, 2u);
    test_adaptive_spec_k();
    test_straggler_failover();

    sodium_memzero(&ckp, sizeof(ckp));
    sodium_memzero(&skp, sizeof(skp));
    printf("ALL SPLIT-SHIM & FP-UDP1 TESTS PASSED.\n");
    return 0;
}
