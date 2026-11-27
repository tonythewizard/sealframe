/*
 * SealFrame Mixed-Inference v2 — Persistent Encrypted Streaming Edge Stage-1 (ISO C11)
 *
 * Uses libsealframe's 1-RTT persistent authenticated encrypted session (fp_session_*):
 *   - Mutual Ed25519 pinning + X25519 PFS + XChaCha20-Poly1305 AEAD + BLAKE3 DNA per message
 *   - ZERO per-token TCP/handshake overhead, ZERO disk I/O on hot decode path
 *   - Incremental KV-cache slice streaming: 10 KiB (FP32) or 5 KiB (FP16) per generated token
 *     instead of re-sending or re-diffing the 4.1 MiB KV-cache on disk!
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe.h"

#include <math.h>
#include <signal.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define D_MODEL     512
#define N_HEADS     8
#define HEAD_DIM    (D_MODEL / N_HEADS)
#define D_FF        1024
#define VOCAB_SZ    4096
#define EDGE_LAYERS 2
#define MAX_SEQ     640

enum {
    TAG_PREFILL   = 1, /* Req: [u32 n | u32 tokens[n]] -> Resp: [u32 seq | u32 edge_us | hidden | K | V] */
    TAG_STEP_FP32 = 2, /* Req: [u32 tok] -> Resp: [u32 seq | u32 edge_us | hidden(512) | K_new(2*512) | V_new(2*512)] */
    TAG_STEP_FP16 = 3, /* Req: [u32 tok] -> Resp: same slice wire-quantized to IEEE-754 binary16 (5 KiB!) */
    TAG_RESET     = 4, /* Req: empty -> resets KV-cache position to 0, replies empty */
    TAG_QUIT      = 5  /* Req: empty -> replies [u64 rss_kb | u64 tx_bytes | u64 rx_bytes] and exits */
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static float det_weight(uint64_t seed, uint64_t idx, float scale) {
    uint64_t z = seed + idx * UINT64_C(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    z = z ^ (z >> 31);
    float u = (float)(z >> 40) * (1.0f / 8388608.0f) - 1.0f;
    return u * scale;
}

static void fill_matrix(float *dst, size_t n, uint64_t seed, float scale) {
    for (size_t i = 0; i < n; i++) dst[i] = det_weight(seed, (uint64_t)i, scale);
}

static void rmsnorm(const float *x, const float *g, float *out, int d) {
    double ss = 0.0;
    for (int i = 0; i < d; i++) ss += (double)x[i] * (double)x[i];
    float inv = 1.0f / sqrtf((float)(ss / (double)d) + 1e-5f);
    for (int i = 0; i < d; i++) out[i] = x[i] * inv * g[i];
}

static void matvec(const float *x, const float *W, float *y, int in_d, int out_d) {
    memset(y, 0, (size_t)out_d * sizeof(float));
    for (int i = 0; i < in_d; i++) {
        float xi = x[i];
        const float *wrow = W + (size_t)i * (size_t)out_d;
        for (int j = 0; j < out_d; j++) y[j] += xi * wrow[j];
    }
}

typedef struct {
    float g1[D_MODEL], g2[D_MODEL];
    float *Wq, *Wk, *Wv, *Wo, *W1, *W2;
} layer_w_t;

static void init_layer(layer_w_t *L, int layer_idx) {
    uint64_t base = UINT64_C(0x5EA1F00000000000) + (uint64_t)layer_idx * UINT64_C(0x10000000);
    for (int i = 0; i < D_MODEL; i++) { L->g1[i] = 1.0f; L->g2[i] = 1.0f; }
    L->Wq = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
    L->Wk = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
    L->Wv = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
    L->Wo = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
    L->W1 = malloc((size_t)D_MODEL * D_FF * sizeof(float));
    L->W2 = malloc((size_t)D_FF * D_MODEL * sizeof(float));
    float s_att = 1.0f / sqrtf((float)D_MODEL);
    float s_ff  = 1.0f / sqrtf((float)D_FF);
    fill_matrix(L->Wq, (size_t)D_MODEL * D_MODEL, base + 1, s_att);
    fill_matrix(L->Wk, (size_t)D_MODEL * D_MODEL, base + 2, s_att);
    fill_matrix(L->Wv, (size_t)D_MODEL * D_MODEL, base + 3, s_att);
    fill_matrix(L->Wo, (size_t)D_MODEL * D_MODEL, base + 4, s_att);
    fill_matrix(L->W1, (size_t)D_MODEL * D_FF,    base + 5, s_att);
    fill_matrix(L->W2, (size_t)D_FF * D_MODEL,    base + 6, s_ff);
}

static void free_layer(layer_w_t *L) {
    free(L->Wq); free(L->Wk); free(L->Wv); free(L->Wo); free(L->W1); free(L->W2);
}

static void run_token_step(int pos, int tok_id, const layer_w_t layers[EDGE_LAYERS],
                           float *K_cache, float *V_cache, float *out_hidden,
                           float *out_k_new, float *out_v_new) {
    float x[D_MODEL], xn[D_MODEL], q[D_MODEL], k[D_MODEL], v[D_MODEL];
    float att[D_MODEL], proj[D_MODEL], ff[D_FF], ff_out[D_MODEL], scores[MAX_SEQ];

    uint64_t emb_seed = UINT64_C(0xE0B0000000000000) + (uint64_t)(tok_id % VOCAB_SZ) * 1024ull;
    for (int i = 0; i < D_MODEL; i++) x[i] = det_weight(emb_seed, (uint64_t)i, 0.25f);

    float inv_sqrt_hd = 1.0f / sqrtf((float)HEAD_DIM);
    for (int l = 0; l < EDGE_LAYERS; l++) {
        rmsnorm(x, layers[l].g1, xn, D_MODEL);
        matvec(xn, layers[l].Wq, q, D_MODEL, D_MODEL);
        matvec(xn, layers[l].Wk, k, D_MODEL, D_MODEL);
        matvec(xn, layers[l].Wv, v, D_MODEL, D_MODEL);

        size_t kv_off = ((size_t)l * MAX_SEQ + (size_t)pos) * D_MODEL;
        memcpy(K_cache + kv_off, k, D_MODEL * sizeof(float));
        memcpy(V_cache + kv_off, v, D_MODEL * sizeof(float));
        if (out_k_new) memcpy(out_k_new + (size_t)l * D_MODEL, k, D_MODEL * sizeof(float));
        if (out_v_new) memcpy(out_v_new + (size_t)l * D_MODEL, v, D_MODEL * sizeof(float));

        memset(att, 0, sizeof(att));
        for (int h = 0; h < N_HEADS; h++) {
            int hoff = h * HEAD_DIM;
            float max_s = -1e30f;
            for (int t = 0; t <= pos; t++) {
                const float *kt = K_cache + ((size_t)l * MAX_SEQ + (size_t)t) * D_MODEL + hoff;
                float dot = 0.0f;
                for (int d = 0; d < HEAD_DIM; d++) dot += q[hoff + d] * kt[d];
                scores[t] = dot * inv_sqrt_hd;
                if (scores[t] > max_s) max_s = scores[t];
            }
            float sum_e = 0.0f;
            for (int t = 0; t <= pos; t++) { scores[t] = expf(scores[t] - max_s); sum_e += scores[t]; }
            float inv_sum = 1.0f / sum_e;
            for (int t = 0; t <= pos; t++) {
                float w = scores[t] * inv_sum;
                const float *vt = V_cache + ((size_t)l * MAX_SEQ + (size_t)t) * D_MODEL + hoff;
                for (int d = 0; d < HEAD_DIM; d++) att[hoff + d] += w * vt[d];
            }
        }
        matvec(att, layers[l].Wo, proj, D_MODEL, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += proj[i];

        rmsnorm(x, layers[l].g2, xn, D_MODEL);
        matvec(xn, layers[l].W1, ff, D_MODEL, D_FF);
        for (int i = 0; i < D_FF; i++) ff[i] = ff[i] / (1.0f + expf(-ff[i]));
        matvec(ff, layers[l].W2, ff_out, D_FF, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += ff_out[i];
    }
    memcpy(out_hidden, x, D_MODEL * sizeof(float));
}

static int read_exact(const char *path, uint8_t *dst, size_t n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(dst, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 4) {
        fprintf(stderr, "usage: edge_infer_stream <bind_ip> <port> <srv.sk> [client.pk]\n");
        return 1;
    }
    if (fp_init() != FP_OK) return 1;

    fp_keypair_t srv_kp;
    if (read_exact(argv[3], srv_kp.sk, FP_SK_LEN) != 0) return 1;
    memcpy(srv_kp.pk, srv_kp.sk + 32, FP_PK_LEN);

    uint8_t allow_pk[FP_PK_LEN];
    const uint8_t *allow_ptr = NULL;
    if (argc >= 5) {
        if (read_exact(argv[4], allow_pk, FP_PK_LEN) != 0) return 1;
        allow_ptr = allow_pk;
    }

    layer_w_t layers[EDGE_LAYERS];
    for (int l = 0; l < EDGE_LAYERS; l++) init_layer(&layers[l], l);
    float *K_cache = calloc((size_t)EDGE_LAYERS * MAX_SEQ * D_MODEL, sizeof(float));
    float *V_cache = calloc((size_t)EDGE_LAYERS * MAX_SEQ * D_MODEL, sizeof(float));

    uint16_t bport = 0;
    int lfd = fp_net_listen(argv[1], (uint16_t)atoi(argv[2]), &bport);
    if (lfd < 0) return 1;
    printf("READY %s:%u\n", argv[1], (unsigned)bport);
    fflush(stdout);

    fp_session_t *sess = NULL;
    if (fp_session_accept(lfd, &srv_kp, allow_ptr, 30000, &sess) != FP_OK) {
        close(lfd);
        return 1;
    }
    close(lfd);

    int cur_seq = 0;
    float last_hidden[D_MODEL];
    float k_new[EDGE_LAYERS * D_MODEL];
    float v_new[EDGE_LAYERS * D_MODEL];

    for (;;) {
        uint8_t tag = 0;
        uint8_t *req = NULL;
        size_t req_len = 0;
        if (fp_session_recv_verified(sess, 4u << 20, &tag, &req, &req_len, NULL) != FP_OK) {
            break;
        }

        if (tag == TAG_RESET) {
            free(req);
            cur_seq = 0;
            if (fp_session_send_verified(sess, TAG_RESET, NULL, 0, NULL) != FP_OK) break;
        } else if (tag == TAG_PREFILL && req_len >= 4u) {
            uint32_t ntok = 0;
            memcpy(&ntok, req, 4);
            if (ntok == 0 || ntok > MAX_SEQ || req_len != 4u + (size_t)ntok * 4u) {
                free(req);
                break;
            }
            cur_seq = 0;
            uint64_t t0 = now_ns();
            for (uint32_t p = 0; p < ntok; p++) {
                uint32_t tok = 0;
                memcpy(&tok, req + 4u + (size_t)p * 4u, 4);
                run_token_step((int)p, (int)tok, layers, K_cache, V_cache, last_hidden, NULL, NULL);
            }
            uint32_t edge_us = (uint32_t)((now_ns() - t0) / 1000u);
            cur_seq = (int)ntok;
            free(req);

            /* Reply: [u32 seq | u32 edge_us | hidden[D] | K[L,seq,D] | V[L,seq,D]] */
            size_t kv_bytes = (size_t)EDGE_LAYERS * (size_t)cur_seq * D_MODEL * sizeof(float);
            size_t resp_len = 8u + D_MODEL * sizeof(float) + 2u * kv_bytes;
            uint8_t *resp = malloc(resp_len);
            if (!resp) break;
            uint32_t hdr[2] = { (uint32_t)cur_seq, edge_us };
            memcpy(resp, hdr, 8);
            size_t off = 8;
            memcpy(resp + off, last_hidden, D_MODEL * sizeof(float));
            off += D_MODEL * sizeof(float);
            for (int l = 0; l < EDGE_LAYERS; l++) {
                size_t lb = (size_t)cur_seq * D_MODEL * sizeof(float);
                memcpy(resp + off, K_cache + (size_t)l * MAX_SEQ * D_MODEL, lb);
                off += lb;
            }
            for (int l = 0; l < EDGE_LAYERS; l++) {
                size_t lb = (size_t)cur_seq * D_MODEL * sizeof(float);
                memcpy(resp + off, V_cache + (size_t)l * MAX_SEQ * D_MODEL, lb);
                off += lb;
            }
            fp_err_t serr = fp_session_send_verified(sess, TAG_PREFILL, resp, resp_len, NULL);
            free(resp);
            if (serr != FP_OK) break;
        } else if ((tag == TAG_STEP_FP32 || tag == TAG_STEP_FP16) && req_len == 4u && cur_seq < MAX_SEQ) {
            uint32_t tok = 0;
            memcpy(&tok, req, 4);
            free(req);

            uint64_t t0 = now_ns();
            run_token_step(cur_seq, (int)tok, layers, K_cache, V_cache, last_hidden, k_new, v_new);
            uint32_t edge_us = (uint32_t)((now_ns() - t0) / 1000u);
            cur_seq++;

            /* Pack incremental slice ONLY: hidden[512] + k_new[1024] + v_new[1024] = [5, 512] FP32
             * Stream via native libsealframe SFT1 tensor API (with optional on-the-fly FP16 wire cast) */
            float slice_f32[D_MODEL + 2 * EDGE_LAYERS * D_MODEL];
            memcpy(slice_f32, last_hidden, D_MODEL * sizeof(float));
            memcpy(slice_f32 + D_MODEL, k_new, EDGE_LAYERS * D_MODEL * sizeof(float));
            memcpy(slice_f32 + D_MODEL + EDGE_LAYERS * D_MODEL, v_new, EDGE_LAYERS * D_MODEL * sizeof(float));

            fp_tensor_meta_t tmeta;
            memset(&tmeta, 0, sizeof(tmeta));
            tmeta.dtype = FP_DTYPE_FP32;
            tmeta.ndim = 2;
            tmeta.dims[0] = 1u + 2u * EDGE_LAYERS;
            tmeta.dims[1] = D_MODEL;
            tmeta.seq_id = ((uint64_t)(uint32_t)cur_seq << 32) | (uint64_t)edge_us;

            int cast_f16 = (tag == TAG_STEP_FP16) ? 1 : 0;
            if (fp_session_send_tensor(sess, tag, &tmeta, slice_f32, sizeof(slice_f32),
                                       cast_f16, NULL) != FP_OK) {
                break;
            }
        } else if (tag == TAG_QUIT) {
            free(req);
            struct rusage ru;
            getrusage(RUSAGE_SELF, &ru);
            uint64_t tx = 0, rx = 0;
            fp_session_stats(sess, &tx, &rx);
            uint64_t out[3] = { (uint64_t)ru.ru_maxrss, tx, rx };
            (void)fp_session_send_verified(sess, TAG_QUIT, (const uint8_t *)out, sizeof(out), NULL);
            break;
        } else {
            free(req);
            break;
        }
    }

    fp_session_close(sess);
    sodium_memzero(&srv_kp, sizeof(srv_kp));
    free(K_cache);
    free(V_cache);
    for (int l = 0; l < EDGE_LAYERS; l++) free_layer(&layers[l]);
    return 0;
}
