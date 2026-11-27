/*
 * SealFrame Mixed-Inference Benchmark — Edge Stage-1 Engine (ISO C11, zero ML deps)
 *
 * Runs deterministic Transformer Stage-1 (Embedding + Layer 0..1: RMSNorm, Causal Self-Attention
 * with persistent FP32 KV-Cache, SwiGLU-style FFN) directly on constrained Edge CPU
 * (e.g., 2010 Pentium P6100, 256 MiB RAM, no AVX) and stores verified tensor snapshots
 * directly into a SealFrame content-addressed store for encrypted FP-NET transfer
 * (ZSTD / DELTA / REF / Merkle) to a stronger Workstation/GPU Stage-2 node.
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#define D_MODEL   512
#define N_HEADS   8
#define HEAD_DIM  (D_MODEL / N_HEADS)
#define D_FF      1024
#define VOCAB_SZ  4096
#define EDGE_LAYERS 2
#define MAX_SEQ   520

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Deterministic SplitMix64 -> uniform float in [-scale, +scale] (identical to NumPy generator!) */
static float det_weight(uint64_t seed, uint64_t idx, float scale) {
    uint64_t z = seed + idx * UINT64_C(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    z = z ^ (z >> 31);
    /* Map top 24 bits to [-1.0, +1.0] */
    float u = (float)(z >> 40) * (1.0f / 8388608.0f) - 1.0f;
    return u * scale;
}

static void fill_matrix(float *dst, size_t n, uint64_t seed, float scale) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = det_weight(seed, (uint64_t)i, scale);
    }
}

static void rmsnorm(const float *x, const float *g, float *out, int d) {
    double ss = 0.0;
    for (int i = 0; i < d; i++) ss += (double)x[i] * (double)x[i];
    float inv = 1.0f / sqrtf((float)(ss / (double)d) + 1e-5f);
    for (int i = 0; i < d; i++) out[i] = x[i] * inv * g[i];
}

/* y[out_d] = x[in_d] @ W[in_d, out_d] (row-major W) */
static void matvec(const float *x, const float *W, float *y, int in_d, int out_d) {
    memset(y, 0, (size_t)out_d * sizeof(float));
    for (int i = 0; i < in_d; i++) {
        float xi = x[i];
        const float *wrow = W + (size_t)i * (size_t)out_d;
        for (int j = 0; j < out_d; j++) {
            y[j] += xi * wrow[j];
        }
    }
}

typedef struct {
    float g1[D_MODEL], g2[D_MODEL];
    float *Wq, *Wk, *Wv, *Wo;   /* [D_MODEL, D_MODEL] */
    float *W1, *W2;             /* [D_MODEL, D_FF], [D_FF, D_MODEL] */
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
                           float *K_cache, float *V_cache, float *out_hidden) {
    float x[D_MODEL], xn[D_MODEL], q[D_MODEL], k[D_MODEL], v[D_MODEL];
    float att[D_MODEL], proj[D_MODEL], ff[D_FF], ff_out[D_MODEL];
    float scores[MAX_SEQ];

    /* Deterministic embedding lookup for tok_id */
    uint64_t emb_seed = UINT64_C(0xE0B0000000000000) + (uint64_t)(tok_id % VOCAB_SZ) * 1024ull;
    for (int i = 0; i < D_MODEL; i++) x[i] = det_weight(emb_seed, (uint64_t)i, 0.25f);

    float inv_sqrt_hd = 1.0f / sqrtf((float)HEAD_DIM);

    for (int l = 0; l < EDGE_LAYERS; l++) {
        rmsnorm(x, layers[l].g1, xn, D_MODEL);
        matvec(xn, layers[l].Wq, q, D_MODEL, D_MODEL);
        matvec(xn, layers[l].Wk, k, D_MODEL, D_MODEL);
        matvec(xn, layers[l].Wv, v, D_MODEL, D_MODEL);

        /* Store K, V at [l, pos, :] in persistent KV-cache */
        size_t kv_off = ((size_t)l * MAX_SEQ + (size_t)pos) * D_MODEL;
        memcpy(K_cache + kv_off, k, D_MODEL * sizeof(float));
        memcpy(V_cache + kv_off, v, D_MODEL * sizeof(float));

        /* Causal Multi-Head Self-Attention over 0..pos */
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
            for (int t = 0; t <= pos; t++) {
                scores[t] = expf(scores[t] - max_s);
                sum_e += scores[t];
            }
            float inv_sum = 1.0f / sum_e;
            for (int t = 0; t <= pos; t++) {
                float w = scores[t] * inv_sum;
                const float *vt = V_cache + ((size_t)l * MAX_SEQ + (size_t)t) * D_MODEL + hoff;
                for (int d = 0; d < HEAD_DIM; d++) att[hoff + d] += w * vt[d];
            }
        }
        matvec(att, layers[l].Wo, proj, D_MODEL, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += proj[i];

        /* FFN with SiLU activation */
        rmsnorm(x, layers[l].g2, xn, D_MODEL);
        matvec(xn, layers[l].W1, ff, D_MODEL, D_FF);
        for (int i = 0; i < D_FF; i++) {
            ff[i] = ff[i] / (1.0f + expf(-ff[i]));
        }
        matvec(ff, layers[l].W2, ff_out, D_FF, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += ff_out[i];
    }
    memcpy(out_hidden, x, D_MODEL * sizeof(float));
}

/* Pack binary tensor packet:
 *   magic "SFT1"(4) | seq_len(4) | d_model(4) | layers(4) |
 *   hidden_last[d_model] (FP32) | K_cache[layers, seq_len, d_model] | V_cache[layers, seq_len, d_model]
 */
static int store_kv_snapshot(const char *store_dir, int seq_len,
                             const float *last_hidden,
                             const float *K_cache, const float *V_cache,
                             char out_hex[65], size_t *out_bytes) {
    size_t kv_floats = (size_t)EDGE_LAYERS * (size_t)seq_len * D_MODEL;
    size_t total = 16u + (D_MODEL + 2u * kv_floats) * sizeof(float);
    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    memcpy(buf, "SFT1", 4);
    uint32_t meta[3] = { (uint32_t)seq_len, D_MODEL, EDGE_LAYERS };
    memcpy(buf + 4, meta, 12);
    size_t off = 16u;
    memcpy(buf + off, last_hidden, D_MODEL * sizeof(float));
    off += D_MODEL * sizeof(float);
    for (int l = 0; l < EDGE_LAYERS; l++) {
        size_t bytes = (size_t)seq_len * D_MODEL * sizeof(float);
        memcpy(buf + off, K_cache + (size_t)l * MAX_SEQ * D_MODEL, bytes);
        off += bytes;
    }
    for (int l = 0; l < EDGE_LAYERS; l++) {
        size_t bytes = (size_t)seq_len * D_MODEL * sizeof(float);
        memcpy(buf + off, V_cache + (size_t)l * MAX_SEQ * D_MODEL, bytes);
        off += bytes;
    }

    fp_dna_t dna;
    fp_err_t err = fp_store_put_object(store_dir, buf, total, &dna);
    free(buf);
    if (err != FP_OK) return -1;
    fp_hex_encode(dna.bytes, FP_DNA_LEN, out_hex);
    *out_bytes = total;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: edge_infer_stage <store_dir> <prefill_tokens> <decode_steps>\n");
        return 1;
    }
    if (fp_init() != FP_OK) return 1;

    const char *store_dir = argv[1];
    int prefill = atoi(argv[2]);
    int decode_steps = atoi(argv[3]);
    if (prefill < 1 || prefill + decode_steps > MAX_SEQ) {
        fprintf(stderr, "invalid prefill/decode bounds (max %d)\n", MAX_SEQ);
        return 1;
    }

    layer_w_t layers[EDGE_LAYERS];
    for (int l = 0; l < EDGE_LAYERS; l++) init_layer(&layers[l], l);

    float *K_cache = calloc((size_t)EDGE_LAYERS * MAX_SEQ * D_MODEL, sizeof(float));
    float *V_cache = calloc((size_t)EDGE_LAYERS * MAX_SEQ * D_MODEL, sizeof(float));
    float last_hidden[D_MODEL];

    /* Stage-1 Prefill */
    uint64_t t0 = now_ns();
    for (int p = 0; p < prefill; p++) {
        int tok = (p * 37 + 13) % VOCAB_SZ;
        run_token_step(p, tok, layers, K_cache, V_cache, last_hidden);
    }
    uint64_t t_prefill = now_ns() - t0;

    char hex[65];
    size_t sz = 0;
    if (store_kv_snapshot(store_dir, prefill, last_hidden, K_cache, V_cache, hex, &sz) != 0) {
        return 1;
    }
    printf("STEP prefill seq=%d bytes=%zu edge_ms=%.2f dna=%s\n",
           prefill, sz, (double)t_prefill / 1e6, hex);

    /* Stage-1 Incremental Autoregressive Decode steps (KV-cache grows by +1 token/step!) */
    for (int s = 1; s <= decode_steps; s++) {
        int pos = prefill + s - 1;
        int tok = (pos * 37 + 13) % VOCAB_SZ;
        uint64_t ts = now_ns();
        run_token_step(pos, tok, layers, K_cache, V_cache, last_hidden);
        uint64_t dt = now_ns() - ts;
        if (store_kv_snapshot(store_dir, pos + 1, last_hidden, K_cache, V_cache, hex, &sz) != 0) {
            return 1;
        }
        printf("STEP decode_%d seq=%d bytes=%zu edge_ms=%.2f dna=%s\n",
               s, pos + 1, sz, (double)dt / 1e6, hex);
    }

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("EDGE_RSS_KB %ld\n", ru.ru_maxrss);

    free(K_cache);
    free(V_cache);
    for (int l = 0; l < EDGE_LAYERS; l++) free_layer(&layers[l]);
    return 0;
}
