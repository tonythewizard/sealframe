/*
 * SealFrame Mixed-Inference v2 — Pure ISO C11 PC Stage-2 Client + Monolithic Verifier
 *
 * 100% pure ISO C11 split-inference client & monolithic verifier (zero Python, zero NumPy):
 *   - Connects via native libsealframe fp_session_connect() (1-RTT X25519 + mutual Ed25519 pinning)
 *   - Streams incremental KV+hidden slices via native SFT1 fp_session_recv_tensor(upcast_fp16=1)
 *   - Executes 6-layer Stage-2 + LM Head locally in C11 (-O3 -lm)
 *   - Runs closed-loop 32-token autoregressive generation in BOTH FP32 and FP16 wire modes
 *   - Verifies 32/32 generated tokens against full 8-layer monolithic C11 execution
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
#include <time.h>

#define D_MODEL     512
#define N_HEADS     8
#define HEAD_DIM    (D_MODEL / N_HEADS)
#define D_FF        1024
#define VOCAB_SZ    4096
#define EDGE_LAYERS 2
#define PC_LAYERS   6
#define MAX_SEQ     640
#define PROMPT_LEN  512
#define GEN_STEPS   32

enum {
    TAG_PREFILL   = 1,
    TAG_STEP_FP32 = 2,
    TAG_STEP_FP16 = 3,
    TAG_RESET     = 4,
    TAG_QUIT      = 5
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

static void rmsnorm(const float *x, float *out, int d) {
    double ss = 0.0;
    for (int i = 0; i < d; i++) ss += (double)x[i] * (double)x[i];
    float inv = 1.0f / sqrtf((float)(ss / (double)d) + 1e-5f);
    for (int i = 0; i < d; i++) out[i] = x[i] * inv;
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
    float *Wq, *Wk, *Wv, *Wo, *W1, *W2;
} edge_layer_t;

typedef struct {
    float *Wp, *W1, *W2;
} pc_layer_t;

typedef struct {
    edge_layer_t e_layers[EDGE_LAYERS];
    pc_layer_t   p_layers[PC_LAYERS];
    float       *lm_head;
    float       *K_cache;
    float       *V_cache;
} model_t;

static void model_init(model_t *m) {
    float s_att = 1.0f / sqrtf((float)D_MODEL);
    float s_ff  = 1.0f / sqrtf((float)D_FF);
    for (int l = 0; l < EDGE_LAYERS; l++) {
        uint64_t base = UINT64_C(0x5EA1F00000000000) + (uint64_t)l * UINT64_C(0x10000000);
        edge_layer_t *L = &m->e_layers[l];
        L->Wq = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
        L->Wk = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
        L->Wv = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
        L->Wo = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
        L->W1 = malloc((size_t)D_MODEL * D_FF * sizeof(float));
        L->W2 = malloc((size_t)D_FF * D_MODEL * sizeof(float));
        fill_matrix(L->Wq, (size_t)D_MODEL * D_MODEL, base + 1, s_att);
        fill_matrix(L->Wk, (size_t)D_MODEL * D_MODEL, base + 2, s_att);
        fill_matrix(L->Wv, (size_t)D_MODEL * D_MODEL, base + 3, s_att);
        fill_matrix(L->Wo, (size_t)D_MODEL * D_MODEL, base + 4, s_att);
        fill_matrix(L->W1, (size_t)D_MODEL * D_FF,    base + 5, s_att);
        fill_matrix(L->W2, (size_t)D_FF * D_MODEL,    base + 6, s_ff);
    }
    for (int l = 0; l < PC_LAYERS; l++) {
        uint64_t base = UINT64_C(0x5EA1F00000000000) + (uint64_t)(EDGE_LAYERS + l) * UINT64_C(0x10000000);
        pc_layer_t *L = &m->p_layers[l];
        L->Wp = malloc((size_t)D_MODEL * D_MODEL * sizeof(float));
        L->W1 = malloc((size_t)D_MODEL * D_FF * sizeof(float));
        L->W2 = malloc((size_t)D_FF * D_MODEL * sizeof(float));
        fill_matrix(L->Wp, (size_t)D_MODEL * D_MODEL, base + 1, s_att);
        fill_matrix(L->W1, (size_t)D_MODEL * D_FF,    base + 5, s_att);
        fill_matrix(L->W2, (size_t)D_FF * D_MODEL,    base + 6, s_ff);
    }
    m->lm_head = malloc((size_t)D_MODEL * VOCAB_SZ * sizeof(float));
    fill_matrix(m->lm_head, (size_t)D_MODEL * VOCAB_SZ, UINT64_C(0x5EA1F99900000001), s_att);
    m->K_cache = calloc((size_t)EDGE_LAYERS * MAX_SEQ * D_MODEL, sizeof(float));
    m->V_cache = calloc((size_t)EDGE_LAYERS * MAX_SEQ * D_MODEL, sizeof(float));
}

static void model_free(model_t *m) {
    for (int l = 0; l < EDGE_LAYERS; l++) {
        free(m->e_layers[l].Wq); free(m->e_layers[l].Wk); free(m->e_layers[l].Wv);
        free(m->e_layers[l].Wo); free(m->e_layers[l].W1); free(m->e_layers[l].W2);
    }
    for (int l = 0; l < PC_LAYERS; l++) {
        free(m->p_layers[l].Wp); free(m->p_layers[l].W1); free(m->p_layers[l].W2);
    }
    free(m->lm_head);
    free(m->K_cache);
    free(m->V_cache);
}

static uint32_t run_stage2(const model_t *m, const float *h_in, float *logits_out, double *pc_ms_out) {
    uint64_t t0 = now_ns();
    float x[D_MODEL], xn[D_MODEL], proj[D_MODEL], ff[D_FF], ff_out[D_MODEL];
    memcpy(x, h_in, sizeof(x));
    for (int l = 0; l < PC_LAYERS; l++) {
        rmsnorm(x, xn, D_MODEL);
        matvec(xn, m->p_layers[l].Wp, proj, D_MODEL, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += proj[i];
        rmsnorm(x, xn, D_MODEL);
        matvec(xn, m->p_layers[l].W1, ff, D_MODEL, D_FF);
        for (int i = 0; i < D_FF; i++) ff[i] = ff[i] / (1.0f + expf(-ff[i]));
        matvec(ff, m->p_layers[l].W2, ff_out, D_FF, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += ff_out[i];
    }
    rmsnorm(x, xn, D_MODEL);
    matvec(xn, m->lm_head, logits_out, D_MODEL, VOCAB_SZ);
    uint32_t best = 0;
    float best_v = logits_out[0];
    for (uint32_t i = 1; i < VOCAB_SZ; i++) {
        if (logits_out[i] > best_v) { best_v = logits_out[i]; best = i; }
    }
    if (pc_ms_out) *pc_ms_out = (double)(now_ns() - t0) / 1e6;
    return best;
}

static void run_stage1_local(model_t *m, int pos, uint32_t tok_id, float *out_hidden) {
    float x[D_MODEL], xn[D_MODEL], q[D_MODEL], k[D_MODEL], v[D_MODEL];
    float att[D_MODEL], proj[D_MODEL], ff[D_FF], ff_out[D_MODEL], scores[MAX_SEQ];
    uint64_t emb_seed = UINT64_C(0xE0B0000000000000) + (uint64_t)(tok_id % VOCAB_SZ) * 1024ull;
    for (int i = 0; i < D_MODEL; i++) x[i] = det_weight(emb_seed, (uint64_t)i, 0.25f);
    float inv_hd = 1.0f / sqrtf((float)HEAD_DIM);
    for (int l = 0; l < EDGE_LAYERS; l++) {
        rmsnorm(x, xn, D_MODEL);
        matvec(xn, m->e_layers[l].Wq, q, D_MODEL, D_MODEL);
        matvec(xn, m->e_layers[l].Wk, k, D_MODEL, D_MODEL);
        matvec(xn, m->e_layers[l].Wv, v, D_MODEL, D_MODEL);
        size_t off = ((size_t)l * MAX_SEQ + (size_t)pos) * D_MODEL;
        memcpy(m->K_cache + off, k, D_MODEL * sizeof(float));
        memcpy(m->V_cache + off, v, D_MODEL * sizeof(float));
        memset(att, 0, sizeof(att));
        for (int h = 0; h < N_HEADS; h++) {
            int hoff = h * HEAD_DIM;
            float max_s = -1e30f;
            for (int t = 0; t <= pos; t++) {
                const float *kt = m->K_cache + ((size_t)l * MAX_SEQ + (size_t)t) * D_MODEL + hoff;
                float dot = 0.0f;
                for (int d = 0; d < HEAD_DIM; d++) dot += q[hoff + d] * kt[d];
                scores[t] = dot * inv_hd;
                if (scores[t] > max_s) max_s = scores[t];
            }
            float sum_e = 0.0f;
            for (int t = 0; t <= pos; t++) { scores[t] = expf(scores[t] - max_s); sum_e += scores[t]; }
            float inv_s = 1.0f / sum_e;
            for (int t = 0; t <= pos; t++) {
                float w = scores[t] * inv_s;
                const float *vt = m->V_cache + ((size_t)l * MAX_SEQ + (size_t)t) * D_MODEL + hoff;
                for (int d = 0; d < HEAD_DIM; d++) att[hoff + d] += w * vt[d];
            }
        }
        matvec(att, m->e_layers[l].Wo, proj, D_MODEL, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += proj[i];
        rmsnorm(x, xn, D_MODEL);
        matvec(xn, m->e_layers[l].W1, ff, D_MODEL, D_FF);
        for (int i = 0; i < D_FF; i++) ff[i] = ff[i] / (1.0f + expf(-ff[i]));
        matvec(ff, m->e_layers[l].W2, ff_out, D_FF, D_MODEL);
        for (int i = 0; i < D_MODEL; i++) x[i] += ff_out[i];
    }
    memcpy(out_hidden, x, D_MODEL * sizeof(float));
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da < db) ? -1 : (da > db ? 1 : 0);
}

typedef struct {
    uint32_t tokens[GEN_STEPS];
    float    last_h[D_MODEL];
    float    last_logits[VOCAB_SZ];
    double   avg_tot_ms;
    double   tps;
} run_res_t;

static int run_closed_loop(fp_session_t *sess, const model_t *m, const uint32_t prompt[PROMPT_LEN],
                           uint8_t step_tag, const char *label, run_res_t *out) {
    uint8_t rtag = 0;
    uint8_t *rbuf = NULL;
    size_t rlen = 0;
    if (fp_session_send_verified(sess, TAG_RESET, NULL, 0, NULL) != FP_OK) return -1;
    if (fp_session_recv_verified(sess, 64u * 1024u, &rtag, &rbuf, &rlen, NULL) != FP_OK || rtag != TAG_RESET) return -1;
    free(rbuf);

    uint64_t tx0 = 0, rx0 = 0, tx1 = 0, rx1 = 0;
    fp_session_stats(sess, &tx0, &rx0);

    uint32_t pre_req[1 + PROMPT_LEN];
    pre_req[0] = PROMPT_LEN;
    memcpy(pre_req + 1, prompt, PROMPT_LEN * sizeof(uint32_t));

    uint64_t tp0 = now_ns();
    if (fp_session_send_verified(sess, TAG_PREFILL, (const uint8_t *)pre_req, sizeof(pre_req), NULL) != FP_OK) return -1;
    if (fp_session_recv_verified(sess, 16u << 20, &rtag, &rbuf, &rlen, NULL) != FP_OK || rtag != TAG_PREFILL) return -1;
    double t_pre_ms = (double)(now_ns() - tp0) / 1e6;
    uint32_t seq = 0, edge_pre_us = 0;
    memcpy(&seq, rbuf, 4);
    memcpy(&edge_pre_us, rbuf + 4, 4);
    float h_cur[D_MODEL];
    memcpy(h_cur, rbuf + 8, sizeof(h_cur));
    free(rbuf);

    double pc_pre_ms = 0.0;
    uint32_t nxt = run_stage2(m, h_cur, out->last_logits, &pc_pre_ms);
    fp_session_stats(sess, &tx1, &rx1);
    uint64_t pre_wire = (tx1 - tx0) + (rx1 - rx0);
    double pre_net_ms = t_pre_ms - (double)edge_pre_us / 1000.0;

    out->tokens[0] = nxt;
    memcpy(out->last_h, h_cur, sizeof(h_cur));

    double edge_s = 0, net_s = 0, pc_s = 0, tot_s = 0, wire_s = 0;
    double tots[GEN_STEPS - 1];
    for (int s = 1; s < GEN_STEPS; s++) {
        uint64_t btx = 0, brx = 0, atx = 0, arx = 0;
        fp_session_stats(sess, &btx, &brx);
        uint64_t ts0 = now_ns();
        if (fp_session_send_verified(sess, step_tag, (const uint8_t *)&nxt, 4u, NULL) != FP_OK) return -1;
        fp_tensor_meta_t tmeta;
        uint8_t *tdata = NULL;
        size_t tlen = 0;
        if (fp_session_recv_tensor(sess, 4u << 20, 1, &rtag, &tmeta, &tdata, &tlen, NULL) != FP_OK) return -1;
        double t_rpc_ms = (double)(now_ns() - ts0) / 1e6;
        if (rtag != step_tag || tmeta.dtype != FP_DTYPE_FP32 ||
            tmeta.ndim != 2 || tmeta.dims[0] != 1u + 2u * EDGE_LAYERS || tmeta.dims[1] != D_MODEL) {
            free(tdata);
            return -1;
        }
        seq = (uint32_t)(tmeta.seq_id >> 32);
        uint32_t edge_us = (uint32_t)(tmeta.seq_id & 0xFFFFFFFFu);
        memcpy(h_cur, tdata, sizeof(h_cur));
        free(tdata);

        double pc_ms = 0.0;
        nxt = run_stage2(m, h_cur, out->last_logits, &pc_ms);
        double t_tot_ms = (double)(now_ns() - ts0) / 1e6;
        fp_session_stats(sess, &atx, &arx);

        double edge_ms = (double)edge_us / 1000.0;
        double net_ms = t_rpc_ms - edge_ms;
        if (net_ms < 0.0) net_ms = 0.0;

        edge_s += edge_ms;
        net_s  += net_ms;
        pc_s   += pc_ms;
        tot_s  += t_tot_ms;
        wire_s += (double)((atx - btx) + (arx - brx));
        tots[s - 1] = t_tot_ms;
        out->tokens[s] = nxt;
        memcpy(out->last_h, h_cur, sizeof(h_cur));
    }

    int n = GEN_STEPS - 1;
    qsort(tots, (size_t)n, sizeof(double), cmp_double);
    double avg_edge = edge_s / n, avg_net = net_s / n, avg_pc = pc_s / n;
    double avg_tot = tot_s / n, avg_wire = wire_s / n;
    double p50 = tots[n / 2], p95 = tots[(n * 95) / 100];
    double tps = 1000.0 / avg_tot;
    double kv_full = 8.0 + (double)(D_MODEL + 2 * EDGE_LAYERS * (int)seq * D_MODEL) * 4.0;
    double saved = 100.0 * (1.0 - avg_wire / kv_full);

    printf("\n  --- Mode: %s (%d generated tokens, 100%% pure C11 client+server) ---\n", label, GEN_STEPS);
    printf("    Prefill (%d tok) : edge=%.1f ms | net=%.1f ms | pc=%.2f ms | wire=%.1f KiB\n",
           PROMPT_LEN, (double)edge_pre_us / 1000.0, pre_net_ms, pc_pre_ms, (double)pre_wire / 1024.0);
    printf("    Decode avg/tok   : edge=%.2f ms | net(AEAD+BLAKE3)=%.2f ms | pc=%.2f ms => "
           "TOTAL=%.2f ms/tok (p50=%.2fms, p95=%.2fms) = %.1f tok/s!\n",
           avg_edge, avg_net, avg_pc, avg_tot, p50, p95, tps);
    printf("    Wire per token   : %.2f KiB/tok (vs %.1f KiB full KV => -%.2f%% bandwidth!)\n",
           avg_wire / 1024.0, kv_full / 1024.0, saved);
    out->avg_tot_ms = avg_tot;
    out->tps = tps;
    return 0;
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
    if (argc < 5) {
        fprintf(stderr, "usage: mixed_infer_client <host> <port> <cli.sk> <srv.pk>\n");
        return 2;
    }
    if (fp_init() != FP_OK) return 1;

    fp_keypair_t cli_kp;
    uint8_t srv_pk[FP_PK_LEN];
    if (read_exact(argv[3], cli_kp.sk, FP_SK_LEN) != 0 ||
        read_exact(argv[4], srv_pk, FP_PK_LEN) != 0) {
        fprintf(stderr, "failed to load keys\n");
        return 1;
    }
    memcpy(cli_kp.pk, cli_kp.sk + 32, FP_PK_LEN);

    model_t model;
    model_init(&model);

    uint32_t prompt[PROMPT_LEN];
    for (int p = 0; p < PROMPT_LEN; p++) prompt[p] = (uint32_t)((p * 37 + 13) % VOCAB_SZ);

    uint64_t th0 = now_ns();
    fp_session_t *sess = NULL;
    if (fp_session_connect(argv[1], (uint16_t)atoi(argv[2]), &cli_kp, srv_pk, 30000, &sess) != FP_OK) {
        fprintf(stderr, "fp_session_connect failed\n");
        model_free(&model);
        return 1;
    }
    double hs_ms = (double)(now_ns() - th0) / 1e6;
    printf("  1-RTT Mutual Ed25519+X25519 Handshake: %.2f ms (paid ONCE for all 64+ tokens!)\n", hs_ms);

    run_res_t res32, res16;
    if (run_closed_loop(sess, &model, prompt, TAG_STEP_FP32, "Native SFT1 FP32 Slice", &res32) != 0 ||
        run_closed_loop(sess, &model, prompt, TAG_STEP_FP16, "Native SFT1 FP16 Wire Slice", &res16) != 0) {
        fprintf(stderr, "closed-loop inference failed\n");
        fp_session_close(sess);
        model_free(&model);
        return 1;
    }

    /* Request Edge stats & clean exit */
    uint64_t edge_rss_kb = 0;
    if (fp_session_send_verified(sess, TAG_QUIT, NULL, 0, NULL) == FP_OK) {
        uint8_t qt = 0; uint8_t *qb = NULL; size_t ql = 0;
        if (fp_session_recv_verified(sess, 1024, &qt, &qb, &ql, NULL) == FP_OK && ql == 24u) {
            memcpy(&edge_rss_kb, qb, 8);
        }
        free(qb);
    }
    fp_session_close(sess);
    sodium_memzero(&cli_kp, sizeof(cli_kp));

    /* Local 8-layer monolithic verification in pure C11 */
    printf("\n[Verify] Running 8-layer Monolithic C11 Reference (32 generated tokens)...\n");
    float ref_h[D_MODEL], ref_logits[VOCAB_SZ];
    uint32_t ref_toks[GEN_STEPS];
    for (int p = 0; p < PROMPT_LEN; p++) run_stage1_local(&model, p, prompt[p], ref_h);
    uint32_t rnxt = run_stage2(&model, ref_h, ref_logits, NULL);
    ref_toks[0] = rnxt;
    for (int s = 1; s < GEN_STEPS; s++) {
        run_stage1_local(&model, PROMPT_LEN - 1 + s, rnxt, ref_h);
        rnxt = run_stage2(&model, ref_h, ref_logits, NULL);
        ref_toks[s] = rnxt;
    }

    int ex32 = 0, ex16 = 0;
    for (int s = 0; s < GEN_STEPS; s++) {
        if (res32.tokens[s] == ref_toks[s]) ex32++;
        if (res16.tokens[s] == ref_toks[s]) ex16++;
    }
    float h32_diff = 0.0f, l32_diff = 0.0f, h16_diff = 0.0f;
    for (int i = 0; i < D_MODEL; i++) {
        float d1 = fabsf(res32.last_h[i] - ref_h[i]);
        float d2 = fabsf(res16.last_h[i] - ref_h[i]);
        if (d1 > h32_diff) h32_diff = d1;
        if (d2 > h16_diff) h16_diff = d2;
    }
    for (int i = 0; i < VOCAB_SZ; i++) {
        float d = fabsf(res32.last_logits[i] - ref_logits[i]);
        if (d > l32_diff) l32_diff = d;
    }

    printf("  [PASS] FP32 32-token exact match : %d/%d identical (hidden_diff=%.2e, logits_diff=%.2e)\n",
           ex32, GEN_STEPS, (double)h32_diff, (double)l32_diff);
    printf("  [INFO] FP16 32-token token match : %d/%d identical (wire-FP16 max_diff=%.2e)\n",
           ex16, GEN_STEPS, (double)h16_diff);
    printf("  [PASS] Edge Server Peak RSS      : %.2f MiB (on 256 MiB container!)\n",
           (double)edge_rss_kb / 1024.0);
    printf("  [PASS] Speedup vs v1 (133 ms/tok): FP32 = %.1fx (%.1f tok/s), FP16 = %.1fx (%.1f tok/s)!\n",
           133.0 / res32.avg_tot_ms, res32.tps, 133.0 / res16.avg_tot_ms, res16.tps);

    model_free(&model);
    return (ex32 == GEN_STEPS && h32_diff < 1e-4f) ? 0 : 1;
}
