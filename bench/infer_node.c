/*
 * SealFrame Distributed Verifiable Inference — Universal Pure-C11 Stage Worker (infer_node)
 *
 * Runs ANY contiguous Transformer layer slice [L_start, L_end) over persistent mutual-pinned
 * encrypted SealFrame sessions (fp_session_* + SFT1 verified tensors + FPD1 signed receipts).
 *
 * Supports:
 *   - Pipeline Parallelism across heterogeneous nodes (e.g. Proxmox L0..2 -> Mac L2..5 -> PC L5..8)
 *   - Multi-precision wire transport: FP32 (bit-exact), SFT1 FP16 (-50%), SFT1 INT8 (-75%)
 *   - Cryptographic Proof-of-Inference receipts (FPD1 Ed25519-signed parent_dna + op_dna -> result_dna)
 *   - Encrypted KV-cache snapshot & live state migration (SFT1) for crash recovery / failover
 *   - Deterministic Byzantine fault injection (--corrupt-step N) for decentralized slashing tests
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
#define TOTAL_LAYERS 8
#define MAX_SEQ     640

enum {
    TAG_RESET          = 1,  /* Req: empty -> resets KV pos=0 */
    TAG_PREFILL_TOK    = 2,  /* Req: [u32 n | u32 tok[n]] (Stage 0) -> SFT1 FP32 [n, D] */
    TAG_PREFILL_HID    = 3,  /* Req: SFT1 FP32 [n, D] (Stage >0) -> SFT1 FP32 [n, D] */
    TAG_STEP_TOK_FP32  = 4,  /* Req: [u32 tok] -> SFT1 FP32 [1, D] */
    TAG_STEP_TOK_FP16  = 5,  /* Req: [u32 tok] -> SFT1 FP16 [1, D] */
    TAG_STEP_TOK_INT8  = 6,  /* Req: [u32 tok] -> SFT1 INT8 [1, D] (scale in seq_id low 32 bits) */
    TAG_STEP_HID_FP32  = 7,  /* Req: SFT1 [1, D] -> SFT1 FP32 [1, D] */
    TAG_STEP_HID_FP16  = 8,  /* Req: SFT1 [1, D] -> SFT1 FP16 [1, D] */
    TAG_STEP_HID_INT8  = 9,  /* Req: SFT1 [1, D] -> SFT1 INT8 [1, D] */
    TAG_GET_RECEIPT    = 10, /* Req: empty -> last FPD1 signed derivation bytes */
    TAG_SNAP_KV        = 11, /* Req: empty -> SFT1 FP32 [2, n_layers, cur_seq, D] */
    TAG_LOAD_KV        = 12, /* Req: SFT1 FP32 [2, n_layers, seq, D] -> empty ACK */
    TAG_STATS          = 13, /* Req: empty -> [u64 rss_kb | u64 tx | u64 rx | u32 cur_seq | u32 op_dna_hi] */
    TAG_DONE           = 14  /* Req: empty -> closes session cleanly */
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
} layer_w_t;

typedef struct {
    int        l_start;
    int        l_end;
    int        n_layers;
    int        cur_seq;
    int        corrupt_step;
    layer_w_t *layers;
    float     *K_cache; /* [n_layers, MAX_SEQ, D_MODEL] */
    float     *V_cache;
    fp_dna_t   op_dna;  /* BLAKE3 identity of this stage's layer slice & model config */
} stage_t;

static void stage_init(stage_t *st, int l_start, int l_end, int corrupt_step) {
    memset(st, 0, sizeof(*st));
    st->l_start = l_start;
    st->l_end = l_end;
    st->n_layers = l_end - l_start;
    st->corrupt_step = corrupt_step;
    st->layers = calloc((size_t)st->n_layers, sizeof(layer_w_t));
    st->K_cache = calloc((size_t)st->n_layers * MAX_SEQ * D_MODEL, sizeof(float));
    st->V_cache = calloc((size_t)st->n_layers * MAX_SEQ * D_MODEL, sizeof(float));

    float s_att = 1.0f / sqrtf((float)D_MODEL);
    float s_ff  = 1.0f / sqrtf((float)D_FF);
    for (int i = 0; i < st->n_layers; i++) {
        int l = l_start + i;
        uint64_t base = UINT64_C(0x5EA1F00000000000) + (uint64_t)l * UINT64_C(0x10000000);
        layer_w_t *L = &st->layers[i];
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

    /* Deterministic op_dna identifying exact architecture + layer slice */
    char op_desc[128];
    int dn = snprintf(op_desc, sizeof(op_desc),
                      "SEALFRAME_TRANSFORMER_V1:D=%d:H=%d:FF=%d:LAYERS=%d..%d",
                      D_MODEL, N_HEADS, D_FF, l_start, l_end);
    (void)fp_dna_compute((const uint8_t *)op_desc, (size_t)dn, &st->op_dna);
}

static void stage_free(stage_t *st) {
    for (int i = 0; i < st->n_layers; i++) {
        free(st->layers[i].Wq); free(st->layers[i].Wk); free(st->layers[i].Wv);
        free(st->layers[i].Wo); free(st->layers[i].W1); free(st->layers[i].W2);
    }
    free(st->layers);
    free(st->K_cache);
    free(st->V_cache);
}

static void embed_token(uint32_t tok_id, float out[D_MODEL]) {
    uint64_t emb_seed = UINT64_C(0xE0B0000000000000) + (uint64_t)(tok_id % VOCAB_SZ) * 1024ull;
    for (int i = 0; i < D_MODEL; i++) out[i] = det_weight(emb_seed, (uint64_t)i, 0.25f);
}

static void stage_forward_pos(stage_t *st, int pos, const float in_h[D_MODEL], float out_h[D_MODEL]) {
    float x[D_MODEL], xn[D_MODEL], q[D_MODEL], k[D_MODEL], v[D_MODEL];
    float att[D_MODEL], proj[D_MODEL], ff[D_FF], ff_out[D_MODEL], scores[MAX_SEQ];
    memcpy(x, in_h, sizeof(x));
    float inv_hd = 1.0f / sqrtf((float)HEAD_DIM);

    for (int i = 0; i < st->n_layers; i++) {
        const layer_w_t *L = &st->layers[i];
        rmsnorm(x, xn, D_MODEL);
        matvec(xn, L->Wq, q, D_MODEL, D_MODEL);
        matvec(xn, L->Wk, k, D_MODEL, D_MODEL);
        matvec(xn, L->Wv, v, D_MODEL, D_MODEL);

        size_t kv_off = ((size_t)i * MAX_SEQ + (size_t)pos) * D_MODEL;
        memcpy(st->K_cache + kv_off, k, D_MODEL * sizeof(float));
        memcpy(st->V_cache + kv_off, v, D_MODEL * sizeof(float));

        memset(att, 0, sizeof(att));
        for (int h = 0; h < N_HEADS; h++) {
            int hoff = h * HEAD_DIM;
            float max_s = -1e30f;
            for (int t = 0; t <= pos; t++) {
                const float *kt = st->K_cache + ((size_t)i * MAX_SEQ + (size_t)t) * D_MODEL + hoff;
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
                const float *vt = st->V_cache + ((size_t)i * MAX_SEQ + (size_t)t) * D_MODEL + hoff;
                for (int d = 0; d < HEAD_DIM; d++) att[hoff + d] += w * vt[d];
            }
        }
        matvec(att, L->Wo, proj, D_MODEL, D_MODEL);
        for (int j = 0; j < D_MODEL; j++) x[j] += proj[j];

        rmsnorm(x, xn, D_MODEL);
        matvec(xn, L->W1, ff, D_MODEL, D_FF);
        for (int j = 0; j < D_FF; j++) ff[j] = ff[j] / (1.0f + expf(-ff[j]));
        matvec(ff, L->W2, ff_out, D_FF, D_MODEL);
        for (int j = 0; j < D_MODEL; j++) x[j] += ff_out[j];
    }

    /* Optional deterministic Byzantine fault injection (simulates dishonest miner / bit-flip) */
    if (st->corrupt_step >= 0 && pos == st->corrupt_step) {
        x[0] += 0.75f;
    }
    memcpy(out_h, x, sizeof(x));
}

static void quantize_int8_sym(const float *src, size_t n, int8_t *dst, float *scale_out) {
    float amax = 1e-8f;
    for (size_t i = 0; i < n; i++) {
        float a = fabsf(src[i]);
        if (a > amax) amax = a;
    }
    float scale = amax / 127.0f;
    float inv = 127.0f / amax;
    for (size_t i = 0; i < n; i++) {
        long q = lroundf(src[i] * inv);
        if (q < -127) q = -127;
        if (q > 127) q = 127;
        dst[i] = (int8_t)q;
    }
    *scale_out = scale;
}

static void dequantize_int8_sym(const int8_t *src, size_t n, float scale, float *dst) {
    for (size_t i = 0; i < n; i++) dst[i] = (float)src[i] * scale;
}

static uint32_t float_to_u32(float f) {
    uint32_t u = 0;
    memcpy(&u, &f, 4);
    return u;
}

static float u32_to_float(uint32_t u) {
    float f = 0.0f;
    memcpy(&f, &u, 4);
    return f;
}

static int read_exact(const char *path, uint8_t *dst, size_t n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(dst, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

static void sign_receipt(const fp_dna_t *in_dna, const fp_dna_t *op_dna, const fp_dna_t *out_dna,
                         uint64_t out_size, const fp_keypair_t *srv_kp,
                         uint8_t dst[512], size_t *dst_len) {
    fp_derivation_t drv;
    memset(&drv, 0, sizeof(drv));
    drv.version = 1;
    drv.parent_dna = *in_dna;
    drv.op_dna = *op_dna;
    drv.result_dna = *out_dna;
    drv.result_size = out_size;
    drv.timestamp_unix = (uint64_t)time(NULL);
    if (fp_derivation_sign(&drv, srv_kp) == FP_OK) {
        uint8_t *eb = NULL; size_t el = 0;
        if (fp_derivation_encode(&drv, &eb, &el) == FP_OK && el <= 512u) {
            memcpy(dst, eb, el);
            *dst_len = el;
        }
        free(eb);
    }
}

static void handle_session(fp_session_t *sess, stage_t *st, const fp_keypair_t *srv_kp) {
    uint8_t last_receipt[512];
    size_t last_receipt_len = 0;

    for (;;) {
        uint8_t tag = 0;
        uint8_t *req = NULL;
        size_t req_len = 0;
        fp_dna_t req_wire_dna;
        if (fp_session_recv_verified(sess, 32u << 20, &tag, &req, &req_len, &req_wire_dna) != FP_OK) {
            break;
        }

        if (tag == TAG_DONE) {
            free(req);
            (void)fp_session_send_verified(sess, TAG_DONE, NULL, 0, NULL);
            break;
        } else if (tag == TAG_RESET) {
            free(req);
            st->cur_seq = 0;
            last_receipt_len = 0;
            if (fp_session_send_verified(sess, TAG_RESET, NULL, 0, NULL) != FP_OK) break;
        } else if (tag == TAG_PREFILL_TOK && req_len >= 4u) {
            uint32_t ntok = 0;
            memcpy(&ntok, req, 4);
            if (ntok == 0 || ntok > MAX_SEQ || req_len != 4u + (size_t)ntok * 4u) {
                free(req);
                break;
            }
            float *out_all = malloc((size_t)ntok * D_MODEL * sizeof(float));
            if (!out_all) { free(req); break; }
            st->cur_seq = 0;
            uint64_t t0 = now_ns();
            for (uint32_t p = 0; p < ntok; p++) {
                uint32_t tok = 0;
                memcpy(&tok, req + 4u + (size_t)p * 4u, 4);
                float h_in[D_MODEL];
                embed_token(tok, h_in);
                stage_forward_pos(st, (int)p, h_in, out_all + (size_t)p * D_MODEL);
            }
            uint32_t comp_us = (uint32_t)((now_ns() - t0) / 1000u);
            st->cur_seq = (int)ntok;

            fp_dna_t in_dna, out_dna;
            (void)fp_dna_compute(req, req_len, &in_dna);
            (void)fp_dna_compute((const uint8_t *)out_all, (size_t)ntok * D_MODEL * sizeof(float), &out_dna);
            free(req);

            sign_receipt(&in_dna, &st->op_dna, &out_dna,
                         (uint64_t)ntok * D_MODEL * sizeof(float), srv_kp,
                         last_receipt, &last_receipt_len);

            fp_tensor_meta_t tm;
            memset(&tm, 0, sizeof(tm));
            tm.dtype = FP_DTYPE_FP32;
            tm.ndim = 2;
            tm.dims[0] = ntok;
            tm.dims[1] = D_MODEL;
            tm.seq_id = ((uint64_t)(uint32_t)st->cur_seq << 32) | (uint64_t)comp_us;
            fp_err_t serr = fp_session_send_tensor(sess, TAG_PREFILL_TOK, &tm, out_all,
                                                   (size_t)ntok * D_MODEL * sizeof(float), 0, NULL);
            free(out_all);
            if (serr != FP_OK) break;
        } else if (tag == TAG_PREFILL_HID) {
            fp_tensor_meta_t im;
            uint8_t *idata = NULL;
            size_t ilen = 0;
            if (fp_tensor_unpack(req, req_len, 1, &im, &idata, &ilen) != FP_OK ||
                im.ndim != 2 || im.dims[1] != D_MODEL || im.dims[0] == 0 || im.dims[0] > MAX_SEQ ||
                im.dtype != FP_DTYPE_FP32) {
                free(req); free(idata); break;
            }
            free(req);
            uint32_t ntok = im.dims[0];
            float *out_all = malloc((size_t)ntok * D_MODEL * sizeof(float));
            if (!out_all) { free(idata); break; }
            st->cur_seq = 0;
            uint64_t t0 = now_ns();
            const float *in_f = (const float *)idata;
            for (uint32_t p = 0; p < ntok; p++) {
                stage_forward_pos(st, (int)p, in_f + (size_t)p * D_MODEL, out_all + (size_t)p * D_MODEL);
            }
            uint32_t comp_us = (uint32_t)((now_ns() - t0) / 1000u);
            st->cur_seq = (int)ntok;

            fp_dna_t in_dna, out_dna;
            (void)fp_dna_compute(idata, ilen, &in_dna);
            (void)fp_dna_compute((const uint8_t *)out_all, (size_t)ntok * D_MODEL * sizeof(float), &out_dna);
            free(idata);

            sign_receipt(&in_dna, &st->op_dna, &out_dna,
                         (uint64_t)ntok * D_MODEL * sizeof(float), srv_kp,
                         last_receipt, &last_receipt_len);

            fp_tensor_meta_t tm;
            memset(&tm, 0, sizeof(tm));
            tm.dtype = FP_DTYPE_FP32;
            tm.ndim = 2;
            tm.dims[0] = ntok;
            tm.dims[1] = D_MODEL;
            tm.seq_id = ((uint64_t)(uint32_t)st->cur_seq << 32) | (uint64_t)comp_us;
            fp_err_t serr = fp_session_send_tensor(sess, TAG_PREFILL_HID, &tm, out_all,
                                                   (size_t)ntok * D_MODEL * sizeof(float), 0, NULL);
            free(out_all);
            if (serr != FP_OK) break;
        } else if ((tag >= TAG_STEP_TOK_FP32 && tag <= TAG_STEP_HID_INT8) && st->cur_seq < MAX_SEQ) {
            float h_in[D_MODEL];
            fp_dna_t in_dna;
            if (tag <= TAG_STEP_TOK_INT8) {
                if (req_len != 4u) { free(req); break; }
                uint32_t tok = 0;
                memcpy(&tok, req, 4);
                (void)fp_dna_compute(req, req_len, &in_dna);
                free(req);
                embed_token(tok, h_in);
            } else {
                fp_tensor_meta_t im;
                uint8_t *idata = NULL;
                size_t ilen = 0;
                if (fp_tensor_unpack(req, req_len, 1, &im, &idata, &ilen) != FP_OK ||
                    im.ndim != 2 || im.dims[0] != 1u || im.dims[1] != D_MODEL) {
                    free(req); free(idata); break;
                }
                free(req);
                if (im.dtype == FP_DTYPE_FP32 && ilen == sizeof(h_in)) {
                    memcpy(h_in, idata, sizeof(h_in));
                } else if (im.dtype == FP_DTYPE_INT8 && ilen == D_MODEL) {
                    float sc = u32_to_float((uint32_t)(im.seq_id & 0xFFFFFFFFu));
                    dequantize_int8_sym((const int8_t *)idata, D_MODEL, sc, h_in);
                } else {
                    free(idata); break;
                }
                (void)fp_dna_compute((const uint8_t *)h_in, sizeof(h_in), &in_dna);
                free(idata);
            }

            float h_out[D_MODEL];
            uint64_t t0 = now_ns();
            stage_forward_pos(st, st->cur_seq, h_in, h_out);
            uint32_t comp_us = (uint32_t)((now_ns() - t0) / 1000u);
            st->cur_seq++;

            fp_dna_t out_dna;
            (void)fp_dna_compute((const uint8_t *)h_out, sizeof(h_out), &out_dna);

            sign_receipt(&in_dna, &st->op_dna, &out_dna,
                         (uint64_t)sizeof(h_out), srv_kp,
                         last_receipt, &last_receipt_len);

            fp_tensor_meta_t tm;
            memset(&tm, 0, sizeof(tm));
            tm.ndim = 2;
            tm.dims[0] = 1u;
            tm.dims[1] = D_MODEL;
            if (tag == TAG_STEP_TOK_INT8 || tag == TAG_STEP_HID_INT8) {
                int8_t qout[D_MODEL];
                float scale = 0.0f;
                quantize_int8_sym(h_out, D_MODEL, qout, &scale);
                tm.dtype = FP_DTYPE_INT8;
                /* High 32: comp_us, Low 32: float32 IEEE-754 scale bits */
                tm.seq_id = ((uint64_t)comp_us << 32) | (uint64_t)float_to_u32(scale);
                if (fp_session_send_tensor(sess, tag, &tm, qout, sizeof(qout), 0, NULL) != FP_OK) break;
            } else {
                int cast16 = (tag == TAG_STEP_TOK_FP16 || tag == TAG_STEP_HID_FP16) ? 1 : 0;
                tm.dtype = FP_DTYPE_FP32;
                tm.seq_id = ((uint64_t)(uint32_t)st->cur_seq << 32) | (uint64_t)comp_us;
                if (fp_session_send_tensor(sess, tag, &tm, h_out, sizeof(h_out), cast16, NULL) != FP_OK) break;
            }
        } else if (tag == TAG_GET_RECEIPT) {
            free(req);
            if (fp_session_send_verified(sess, TAG_GET_RECEIPT, last_receipt, last_receipt_len, NULL) != FP_OK) break;
        } else if (tag == TAG_SNAP_KV) {
            free(req);
            uint32_t seq = (uint32_t)st->cur_seq;
            if (seq == 0) {
                if (fp_session_send_verified(sess, TAG_SNAP_KV, NULL, 0, NULL) != FP_OK) break;
                continue;
            }
            size_t layer_bytes = (size_t)seq * D_MODEL * sizeof(float);
            size_t total = 2u * (size_t)st->n_layers * layer_bytes;
            uint8_t *snap = malloc(total);
            if (!snap) break;
            size_t off = 0;
            for (int i = 0; i < st->n_layers; i++) {
                memcpy(snap + off, st->K_cache + (size_t)i * MAX_SEQ * D_MODEL, layer_bytes);
                off += layer_bytes;
            }
            for (int i = 0; i < st->n_layers; i++) {
                memcpy(snap + off, st->V_cache + (size_t)i * MAX_SEQ * D_MODEL, layer_bytes);
                off += layer_bytes;
            }
            fp_tensor_meta_t tm;
            memset(&tm, 0, sizeof(tm));
            tm.dtype = FP_DTYPE_FP32;
            tm.ndim = 4;
            tm.dims[0] = 2u;
            tm.dims[1] = (uint32_t)st->n_layers;
            tm.dims[2] = seq;
            tm.dims[3] = D_MODEL;
            tm.seq_id = seq;
            fp_err_t serr = fp_session_send_tensor(sess, TAG_SNAP_KV, &tm, snap, total, 0, NULL);
            free(snap);
            if (serr != FP_OK) break;
        } else if (tag == TAG_LOAD_KV) {
            fp_tensor_meta_t im;
            uint8_t *idata = NULL;
            size_t ilen = 0;
            if (fp_tensor_unpack(req, req_len, 1, &im, &idata, &ilen) != FP_OK ||
                im.ndim != 4 || im.dims[0] != 2u || im.dims[1] != (uint32_t)st->n_layers ||
                im.dims[2] == 0 || im.dims[2] > MAX_SEQ || im.dims[3] != D_MODEL ||
                im.dtype != FP_DTYPE_FP32) {
                free(req); free(idata); break;
            }
            free(req);
            uint32_t seq = im.dims[2];
            size_t layer_bytes = (size_t)seq * D_MODEL * sizeof(float);
            size_t off = 0;
            for (int i = 0; i < st->n_layers; i++) {
                memcpy(st->K_cache + (size_t)i * MAX_SEQ * D_MODEL, idata + off, layer_bytes);
                off += layer_bytes;
            }
            for (int i = 0; i < st->n_layers; i++) {
                memcpy(st->V_cache + (size_t)i * MAX_SEQ * D_MODEL, idata + off, layer_bytes);
                off += layer_bytes;
            }
            st->cur_seq = (int)seq;
            free(idata);
            if (fp_session_send_verified(sess, TAG_LOAD_KV, NULL, 0, NULL) != FP_OK) break;
        } else if (tag == TAG_STATS) {
            free(req);
            struct rusage ru;
            getrusage(RUSAGE_SELF, &ru);
            uint64_t tx = 0, rx = 0;
            fp_session_stats(sess, &tx, &rx);
            uint64_t out[4] = { (uint64_t)ru.ru_maxrss, tx, rx, (uint64_t)(uint32_t)st->cur_seq };
            if (fp_session_send_verified(sess, TAG_STATS, (const uint8_t *)out, sizeof(out), NULL) != FP_OK) break;
        } else {
            free(req);
            break;
        }
    }
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (fp_init() != FP_OK) return 1;

    const char *bind_ip = "0.0.0.0";
    uint16_t port = 17915;
    int l_start = 0, l_end = 2;
    const char *sk_path = NULL;
    const char *allow_pk_path = NULL;
    int max_sessions = 1;
    int corrupt_step = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) bind_ip = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--layers") == 0 && i + 1 < argc) {
            if (sscanf(argv[++i], "%d:%d", &l_start, &l_end) != 2) return 2;
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) sk_path = argv[++i];
        else if (strcmp(argv[i], "--allow-pub") == 0 && i + 1 < argc) allow_pk_path = argv[++i];
        else if (strcmp(argv[i], "--max-sessions") == 0 && i + 1 < argc) max_sessions = atoi(argv[++i]);
        else if (strcmp(argv[i], "--corrupt-step") == 0 && i + 1 < argc) corrupt_step = atoi(argv[++i]);
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); return 2; }
    }
    if (!sk_path || l_start < 0 || l_end <= l_start || l_end > TOTAL_LAYERS) {
        fprintf(stderr, "usage: infer_node --bind IP --port PORT --layers S:E --key srv.sk [--allow-pub cli.pk] [--max-sessions N] [--corrupt-step K]\n");
        return 2;
    }

    fp_keypair_t srv_kp;
    if (read_exact(sk_path, srv_kp.sk, FP_SK_LEN) != 0) return 1;
    memcpy(srv_kp.pk, srv_kp.sk + 32, FP_PK_LEN);

    uint8_t allow_pk[FP_PK_LEN];
    const uint8_t *allow_ptr = NULL;
    if (allow_pk_path) {
        if (read_exact(allow_pk_path, allow_pk, FP_PK_LEN) != 0) return 1;
        allow_ptr = allow_pk;
    }

    stage_t st;
    stage_init(&st, l_start, l_end, corrupt_step);

    uint16_t bport = 0;
    int lfd = fp_net_listen(bind_ip, port, &bport);
    if (lfd < 0) { stage_free(&st); return 1; }
    printf("READY %s:%u layers=%d..%d corrupt=%d\n", bind_ip, (unsigned)bport, l_start, l_end, corrupt_step);
    fflush(stdout);

    for (int s = 0; max_sessions <= 0 || s < max_sessions; s++) {
        fp_session_t *sess = NULL;
        fp_err_t aerr = fp_session_accept(lfd, &srv_kp, allow_ptr, 60000, &sess);
        if (aerr != FP_OK) {
            /* Rejected unauthorized peer or timeout; count attempt so security tests terminate cleanly */
            continue;
        }
        handle_session(sess, &st, &srv_kp);
        fp_session_close(sess);
    }

    close(lfd);
    sodium_memzero(&srv_kp, sizeof(srv_kp));
    stage_free(&st);
    return 0;
}
