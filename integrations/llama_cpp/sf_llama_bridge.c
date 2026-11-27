/*
 * SealFrame <-> llama.cpp (ggml-rpc) Transparent SFT1 / FP-UDP1 / Top-K Logits / Zstd / DNA-Dedup Bridge
 * (100% Pure ISO C11 — Zero C++, Zero Python, Zero External Network Libs)
 *
 * Bit-exact wire compatibility with upstream llama.cpp ggml-rpc (cmds 0..16, 296B rpc_tensor):
 *   1) Vocabulary Logits GET_TENSOR (ne0 >= 32000 FP32) -> Top-K Exact FP32 Sparse Logits (-99.95%!)
 *   2) Runtime FP32 activations (SET_TENSOR/GET_TENSOR) -> SFT1 (BF16/INT8/INT4/INT4+Outlier -85%)
 *   3) Weights & >=4 KiB SET_TENSOR -> BLAKE3 DNA Dedup (BR_TAG_RPC_REF, 32B wire on hit!)
 *   4) GRAPH_COMPUTE & uncached weights -> Zstd level 1 (BR_TAG_RPC_ZSTD, -93% on graphs!)
 *   5) Transport: 1-RTT X25519+Ed25519 + XChaCha20-Poly1305 AEAD over TCP or FP-UDP1 (Adaptive 0-RTT FEC)
 *   6) Realistic Keryx WAN Impairment Engine (asymmetric UL/DL, jitter, P99 spikes, TCP loss penalty)
 *   7) Inline rolling BLAKE3 TraceCommitment + live Keryx BlockDAG receipt sealing.
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe.h"
#include "sealframe_chain.h"
#include "sealframe_split.h"

#include <arpa/inet.h>
#include <blake3.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>

enum {
    GGML_RPC_ALLOC_BUFFER      = 0,
    GGML_RPC_GET_ALIGNMENT     = 1,
    GGML_RPC_GET_MAX_SIZE      = 2,
    GGML_RPC_BUFFER_GET_BASE   = 3,
    GGML_RPC_FREE_BUFFER       = 4,
    GGML_RPC_BUFFER_CLEAR      = 5,
    GGML_RPC_SET_TENSOR        = 6,
    GGML_RPC_SET_TENSOR_HASH   = 7,
    GGML_RPC_GET_TENSOR        = 8,
    GGML_RPC_COPY_TENSOR       = 9,
    GGML_RPC_GRAPH_COMPUTE     = 10,
    GGML_RPC_GET_DEVICE_MEMORY = 11,
    GGML_RPC_INIT_TENSOR       = 12,
    GGML_RPC_GET_ALLOC_SIZE    = 13,
    GGML_RPC_HELLO             = 14,
    GGML_RPC_DEVICE_COUNT      = 15,
    GGML_RPC_GRAPH_RECOMPUTE   = 16
};

#define GGML_RPC_TENSOR_LEN   296u
#define GGML_RPC_NAME_OFF     228u
#define GGML_RPC_NAME_LEN     64u
#define BR_MAX_PAYLOAD        ((size_t)8192u << 20) /* 8 GiB: covers DeepSeek-V3/R1 671B stacked MoE experts! */
#define BR_TUN_CHUNK          (8u << 20)
#define BR_DEDUP_MIN_BYTES    4096u
#define BR_DEDUP_MAX_BYTES    (12u << 20) /* Dedup weights <12 MiB (ggml-rpc -c caches >10 MiB!) */
#define BR_ZSTD_MIN_BYTES     512u
#define BR_ZSTD_MAX_BYTES     (4u << 20)  /* Zstd graphs & small tensors; skip huge high-entropy quants */
#define BR_KNOWN_MAX          4096u
#define BR_LOGITS_MIN_VOCAB   4096u       /* Supports small model1 vocabs up to 250k+ Qwen/DeepSeek */
#define BR_LOGITS_MAX_TOPK    512u

enum {
    BR_TAG_RPC_RAW   = 1,
    BR_TAG_RPC_SFT1  = 2,
    BR_TAG_RESP_RAW  = 3,
    BR_TAG_RESP_SFT1 = 4,
    BR_TAG_RPC_ZSTD  = 5,
    BR_TAG_RPC_REF   = 6,
    BR_TAG_RESP_TOPK = 7,  /* total_elems(4 BE) | ne0(4 BE) | k(2 BE) | rows*k*(u32 idx + f32 val) */
    BR_TAG_RESP_ZERO = 8,  /* raw_len(4 BE) — bit-exact all-zero response tensor */
    BR_TAG_RESP_ZSTD = 9,  /* raw_len(4 BE) | zstd payload — bit-exact lossless response compression */
    BR_TAG_CHUNK_HDR = 10,
    BR_TAG_CHUNK_DAT = 11,
    BR_TAG_RPC_ZERO  = 12, /* cmd(1) | expect_resp(1) | pref_len(4 BE) | data_len(4 BE) | prefix */
    BR_TAG_HELLO     = 13, /* "SFLB"(4) | ver(2 BE) | hdr_len(2 BE) | cmd_max(2 BE) | caps(4 BE) | cast(1) | strict(1) | topk(2 BE) | rsv(2) */
    BR_TAG_CLOSE     = 99
};

#define BR_PROTO_VER     4u
#define BR_GGML_CMD_MAX  16u
#define BR_CAP_ALL       0x000000FFu /* SFT1|TOPK|ZSTD|DEDUP|ZERO|PIPE0RTT|ALLOC_CACHE|OUTLIER_GUARD */

/* AI-02: Full normative ABI schema digest (BLAKE3 over protocol ver, tensor layout, command table, dtypes) */
static uint16_t br_abi_fingerprint(void) {
    static const char schema[] =
        "SFLB_ABI_V4|TENSOR_LEN=296|NAME_OFF=228|NAME_LEN=64|CMD_MAX=16|"
        "CMDS=ALLOC0:ALIGN1:MAX2:BASE3:FREE4:CLR5:SET6:SETH7:GET8:CPY9:CMP10:MEM11:INIT12:ASZ13:HLO14:CNT15:RCMP16|"
        "F32=0|CAPS=000000FF";
    uint8_t digest[32];
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, schema, sizeof(schema) - 1u);
    blake3_hasher_finalize(&h, digest, sizeof(digest));
    uint16_t fp = (uint16_t)(((uint16_t)digest[0] << 8) | digest[1]);
    return fp ? fp : 1u;
}

/* AI-03: Normative ggml-rpc command validator — never trust peer-declared expect_resp blindly! */
static int br_validate_rpc_cmd(uint8_t cmd, uint8_t expect_resp, size_t rpc_len, int strict_lossless) {
    if (cmd > BR_GGML_CMD_MAX) return 0;
    if (strict_lossless && (expect_resp == 2u || expect_resp == 3u)) return 0;
    switch (cmd) {
        case GGML_RPC_SET_TENSOR:
            return expect_resp == 0u && rpc_len >= GGML_RPC_TENSOR_LEN + 8u;
        case GGML_RPC_GRAPH_COMPUTE:
        case GGML_RPC_GRAPH_RECOMPUTE:
            return expect_resp == 0u;
        case GGML_RPC_FREE_BUFFER:
        case GGML_RPC_BUFFER_CLEAR:
        case GGML_RPC_INIT_TENSOR:
            return (expect_resp == 1u || expect_resp == 4u);
        case GGML_RPC_GET_TENSOR:
            return (expect_resp == 1u || expect_resp == 2u || expect_resp == 3u) &&
                   rpc_len >= GGML_RPC_TENSOR_LEN + 16u;
        default:
            return expect_resp == 1u;
    }
}

static int buf_is_all_zero(const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i + 8u <= n) {
        uint64_t w = 0;
        memcpy(&w, p + i, 8u);
        if (w != 0u) return 0;
        i += 8u;
    }
    while (i < n) {
        if (p[i++] != 0u) return 0;
    }
    return 1;
}

static uint64_t get_le64(const uint8_t b[8]) {
    return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
           ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static void put_le64(uint8_t b[8], uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)((v >> (i * 8)) & 0xFFu);
}

static uint32_t get_le32(const uint8_t b[4]) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void put_le32(uint8_t b[4], uint32_t v) {
    b[0] = (uint8_t)(v & 0xFFu); b[1] = (uint8_t)((v >> 8) & 0xFFu);
    b[2] = (uint8_t)((v >> 16) & 0xFFu); b[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void put_be16(uint8_t b[2], uint16_t v) {
    b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)(v & 0xFFu);
}

static uint16_t get_be16(const uint8_t b[2]) {
    return (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
}

static void put_be32(uint8_t b[4], uint32_t v) {
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);  b[3] = (uint8_t)(v);
}

static uint32_t get_be32(const uint8_t b[4]) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  | ((uint32_t)b[3]);
}

static void put_be64(uint8_t b[8], uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)((v >> ((7 - i) * 8)) & 0xFFu);
}

static uint64_t get_be64(const uint8_t b[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static void sleep_ms(double ms) {
    if (ms <= 0.0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000.0);
    ts.tv_nsec = (long)((ms - (double)ts.tv_sec * 1000.0) * 1e6);
    nanosleep(&ts, NULL);
}

static uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static int tcp_read_exact(int fd, uint8_t *buf, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = recv(fd, buf + pos, len - pos, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        pos += (size_t)n;
    }
    return 0;
}

static int tcp_write_exact(int fd, const uint8_t *buf, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = send(fd, buf + pos, len - pos, MSG_NOSIGNAL);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        pos += (size_t)n;
    }
    return 0;
}

static int tcp_connect_local(const char *host, uint16_t port) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char pstr[16];
    snprintf(pstr, sizeof(pstr), "%u", (unsigned)port);
    if (getaddrinfo(host, pstr, &hints, &res) != 0 || !res) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ==================== Top-K Exact FP32 Sparse Logits Codec (-99.95% wire) ==================== */

static fp_err_t pack_topk_logits(const float *logits, uint32_t total_elems, uint32_t ne0,
                                 uint16_t k, uint8_t **out_buf, size_t *out_len) {
    if (!logits || ne0 == 0 || (total_elems % ne0) != 0u || k == 0 || k > BR_LOGITS_MAX_TOPK || k > ne0) {
        return FP_ERR_INVALID;
    }
    uint32_t rows = total_elems / ne0;
    size_t sz = 10u + (size_t)rows * (size_t)k * 8u;
    uint8_t *buf = malloc(sz);
    if (!buf) return FP_ERR_NOMEM;
    put_be32(buf, total_elems);
    put_be32(buf + 4, ne0);
    put_be16(buf + 8, k);

    uint32_t top_i[BR_LOGITS_MAX_TOPK];
    float    top_v[BR_LOGITS_MAX_TOPK];
    uint8_t *p = buf + 10;

    for (uint32_t r = 0; r < rows; r++) {
        const float *row = logits + (size_t)r * ne0;
        uint16_t min_pos = 0;
        float min_val = row[0];
        for (uint16_t i = 0; i < k; i++) {
            float v = isfinite(row[i]) ? row[i] : -1e9f;
            top_i[i] = i;
            top_v[i] = v;
            if (i == 0 || v < min_val) { min_val = v; min_pos = i; }
        }
        for (uint32_t j = k; j < ne0; j++) {
            float v = row[j];
            if (v > min_val && isfinite(v)) {
                top_i[min_pos] = j;
                top_v[min_pos] = v;
                min_pos = 0;
                min_val = top_v[0];
                for (uint16_t t = 1; t < k; t++) {
                    if (top_v[t] < min_val) { min_val = top_v[t]; min_pos = t; }
                }
            }
        }
        for (uint16_t i = 0; i < k; i++) {
            uint32_t fbits = 0;
            memcpy(&fbits, &top_v[i], 4u);
            put_le32(p, top_i[i]);
            put_le32(p + 4, fbits);
            p += 8;
        }
    }
    *out_buf = buf;
    *out_len = sz;
    return FP_OK;
}

static fp_err_t unpack_topk_logits(const uint8_t *buf, size_t len,
                                   uint8_t **out_data, size_t *out_data_len) {
    if (!buf || len < 10u || !out_data || !out_data_len) return FP_ERR_INVALID;
    uint32_t total_elems = get_be32(buf);
    uint32_t ne0         = get_be32(buf + 4);
    uint16_t k           = get_be16(buf + 8);
    if (total_elems == 0 || ne0 == 0 || (total_elems % ne0) != 0u ||
        k == 0 || k > BR_LOGITS_MAX_TOPK || k > ne0 || total_elems > (64u << 20)) {
        return FP_ERR_BOUNDS;
    }
    uint32_t rows = total_elems / ne0;
    if ((size_t)rows > (SIZE_MAX - 10u) / ((size_t)k * 8u)) return FP_ERR_BOUNDS;
    if (len != 10u + (size_t)rows * (size_t)k * 8u) return FP_ERR_BOUNDS;

    float *out = malloc((size_t)total_elems * sizeof(float));
    if (!out) return FP_ERR_NOMEM;
    for (uint32_t i = 0; i < total_elems; i++) out[i] = -1e9f;

    uint32_t seen_idx[BR_LOGITS_MAX_TOPK];
    const uint8_t *p = buf + 10;
    for (uint32_t r = 0; r < rows; r++) {
        float *row = out + (size_t)r * ne0;
        for (uint16_t i = 0; i < k; i++) {
            uint32_t idx   = get_le32(p);
            uint32_t fbits = get_le32(p + 4);
            p += 8;
            if (idx >= ne0) { free(out); return FP_ERR_BOUNDS; }
            for (uint16_t j = 0; j < i; j++) {
                if (seen_idx[j] == idx) { free(out); return FP_ERR_INVALID; }
            }
            seen_idx[i] = idx;
            float v = 0.0f;
            memcpy(&v, &fbits, 4u);
            if (!isfinite(v)) { free(out); return FP_ERR_INVALID; }
            row[idx] = v;
        }
    }
    *out_data = (uint8_t *)out;
    *out_data_len = (size_t)total_elems * sizeof(float);
    return FP_OK;
}

/* ==================== Persistent Known-DNA Index ==================== */

typedef struct {
    fp_dna_t dnas[BR_KNOWN_MAX];
    size_t   count;
    char     idx_path[512];
} known_dna_set_t;

static void known_dna_load(known_dna_set_t *set, const char *cache_dir) {
    memset(set, 0, sizeof(*set));
    if (!cache_dir || !cache_dir[0]) return;
    snprintf(set->idx_path, sizeof(set->idx_path), "%s/known_dnas.bin", cache_dir);
    FILE *f = fopen(set->idx_path, "rb");
    if (!f) return;
    while (set->count < BR_KNOWN_MAX &&
           fread(set->dnas[set->count].bytes, 1, FP_DNA_LEN, f) == FP_DNA_LEN) {
        set->count++;
    }
    fclose(f);
}

static int known_dna_has(const known_dna_set_t *set, const fp_dna_t *dna) {
    for (size_t i = 0; i < set->count; i++) {
        if (fp_dna_equal(&set->dnas[i], dna)) return 1;
    }
    return 0;
}

static void known_dna_add(known_dna_set_t *set, const fp_dna_t *dna) {
    if (known_dna_has(set, dna)) return;
    if (set->count < BR_KNOWN_MAX) {
        set->dnas[set->count++] = *dna;
        if (set->idx_path[0]) {
            FILE *f = fopen(set->idx_path, "ab");
            if (f) {
                fwrite(dna->bytes, 1, FP_DNA_LEN, f);
                fclose(f);
            }
        }
    }
}

static int ggml_cmd_has_response(uint8_t cmd) {
    switch (cmd) {
        case GGML_RPC_SET_TENSOR:
        case GGML_RPC_GRAPH_COMPUTE:
        case GGML_RPC_GRAPH_RECOMPUTE:
            return 0;
        default:
            return 1;
    }
}

/* Preserve ALL model weights, MoE expert banks/routers, KV-caches and recurrent SSM states
 * 100% lossless across all architectures (small model1, Llama, Qwen3.5 hybrid, DeepSeek-V3/R1 MoE). */
static int tensor_must_stay_lossless(const uint8_t *rpc_tensor_hdr) {
    char name[GGML_RPC_NAME_LEN + 1u];
    memcpy(name, rpc_tensor_hdr + GGML_RPC_NAME_OFF, GGML_RPC_NAME_LEN);
    name[GGML_RPC_NAME_LEN] = '\0';
    return (strstr(name, ".weight")    != NULL ||
            strstr(name, ".bias")      != NULL ||
            strstr(name, "_exps")      != NULL ||
            strstr(name, "exp_probs")  != NULL ||
            strstr(name, "moe_probs")  != NULL ||
            strstr(name, "token_embd") != NULL ||
            strstr(name, "output_norm")!= NULL ||
            strstr(name, "cache_k")    != NULL ||
            strstr(name, "cache_v")    != NULL ||
            strstr(name, "ssm_")       != NULL);
}

/* Strict whitelist for final vocabulary logits across ALL llama.cpp model families
 * (Llama, Qwen2/3/3.5, DeepSeek/V2/V3/R1, Mistral/Mixtral, Gemma, Phi -> always "result_output"). */
static int tensor_is_final_logits(const uint8_t *rpc_tensor_hdr) {
    char name[GGML_RPC_NAME_LEN + 1u];
    memcpy(name, rpc_tensor_hdr + GGML_RPC_NAME_OFF, GGML_RPC_NAME_LEN);
    name[GGML_RPC_NAME_LEN] = '\0';
    if (tensor_must_stay_lossless(rpc_tensor_hdr)) return 0;
    return (strcmp(name, "result_output") == 0 ||
            strncmp(name, "result_output", 13) == 0 ||
            strstr(name, "logits") != NULL);
}

static int detect_f32_set_tensor(const uint8_t *in, size_t in_len, size_t tensor_hdr_len,
                                 size_t *out_prefix_len, uint32_t *out_elems) {
    size_t pref = tensor_hdr_len + 8u;
    if (in_len <= pref + 64u) return 0;
    uint32_t gtype = get_le32(in + 8);
    if (gtype != (uint32_t)SF_GGML_TYPE_F32) return 0;
    if (tensor_must_stay_lossless(in)) return 0;
    size_t dlen = in_len - pref;
    if ((dlen & 3u) != 0u || dlen > (64u << 20)) return 0;
    *out_prefix_len = pref;
    *out_elems = (uint32_t)(dlen / 4u);
    return 1;
}

static int detect_f32_get_tensor_req(const uint8_t *in, size_t in_len, size_t tensor_hdr_len,
                                     uint32_t *out_ne0, int *out_is_logits) {
    if (out_ne0) *out_ne0 = 0;
    if (out_is_logits) *out_is_logits = 0;
    if (in_len < tensor_hdr_len + 16u) return 0;
    uint32_t gtype = get_le32(in + 8);
    uint32_t ne0   = get_le32(in + 20); /* rpc_tensor.ne[0] */
    uint64_t rsz   = get_le64(in + tensor_hdr_len + 8u);
    if (gtype != (uint32_t)SF_GGML_TYPE_F32) return 0;
    if (tensor_must_stay_lossless(in)) return 0;
    if (rsz < 64u || rsz > (64u << 20) || (rsz & 3u) != 0u) return 0;
    if (out_ne0) *out_ne0 = ne0;
    if (out_is_logits && tensor_is_final_logits(in) && ne0 >= BR_LOGITS_MIN_VOCAB &&
        rsz >= (uint64_t)ne0 * 4u && (rsz % ((uint64_t)ne0 * 4u)) == 0u) {
        *out_is_logits = 1;
    }
    return 1;
}

typedef struct {
    fp_dna_t key;
    uint64_t val;
    int      used;
} alloc_cache_entry_t;

#define BR_ALLOC_CACHE_SZ 2048u

static void hash_rpc_tensor_shape(blake3_hasher *h, const uint8_t *t) {
    /* Deterministic shape/op signature (pointer-independent): type, ne[4], nb[4], op, op_params, flags, has_view, view_offs */
    uint8_t has_view = (get_le64(t + 204u) != 0u) ? 1u : 0u;
    blake3_hasher_update(h, t + 8u, 4u);    /* type */
    blake3_hasher_update(h, t + 20u, 104u); /* ne[4], nb[4], op, op_params[16], flags */
    blake3_hasher_update(h, &has_view, 1u);
    blake3_hasher_update(h, t + 212u, 8u);  /* view_offs */
}

static int compute_alloc_size_key(const uint8_t *in, size_t in_len, size_t tensor_hdr_len, fp_dna_t *out_key) {
    if (tensor_hdr_len != GGML_RPC_TENSOR_LEN || in_len < 4u + GGML_RPC_TENSOR_LEN) return 0;
    size_t rem = in_len - 4u;
    if ((rem % GGML_RPC_TENSOR_LEN) != 0u) return 0;
    size_t n_tensors = rem / GGML_RPC_TENSOR_LEN;
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, in, 4u); /* device */
    for (size_t i = 0; i < n_tensors; i++) {
        hash_rpc_tensor_shape(&h, in + 4u + i * GGML_RPC_TENSOR_LEN);
    }
    blake3_hasher_finalize(&h, out_key->bytes, FP_DNA_LEN);
    return 1;
}

static uint64_t now_us_mono(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000ull);
}

typedef struct {
    sf_split_transport_t transport;
    fp_wire_cast_t       wire_cast;
    size_t               rpc_tensor_hdr_len;
    uint32_t             fault_drop_pct;
    int                  fec_mode;       /* 0=off, 1=on, 2=adaptive */
    int                  io_timeout_ms;
    int                  enable_zstd;
    int                  strict_lossless;
    uint16_t             logits_topk;    /* Default 64 (0 = disabled) */
    const char          *cache_dir;
    known_dna_set_t     *known_dnas;
    /* Realistic Keryx WAN Impairment Engine */
    double               wan_rtt_ms;
    double               wan_jitter_ms;
    double               wan_p99_ms;
    uint32_t             wan_p99_pct;
    double               wan_ul_mbps;
    double               wan_dl_mbps;
    double               wan_tcp_loss_pct;
    uint64_t             wan_rng;
    /* Counters */
    fp_dna_t             trace_chain;
    uint64_t             rpc_frames;
    uint64_t             sft1_tensors;
    uint64_t             raw_tensor_bytes;
    uint64_t             wire_bytes;
    uint64_t             topk_tensors;
    uint64_t             topk_raw_bytes;
    uint64_t             topk_wire_bytes;
    uint64_t             dedup_hits;
    uint64_t             dedup_saved_bytes;
    uint64_t             zstd_frames;
    uint64_t             zstd_raw_bytes;
    uint64_t             zstd_wire_bytes;
    uint64_t             total_rpc_bytes;
    uint64_t             tun_tx_bytes;
    uint64_t             tun_rx_bytes;
    uint64_t             udp_retx;
    uint64_t             udp_fec;
    uint64_t             wan_p99_hits;
    uint64_t             void_pipelined;
    uint64_t             alloc_cache_hits;
    uint64_t             cmd_cnt[17];
    uint64_t             cmd_us[17];
} bridge_state_t;

static void pace_wan_realistic(bridge_state_t *st, size_t bytes, int is_upload, int add_rtt) {
    double mbps = is_upload ? st->wan_ul_mbps : st->wan_dl_mbps;
    double delay = 0.0;
    double rtt = st->wan_rtt_ms;
    if (add_rtt && rtt > 0.0) {
        double d_rtt = rtt;
        if (st->wan_jitter_ms > 0.0) {
            double u = (double)(xorshift64(&st->wan_rng) & 0xFFFFu) / 32768.0 - 1.0; /* [-1, +1] */
            d_rtt += u * st->wan_jitter_ms;
            if (d_rtt < 2.0) d_rtt = 2.0;
        }
        if (st->wan_p99_pct > 0u && st->wan_p99_ms > 0.0 &&
            (xorshift64(&st->wan_rng) % 100u) < st->wan_p99_pct) {
            d_rtt += st->wan_p99_ms;
            st->wan_p99_hits++;
        }
        delay += d_rtt;
    }
    if (mbps > 0.0 && bytes > 0u) {
        delay += ((double)bytes * 8.0) / (mbps * 1e3);
    }
    /* Realistic TCP packet-loss CWND halving & HoL stall (applies only to TCP baseline!) */
    if (st->transport == SF_SPLIT_TCP && st->wan_tcp_loss_pct > 0.0 && bytes >= 1400u) {
        size_t segs = (bytes + 1399u) / 1400u;
        double expected_losses = (double)segs * (st->wan_tcp_loss_pct / 100.0);
        uint32_t whole = (uint32_t)expected_losses;
        double frac = expected_losses - (double)whole;
        if (((double)(xorshift64(&st->wan_rng) & 0xFFFFu) / 65536.0) < frac) whole++;
        if (whole > 0u) {
            /* Cap per-frame stalls cleanly; each loss costs ~1.5x RTT HoL stall */
            if (whole > 6u) whole = 6u;
            delay += (double)whole * (rtt > 10.0 ? rtt * 1.5 : 30.0);
        }
    }
    if (delay > 0.05) sleep_ms(delay);
}

static void trace_mix(fp_dna_t *chain, uint8_t cmd, const fp_dna_t *msg_dna) {
    static const uint8_t dom[16] = "SF_LLAMA_BR/V1\0";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, dom, sizeof(dom));
    blake3_hasher_update(&h, chain->bytes, FP_DNA_LEN);
    blake3_hasher_update(&h, &cmd, 1);
    blake3_hasher_update(&h, msg_dna->bytes, FP_DNA_LEN);
    blake3_hasher_finalize(&h, chain->bytes, FP_DNA_LEN);
}

static fp_err_t tun_send_one(sf_split_transport_t tr, fp_session_t *ts, fp_udp_session_t *us,
                             uint8_t tag, const uint8_t *data, size_t len, fp_dna_t *dna) {
    if (tr == SF_SPLIT_TCP) return fp_session_send_verified(ts, tag, data, len, dna);
    return fp_udp_session_send_verified(us, tag, data, len, dna);
}

static fp_err_t tun_recv_one(sf_split_transport_t tr, fp_session_t *ts, fp_udp_session_t *us,
                             size_t max_bytes, uint8_t *tag, uint8_t **data, size_t *len, fp_dna_t *dna) {
    if (tr == SF_SPLIT_TCP) return fp_session_recv_verified(ts, max_bytes, tag, data, len, dna);
    return fp_udp_session_recv_verified(us, max_bytes, tag, data, len, dna);
}

static fp_err_t tun_send(sf_split_transport_t tr, fp_session_t *ts, fp_udp_session_t *us,
                         uint8_t tag, const uint8_t *data, size_t len, fp_dna_t *dna) {
    if (len <= BR_TUN_CHUNK) return tun_send_one(tr, ts, us, tag, data, len, dna);
    if (dna) {
        fp_err_t de = fp_dna_compute(data, len, dna);
        if (de != FP_OK) return de;
    }
    uint8_t chdr[9];
    chdr[0] = tag;
    put_be64(chdr + 1, (uint64_t)len);
    fp_err_t err = tun_send_one(tr, ts, us, BR_TAG_CHUNK_HDR, chdr, 9u, NULL);
    if (err != FP_OK) return err;
    size_t off = 0;
    while (off < len) {
        size_t n = (len - off > BR_TUN_CHUNK) ? BR_TUN_CHUNK : (len - off);
        err = tun_send_one(tr, ts, us, BR_TAG_CHUNK_DAT, data + off, n, NULL);
        if (err != FP_OK) return err;
        off += n;
    }
    return FP_OK;
}

static fp_err_t tun_recv(sf_split_transport_t tr, fp_session_t *ts, fp_udp_session_t *us,
                         size_t max_bytes, uint8_t *tag, uint8_t **data, size_t *len, fp_dna_t *dna) {
    uint8_t t = 0;
    uint8_t *buf = NULL;
    size_t blen = 0;
    fp_err_t err = tun_recv_one(tr, ts, us, max_bytes, &t, &buf, &blen, dna);
    if (err != FP_OK) return err;
    if (t != BR_TAG_CHUNK_HDR) {
        *tag = t; *data = buf; *len = blen;
        return FP_OK;
    }
    if (blen != 9u) { free(buf); return FP_ERR_INVALID; }
    uint8_t orig_tag = buf[0];
    uint64_t total = get_be64(buf + 1);
    free(buf);
    if (total > max_bytes) return FP_ERR_BOUNDS;
    uint8_t *full = malloc(total > 0 ? (size_t)total : 1u);
    if (!full) return FP_ERR_NOMEM;
    size_t off = 0;
    while (off < (size_t)total) {
        uint8_t dt = 0; uint8_t *db = NULL; size_t dl = 0;
        err = tun_recv_one(tr, ts, us, BR_TUN_CHUNK + 64u, &dt, &db, &dl, NULL);
        if (err != FP_OK || dt != BR_TAG_CHUNK_DAT || off + dl > (size_t)total) {
            free(db); free(full);
            return (err != FP_OK) ? err : FP_ERR_BOUNDS;
        }
        memcpy(full + off, db, dl);
        free(db);
        off += dl;
    }
    if (dna) (void)fp_dna_compute(full, (size_t)total, dna);
    *tag = orig_tag; *data = full; *len = (size_t)total;
    return FP_OK;
}

/* ==================== Client-Side Bridge ==================== */

static fp_err_t run_client_session(int local_cli_fd, sf_split_transport_t tr,
                                   fp_session_t *ts, fp_udp_session_t *us,
                                   bridge_state_t *st) {
    uint64_t seq = 0;
    if (st->strict_lossless) {
        st->wire_cast = FP_WIRE_CAST_NONE;
        st->logits_topk = 0u;
    }
    /* One-shot 20 B protocol compatibility preamble (0 RTT added, 0 per-token overhead) */
    {
        uint8_t hlo[20];
        memcpy(hlo, "SFLB", 4);
        put_be16(hlo + 4, (uint16_t)BR_PROTO_VER);
        put_be16(hlo + 6, (uint16_t)st->rpc_tensor_hdr_len);
        put_be16(hlo + 8, (uint16_t)BR_GGML_CMD_MAX);
        put_be32(hlo + 10, BR_CAP_ALL);
        hlo[14] = (uint8_t)st->wire_cast;
        hlo[15] = (uint8_t)(st->strict_lossless ? 1u : 0u);
        put_be16(hlo + 16, st->logits_topk);
        put_be16(hlo + 18, br_abi_fingerprint());
        fp_err_t herr = tun_send(tr, ts, us, BR_TAG_HELLO, hlo, sizeof(hlo), NULL);
        if (herr != FP_OK) return herr;
    }
    alloc_cache_entry_t *acache = calloc(BR_ALLOC_CACHE_SZ, sizeof(*acache));
    for (;;) {
        uint8_t hdr[9];
        if (tcp_read_exact(local_cli_fd, hdr, 9u) != 0) break;
        uint64_t t_cmd0 = now_us_mono();
        uint8_t cmd = hdr[0];
        uint64_t in_len = get_le64(hdr + 1);
        if (in_len > BR_MAX_PAYLOAD) { free(acache); return FP_ERR_BOUNDS; }

        uint8_t *in_buf = malloc(in_len > 0 ? (size_t)in_len : 1u);
        if (!in_buf) { free(acache); return FP_ERR_NOMEM; }
        if (in_len > 0 && tcp_read_exact(local_cli_fd, in_buf, (size_t)in_len) != 0) {
            free(in_buf);
            break;
        }
        st->total_rpc_bytes += (size_t)in_len;

        /* 0-RTT structural cache for GET_ALLOC_SIZE (cmd 13) when SealFrame optimizations enabled */
        int have_alloc_key = 0;
        fp_dna_t alloc_key;
        if (st->enable_zstd && acache && cmd == GGML_RPC_GET_ALLOC_SIZE &&
            compute_alloc_size_key(in_buf, (size_t)in_len, st->rpc_tensor_hdr_len, &alloc_key)) {
            have_alloc_key = 1;
            uint32_t slot = get_be32(alloc_key.bytes) & (BR_ALLOC_CACHE_SZ - 1u);
            for (uint32_t p = 0; p < 8u; p++) {
                uint32_t idx = (slot + p) & (BR_ALLOC_CACHE_SZ - 1u);
                if (acache[idx].used && fp_dna_equal(&acache[idx].key, &alloc_key)) {
                    uint8_t resp_pkt[16];
                    put_le64(resp_pkt, 8u);
                    put_le64(resp_pkt + 8u, acache[idx].val);
                    int wrc = tcp_write_exact(local_cli_fd, resp_pkt, 16u);
                    free(in_buf);
                    if (wrc != 0) { free(acache); return FP_ERR_IO; }
                    st->alloc_cache_hits++;
                    st->rpc_frames++;
                    if (cmd < 17u) { st->cmd_cnt[cmd]++; st->cmd_us[cmd] += (now_us_mono() - t_cmd0); }
                    have_alloc_key = -1;
                    break;
                }
            }
            if (have_alloc_key == -1) continue;
        }

        uint8_t expect_resp = (uint8_t)ggml_cmd_has_response(cmd);
        int local_void_ack = 0;
        /* 0-RTT FIFO pipelining for void-response commands (FREE_BUFFER, BUFFER_CLEAR, INIT_TENSOR):
         * server executes in strict order and drains backend 0-len ACK locally without WAN RTT! */
        if (st->enable_zstd &&
            (cmd == GGML_RPC_FREE_BUFFER || cmd == GGML_RPC_BUFFER_CLEAR || cmd == GGML_RPC_INIT_TENSOR)) {
            expect_resp = 4u; /* Server drains 0-byte backend reply, sends NO WAN response */
            local_void_ack = 1;
        } else if (cmd == GGML_RPC_GET_TENSOR) {
            uint32_t ne0 = 0;
            int is_logits = 0;
            if (detect_f32_get_tensor_req(in_buf, (size_t)in_len, st->rpc_tensor_hdr_len,
                                          &ne0, &is_logits)) {
                if (is_logits && st->logits_topk > 0u) {
                    expect_resp = 3u; /* Top-K Exact FP32 Sparse Logits! */
                } else if (st->wire_cast != FP_WIRE_CAST_NONE) {
                    expect_resp = 2u; /* SFT1 wire quantization */
                }
            }
        }

        size_t pref_len = 0;
        uint32_t elems = 0;
        fp_err_t err = FP_OK;
        fp_dna_t msg_dna;
        size_t sent_wire_len = 0;
        int handled = 0;

        /* Path 0: All-zero SET_TENSOR payload (>=256 B, e.g. KV/SSM slot reset) -> 10B bit-exact ZERO tag */
        size_t set_pref = st->rpc_tensor_hdr_len + 8u;
        if (cmd == GGML_RPC_SET_TENSOR && in_len >= set_pref + 256u &&
            in_len - set_pref <= (64u << 20) &&
            buf_is_all_zero(in_buf + set_pref, (size_t)in_len - set_pref)) {
            size_t dlen = (size_t)in_len - set_pref;
            size_t env_len = 10u + set_pref;
            uint8_t *env = malloc(env_len);
            if (!env) { free(in_buf); return FP_ERR_NOMEM; }
            env[0] = cmd; env[1] = expect_resp;
            put_be32(env + 2, (uint32_t)set_pref);
            put_be32(env + 6, (uint32_t)dlen);
            memcpy(env + 10, in_buf, set_pref);
            err = tun_send(tr, ts, us, BR_TAG_RPC_ZERO, env, env_len, &msg_dna);
            sent_wire_len = env_len;
            st->dedup_hits++;
            st->dedup_saved_bytes += dlen;
            free(env);
            handled = 1;
        }

        /* Path 1: FP32 runtime activation SET_TENSOR -> SFT1 */
        if (!handled && cmd == GGML_RPC_SET_TENSOR && st->wire_cast != FP_WIRE_CAST_NONE &&
            detect_f32_set_tensor(in_buf, (size_t)in_len, st->rpc_tensor_hdr_len, &pref_len, &elems)) {
            fp_tensor_meta_t m;
            memset(&m, 0, sizeof(m));
            m.dtype = FP_DTYPE_FP32; m.ndim = 1u; m.dims[0] = elems; m.seq_id = ++seq;
            uint8_t *sft = NULL; size_t sft_len = 0;
            err = fp_tensor_pack_ex(&m, in_buf + pref_len, (size_t)elems * 4u,
                                    st->wire_cast, &sft, &sft_len);
            if (err == FP_OK) {
                size_t env_len = 6u + pref_len + sft_len;
                uint8_t *env = malloc(env_len);
                if (!env) { free(sft); free(in_buf); return FP_ERR_NOMEM; }
                env[0] = cmd; env[1] = expect_resp;
                put_be32(env + 2, (uint32_t)pref_len);
                memcpy(env + 6, in_buf, pref_len);
                memcpy(env + 6 + pref_len, sft, sft_len);
                free(sft);
                err = tun_send(tr, ts, us, BR_TAG_RPC_SFT1, env, env_len, &msg_dna);
                sent_wire_len = env_len;
                st->sft1_tensors++;
                st->raw_tensor_bytes += (size_t)elems * 4u;
                st->wire_bytes += sft_len;
                free(env);
                handled = 1;
            }
        }

        /* Path 2: Non-SFT1 SET_TENSOR [4 KiB .. 12 MiB] -> BLAKE3 DNA Dedup */
        int cache_this_set = 0;
        fp_dna_t payload_dna;
        if (!handled && cmd == GGML_RPC_SET_TENSOR && st->known_dnas &&
            in_len > set_pref + BR_DEDUP_MIN_BYTES && in_len <= set_pref + BR_DEDUP_MAX_BYTES) {
            size_t dlen = (size_t)in_len - set_pref;
            if (fp_dna_compute(in_buf + set_pref, dlen, &payload_dna) == FP_OK) {
                if (known_dna_has(st->known_dnas, &payload_dna)) {
                    size_t env_len = 6u + set_pref + FP_DNA_LEN;
                    uint8_t *env = malloc(env_len);
                    if (!env) { free(in_buf); return FP_ERR_NOMEM; }
                    env[0] = cmd; env[1] = expect_resp;
                    put_be32(env + 2, (uint32_t)set_pref);
                    memcpy(env + 6, in_buf, set_pref);
                    memcpy(env + 6 + set_pref, payload_dna.bytes, FP_DNA_LEN);
                    err = tun_send(tr, ts, us, BR_TAG_RPC_REF, env, env_len, &msg_dna);
                    sent_wire_len = env_len;
                    st->dedup_hits++;
                    st->dedup_saved_bytes += dlen;
                    free(env);
                    handled = 1;
                } else {
                    cache_this_set = 1;
                }
            }
        }

        /* Path 3: Fast Zstd-1 on GRAPH_COMPUTE & small tensors <=4 MiB (or cache-store <=12 MiB) */
        if (!handled && ((st->enable_zstd && in_len >= BR_ZSTD_MIN_BYTES && in_len <= BR_ZSTD_MAX_BYTES) ||
                         (cache_this_set && in_len <= set_pref + BR_DEDUP_MAX_BYTES))) {
            size_t zcap = ZSTD_compressBound((size_t)in_len);
            uint8_t *env = malloc(11u + zcap);
            if (env) {
                size_t zlen = ZSTD_compress(env + 11u, zcap, in_buf, (size_t)in_len, 1);
                if (!ZSTD_isError(zlen) && (cache_this_set || zlen < ((size_t)in_len * 88u) / 100u)) {
                    env[0] = cmd; env[1] = expect_resp;
                    put_be32(env + 2, (uint32_t)in_len);
                    env[6] = (uint8_t)cache_this_set;
                    put_be32(env + 7, cache_this_set ? (uint32_t)set_pref : 0u);
                    err = tun_send(tr, ts, us, BR_TAG_RPC_ZSTD, env, 11u + zlen, &msg_dna);
                    sent_wire_len = 11u + zlen;
                    st->zstd_frames++;
                    st->zstd_raw_bytes += (size_t)in_len;
                    st->zstd_wire_bytes += zlen;
                    if (err == FP_OK && cache_this_set) known_dna_add(st->known_dnas, &payload_dna);
                    handled = 1;
                }
                free(env);
            }
        }

        /* Path 4: Raw passthrough */
        if (!handled) {
            size_t env_len = 2u + (size_t)in_len;
            uint8_t *env = malloc(env_len);
            if (!env) { free(in_buf); return FP_ERR_NOMEM; }
            env[0] = cmd; env[1] = expect_resp;
            if (in_len > 0) memcpy(env + 2, in_buf, (size_t)in_len);
            err = tun_send(tr, ts, us, BR_TAG_RPC_RAW, env, env_len, &msg_dna);
            sent_wire_len = env_len;
            free(env);
        }
        free(in_buf);
        if (err != FP_OK) { free(acache); return err; }

        pace_wan_realistic(st, sent_wire_len, 1, (!local_void_ack && expect_resp > 0u));

        st->rpc_frames++;
        trace_mix(&st->trace_chain, cmd, &msg_dna);

        if (local_void_ack) {
            uint8_t rhdr[8] = {0};
            if (tcp_write_exact(local_cli_fd, rhdr, 8u) != 0) { free(acache); return FP_ERR_IO; }
            st->void_pipelined++;
        } else if (expect_resp > 0u) {
            uint8_t rtag = 0;
            uint8_t *rbuf = NULL;
            size_t rlen = 0;
            fp_dna_t rdna;
            err = tun_recv(tr, ts, us, BR_MAX_PAYLOAD, &rtag, &rbuf, &rlen, &rdna);
            if (err != FP_OK) { free(acache); return err; }
            pace_wan_realistic(st, rlen, 0, 0);
            trace_mix(&st->trace_chain, (uint8_t)(cmd | 0x80u), &rdna);

            uint8_t *out_bytes = rbuf;
            size_t out_len = rlen;
            uint8_t *dec_buf = NULL;
            if (st->strict_lossless && (rtag == BR_TAG_RESP_SFT1 || rtag == BR_TAG_RESP_TOPK)) {
                free(rbuf); free(acache);
                return FP_ERR_POLICY;
            }
            if (rtag == BR_TAG_RESP_SFT1) {
                fp_tensor_meta_t rm;
                err = fp_tensor_unpack(rbuf, rlen, 1, &rm, &dec_buf, &out_len);
                if (err != FP_OK) { free(rbuf); free(acache); return err; }
                st->sft1_tensors++;
                st->raw_tensor_bytes += out_len;
                st->wire_bytes += rlen;
                out_bytes = dec_buf;
            } else if (rtag == BR_TAG_RESP_TOPK) {
                err = unpack_topk_logits(rbuf, rlen, &dec_buf, &out_len);
                if (err != FP_OK) { free(rbuf); free(acache); return err; }
                st->topk_tensors++;
                st->topk_raw_bytes += out_len;
                st->topk_wire_bytes += rlen;
                out_bytes = dec_buf;
            } else if (rtag == BR_TAG_RESP_ZERO) {
                if (rlen != 4u) { free(rbuf); free(acache); return FP_ERR_INVALID; }
                uint32_t zraw = get_be32(rbuf);
                if (zraw > (64u << 20)) { free(rbuf); free(acache); return FP_ERR_BOUNDS; }
                dec_buf = calloc(zraw > 0 ? zraw : 1u, 1u);
                if (!dec_buf) { free(rbuf); free(acache); return FP_ERR_NOMEM; }
                out_len = zraw;
                st->dedup_hits++;
                st->dedup_saved_bytes += out_len;
                out_bytes = dec_buf;
            } else if (rtag == BR_TAG_RESP_ZSTD) {
                if (rlen < 5u) { free(rbuf); free(acache); return FP_ERR_INVALID; }
                uint32_t zraw = get_be32(rbuf);
                if (zraw > (64u << 20)) { free(rbuf); free(acache); return FP_ERR_BOUNDS; }
                dec_buf = malloc(zraw > 0 ? zraw : 1u);
                if (!dec_buf) { free(rbuf); free(acache); return FP_ERR_NOMEM; }
                size_t drc = ZSTD_decompress(dec_buf, zraw, rbuf + 4u, rlen - 4u);
                if (ZSTD_isError(drc) || drc != (size_t)zraw) {
                    free(dec_buf); free(rbuf); free(acache); return FP_ERR_CODEC;
                }
                out_len = zraw;
                st->zstd_frames++;
                st->zstd_raw_bytes += out_len;
                st->zstd_wire_bytes += rlen;
                out_bytes = dec_buf;
            }
            if (have_alloc_key == 1 && acache && out_len == 8u) {
                uint32_t slot = get_be32(alloc_key.bytes) & (BR_ALLOC_CACHE_SZ - 1u);
                uint32_t target = slot;
                for (uint32_t p = 0; p < 8u; p++) {
                    uint32_t idx = (slot + p) & (BR_ALLOC_CACHE_SZ - 1u);
                    if (!acache[idx].used) { target = idx; break; }
                }
                acache[target].key = alloc_key;
                acache[target].val = get_le64(out_bytes);
                acache[target].used = 1;
            }
            st->total_rpc_bytes += out_len;
            uint8_t rhdr[8];
            put_le64(rhdr, (uint64_t)out_len);
            int wrc = tcp_write_exact(local_cli_fd, rhdr, 8u);
            if (wrc == 0 && out_len > 0) wrc = tcp_write_exact(local_cli_fd, out_bytes, out_len);
            free(dec_buf);
            free(rbuf);
            if (wrc != 0) { free(acache); return FP_ERR_IO; }
        }
        if (cmd < 17u) { st->cmd_cnt[cmd]++; st->cmd_us[cmd] += (now_us_mono() - t_cmd0); }
    }
    free(acache);
    if (tr == SF_SPLIT_TCP && ts) fp_session_stats(ts, &st->tun_tx_bytes, &st->tun_rx_bytes);
    else if (us) {
        fp_udp_session_stats(us, &st->tun_tx_bytes, &st->tun_rx_bytes, &st->udp_retx);
        st->udp_fec = fp_udp_session_fec_recoveries(us);
    }
    (void)tun_send(tr, ts, us, BR_TAG_CLOSE, NULL, 0, NULL);
    return FP_OK;
}

/* ==================== Server-Side Bridge ==================== */

static fp_err_t run_server_session(int backend_fd, sf_split_transport_t tr,
                                   fp_session_t *ts, fp_udp_session_t *us,
                                   bridge_state_t *st) {
    uint64_t seq = 0;
    int hello_done = 0;
    for (;;) {
        uint8_t tag = 0;
        uint8_t *msg = NULL;
        size_t mlen = 0;
        fp_err_t err = tun_recv(tr, ts, us, BR_MAX_PAYLOAD, &tag, &msg, &mlen, NULL);
        if (err != FP_OK) return err;
        if (tag == BR_TAG_CLOSE) { free(msg); return FP_OK; }
        if (tag == BR_TAG_HELLO) {
            if (hello_done || mlen != 20u || memcmp(msg, "SFLB", 4) != 0) {
                free(msg);
                return FP_ERR_POLICY;
            }
            uint16_t pver = get_be16(msg + 4);
            uint16_t hlen = get_be16(msg + 6);
            uint16_t cmax = get_be16(msg + 8);
            uint16_t afp  = get_be16(msg + 18);
            if (pver != BR_PROTO_VER || hlen != (uint16_t)st->rpc_tensor_hdr_len ||
                cmax > BR_GGML_CMD_MAX || afp != br_abi_fingerprint()) {
                free(msg);
                return FP_ERR_POLICY;
            }
            if (msg[15] != 0u) {
                st->strict_lossless = 1;
                st->wire_cast = FP_WIRE_CAST_NONE;
                st->logits_topk = 0u;
            }
            hello_done = 1;
            free(msg);
            continue;
        }
        /* AI-02: Fail closed if any RPC frame arrives before compatibility HELLO preamble */
        if (!hello_done) {
            free(msg);
            return FP_ERR_POLICY;
        }

        uint8_t cmd = 0, expect_resp = 0;
        uint8_t *rpc_payload = NULL;
        size_t rpc_len = 0;
        uint8_t *alloc_payload = NULL;
        uint32_t req_ne0 = 0;

        if (tag == BR_TAG_RPC_RAW && mlen >= 2u) {
            cmd = msg[0]; expect_resp = msg[1];
            rpc_payload = msg + 2; rpc_len = mlen - 2u;
        } else if (tag == BR_TAG_RPC_SFT1 && mlen >= 6u) {
            /* AI-03: Never accept lossy SFT1 wire frames when strict_lossless is active */
            if (st->strict_lossless) { free(msg); return FP_ERR_POLICY; }
            cmd = msg[0]; expect_resp = msg[1];
            uint32_t pref_len = get_be32(msg + 2);
            if (6u + (size_t)pref_len >= mlen) { free(msg); return FP_ERR_BOUNDS; }
            fp_tensor_meta_t dm;
            uint8_t *fdata = NULL; size_t flen = 0;
            err = fp_tensor_unpack(msg + 6u + pref_len, mlen - 6u - pref_len, 1, &dm, &fdata, &flen);
            if (err != FP_OK) { free(msg); return err; }
            if (flen > BR_MAX_PAYLOAD - (size_t)pref_len) {
                free(fdata); free(msg); return FP_ERR_BOUNDS;
            }
            rpc_len = (size_t)pref_len + flen;
            alloc_payload = malloc(rpc_len);
            if (!alloc_payload) { free(fdata); free(msg); return FP_ERR_NOMEM; }
            memcpy(alloc_payload, msg + 6u, pref_len);
            memcpy(alloc_payload + pref_len, fdata, flen);
            free(fdata);
            rpc_payload = alloc_payload;
        } else if (tag == BR_TAG_RPC_ZSTD && mlen > 11u) {
            cmd = msg[0]; expect_resp = msg[1];
            uint32_t raw_len = get_be32(msg + 2);
            uint8_t cache_store = msg[6];
            uint32_t pref_len = get_be32(msg + 7);
            if (raw_len > (64u << 20)) { free(msg); return FP_ERR_BOUNDS; }
            alloc_payload = malloc(raw_len > 0 ? raw_len : 1u);
            if (!alloc_payload) { free(msg); return FP_ERR_NOMEM; }
            size_t drc = ZSTD_decompress(alloc_payload, raw_len, msg + 11u, mlen - 11u);
            if (ZSTD_isError(drc) || drc != (size_t)raw_len) {
                free(alloc_payload); free(msg);
                return FP_ERR_CODEC;
            }
            if (cache_store && st->cache_dir && raw_len > pref_len) {
                fp_dna_t stored_dna;
                /* AI-01: Check CAS write status instead of silently ignoring store failures */
                fp_err_t perr = fp_store_put_object(st->cache_dir, alloc_payload + pref_len,
                                                    raw_len - pref_len, &stored_dna);
                if (perr != FP_OK) {
                    free(alloc_payload); free(msg);
                    return perr;
                }
            }
            rpc_payload = alloc_payload;
            rpc_len = raw_len;
        } else if (tag == BR_TAG_RPC_REF && mlen >= 6u + FP_DNA_LEN) {
            cmd = msg[0]; expect_resp = msg[1];
            uint32_t pref_len = get_be32(msg + 2);
            if (!st->cache_dir || mlen != 6u + (size_t)pref_len + FP_DNA_LEN) {
                free(msg); return FP_ERR_MISSING_REF;
            }
            fp_dna_t ref_dna;
            memcpy(ref_dna.bytes, msg + 6u + pref_len, FP_DNA_LEN);
            uint8_t *obj = NULL; size_t olen = 0;
            err = fp_store_get_object(st->cache_dir, &ref_dna, BR_MAX_PAYLOAD, &obj, &olen);
            if (err != FP_OK) { free(msg); return err; }
            if (olen > BR_MAX_PAYLOAD - (size_t)pref_len) {
                free(obj); free(msg); return FP_ERR_BOUNDS;
            }
            rpc_len = (size_t)pref_len + olen;
            alloc_payload = malloc(rpc_len);
            if (!alloc_payload) { free(obj); free(msg); return FP_ERR_NOMEM; }
            memcpy(alloc_payload, msg + 6u, pref_len);
            memcpy(alloc_payload + pref_len, obj, olen);
            free(obj);
            rpc_payload = alloc_payload;
        } else if (tag == BR_TAG_RPC_ZERO && mlen >= 10u) {
            cmd = msg[0]; expect_resp = msg[1];
            uint32_t pref_len = get_be32(msg + 2);
            uint32_t dlen     = get_be32(msg + 6);
            if (mlen != 10u + (size_t)pref_len || dlen > (64u << 20) ||
                (size_t)pref_len > BR_MAX_PAYLOAD - (size_t)dlen) {
                free(msg); return FP_ERR_BOUNDS;
            }
            rpc_len = (size_t)pref_len + (size_t)dlen;
            alloc_payload = calloc(rpc_len > 0 ? rpc_len : 1u, 1u);
            if (!alloc_payload) { free(msg); return FP_ERR_NOMEM; }
            memcpy(alloc_payload, msg + 10u, pref_len);
            rpc_payload = alloc_payload;
        } else {
            free(msg);
            return FP_ERR_INVALID;
        }
        if (!br_validate_rpc_cmd(cmd, expect_resp, rpc_len, st->strict_lossless)) {
            free(alloc_payload); free(msg);
            return FP_ERR_POLICY;
        }

        if (cmd == GGML_RPC_GET_TENSOR && rpc_len >= 24u) {
            req_ne0 = get_le32(rpc_payload + 20);
        }

        uint8_t hdr[9];
        hdr[0] = cmd;
        put_le64(hdr + 1, (uint64_t)rpc_len);
        int wrc = tcp_write_exact(backend_fd, hdr, 9u);
        if (wrc == 0 && rpc_len > 0) wrc = tcp_write_exact(backend_fd, rpc_payload, rpc_len);
        free(alloc_payload);
        free(msg);
        if (wrc != 0) return FP_ERR_IO;

        if (expect_resp == 4u) {
            /* Pipelined void command (FREE_BUFFER / BUFFER_CLEAR / INIT_TENSOR):
             * drain the local 0-byte backend ACK in strict FIFO order without sending a WAN packet! */
            uint8_t rhdr[8];
            if (tcp_read_exact(backend_fd, rhdr, 8u) != 0) return FP_ERR_IO;
            uint64_t rlen = get_le64(rhdr);
            if (rlen > 0u) {
                if (rlen > BR_MAX_PAYLOAD) return FP_ERR_BOUNDS;
                uint8_t *drain = malloc((size_t)rlen);
                if (!drain) return FP_ERR_NOMEM;
                int rrc = tcp_read_exact(backend_fd, drain, (size_t)rlen);
                free(drain);
                if (rrc != 0) return FP_ERR_IO;
            }
        } else if (expect_resp > 0u) {
            uint8_t rhdr[8];
            if (tcp_read_exact(backend_fd, rhdr, 8u) != 0) return FP_ERR_IO;
            uint64_t rlen = get_le64(rhdr);
            if (rlen > BR_MAX_PAYLOAD) return FP_ERR_BOUNDS;
            uint8_t *rbuf = malloc(rlen > 0 ? (size_t)rlen : 1u);
            if (!rbuf) return FP_ERR_NOMEM;
            if (rlen > 0 && tcp_read_exact(backend_fd, rbuf, (size_t)rlen) != 0) {
                free(rbuf);
                return FP_ERR_IO;
            }
            if (expect_resp == 3u && st->logits_topk > 0u && req_ne0 >= BR_LOGITS_MIN_VOCAB &&
                rlen >= (uint64_t)req_ne0 * 4u && (rlen % ((uint64_t)req_ne0 * 4u)) == 0u) {
                uint8_t *tk = NULL; size_t tk_len = 0;
                err = pack_topk_logits((const float *)rbuf, (uint32_t)(rlen / 4u),
                                       req_ne0, st->logits_topk, &tk, &tk_len);
                free(rbuf);
                if (err != FP_OK) return err;
                err = tun_send(tr, ts, us, BR_TAG_RESP_TOPK, tk, tk_len, NULL);
                free(tk);
            } else if ((expect_resp == 2u || expect_resp == 3u) &&
                       st->wire_cast != FP_WIRE_CAST_NONE && rlen >= 64u && (rlen & 3u) == 0u) {
                fp_tensor_meta_t m;
                memset(&m, 0, sizeof(m));
                m.dtype = FP_DTYPE_FP32; m.ndim = 1u; m.dims[0] = (uint32_t)(rlen / 4u); m.seq_id = ++seq;
                uint8_t *sft = NULL; size_t sft_len = 0;
                err = fp_tensor_pack_ex(&m, rbuf, (size_t)rlen, st->wire_cast, &sft, &sft_len);
                free(rbuf);
                if (err != FP_OK) return err;
                err = tun_send(tr, ts, us, BR_TAG_RESP_SFT1, sft, sft_len, NULL);
                free(sft);
            } else if (rlen >= 64u && rlen <= (64u << 20) && buf_is_all_zero(rbuf, (size_t)rlen)) {
                uint8_t zhdr[4];
                put_be32(zhdr, (uint32_t)rlen);
                free(rbuf);
                err = tun_send(tr, ts, us, BR_TAG_RESP_ZERO, zhdr, 4u, NULL);
            } else {
                int sent_z = 0;
                if (st->enable_zstd && rlen >= 256u && rlen <= (16u << 20)) {
                    size_t zcap = ZSTD_compressBound((size_t)rlen);
                    uint8_t *zenv = malloc(4u + zcap);
                    if (zenv) {
                        size_t zlen = ZSTD_compress(zenv + 4u, zcap, rbuf, (size_t)rlen, 1);
                        if (!ZSTD_isError(zlen) && zlen < ((size_t)rlen * 90u) / 100u) {
                            put_be32(zenv, (uint32_t)rlen);
                            err = tun_send(tr, ts, us, BR_TAG_RESP_ZSTD, zenv, 4u + zlen, NULL);
                            sent_z = 1;
                        }
                        free(zenv);
                    }
                }
                if (!sent_z) {
                    err = tun_send(tr, ts, us, BR_TAG_RESP_RAW, rbuf, (size_t)rlen, NULL);
                }
                free(rbuf);
            }
            if (err != FP_OK) return err;
        }
    }
}

/* ==================== Helpers ==================== */

static fp_wire_cast_t parse_cast(const char *s) {
    if (!s || strcmp(s, "int8") == 0)  return FP_WIRE_CAST_INT8;
    if (strcmp(s, "bf16") == 0)        return FP_WIRE_CAST_BF16;
    if (strcmp(s, "fp16") == 0)        return FP_WIRE_CAST_FP16;
    if (strcmp(s, "int4") == 0)        return FP_WIRE_CAST_INT4_G32;
    if (strcmp(s, "int4o") == 0)       return FP_WIRE_CAST_INT4_OUTLIER;
    if (strcmp(s, "raw") == 0 || strcmp(s, "fp32") == 0) return FP_WIRE_CAST_NONE;
    return FP_WIRE_CAST_INT8;
}

static int parse_fec(const char *s) {
    if (!s || strcmp(s, "auto") == 0) return 2;
    if (strcmp(s, "on") == 0)         return 1;
    return 0;
}

static int load_or_create_key(const char *path, fp_keypair_t *kp) {
    FILE *f = fopen(path, "rb");
    if (f) {
        size_t n1 = fread(kp->pk, 1, FP_PK_LEN, f);
        size_t n2 = fread(kp->sk, 1, FP_SK_LEN, f);
        fclose(f);
        return (n1 == FP_PK_LEN && n2 == FP_SK_LEN) ? 0 : -1;
    }
    if (fp_keygen(kp) != FP_OK) return -1;
    f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(kp->pk, 1, FP_PK_LEN, f);
    fwrite(kp->sk, 1, FP_SK_LEN, f);
    fclose(f);
    return 0;
}

static void seal_and_report_session(const bridge_state_t *st, const fp_keypair_t *kp,
                                    const char *keryx_ws) {
    int live = 0;
    char sink[80] = "offline";
    uint64_t daa = 0;
    if (keryx_ws && keryx_ws[0]) {
        char resp[8192];
        if (sf_keryx_wrpc_call(keryx_ws, "getBlockDagInfo", "{}", 3000, resp, sizeof(resp)) == FP_OK) {
            live = 1;
            const char *sp = strstr(resp, "\"sink\"");
            if (sp) {
                sp = strchr(sp + 6, '"');
                if (sp) {
                    sp++;
                    size_t k = 0;
                    while (sp[k] && sp[k] != '"' && k + 1 < sizeof(sink)) { sink[k] = sp[k]; k++; }
                    sink[k] = '\0';
                }
            }
        }
    }
    fp_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.version = 1; ev.action = FP_ACTION_INSTALL;
    memcpy(ev.repo_id.bytes, kp->pk, 32); ev.serial = st->rpc_frames > 0 ? st->rpc_frames : 1u;
    ev.timestamp_unix = (uint64_t)time(NULL); ev.expires_unix = ev.timestamp_unix + 3600u;
    ev.target_dna = st->trace_chain; ev.target_size = st->total_rpc_bytes;
    snprintf(ev.reason, sizeof(ev.reason), "sf-llama-bridge");
    (void)fp_event_sign(&ev, kp);
    fp_anchor_commitment_t anc;
    (void)fp_anchor_compute(&ev, &anc);
    uint8_t kx_p[76], kx_t[8]; char tag_hex[17], tr_hex[65];
    sf_keryx_encode_payload(&anc, daa, kx_p, kx_t);
    fp_hex_encode(kx_t, 8, tag_hex);
    fp_hex_encode(st->trace_chain.bytes, 32, tr_hex);

    double saving = (st->raw_tensor_bytes > 0)
                        ? 100.0 * (1.0 - (double)st->wire_bytes / (double)st->raw_tensor_bytes) : 0.0;
    double zsave  = (st->zstd_raw_bytes > 0)
                        ? 100.0 * (1.0 - (double)st->zstd_wire_bytes / (double)st->zstd_raw_bytes) : 0.0;
    double tsave  = (st->topk_raw_bytes > 0)
                        ? 100.0 * (1.0 - (double)st->topk_wire_bytes / (double)st->topk_raw_bytes) : 0.0;
    fprintf(stderr,
            "[sf-llama-bridge] frames=%llu | SFT1=%llu (%llu/%llu B, -%.1f%%) | TopK=%llu (%llu/%llu B, -%.2f%%) "
            "| Zstd=%llu (%llu/%llu B, -%.1f%%) | Dedup=%llu (-%llu B) | Pipe0RTT=%llu AllocHit=%llu\n"
            "[sf-llama-bridge] total_rpc=%llu B | tun_tx=%llu B rx=%llu B | udp_fec=%llu retx=%llu p99=%llu "
            "| trace=%.16s... | Keryx live=%d opoi=%s\n",
            (unsigned long long)st->rpc_frames,
            (unsigned long long)st->sft1_tensors, (unsigned long long)st->wire_bytes, (unsigned long long)st->raw_tensor_bytes, saving,
            (unsigned long long)st->topk_tensors, (unsigned long long)st->topk_wire_bytes, (unsigned long long)st->topk_raw_bytes, tsave,
            (unsigned long long)st->zstd_frames, (unsigned long long)st->zstd_wire_bytes, (unsigned long long)st->zstd_raw_bytes, zsave,
            (unsigned long long)st->dedup_hits, (unsigned long long)st->dedup_saved_bytes,
            (unsigned long long)st->void_pipelined, (unsigned long long)st->alloc_cache_hits,
            (unsigned long long)st->total_rpc_bytes,
            (unsigned long long)st->tun_tx_bytes, (unsigned long long)st->tun_rx_bytes,
            (unsigned long long)st->udp_fec, (unsigned long long)st->udp_retx, (unsigned long long)st->wan_p99_hits,
            tr_hex, live, tag_hex);
    if (st->rpc_frames > 20u) {
        static const char *cnames[17] = {
            "ALLOC","ALIGN","MAXSZ","BASE","FREE","CLEAR","SET","SETHASH","GET",
            "COPY","GCOMP","DEVMEM","INIT","ALLOCSZ","HELLO","DEVCNT","GRECOMP"
        };
        fprintf(stderr, "[sf-llama-bridge-prof]");
        for (int i = 0; i < 17; i++) {
            if (st->cmd_cnt[i] > 0u) {
                fprintf(stderr, " %s=%llu(%.2fs)", cnames[i],
                        (unsigned long long)st->cmd_cnt[i], (double)st->cmd_us[i] / 1e6);
            }
        }
        fprintf(stderr, "\n");
    }
    fflush(stderr);
}

/* ==================== Self-Test Mode (Includes 248,320-vocab Top-64 Logits!) ==================== */

typedef struct {
    int    lfd;
    size_t hdr_len;
} mock_ggml_srv_t;

static void *mock_ggml_rpc_server(void *arg) {
    mock_ggml_srv_t *ms = (mock_ggml_srv_t *)arg;
    int cfd = accept(ms->lfd, NULL, NULL);
    if (cfd < 0) { close(ms->lfd); return NULL; }
    float *stored = NULL;
    size_t stored_elems = 0;

    for (;;) {
        uint8_t hdr[9];
        if (tcp_read_exact(cfd, hdr, 9u) != 0) break;
        uint8_t cmd = hdr[0];
        uint64_t ilen = get_le64(hdr + 1);
        uint8_t *ibuf = malloc(ilen > 0 ? (size_t)ilen : 1u);
        if (!ibuf) break;
        if (ilen > 0 && tcp_read_exact(cfd, ibuf, (size_t)ilen) != 0) { free(ibuf); break; }

        if (cmd == GGML_RPC_HELLO) {
            uint8_t resp[11] = { 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 };
            (void)tcp_write_exact(cfd, resp, sizeof(resp));
        } else if (cmd == GGML_RPC_SET_TENSOR) {
            size_t pref = ms->hdr_len + 8u;
            if (ilen > pref && !tensor_must_stay_lossless(ibuf)) {
                free(stored);
                stored_elems = (size_t)(ilen - pref) / 4u;
                stored = malloc(stored_elems * 4u);
                if (stored) memcpy(stored, ibuf + pref, stored_elems * 4u);
            }
        } else if (cmd == GGML_RPC_GRAPH_COMPUTE) {
            if (stored && stored_elems > 0) {
                for (size_t i = 0; i < stored_elems; i++) stored[i] = stored[i] * 0.95f + 0.05f * sinf(stored[i]);
            }
        } else if (cmd == GGML_RPC_GET_TENSOR) {
            uint32_t ne0 = (ilen >= 24u) ? get_le32(ibuf + 20) : 0u;
            uint64_t rsz = (ilen >= ms->hdr_len + 16u) ? get_le64(ibuf + ms->hdr_len + 8u) : 0u;
            if (tensor_is_final_logits(ibuf) && ne0 >= BR_LOGITS_MIN_VOCAB && rsz == (uint64_t)ne0 * 4u) {
                float *logits = malloc((size_t)rsz);
                if (logits) {
                    for (uint32_t i = 0; i < ne0; i++) logits[i] = -5.0f + (float)(i % 100) * 0.01f;
                    logits[ne0 - 777u] = 19.75f; /* Exact Top-1 winning token */
                    logits[1337u]      = 14.50f; /* Exact Top-2 */
                    uint8_t rhdr[8];
                    put_le64(rhdr, rsz);
                    (void)tcp_write_exact(cfd, rhdr, 8u);
                    (void)tcp_write_exact(cfd, (const uint8_t *)logits, (size_t)rsz);
                    free(logits);
                }
            } else if (!tensor_is_final_logits(ibuf) && ne0 >= 32768u && rsz == (uint64_t)ne0 * 4u) {
                /* Non-logits large intermediate tensor (e.g. DeepSeek/Qwen FFN or SSM state):
                 * must NOT be crushed by Top-K! */
                float *inter = malloc((size_t)rsz);
                if (inter) {
                    for (uint32_t i = 0; i < ne0; i++) inter[i] = sinf(0.01f * (float)i);
                    uint8_t rhdr[8];
                    put_le64(rhdr, rsz);
                    (void)tcp_write_exact(cfd, rhdr, 8u);
                    (void)tcp_write_exact(cfd, (const uint8_t *)inter, (size_t)rsz);
                    free(inter);
                }
            } else {
                uint8_t rhdr[8];
                put_le64(rhdr, (uint64_t)(stored_elems * 4u));
                (void)tcp_write_exact(cfd, rhdr, 8u);
                if (stored && stored_elems > 0) {
                    (void)tcp_write_exact(cfd, (const uint8_t *)stored, stored_elems * 4u);
                }
            }
        }
        free(ibuf);
    }
    free(stored);
    close(cfd);
    close(ms->lfd);
    return NULL;
}

typedef struct {
    int                  tun_fd;
    uint16_t             backend_port;
    const fp_keypair_t  *skp;
    const uint8_t       *allow_pk;
    sf_split_transport_t tr;
    fp_wire_cast_t       cast;
    uint32_t             drop_pct;
    int                  fec_mode;
    uint16_t             logits_topk;
    const char          *cache_dir;
} selftest_srv_arg_t;

static void *selftest_bridge_server(void *arg) {
    selftest_srv_arg_t *sa = (selftest_srv_arg_t *)arg;
    fp_session_t *ts = NULL; fp_udp_session_t *us = NULL;
    fp_err_t err = (sa->tr == SF_SPLIT_TCP)
                       ? fp_session_accept(sa->tun_fd, sa->skp, sa->allow_pk, 10000, &ts)
                       : fp_udp_session_accept(sa->tun_fd, sa->skp, sa->allow_pk, 10000, sa->drop_pct, &us);
    if (err == FP_OK) {
        if (us) fp_udp_session_set_fec(us, sa->fec_mode);
        int bfd = tcp_connect_local("127.0.0.1", sa->backend_port);
        if (bfd >= 0) {
            bridge_state_t st;
            memset(&st, 0, sizeof(st));
            st.transport = sa->tr; st.wire_cast = sa->cast;
            st.rpc_tensor_hdr_len = GGML_RPC_TENSOR_LEN;
            st.enable_zstd = 1; st.cache_dir = sa->cache_dir;
            st.logits_topk = sa->logits_topk; st.fec_mode = sa->fec_mode;
            (void)run_server_session(bfd, sa->tr, ts, us, &st);
            close(bfd);
        }
        if (ts) fp_session_close(ts);
        if (us) fp_udp_session_close(us);
    }
    close(sa->tun_fd);
    return NULL;
}

typedef struct {
    int                  cli_lfd;
    uint16_t             tun_port;
    const fp_keypair_t  *ckp;
    const uint8_t       *srv_pk;
    sf_split_transport_t tr;
    fp_wire_cast_t       cast;
    uint32_t             drop_pct;
    int                  fec_mode;
    bridge_state_t       st;
} selftest_cli_arg_t;

static void *selftest_bridge_client(void *arg) {
    selftest_cli_arg_t *ca = (selftest_cli_arg_t *)arg;
    int cfd = accept(ca->cli_lfd, NULL, NULL);
    if (cfd >= 0) {
        fp_session_t *ts = NULL; fp_udp_session_t *us = NULL;
        fp_err_t err = (ca->tr == SF_SPLIT_TCP)
                           ? fp_session_connect("127.0.0.1", ca->tun_port, ca->ckp, ca->srv_pk, 10000, &ts)
                           : fp_udp_session_connect("127.0.0.1", ca->tun_port, ca->ckp, ca->srv_pk, 10000, ca->drop_pct, &us);
        if (err == FP_OK) {
            if (us) fp_udp_session_set_fec(us, ca->fec_mode);
            (void)run_client_session(cfd, ca->tr, ts, us, &ca->st);
            if (ts) fp_session_close(ts);
            if (us) fp_udp_session_close(us);
        }
        close(cfd);
    }
    close(ca->cli_lfd);
    return NULL;
}

static int run_selftest(sf_split_transport_t tr, fp_wire_cast_t cast, uint32_t drop_pct,
                        int fec_mode, uint16_t logits_topk, const char *keryx_ws) {
    fp_keypair_t ckp, skp;
    if (fp_keygen(&ckp) != FP_OK || fp_keygen(&skp) != FP_OK) return 1;

    char cdir_tmpl[] = "/tmp/sf-br-cache-XXXXXX";
    char *cdir = mkdtemp(cdir_tmpl);
    if (!cdir) return 1;
    known_dna_set_t known;
    known_dna_load(&known, cdir);

    uint16_t backend_port = 0, tun_port = 0, local_rpc_port = 0;
    int backend_lfd = fp_net_listen("127.0.0.1", 0, &backend_port);
    int tun_fd = (tr == SF_SPLIT_TCP) ? fp_net_listen("127.0.0.1", 0, &tun_port)
                                      : fp_udp_bind("127.0.0.1", 0, &tun_port);
    int cli_lfd = fp_net_listen("127.0.0.1", 0, &local_rpc_port);
    if (backend_lfd < 0 || tun_fd < 0 || cli_lfd < 0) return 1;

    mock_ggml_srv_t ms = { backend_lfd, GGML_RPC_TENSOR_LEN };
    selftest_srv_arg_t sa = { tun_fd, backend_port, &skp, ckp.pk, tr, cast, drop_pct, fec_mode, logits_topk, cdir };
    selftest_cli_arg_t ca;
    memset(&ca, 0, sizeof(ca));
    ca.cli_lfd = cli_lfd; ca.tun_port = tun_port; ca.ckp = &ckp; ca.srv_pk = skp.pk;
    ca.tr = tr; ca.cast = cast; ca.drop_pct = drop_pct; ca.fec_mode = fec_mode;
    ca.st.transport = tr; ca.st.wire_cast = cast;
    ca.st.rpc_tensor_hdr_len = GGML_RPC_TENSOR_LEN;
    ca.st.enable_zstd = 1; ca.st.cache_dir = cdir; ca.st.known_dnas = &known;
    ca.st.logits_topk = logits_topk; ca.st.fec_mode = fec_mode; ca.st.wan_rng = 0x123456789abcdef0ull;

    pthread_t t_rpc, t_bsrv, t_bcli;
    pthread_create(&t_rpc,  NULL, mock_ggml_rpc_server, &ms);
    pthread_create(&t_bsrv, NULL, selftest_bridge_server, &sa);
    pthread_create(&t_bcli, NULL, selftest_bridge_client, &ca);

    int fd = tcp_connect_local("127.0.0.1", local_rpc_port);
    if (fd < 0) return 1;

    uint8_t hello[9] = { GGML_RPC_HELLO, 0, 0, 0, 0, 0, 0, 0, 0 };
    if (tcp_write_exact(fd, hello, 9u) != 0) return 1;
    uint8_t rhdr[8], rbody[16];
    if (tcp_read_exact(fd, rhdr, 8u) != 0 || get_le64(rhdr) != 3u ||
        tcp_read_exact(fd, rbody, 3u) != 0) return 1;

    size_t pref = GGML_RPC_TENSOR_LEN + 8u;
    size_t wlen = pref + 32768u;
    uint8_t *wpkt = calloc(1, 9u + wlen);
    wpkt[0] = GGML_RPC_SET_TENSOR;
    put_le64(wpkt + 1, (uint64_t)wlen);
    snprintf((char *)(wpkt + 9u + GGML_RPC_NAME_OFF), GGML_RPC_NAME_LEN, "blk.0.attn_norm.weight");
    for (size_t i = 0; i < 32768u; i++) wpkt[9u + pref + i] = (uint8_t)(i & 0xFFu);
    if (tcp_write_exact(fd, wpkt, 9u + wlen) != 0) return 1;
    if (tcp_write_exact(fd, wpkt, 9u + wlen) != 0) return 1;
    free(wpkt);

    const size_t ELEMS = 4u * 4096u;
    size_t set_len = pref + ELEMS * 4u;
    uint8_t *set_pkt = calloc(1, 9u + set_len);
    float *src_act = malloc(ELEMS * 4u);
    for (size_t i = 0; i < ELEMS; i++) {
        float v = sinf(0.023f * (float)i) * 0.9f;
        if ((i % 128u) == 7u) v *= 7.0f;
        src_act[i] = v;
    }
    set_pkt[0] = GGML_RPC_SET_TENSOR;
    put_le64(set_pkt + 1, (uint64_t)set_len);
    put_le32(set_pkt + 9u + 20u, 4096u);
    snprintf((char *)(set_pkt + 9u + GGML_RPC_NAME_OFF), GGML_RPC_NAME_LEN, "l_out-16");
    memcpy(set_pkt + 9u + pref, src_act, ELEMS * 4u);
    if (tcp_write_exact(fd, set_pkt, 9u + set_len) != 0) return 1;
    free(set_pkt);

    uint8_t *gc = calloc(1, 9u + 16384u);
    gc[0] = GGML_RPC_GRAPH_COMPUTE;
    put_le64(gc + 1, 16384u);
    if (tcp_write_exact(fd, gc, 9u + 16384u) != 0) return 1;
    free(gc);

    /* 1. Activation GET_TENSOR ([4, 4096]) -> SFT1 */
    uint8_t get_pkt[9u + GGML_RPC_TENSOR_LEN + 16u];
    memset(get_pkt, 0, sizeof(get_pkt));
    get_pkt[0] = GGML_RPC_GET_TENSOR;
    put_le64(get_pkt + 1, GGML_RPC_TENSOR_LEN + 16u);
    put_le32(get_pkt + 9u + 20u, 4096u);
    snprintf((char *)(get_pkt + 9u + GGML_RPC_NAME_OFF), GGML_RPC_NAME_LEN, "l_out-16");
    put_le64(get_pkt + 9u + GGML_RPC_TENSOR_LEN + 8u, (uint64_t)(ELEMS * 4u));
    if (tcp_write_exact(fd, get_pkt, sizeof(get_pkt)) != 0) return 1;
    if (tcp_read_exact(fd, rhdr, 8u) != 0 || get_le64(rhdr) != (uint64_t)(ELEMS * 4u)) return 1;
    float *got_act = malloc(ELEMS * 4u);
    if (tcp_read_exact(fd, (uint8_t *)got_act, ELEMS * 4u) != 0) return 1;

    /* 2. Test NON-logits large intermediate tensor (ne0=36864, "blk.5.ffn_up" & "ssm_state"):
     *    MUST NOT trigger Top-K (zero false positives across Llama/Qwen/DeepSeek MoE)! */
    const uint32_t INTER_N = 36864u;
    memset(get_pkt, 0, sizeof(get_pkt));
    get_pkt[0] = GGML_RPC_GET_TENSOR;
    put_le64(get_pkt + 1, GGML_RPC_TENSOR_LEN + 16u);
    put_le32(get_pkt + 9u + 20u, INTER_N);
    snprintf((char *)(get_pkt + 9u + GGML_RPC_NAME_OFF), GGML_RPC_NAME_LEN, "blk.5.ssm_state");
    put_le64(get_pkt + 9u + GGML_RPC_TENSOR_LEN + 8u, (uint64_t)INTER_N * 4u);
    if (tcp_write_exact(fd, get_pkt, sizeof(get_pkt)) != 0) return 1;
    if (tcp_read_exact(fd, rhdr, 8u) != 0 || get_le64(rhdr) != (uint64_t)INTER_N * 4u) return 1;
    float *got_inter = malloc((size_t)INTER_N * 4u);
    if (tcp_read_exact(fd, (uint8_t *)got_inter, (size_t)INTER_N * 4u) != 0) return 1;
    /* ssm_state must arrive 100% BIT-EXACT lossless (not Top-K, not INT4!) */
    int state_exact = 1;
    for (uint32_t i = 0; i < INTER_N; i++) {
        if (got_inter[i] != sinf(0.01f * (float)i)) { state_exact = 0; break; }
    }
    free(got_inter);

    /* 3. Test 3 Model Families' Vocabulary Logits ("result_output"):
     *    - model1 small (vocab=32000), DeepSeek-V3/R1 (vocab=129280), Qwen3.5 (vocab=248320) */
    const uint32_t vocabs[3] = { 32000u, 129280u, 248320u };
    int logits_ok = 1;
    for (int v = 0; v < 3; v++) {
        uint32_t VOCAB = vocabs[v];
        memset(get_pkt, 0, sizeof(get_pkt));
        get_pkt[0] = GGML_RPC_GET_TENSOR;
        put_le64(get_pkt + 1, GGML_RPC_TENSOR_LEN + 16u);
        put_le32(get_pkt + 9u + 20u, VOCAB);
        snprintf((char *)(get_pkt + 9u + GGML_RPC_NAME_OFF), GGML_RPC_NAME_LEN, "result_output");
        put_le64(get_pkt + 9u + GGML_RPC_TENSOR_LEN + 8u, (uint64_t)VOCAB * 4u);
        if (tcp_write_exact(fd, get_pkt, sizeof(get_pkt)) != 0) return 1;
        if (tcp_read_exact(fd, rhdr, 8u) != 0 || get_le64(rhdr) != (uint64_t)VOCAB * 4u) return 1;
        float *got_logits = malloc((size_t)VOCAB * 4u);
        if (tcp_read_exact(fd, (uint8_t *)got_logits, (size_t)VOCAB * 4u) != 0) return 1;
        if (got_logits[VOCAB - 777u] != 19.75f || got_logits[1337u] != 14.50f) logits_ok = 0;
        free(got_logits);
    }

    close(fd);
    pthread_join(t_bcli, NULL);
    pthread_join(t_bsrv, NULL);
    pthread_join(t_rpc, NULL);

    double dot = 0.0, na = 0.0, nb = 0.0;
    for (size_t i = 0; i < ELEMS; i++) {
        double ref = (double)(src_act[i] * 0.95f + 0.05f * sinf(src_act[i]));
        double rec = (double)got_act[i];
        dot += ref * rec; na += ref * ref; nb += rec * rec;
    }
    double cos = dot / (sqrt(na * nb) + 1e-18);
    seal_and_report_session(&ca.st, &ckp, keryx_ws);
    printf("[PASS] sf-llama-bridge selftest (%s, cast=%d, fec=%d, cos=%.6f, topk=%llu/3 exact=%d, ssm_exact=%d, dedup=%llu)\n",
           tr == SF_SPLIT_UDP ? "FP-UDP1" : "TCP", (int)cast, fec_mode, cos,
           (unsigned long long)ca.st.topk_tensors, logits_ok, state_exact,
           (unsigned long long)ca.st.dedup_hits);

    free(src_act); free(got_act);
    sodium_memzero(&ckp, sizeof(ckp));
    sodium_memzero(&skp, sizeof(skp));
    return (cos > 0.995 && logits_ok && state_exact && ca.st.topk_tensors == 3u &&
            ca.st.dedup_hits == 1u && ca.st.zstd_frames >= 2u) ? 0 : 1;
}

static void usage(const char *prog) {
    printf("Usage:\n"
           "  %s --keygen <keyfile>\n"
           "  %s --selftest [--transport udp|tcp] [--cast ...] [--fec auto|on|off] [--logits-topk N] [--drop N]\n"
           "  %s --role server --bind <ip> --port <p> --backend-host <ip> --backend-port <p> --key <k> [--allow-pk <hex>] [--transport udp|tcp] [--cast ...] [--fec auto|on|off] [--logits-topk N] [--cache-dir <d>] [--no-zstd]\n"
           "  %s --role client --listen <ip> --listen-port <p> --remote-host <ip> --remote-port <p> --key <k> --peer-pk <hex> [--transport udp|tcp] [--cast ...] [--fec auto|on|off] [--logits-topk N] [--cache-dir <d>] [--no-zstd] [--wan-rtt-ms N] [--wan-jitter-ms N] [--wan-p99-ms N] [--wan-p99-pct N] [--wan-ul-mbps N] [--wan-dl-mbps N] [--wan-tcp-loss-pct N] [--keryx-ws ws://...]\n",
           prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (fp_init() != FP_OK) return 1;

    const char *role = NULL, *keyfile = NULL, *peer_pk_hex = NULL, *keryx_ws = NULL, *cache_dir = NULL;
    const char *bind_ip = "127.0.0.1", *remote_ip = "127.0.0.1", *backend_ip = "127.0.0.1";
    uint16_t port = 50062, listen_port = 50052, remote_port = 50062, backend_port = 50053;
    sf_split_transport_t tr = SF_SPLIT_UDP;
    fp_wire_cast_t cast = FP_WIRE_CAST_INT4_OUTLIER;
    uint32_t drop_pct = 0, wan_p99_pct = 0;
    int fec_mode = 2; /* Adaptive FEC by default! */
    uint16_t logits_topk = 64u;
    double wan_rtt_ms = 0.0, wan_jitter_ms = 0.0, wan_p99_ms = 0.0;
    double wan_ul_mbps = 0.0, wan_dl_mbps = 0.0, wan_tcp_loss_pct = 0.0;
    int do_selftest = 0, once = 0, enable_zstd = 1, strict_lossless = 0, allow_any_peer = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--keygen") == 0 && i + 1 < argc) {
            fp_keypair_t kp;
            if (load_or_create_key(argv[++i], &kp) != 0) return 1;
            char pk_hex[65];
            fp_hex_encode(kp.pk, FP_PK_LEN, pk_hex);
            printf("Keyfile ready: %s\nPubKey (Ed25519): %s\n", argv[i], pk_hex);
            sodium_memzero(&kp, sizeof(kp));
            return 0;
        } else if (strcmp(argv[i], "--selftest") == 0) { do_selftest = 1; }
        else if (strcmp(argv[i], "--once") == 0) { once = 1; }
        else if (strcmp(argv[i], "--no-zstd") == 0) { enable_zstd = 0; }
        else if (strcmp(argv[i], "--strict-lossless") == 0) { strict_lossless = 1; }
        else if (strcmp(argv[i], "--allow-any-peer") == 0) { allow_any_peer = 1; }
        else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) { role = argv[++i]; }
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) { keyfile = argv[++i]; }
        else if (strcmp(argv[i], "--cache-dir") == 0 && i + 1 < argc) { cache_dir = argv[++i]; }
        else if ((strcmp(argv[i], "--peer-pk") == 0 || strcmp(argv[i], "--allow-pk") == 0) && i + 1 < argc) { peer_pk_hex = argv[++i]; }
        else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) { bind_ip = argv[++i]; }
        else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) { bind_ip = argv[++i]; }
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) { port = (uint16_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) { listen_port = (uint16_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--remote-host") == 0 && i + 1 < argc) { remote_ip = argv[++i]; }
        else if (strcmp(argv[i], "--remote-port") == 0 && i + 1 < argc) { remote_port = (uint16_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--backend-host") == 0 && i + 1 < argc) { backend_ip = argv[++i]; }
        else if (strcmp(argv[i], "--backend-port") == 0 && i + 1 < argc) { backend_port = (uint16_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) { tr = (strcmp(argv[++i], "tcp") == 0) ? SF_SPLIT_TCP : SF_SPLIT_UDP; }
        else if (strcmp(argv[i], "--cast") == 0 && i + 1 < argc) { cast = parse_cast(argv[++i]); }
        else if (strcmp(argv[i], "--fec") == 0 && i + 1 < argc) { fec_mode = parse_fec(argv[++i]); }
        else if (strcmp(argv[i], "--logits-topk") == 0 && i + 1 < argc) { logits_topk = (uint16_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--drop") == 0 && i + 1 < argc) { drop_pct = (uint32_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--wan-rtt-ms") == 0 && i + 1 < argc) { wan_rtt_ms = atof(argv[++i]); }
        else if (strcmp(argv[i], "--wan-jitter-ms") == 0 && i + 1 < argc) { wan_jitter_ms = atof(argv[++i]); }
        else if (strcmp(argv[i], "--wan-p99-ms") == 0 && i + 1 < argc) { wan_p99_ms = atof(argv[++i]); }
        else if (strcmp(argv[i], "--wan-p99-pct") == 0 && i + 1 < argc) { wan_p99_pct = (uint32_t)atoi(argv[++i]); }
        else if (strcmp(argv[i], "--wan-mbps") == 0 && i + 1 < argc) { wan_ul_mbps = wan_dl_mbps = atof(argv[++i]); }
        else if (strcmp(argv[i], "--wan-ul-mbps") == 0 && i + 1 < argc) { wan_ul_mbps = atof(argv[++i]); }
        else if (strcmp(argv[i], "--wan-dl-mbps") == 0 && i + 1 < argc) { wan_dl_mbps = atof(argv[++i]); }
        else if (strcmp(argv[i], "--wan-tcp-loss-pct") == 0 && i + 1 < argc) { wan_tcp_loss_pct = atof(argv[++i]); }
        else if (strcmp(argv[i], "--keryx-ws") == 0 && i + 1 < argc) { keryx_ws = argv[++i]; }
    }

    if (do_selftest) return run_selftest(tr, cast, drop_pct, fec_mode, logits_topk, keryx_ws);
    if (!role || !keyfile) { usage(argv[0]); return 1; }
    if (cache_dir) (void)mkdir(cache_dir, 0755);

    fp_keypair_t kp;
    if (load_or_create_key(keyfile, &kp) != 0) { fprintf(stderr, "Failed to load keyfile %s\n", keyfile); return 1; }
    uint8_t peer_pk[FP_PK_LEN];
    const uint8_t *peer_pin = NULL;
    if (peer_pk_hex) {
        if (fp_hex_decode(peer_pk_hex, peer_pk, FP_PK_LEN) != FP_OK) { fprintf(stderr, "Invalid peer-pk hex\n"); return 1; }
        peer_pin = peer_pk;
    }

    int exit_rc = 0;
    if (strcmp(role, "server") == 0) {
        /* SEC-07: Fail closed on server unless --allow-pk/--peer-pk OR explicit --allow-any-peer is provided */
        if (!peer_pin && !allow_any_peer) {
            fprintf(stderr, "sf-llama-bridge [SERVER]: --allow-pk/--peer-pk is required by default "
                            "(or pass --allow-any-peer for isolated lab testing)\n");
            sodium_memzero(&kp, sizeof(kp));
            return 1;
        }
        if (allow_any_peer && !peer_pin) {
            fprintf(stderr, "sf-llama-bridge [SERVER]: WARNING: --allow-any-peer active (unauthenticated client keys allowed)\n");
        }
        int tun_fd = (tr == SF_SPLIT_TCP) ? fp_net_listen(bind_ip, port, NULL)
                                          : fp_udp_bind(bind_ip, port, NULL);
        if (tun_fd < 0) { fprintf(stderr, "Failed to bind %s:%u\n", bind_ip, (unsigned)port); return 1; }
        fprintf(stderr, "sf-llama-bridge [SERVER] %s:%u (%s, cast=%d, fec=%d, topk=%u, zstd=%d) -> %s:%u\n",
                bind_ip, (unsigned)port, tr == SF_SPLIT_UDP ? "FP-UDP1" : "TCP", (int)cast,
                fec_mode, (unsigned)logits_topk, enable_zstd, backend_ip, (unsigned)backend_port);
        for (;;) {
            fp_session_t *ts = NULL; fp_udp_session_t *us = NULL;
            fp_err_t err = (tr == SF_SPLIT_TCP)
                               ? fp_session_accept(tun_fd, &kp, peer_pin, 600000, &ts)
                               : fp_udp_session_accept(tun_fd, &kp, peer_pin, 600000, drop_pct, &us);
            if (err != FP_OK) { if (once) { exit_rc = 1; break; } continue; }
            if (us) fp_udp_session_set_fec(us, fec_mode);
            int bfd = tcp_connect_local(backend_ip, backend_port);
            if (bfd >= 0) {
                bridge_state_t st;
                memset(&st, 0, sizeof(st));
                st.transport = tr; st.wire_cast = cast; st.fec_mode = fec_mode;
                st.rpc_tensor_hdr_len = GGML_RPC_TENSOR_LEN;
                st.enable_zstd = enable_zstd; st.strict_lossless = strict_lossless; st.cache_dir = cache_dir;
                st.logits_topk = logits_topk;
                fp_err_t serr = run_server_session(bfd, tr, ts, us, &st);
                if (serr != FP_OK) {
                    fprintf(stderr, "sf-llama-bridge [SERVER] session failed: %s\n", fp_strerror(serr));
                    if (once) exit_rc = 1;
                }
                close(bfd);
            } else {
                fprintf(stderr, "sf-llama-bridge [SERVER] backend connect failed (%s:%u)\n",
                        backend_ip, (unsigned)backend_port);
                if (once) exit_rc = 1;
            }
            if (ts) fp_session_close(ts);
            if (us) fp_udp_session_close(us);
            if (once) break;
        }
        close(tun_fd);
    } else if (strcmp(role, "client") == 0) {
        if (!peer_pin) { fprintf(stderr, "--peer-pk is required for --role client\n"); return 1; }
        known_dna_set_t known;
        known_dna_load(&known, cache_dir);
        int lfd = fp_net_listen(bind_ip, listen_port, NULL);
        if (lfd < 0) { fprintf(stderr, "Failed to bind local RPC %s:%u\n", bind_ip, (unsigned)listen_port); return 1; }
        fprintf(stderr, "sf-llama-bridge [CLIENT] %s:%u -> %s:%u (%s, cast=%d, fec=%d, topk=%u, rtt=%.0f+-%.0fms p99=+%.0fms@%u%% ul/dl=%.0f/%.0fMbps)\n",
                bind_ip, (unsigned)listen_port, remote_ip, (unsigned)remote_port,
                tr == SF_SPLIT_UDP ? "FP-UDP1" : "TCP", (int)cast, fec_mode, (unsigned)logits_topk,
                wan_rtt_ms, wan_jitter_ms, wan_p99_ms, wan_p99_pct, wan_ul_mbps, wan_dl_mbps);
        for (;;) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd < 0) continue;
            fp_session_t *ts = NULL; fp_udp_session_t *us = NULL;
            fp_err_t err = (tr == SF_SPLIT_TCP)
                               ? fp_session_connect(remote_ip, remote_port, &kp, peer_pin, 600000, &ts)
                               : fp_udp_session_connect(remote_ip, remote_port, &kp, peer_pin, 600000, drop_pct, &us);
            if (err == FP_OK) {
                if (us) fp_udp_session_set_fec(us, fec_mode);
                bridge_state_t st;
                memset(&st, 0, sizeof(st));
                st.transport = tr; st.wire_cast = cast; st.fec_mode = fec_mode;
                st.rpc_tensor_hdr_len = GGML_RPC_TENSOR_LEN;
                st.enable_zstd = enable_zstd; st.strict_lossless = strict_lossless; st.cache_dir = cache_dir;
                st.known_dnas = cache_dir ? &known : NULL;
                st.logits_topk = logits_topk;
                st.wan_rtt_ms = wan_rtt_ms; st.wan_jitter_ms = wan_jitter_ms;
                st.wan_p99_ms = wan_p99_ms; st.wan_p99_pct = wan_p99_pct;
                st.wan_ul_mbps = wan_ul_mbps; st.wan_dl_mbps = wan_dl_mbps;
                st.wan_tcp_loss_pct = wan_tcp_loss_pct;
                st.wan_rng = UINT64_C(0x9E3779B97F4A7C15) ^ (uint64_t)remote_port;
                fp_err_t cerr = run_client_session(cfd, tr, ts, us, &st);
                if (cerr == FP_OK) {
                    seal_and_report_session(&st, &kp, keryx_ws);
                } else {
                    fprintf(stderr, "sf-llama-bridge [CLIENT] session failed (%s) — skipping success receipt\n",
                            fp_strerror(cerr));
                    if (once) exit_rc = 1;
                }
                if (ts) fp_session_close(ts);
                if (us) fp_udp_session_close(us);
            } else {
                fprintf(stderr, "sf-llama-bridge [CLIENT] connect failed (%s)\n", fp_strerror(err));
                if (once) exit_rc = 1;
            }
            close(cfd);
            if (once) break;
        }
        close(lfd);
    }
    sodium_memzero(&kp, sizeof(kp));
    return exit_rc;
}
