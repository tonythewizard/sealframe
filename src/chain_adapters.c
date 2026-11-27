/*
 * SealFrame Blockchain Anchor Adapters (Generic JSON-RPC 2.0, EVM, Solana, Keryx BlockDAG/OPoI)
 * 100% Pure ISO C11 — Zero Python, Zero C++, Zero OpenSSL, Zero libcurl.
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe_chain.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ==================== 1. Pure-C11 Ethereum Keccak-256 ==================== */

static uint64_t rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64u - n));
}

static void keccak_f1600(uint64_t st[25]) {
    static const uint64_t RC[24] = {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
        UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };
    static const unsigned RHO[24] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };
    static const unsigned PIL[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    for (int round = 0; round < 24; round++) {
        uint64_t bc[5];
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1u);
            for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
        }
        uint64_t t = st[1];
        for (int i = 0; i < 24; i++) {
            unsigned j = PIL[i];
            uint64_t tmp = st[j];
            st[j] = rotl64(t, RHO[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j + i];
            for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        st[0] ^= RC[round];
    }
}

void sf_keccak256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    const size_t rate = 136u;
    uint8_t block[136];
    size_t off = 0;

    while (len - off >= rate) {
        for (size_t i = 0; i < rate / 8u; i++) {
            uint64_t v = 0;
            for (int b = 0; b < 8; b++) v |= ((uint64_t)data[off + i * 8u + (size_t)b]) << (b * 8);
            st[i] ^= v;
        }
        keccak_f1600(st);
        off += rate;
    }
    memset(block, 0, sizeof(block));
    size_t rem = len - off;
    if (rem > 0) memcpy(block, data + off, rem);
    block[rem] ^= 0x01u; /* Ethereum Keccak-256 domain padding */
    block[rate - 1u] ^= 0x80u;
    for (size_t i = 0; i < rate / 8u; i++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v |= ((uint64_t)block[i * 8u + (size_t)b]) << (b * 8);
        st[i] ^= v;
    }
    keccak_f1600(st);

    for (size_t i = 0; i < 4u; i++) {
        for (int b = 0; b < 8; b++) out[i * 8u + (size_t)b] = (uint8_t)(st[i] >> (b * 8));
    }
}

void sf_evm_selector(const char *signature, uint8_t out[4]) {
    uint8_t h[32];
    sf_keccak256((const uint8_t *)signature, strlen(signature), h);
    memcpy(out, h, 4);
}

void sf_evm_encode_anchor(const fp_anchor_commitment_t *c, uint8_t out[100]) {
    memset(out, 0, 100);
    sf_evm_selector("anchor(bytes32,bytes32,uint64)", out);
    memcpy(out + 4,  c->commitment.bytes, 32);
    memcpy(out + 36, c->target_dna.bytes, 32);
    /* uint64 big-endian right-aligned in 32-byte ABI slot [68..100) */
    uint64_t s = c->serial;
    for (int i = 0; i < 8; i++) out[99 - i] = (uint8_t)(s >> (i * 8));
}

void sf_evm_encode_is_anchored(const fp_dna_t *commitment, uint8_t out[36]) {
    sf_evm_selector("isAnchored(bytes32)", out);
    memcpy(out + 4, commitment->bytes, 32);
}

/* ==================== 2. Solana Encoders (Anchor + Borsh + Base58/64) ==================== */

void sf_solana_encode_anchor_ix(const fp_anchor_commitment_t *c, uint8_t out[144]) {
    /* Anchor 8-byte discriminator = SHA-256("global:anchor_commitment")[0..8] */
    const char *disc_src = "global:anchor_commitment";
    uint8_t h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, (const uint8_t *)disc_src, (unsigned long long)strlen(disc_src));
    memcpy(out, h, 8);
    /* Borsh layout: repo_id[32] | serial(u64 LE) | event_hash[32] | target_dna[32] | commitment[32] */
    memcpy(out + 8, c->repo_id.bytes, 32);
    for (int i = 0; i < 8; i++) out[40 + i] = (uint8_t)(c->serial >> (i * 8));
    memcpy(out + 48,  c->event_hash.bytes, 32);
    memcpy(out + 80,  c->target_dna.bytes, 32);
    memcpy(out + 112, c->commitment.bytes, 32);
}

size_t sf_base58_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    static const char ALPH[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (!in || !out || out_cap == 0) return 0;
    size_t zeros = 0;
    while (zeros < in_len && in[zeros] == 0) zeros++;

    size_t bsize = (in_len - zeros) * 138u / 100u + 1u;
    uint8_t *buf = calloc(bsize > 0 ? bsize : 1u, 1u);
    if (!buf) return 0;
    size_t length = 0;
    for (size_t i = zeros; i < in_len; i++) {
        uint32_t carry = in[i];
        size_t j = 0;
        for (size_t k = bsize; (carry != 0 || j < length) && k > 0; k--, j++) {
            carry += 256u * (uint32_t)buf[k - 1u];
            buf[k - 1u] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
        length = j;
    }
    size_t it = bsize - length;
    while (it < bsize && buf[it] == 0) it++;
    size_t need = zeros + (bsize - it);
    if (need + 1u > out_cap) { free(buf); return 0; }
    size_t pos = 0;
    for (size_t i = 0; i < zeros; i++) out[pos++] = '1';
    while (it < bsize) out[pos++] = ALPH[buf[it++]];
    out[pos] = '\0';
    free(buf);
    return pos;
}

size_t sf_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t need = 4u * ((in_len + 2u) / 3u);
    if (!out || need + 1u > out_cap) return 0;
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3u) {
        uint32_t v = ((uint32_t)in[i]) << 16;
        if (i + 1u < in_len) v |= ((uint32_t)in[i + 1u]) << 8;
        if (i + 2u < in_len) v |= (uint32_t)in[i + 2u];
        out[o++] = T[(v >> 18) & 0x3Fu];
        out[o++] = T[(v >> 12) & 0x3Fu];
        out[o++] = (i + 1u < in_len) ? T[(v >> 6) & 0x3Fu] : '=';
        out[o++] = (i + 2u < in_len) ? T[v & 0x3Fu] : '=';
    }
    out[o] = '\0';
    return o;
}

/* ==================== 3. Keryx OPoI Phase-2 Deterministic Fixed-Point MLP ==================== */

#define KX_MODEL_SEED   UINT64_C(0x4B657279784F5000)
#define KX_OPOI_SALT    UINT64_C(0x00323A585952454B) /* u64::from_le_bytes(*b"KERYX:2\0") */
#define KX_NORM_SHIFT   10u
#define KX_N_IN         32
#define KX_N_H1         256
#define KX_N_H2         128
#define KX_N_OUT        32

static int64_t arith_shr64(int64_t x, unsigned sh) {
    if (x >= 0) return (int64_t)((uint64_t)x >> sh);
    return (int64_t)(~((~(uint64_t)x) >> sh));
}

static int32_t kx_lcg_weight(uint64_t *state, int64_t he_scale) {
    *state = (*state) * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    uint32_t u32 = (uint32_t)((*state) >> 32);
    int32_t s32 = 0;
    memcpy(&s32, &u32, 4);
    int64_t prod = (int64_t)s32 * he_scale;
    return (int32_t)arith_shr64(prod, 31u);
}

static int32_t g_kx_w1[KX_N_H1 * KX_N_IN];
static int32_t g_kx_w2[KX_N_H2 * KX_N_H1];
static int32_t g_kx_w3[KX_N_OUT * KX_N_H2];
static pthread_once_t g_kx_once = PTHREAD_ONCE_INIT;

static void kx_fill_w(int32_t *dst, size_t n, uint64_t layer_id, int64_t he) {
    uint64_t s = KX_MODEL_SEED + layer_id * UINT64_C(0xDEADBEEFCAFE1337);
    for (size_t i = 0; i < n; i++) dst[i] = kx_lcg_weight(&s, he);
}

static void kx_init_weights(void) {
    kx_fill_w(g_kx_w1, KX_N_H1 * KX_N_IN,  0, 256);
    kx_fill_w(g_kx_w2, KX_N_H2 * KX_N_H1,  1, 90);
    kx_fill_w(g_kx_w3, KX_N_OUT * KX_N_H2, 2, 128);
}

void sf_keryx_opoi_forward_nonce(uint64_t raw_nonce, uint8_t out32[32]) {
    pthread_once(&g_kx_once, kx_init_weights);

    uint8_t input[32];
    for (int i = 0; i < 8; i++) input[i] = (uint8_t)(raw_nonce >> (i * 8));
    for (int c = 8; c < 32; c += 8) {
        for (int i = 0; i < 8; i++) input[c + i] = (uint8_t)(KX_MODEL_SEED >> (i * 8));
    }

    int64_t x[KX_N_IN], h1[KX_N_H1], h2[KX_N_H2];
    for (int i = 0; i < KX_N_IN; i++) x[i] = (int64_t)input[i] - 128;

    for (int i = 0; i < KX_N_H1; i++) {
        int64_t acc = 0;
        const int32_t *row = g_kx_w1 + i * KX_N_IN;
        for (int j = 0; j < KX_N_IN; j++) acc += x[j] * (int64_t)row[j];
        int64_t v = arith_shr64(acc, KX_NORM_SHIFT);
        h1[i] = v > 0 ? v : 0;
    }
    for (int i = 0; i < KX_N_H2; i++) {
        int64_t acc = 0;
        const int32_t *row = g_kx_w2 + i * KX_N_H1;
        for (int j = 0; j < KX_N_H1; j++) acc += h1[j] * (int64_t)row[j];
        int64_t v = arith_shr64(acc, KX_NORM_SHIFT);
        h2[i] = v > 0 ? v : 0;
    }
    for (int i = 0; i < KX_N_OUT; i++) {
        int64_t acc = 0;
        const int32_t *row = g_kx_w3 + i * KX_N_H2;
        for (int j = 0; j < KX_N_H2; j++) acc += h2[j] * (int64_t)row[j];
        uint64_t u = (uint64_t)acc;
        uint8_t fold = 0;
        for (int b = 0; b < 8; b++) fold ^= (uint8_t)(u >> (b * 8));
        out32[i] = fold;
    }
}

void sf_keryx_opoi_tag(uint64_t nonce, uint8_t out8[8], char out_hex16[17]) {
    uint8_t full[32];
    sf_keryx_opoi_forward_nonce(nonce ^ KX_OPOI_SALT, full);
    memcpy(out8, full, 8);
    if (out_hex16) fp_hex_encode(full, 8, out_hex16);
}

void sf_keryx_encode_payload(const fp_anchor_commitment_t *c, uint64_t nonce,
                             uint8_t out[76], uint8_t out_tag[8]) {
    uint64_t use_nonce = nonce;
    if (use_nonce == 0) {
        for (int i = 0; i < 8; i++) use_nonce |= ((uint64_t)c->commitment.bytes[i]) << (i * 8);
    }
    uint8_t tag8[8];
    sf_keryx_opoi_tag(use_nonce, tag8, NULL);
    if (out_tag) memcpy(out_tag, tag8, 8);

    out[0] = 'S'; out[1] = 'F'; out[2] = '1'; out[3] = 0u;
    memcpy(out + 4,  c->commitment.bytes, 32);
    memcpy(out + 36, tag8, 8);
    memcpy(out + 44, c->target_dna.bytes, 32);
}

/* ==================== 4. Minimal Hardened HTTP/1.1 JSON-RPC Client ==================== */

static int parse_url_scheme(const char *url, const char *scheme, uint16_t def_port,
                            char host[256], uint16_t *port, char path[256]) {
    size_t slen = strlen(scheme);
    if (!url || strncmp(url, scheme, slen) != 0) return -1;
    const char *p = url + slen;
    for (const char *q = p; *q; q++) {
        if (*q == '\r' || *q == '\n' || (unsigned char)*q < 0x20u) return -1;
    }
    const char *slash = strchr(p, '/');
    size_t hp_len = slash ? (size_t)(slash - p) : strlen(p);
    if (hp_len == 0 || hp_len >= 256u) return -1;

    char hp[256];
    memcpy(hp, p, hp_len);
    hp[hp_len] = '\0';
    char *colon = strrchr(hp, ':');
    if (colon) {
        *colon = '\0';
        unsigned long pv = strtoul(colon + 1, NULL, 10);
        if (pv == 0 || pv > 65535ul) return -1;
        *port = (uint16_t)pv;
    } else {
        *port = def_port;
    }
    if (strlen(hp) == 0 || strlen(hp) >= 256u) return -1;
    snprintf(host, 256, "%s", hp);
    if (slash) snprintf(path, 256, "%s", slash);
    else snprintf(path, 256, "/");
    return 0;
}

static int parse_http_url(const char *url, char host[256], uint16_t *port, char path[256]) {
    return parse_url_scheme(url, "http://", 80, host, port, path);
}

static int send_exact(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int recv_exact(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = recv(fd, p + off, len - off, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* Pure-C11 RFC 6455 WebSocket wRPC-JSON call for live Keryx keryxd nodes */
fp_err_t sf_keryx_wrpc_call(const char *ws_url, const char *method, const char *params_json,
                            int timeout_ms, char *resp_buf, size_t resp_cap) {
    if (!ws_url || !method || !resp_buf || resp_cap < 16u) return FP_ERR_INVALID;
    resp_buf[0] = '\0';

    char host[256], path[256];
    uint16_t port = 0;
    if (parse_url_scheme(ws_url, "ws://", 24110, host, &port, path) != 0) return FP_ERR_INVALID;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
    if (getaddrinfo(host, port_s, &hints, &res) != 0 || !res) return FP_ERR_IO;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return FP_ERR_IO; }
    int tmo = timeout_ms > 0 ? timeout_ms : 10000;
    struct timeval tv = { tmo / 1000, (tmo % 1000) * 1000 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return FP_ERR_IO;
    }
    freeaddrinfo(res);

    /* 1. RFC 6455 HTTP/1.1 Upgrade handshake */
    uint8_t key_raw[16];
    char key_b64[32];
    randombytes_buf(key_raw, sizeof(key_raw));
    sf_base64_encode(key_raw, sizeof(key_raw), key_b64, sizeof(key_b64));

    char hreq[1024];
    int hn = snprintf(hreq, sizeof(hreq),
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s:%u\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Key: %s\r\n"
                      "Sec-WebSocket-Version: 13\r\n\r\n",
                      path, host, (unsigned)port, key_b64);
    if (hn <= 0 || send_exact(fd, hreq, (size_t)hn) != 0) { close(fd); return FP_ERR_IO; }

    /* Read HTTP 101 response header byte-by-byte so we never over-read the WS frame */
    char hresp[2048];
    size_t hgot = 0;
    while (hgot + 1u < sizeof(hresp)) {
        char ch = 0;
        ssize_t r = recv(fd, &ch, 1, 0);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return FP_ERR_IO; }
        if (r == 0) { close(fd); return FP_ERR_IO; }
        hresp[hgot++] = ch;
        hresp[hgot] = '\0';
        if (hgot >= 4u && memcmp(hresp + hgot - 4u, "\r\n\r\n", 4) == 0) break;
    }
    if (strncmp(hresp, "HTTP/1.1 101", 12) != 0) { close(fd); return FP_ERR_IO; }

    /* 2. Send masked RFC 6455 text frame with JSON-RPC payload */
    char jreq[4096];
    int jlen = snprintf(jreq, sizeof(jreq), "{\"id\":1,\"method\":\"%s\",\"params\":%s}",
                        method, (params_json && params_json[0]) ? params_json : "{}");
    if (jlen <= 0 || (size_t)jlen >= sizeof(jreq)) { close(fd); return FP_ERR_BOUNDS; }

    uint8_t fhdr[14];
    size_t fhl = 0;
    fhdr[fhl++] = 0x81u; /* FIN=1, opcode=TEXT */
    if ((size_t)jlen < 126u) {
        fhdr[fhl++] = (uint8_t)(0x80u | (size_t)jlen);
    } else {
        fhdr[fhl++] = 0x80u | 126u;
        fhdr[fhl++] = (uint8_t)((jlen >> 8) & 0xFF);
        fhdr[fhl++] = (uint8_t)(jlen & 0xFF);
    }
    uint8_t mask[4];
    randombytes_buf(mask, 4);
    memcpy(fhdr + fhl, mask, 4);
    fhl += 4;
    for (int i = 0; i < jlen; i++) jreq[i] ^= (char)mask[i & 3];
    if (send_exact(fd, fhdr, fhl) != 0 || send_exact(fd, jreq, (size_t)jlen) != 0) {
        close(fd);
        return FP_ERR_IO;
    }

    /* 3. Receive server WebSocket frame(s) until a TEXT/BINARY response arrives */
    fp_err_t rc = FP_ERR_IO;
    for (int iter = 0; iter < 8; iter++) {
        uint8_t b2[2];
        if (recv_exact(fd, b2, 2) != 0) break;
        uint8_t opcode = b2[0] & 0x0Fu;
        int masked = (b2[1] & 0x80u) != 0;
        uint64_t plen = b2[1] & 0x7Fu;
        if (plen == 126u) {
            uint8_t ext[2];
            if (recv_exact(fd, ext, 2) != 0) break;
            plen = ((uint64_t)ext[0] << 8) | (uint64_t)ext[1];
        } else if (plen == 127u) {
            uint8_t ext[8];
            if (recv_exact(fd, ext, 8) != 0) break;
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | (uint64_t)ext[i];
        }
        uint8_t rmask[4] = {0};
        if (masked && recv_exact(fd, rmask, 4) != 0) break;
        if (plen >= (uint64_t)resp_cap) { rc = FP_ERR_BOUNDS; break; }
        if (plen > 0 && recv_exact(fd, resp_buf, (size_t)plen) != 0) break;
        if (masked) {
            for (size_t i = 0; i < (size_t)plen; i++) resp_buf[i] ^= (char)rmask[i & 3];
        }
        resp_buf[plen] = '\0';

        if (opcode == 0x09u) {
            /* PING -> reply PONG */
            uint8_t pong[6] = { 0x8Au, 0x80u, 0, 0, 0, 0 };
            (void)send_exact(fd, pong, sizeof(pong));
            continue;
        }
        if (opcode == 0x01u || opcode == 0x02u) {
            rc = FP_OK;
            break;
        }
        break;
    }

    uint8_t bye[6] = { 0x88u, 0x80u, 0, 0, 0, 0 };
    (void)send_exact(fd, bye, sizeof(bye));
    close(fd);
    return rc;
}

static fp_err_t http_post_json(const char *url, const char *bearer, const char *body,
                               int timeout_ms, int *http_status, char *resp_buf, size_t resp_cap) {
    char host[256], path[256];
    uint16_t port = 0;
    if (parse_http_url(url, host, &port, path) != 0) return FP_ERR_INVALID;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
    if (getaddrinfo(host, port_s, &hints, &res) != 0 || !res) return FP_ERR_IO;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return FP_ERR_IO; }
    int tmo = timeout_ms > 0 ? timeout_ms : 10000;
    struct timeval tv = { tmo / 1000, (tmo % 1000) * 1000 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return FP_ERR_IO;
    }
    freeaddrinfo(res);

    size_t blen = strlen(body);
    char auth_hdr[320] = "";
    if (bearer && bearer[0]) {
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s\r\n", bearer);
    }
    char hdr[1024];
    int hn = snprintf(
        hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: close\r\n\r\n",
        path, host, (unsigned)port, blen, auth_hdr);
    if (hn <= 0 || (size_t)hn >= sizeof(hdr)) { close(fd); return FP_ERR_BOUNDS; }

    /* Send header + body */
    const uint8_t *parts[2] = { (const uint8_t *)hdr, (const uint8_t *)body };
    size_t plens[2] = { (size_t)hn, blen };
    for (int p = 0; p < 2; p++) {
        size_t off = 0;
        while (off < plens[p]) {
            ssize_t w = send(fd, parts[p] + off, plens[p] - off, MSG_NOSIGNAL);
            if (w < 0) { if (errno == EINTR) continue; close(fd); return FP_ERR_IO; }
            if (w == 0) { close(fd); return FP_ERR_IO; }
            off += (size_t)w;
        }
    }

    /* Read response */
    char *raw = malloc(65536u);
    if (!raw) { close(fd); return FP_ERR_NOMEM; }
    size_t got = 0;
    while (got + 1u < 65536u) {
        ssize_t r = recv(fd, raw + got, 65535u - got, 0);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    raw[got] = '\0';

    int code = 0;
    if (strncmp(raw, "HTTP/1.", 7) == 0 && got >= 12u) {
        code = atoi(raw + 9);
    }
    if (http_status) *http_status = code;
    char *sep = strstr(raw, "\r\n\r\n");
    if (!sep) { free(raw); return FP_ERR_IO; }
    const char *rbody = sep + 4;
    size_t rblen = strlen(rbody);
    if (rblen >= resp_cap) rblen = resp_cap - 1u;
    memcpy(resp_buf, rbody, rblen);
    resp_buf[rblen] = '\0';
    free(raw);
    return (code >= 200 && code < 300) ? FP_OK : FP_ERR_IO;
}

static void extract_json_str_field(const char *json, const char *key, char *out, size_t cap) {
    out[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1u < cap) out[i++] = *p++;
    out[i] = '\0';
}

/* ==================== 5. Unified fp_anchor_ops_t Implementations ==================== */

static fp_err_t chain_publish(void *user_ctx, const fp_anchor_commitment_t *c) {
    sf_chain_ctx_t *ctx = (sf_chain_ctx_t *)user_ctx;
    if (!ctx || !c || !ctx->cfg.rpc_url) return FP_ERR_INVALID;

    char h_repo[65], h_ev[65], h_tgt[65], h_comm[65];
    fp_hex_encode(c->repo_id.bytes, 32, h_repo);
    fp_hex_encode(c->event_hash.bytes, 32, h_ev);
    fp_hex_encode(c->target_dna.bytes, 32, h_tgt);
    fp_hex_encode(c->commitment.bytes, 32, h_comm);

    char req[4096], resp[8192];
    int status = 0;

    if (ctx->cfg.kind == SF_CHAIN_GENERIC) {
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sealframe_anchorPublish\",\"params\":{"
                 "\"repo_id\":\"%s\",\"serial\":%llu,\"event_hash\":\"%s\","
                 "\"target_dna\":\"%s\",\"commitment\":\"%s\"}}",
                 h_repo, (unsigned long long)c->serial, h_ev, h_tgt, h_comm);
    } else if (ctx->cfg.kind == SF_CHAIN_EVM) {
        if (!ctx->cfg.contract_addr) return FP_ERR_INVALID;
        uint8_t abi[100];
        char abi_hex[201];
        sf_evm_encode_anchor(c, abi);
        fp_hex_encode(abi, sizeof(abi), abi_hex);
        const char *from = (ctx->cfg.sender_addr && ctx->cfg.sender_addr[0])
            ? ctx->cfg.sender_addr : "0x0000000000000000000000000000000000000000";
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendTransaction\",\"params\":[{"
                 "\"from\":\"%s\",\"to\":\"%s\",\"data\":\"0x%s\"}]}",
                 from, ctx->cfg.contract_addr, abi_hex);
    } else if (ctx->cfg.kind == SF_CHAIN_SOLANA) {
        uint8_t ix[144];
        sf_solana_encode_anchor_ix(c, ix);
        /* Wire envelope: [sig(64) if signer_kp else 0 | pk(32) | ix(144)] = 240 B -> base64 */
        uint8_t tx_blob[240];
        memset(tx_blob, 0, sizeof(tx_blob));
        if (ctx->cfg.signer_kp) {
            crypto_sign_ed25519_detached(tx_blob, NULL, ix, sizeof(ix), ctx->cfg.signer_kp->sk);
            memcpy(tx_blob + 64, ctx->cfg.signer_kp->pk, 32);
        }
        memcpy(tx_blob + 96, ix, sizeof(ix));
        char b64[512];
        if (sf_base64_encode(tx_blob, sizeof(tx_blob), b64, sizeof(b64)) == 0) return FP_ERR_BOUNDS;
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendTransaction\",\"params\":[\"%s\",{\"encoding\":\"base64\"}]}",
                 b64);
    } else if (ctx->cfg.kind == SF_CHAIN_KERYX) {
        uint8_t payload[76];
        char p_hex[153], tag_hex[17];
        sf_keryx_encode_payload(c, ctx->cfg.keryx_nonce, payload, ctx->last_opoi_tag);
        fp_hex_encode(payload, sizeof(payload), p_hex);
        fp_hex_encode(ctx->last_opoi_tag, 8, tag_hex);
        const char *addr = (ctx->cfg.contract_addr && ctx->cfg.contract_addr[0])
            ? ctx->cfg.contract_addr : "keryx:anchor";
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"keryx_submitAnchor\",\"params\":{"
                 "\"address\":\"%s\",\"commitment\":\"%s\",\"opoi_tag\":\"%s\",\"payload\":\"%s\"}}",
                 addr, h_comm, tag_hex, p_hex);
    } else {
        return FP_ERR_INVALID;
    }

    fp_err_t err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                                  ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
    if (err != FP_OK) return err;
    if (strstr(resp, "\"error\"") != NULL && strstr(resp, "\"error\":null") == NULL) {
        return FP_ERR_IO;
    }
    extract_json_str_field(resp, "result", ctx->last_tx_id, sizeof(ctx->last_tx_id));
    if (!ctx->last_tx_id[0]) {
        extract_json_str_field(resp, "tx_id", ctx->last_tx_id, sizeof(ctx->last_tx_id));
    }
    return FP_OK;
}

static fp_err_t chain_verify(void *user_ctx, const fp_anchor_commitment_t *c) {
    sf_chain_ctx_t *ctx = (sf_chain_ctx_t *)user_ctx;
    if (!ctx || !c || !ctx->cfg.rpc_url) return FP_ERR_INVALID;

    char h_comm[65];
    fp_hex_encode(c->commitment.bytes, 32, h_comm);

    char req[2048], resp[8192];
    int status = 0;

    if (ctx->cfg.kind == SF_CHAIN_GENERIC) {
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"sealframe_anchorVerify\",\"params\":{"
                 "\"commitment\":\"%s\"}}", h_comm);
        fp_err_t err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                                      ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
        if (err != FP_OK) return err;
        return (strstr(resp, "\"verified\":true") != NULL) ? FP_OK : FP_ERR_INTEGRITY;
    }

    if (ctx->cfg.kind == SF_CHAIN_EVM) {
        if (!ctx->cfg.contract_addr) return FP_ERR_INVALID;
        uint8_t abi[36];
        char abi_hex[73];
        sf_evm_encode_is_anchored(&c->commitment, abi);
        fp_hex_encode(abi, sizeof(abi), abi_hex);
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_call\",\"params\":[{"
                 "\"to\":\"%s\",\"data\":\"0x%s\"},\"latest\"]}",
                 ctx->cfg.contract_addr, abi_hex);
        fp_err_t err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                                      ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
        if (err != FP_OK) return err;
        /* EVM bool true = 32-byte word ending in 01 */
        char res_hex[128];
        extract_json_str_field(resp, "result", res_hex, sizeof(res_hex));
        size_t rl = strlen(res_hex);
        if (rl == 66u && strncmp(res_hex, "0x", 2) == 0 && res_hex[65] == '1') {
            for (size_t i = 2; i < 65; i++) if (res_hex[i] != '0') return FP_ERR_INTEGRITY;
            return FP_OK;
        }
        return FP_ERR_INTEGRITY;
    }

    if (ctx->cfg.kind == SF_CHAIN_SOLANA) {
        char pda_b58[64];
        if (sf_base58_encode(c->commitment.bytes, 32, pda_b58, sizeof(pda_b58)) == 0) return FP_ERR_BOUNDS;
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"getAccountInfo\",\"params\":[\"%s\",{\"encoding\":\"base64\"}]}",
                 pda_b58);
        fp_err_t err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                                      ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
        if (err != FP_OK) return err;
        char b64_comm[64];
        sf_base64_encode(c->commitment.bytes, 32, b64_comm, sizeof(b64_comm));
        return (strstr(resp, b64_comm) != NULL) ? FP_OK : FP_ERR_INTEGRITY;
    }

    if (ctx->cfg.kind == SF_CHAIN_KERYX) {
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"keryx_verifyAnchor\",\"params\":{"
                 "\"commitment\":\"%s\"}}", h_comm);
        fp_err_t err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                                      ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
        if (err != FP_OK) return err;
        return (strstr(resp, "\"anchored\":true") != NULL) ? FP_OK : FP_ERR_INTEGRITY;
    }

    return FP_ERR_INVALID;
}

fp_err_t sf_chain_adapter_init(sf_chain_ctx_t *ctx, const sf_chain_cfg_t *cfg,
                               fp_anchor_ops_t *out_ops) {
    if (!ctx || !cfg || !cfg->rpc_url || !out_ops) return FP_ERR_INVALID;
    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg = *cfg;
    if (ctx->cfg.io_timeout_ms <= 0) ctx->cfg.io_timeout_ms = 10000;
    out_ops->publish = chain_publish;
    out_ops->verify  = chain_verify;
    out_ops->user_ctx = ctx;
    return FP_OK;
}

fp_err_t sf_chain_submit_derivation(sf_chain_ctx_t *ctx, const fp_derivation_t *drv,
                                    const fp_dna_t *expected_result_dna) {
    if (!ctx || !drv || !ctx->cfg.rpc_url) return FP_ERR_INVALID;
    uint8_t *ebuf = NULL;
    size_t elen = 0;
    fp_err_t err = fp_derivation_encode(drv, &ebuf, &elen);
    if (err != FP_OK) return err;

    char fpd_hex[1024];
    if (elen * 2u + 1u > sizeof(fpd_hex)) { free(ebuf); return FP_ERR_BOUNDS; }
    fp_hex_encode(ebuf, elen, fpd_hex);
    free(ebuf);

    char exp_hex[65] = "";
    if (expected_result_dna) fp_hex_encode(expected_result_dna->bytes, 32, exp_hex);

    const char *method = "sealframe_submitDerivation";
    if (ctx->cfg.kind == SF_CHAIN_EVM)         method = "sealframe_evmSubmitDerivation";
    else if (ctx->cfg.kind == SF_CHAIN_SOLANA) method = "sealframe_solanaSubmitDerivation";
    else if (ctx->cfg.kind == SF_CHAIN_KERYX)  method = "keryx_submitOpoiFraudProof";

    char req[2048], resp[4096];
    int status = 0;
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"%s\",\"params\":{"
             "\"fpd1_hex\":\"%s\",\"expected_result_dna\":\"%s\"}}",
             method, fpd_hex, exp_hex);
    err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                         ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
    if (err != FP_OK) return err;
    if (strstr(resp, "\"error\"") != NULL && strstr(resp, "\"error\":null") == NULL) {
        return FP_ERR_IO;
    }
    return FP_OK;
}
