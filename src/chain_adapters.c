/*
 * SealFrame Anchor Adapters (Generic JSON-RPC 2.0 & Keryx BlockDAG/OPoI)
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

/* ==================== 1. Base64 Helper (RFC 6455 WebSocket Key) ==================== */

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

/* A8-SEC-04: Strict pure-C11 JSON-RPC 2.0 structural parser (replaces substring matching). */
static const char *j_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

static const char *j_skip_str(const char *p) {
    if (*p != '"') return NULL;
    p++;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            if (!*p) return NULL;
        }
        p++;
    }
    return (*p == '"') ? p + 1 : NULL;
}

static const char *j_skip_val(const char *p, int depth) {
    if (depth > 16) return NULL;
    p = j_skip_ws(p);
    if (*p == '"') return j_skip_str(p);
    if (*p == '{') {
        p = j_skip_ws(p + 1);
        if (*p == '}') return p + 1;
        for (;;) {
            p = j_skip_str(p);
            if (!p) return NULL;
            p = j_skip_ws(p);
            if (*p != ':') return NULL;
            p = j_skip_val(p + 1, depth + 1);
            if (!p) return NULL;
            p = j_skip_ws(p);
            if (*p == '}') return p + 1;
            if (*p != ',') return NULL;
            p = j_skip_ws(p + 1);
        }
    }
    if (*p == '[') {
        p = j_skip_ws(p + 1);
        if (*p == ']') return p + 1;
        for (;;) {
            p = j_skip_val(p, depth + 1);
            if (!p) return NULL;
            p = j_skip_ws(p);
            if (*p == ']') return p + 1;
            if (*p != ',') return NULL;
            p = j_skip_ws(p + 1);
        }
    }
    if (strncmp(p, "true", 4) == 0)  return p + 4;
    if (strncmp(p, "false", 5) == 0) return p + 5;
    if (strncmp(p, "null", 4) == 0)  return p + 4;
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        if (*p == '-') p++;
        if (!(*p >= '0' && *p <= '9')) return NULL;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') {
            p++;
            if (!(*p >= '0' && *p <= '9')) return NULL;
            while (*p >= '0' && *p <= '9') p++;
        }
        if (*p == 'e' || *p == 'E') {
            p++;
            if (*p == '+' || *p == '-') p++;
            if (!(*p >= '0' && *p <= '9')) return NULL;
            while (*p >= '0' && *p <= '9') p++;
        }
        return p;
    }
    return NULL;
}

static int j_parse_str(const char *p, char *out, size_t cap) {
    if (!p || !out || cap == 0) return -1;
    p = j_skip_ws(p);
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"') {
        char ch = *p++;
        if (ch == '\\') {
            if (!*p) return -1;
            ch = *p++;
        }
        if (i + 1u >= cap) return -1;
        out[i++] = ch;
    }
    if (*p != '"') return -1;
    out[i] = '\0';
    return 0;
}

static int j_parse_i64(const char *p, int64_t *out) {
    p = j_skip_ws(p);
    if (!(*p == '-' || (*p >= '0' && *p <= '9'))) return -1;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(p, &end, 10);
    if (errno != 0 || end == p) return -1;
    if (*end == '.' || *end == 'e' || *end == 'E') return -1;
    *out = (int64_t)v;
    return 0;
}

/* Find a key strictly at the TOP LEVEL of a JSON object `{ ... }` (returns pointer to value). */
static const char *j_find_top_field(const char *obj, const char *key) {
    const char *p = j_skip_ws(obj);
    if (*p != '{') return NULL;
    p = j_skip_ws(p + 1);
    if (*p == '}') return NULL;
    size_t klen = strlen(key);
    for (;;) {
        if (*p != '"') return NULL;
        const char *kstart = p + 1;
        const char *kend = j_skip_str(p);
        if (!kend) return NULL;
        size_t found_len = (size_t)((kend - 1) - kstart);
        p = j_skip_ws(kend);
        if (*p != ':') return NULL;
        const char *val = j_skip_ws(p + 1);
        if (found_len == klen && memcmp(kstart, key, klen) == 0) {
            return val;
        }
        p = j_skip_val(val, 1);
        if (!p) return NULL;
        p = j_skip_ws(p);
        if (*p == '}') return NULL;
        if (*p != ',') return NULL;
        p = j_skip_ws(p + 1);
    }
}

/* Validate strict JSON-RPC 2.0 response envelope:
 *   - Well-formed root JSON object with no trailing garbage
 *   - "jsonrpc": "2.0"
 *   - "id": exact integer matching expected_id
 *   - "error": absent or literal null
 *   - "result": present and NOT literal null */
static fp_err_t validate_jsonrpc_resp(const char *resp, int64_t expected_id, const char **out_result) {
    if (!resp || !out_result) return FP_ERR_INVALID;
    *out_result = NULL;
    const char *root = j_skip_ws(resp);
    if (*root != '{') return FP_ERR_INTEGRITY;
    const char *end = j_skip_val(root, 0);
    if (!end || *j_skip_ws(end) != '\0') return FP_ERR_INTEGRITY;

    const char *ver_v = j_find_top_field(root, "jsonrpc");
    char ver_s[16];
    if (!ver_v || j_parse_str(ver_v, ver_s, sizeof(ver_s)) != 0 || strcmp(ver_s, "2.0") != 0) {
        return FP_ERR_INTEGRITY;
    }

    const char *id_v = j_find_top_field(root, "id");
    int64_t got_id = -1;
    if (!id_v || j_parse_i64(id_v, &got_id) != 0 || got_id != expected_id) {
        return FP_ERR_INTEGRITY;
    }

    const char *err_v = j_find_top_field(root, "error");
    if (err_v != NULL) {
        const char *ev = j_skip_ws(err_v);
        if (strncmp(ev, "null", 4) != 0) return FP_ERR_IO;
        const char *after = j_skip_ws(ev + 4);
        if (*after != ',' && *after != '}') return FP_ERR_IO;
    }

    const char *res_v = j_find_top_field(root, "result");
    if (!res_v) return FP_ERR_INTEGRITY;
    const char *rv = j_skip_ws(res_v);
    if (strncmp(rv, "null", 4) == 0) {
        const char *after = j_skip_ws(rv + 4);
        if (*after == ',' || *after == '}') return FP_ERR_INTEGRITY;
    }
    *out_result = rv;
    return FP_OK;
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

    const char *res_v = NULL;
    err = validate_jsonrpc_resp(resp, 1, &res_v);
    if (err != FP_OK) return err;

    ctx->last_tx_id[0] = '\0';
    if (*res_v == '"') {
        if (j_parse_str(res_v, ctx->last_tx_id, sizeof(ctx->last_tx_id)) != 0) return FP_ERR_INTEGRITY;
    } else if (*res_v == '{') {
        const char *tx_v = j_find_top_field(res_v, "tx_id");
        if (!tx_v || j_parse_str(tx_v, ctx->last_tx_id, sizeof(ctx->last_tx_id)) != 0) return FP_ERR_INTEGRITY;
    } else {
        return FP_ERR_INTEGRITY;
    }
    return (ctx->last_tx_id[0] != '\0') ? FP_OK : FP_ERR_INTEGRITY;
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
        const char *res_v = NULL;
        err = validate_jsonrpc_resp(resp, 2, &res_v);
        if (err != FP_OK || *res_v != '{') return FP_ERR_INTEGRITY;
        const char *ver_v = j_find_top_field(res_v, "verified");
        if (!ver_v || strncmp(ver_v, "true", 4) != 0) return FP_ERR_INTEGRITY;
        const char *after = j_skip_ws(ver_v + 4);
        return (*after == ',' || *after == '}') ? FP_OK : FP_ERR_INTEGRITY;
    }

    if (ctx->cfg.kind == SF_CHAIN_KERYX) {
        snprintf(req, sizeof(req),
                 "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"keryx_verifyAnchor\",\"params\":{"
                 "\"commitment\":\"%s\"}}", h_comm);
        fp_err_t err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                                      ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
        if (err != FP_OK) return err;
        const char *res_v = NULL;
        err = validate_jsonrpc_resp(resp, 2, &res_v);
        if (err != FP_OK || *res_v != '{') return FP_ERR_INTEGRITY;
        const char *anc_v = j_find_top_field(res_v, "anchored");
        if (!anc_v || strncmp(anc_v, "true", 4) != 0) return FP_ERR_INTEGRITY;
        const char *after = j_skip_ws(anc_v + 4);
        return (*after == ',' || *after == '}') ? FP_OK : FP_ERR_INTEGRITY;
    }

    return FP_ERR_INVALID;
}

fp_err_t sf_chain_adapter_init(sf_chain_ctx_t *ctx, const sf_chain_cfg_t *cfg,
                               fp_anchor_ops_t *out_ops) {
    if (!ctx || !cfg || !cfg->rpc_url || !out_ops) return FP_ERR_INVALID;
    if (cfg->kind != SF_CHAIN_GENERIC && cfg->kind != SF_CHAIN_KERYX) return FP_ERR_INVALID;
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
    if (ctx->cfg.kind == SF_CHAIN_KERYX) method = "keryx_submitOpoiFraudProof";

    char req[2048], resp[4096];
    int status = 0;
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"%s\",\"params\":{"
             "\"fpd1_hex\":\"%s\",\"expected_result_dna\":\"%s\"}}",
             method, fpd_hex, exp_hex);
    err = http_post_json(ctx->cfg.rpc_url, ctx->cfg.bearer_token, req,
                         ctx->cfg.io_timeout_ms, &status, resp, sizeof(resp));
    if (err != FP_OK) return err;
    const char *res_v = NULL;
    return validate_jsonrpc_resp(resp, 3, &res_v);
}
