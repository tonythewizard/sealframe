/*
 * SealFrame (sf-cp) — Pure ISO C11 On-Premises Enterprise Control Plane & EU CRA Audit Server
 *
 * Zero Python, zero C++, zero OpenSSL, zero external JSON/HTTP dependencies.
 * Links only pure C libraries: libsealframe, libsodium, sqlite3, libzstd, pthread, libc.
 *
 * Endpoints (100% wire-compatible with SealFrame v0.5.1):
 *   - GET  /                              -> Interactive Fleet & CRA Compliance Dashboard
 *   - GET  /repo/root.fpr                 -> Signed Multi-Sig Root document (FPR1)
 *   - GET  /repo/channels/<ch>/latest.ev  -> Signed target event for channel
 *   - GET  /repo/latest.ev                -> Default stable channel latest.ev
 *   - GET  /repo/events/<serial>.ev       -> Immutable signed event ledger
 *   - GET  /repo/objects/<dna_hex>        -> Content-addressed blobs (HTTP 206 Range + O(1) RAM)
 *   - POST /api/v1/heartbeat              -> Edge Agent telemetry (Ed25519 verified via libsodium)
 *   - GET  /api/v1/fleet                  -> Live fleet compliance JSON
 *   - POST /api/v1/approvals              -> [Bearer Admin] Record 2-of-3 release approval quorum
 *   - GET  /api/v1/approvals              -> List approval quorum records
 *   - POST /api/v1/channels/<ch>          -> [Bearer Admin] Promote signed serial {"serial": N}
 *   - POST /api/v1/emergency/rollback     -> [Bearer Admin] Emergency rollback {"channel":..,"serial":N}
 *   - GET  /api/v1/audit/cra              -> EU CRA Annex I/VII Compliance Audit Report JSON
 *   - GET  /api/v1/audit/cra.html         -> Printable EU CRA Compliance Report (HTML/PDF ready)
 */
#define _XOPEN_SOURCE 700

#include "fp.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CP_MAX_HDR_BYTES   16384u
#define CP_MAX_BODY_BYTES  (1024u * 1024u)
#define CP_MAX_JSON_DEPTH  32
#define CP_MAX_WORKERS     64

static _Atomic int g_stop = 0;
static _Atomic int g_listen_fd = -1;

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&g_stop, 1);
    int fd = atomic_exchange(&g_listen_fd, -1);
    if (fd >= 0) close(fd);
}

/* ==================== Dynamic String Buffer ==================== */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
    int    oom;
} sbuf_t;

static void sb_init(sbuf_t *b, size_t cap) {
    b->len = 0;
    b->oom = 0;
    b->cap = cap > 64 ? cap : 64;
    b->data = malloc(b->cap);
    if (!b->data) { b->cap = 0; b->oom = 1; }
    else b->data[0] = '\0';
}

static void sb_free(sbuf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static int sb_reserve(sbuf_t *b, size_t add) {
    if (b->oom) return -1;
    if (add > SIZE_MAX - b->len - 1u) { b->oom = 1; return -1; }
    size_t need = b->len + add + 1u;
    if (need <= b->cap) return 0;
    size_t ncap = b->cap ? b->cap : 64;
    while (ncap < need) {
        if (ncap > SIZE_MAX / 2u) { ncap = need; break; }
        ncap *= 2u;
    }
    char *nd = realloc(b->data, ncap);
    if (!nd) { b->oom = 1; return -1; }
    b->data = nd;
    b->cap = ncap;
    return 0;
}

static void sb_putn(sbuf_t *b, const char *s, size_t n) {
    if (!s || n == 0 || sb_reserve(b, n) != 0) return;
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void sb_puts(sbuf_t *b, const char *s) {
    if (s) sb_putn(b, s, strlen(s));
}

static void sb_putc(sbuf_t *b, char c) {
    sb_putn(b, &c, 1);
}

static void sb_printf(sbuf_t *b, const char *fmt, ...) {
    if (b->oom) return;
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0 || sb_reserve(b, (size_t)n) != 0) { va_end(ap2); return; }
    vsnprintf(b->data + b->len, (size_t)n + 1u, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
}

static void sb_json_str(sbuf_t *b, const char *s) {
    sb_putc(b, '"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            unsigned char c = *p;
            if (c == '"')       sb_puts(b, "\\\"");
            else if (c == '\\') sb_puts(b, "\\\\");
            else if (c == '\b') sb_puts(b, "\\b");
            else if (c == '\f') sb_puts(b, "\\f");
            else if (c == '\n') sb_puts(b, "\\n");
            else if (c == '\r') sb_puts(b, "\\r");
            else if (c == '\t') sb_puts(b, "\\t");
            else if (c < 0x20u) sb_printf(b, "\\u%04x", (unsigned)c);
            else                sb_putc(b, (char)c);
        }
    }
    sb_putc(b, '"');
}

static void sb_html_esc(sbuf_t *b, const char *s) {
    if (!s) return;
    for (const char *p = s; *p; p++) {
        if (*p == '&')       sb_puts(b, "&amp;");
        else if (*p == '<')  sb_puts(b, "&lt;");
        else if (*p == '>')  sb_puts(b, "&gt;");
        else if (*p == '"')  sb_puts(b, "&quot;");
        else if (*p == '\'') sb_puts(b, "&#39;");
        else                 sb_putc(b, *p);
    }
}

/* ==================== Strict RFC 8259 JSON Parser ==================== */

typedef enum {
    J_NULL = 0,
    J_BOOL,
    J_INT,
    J_FLOAT,
    J_STR,
    J_ARR,
    J_OBJ
} jtype_t;

typedef struct jval jval_t;

typedef struct {
    char   *key;
    jval_t *val;
} jkv_t;

struct jval {
    jtype_t type;
    int     bval;
    int64_t ival;
    double  fval;
    char   *sval;
    jval_t **items;
    jkv_t  *kvs;
    size_t  count;
};

static void jval_free(jval_t *v) {
    if (!v) return;
    if (v->type == J_STR) {
        free(v->sval);
    } else if (v->type == J_ARR) {
        for (size_t i = 0; i < v->count; i++) jval_free(v->items[i]);
        free(v->items);
    } else if (v->type == J_OBJ) {
        for (size_t i = 0; i < v->count; i++) {
            free(v->kvs[i].key);
            jval_free(v->kvs[i].val);
        }
        free(v->kvs);
    }
    free(v);
}

typedef struct {
    const char *s;
    size_t      len;
    size_t      pos;
    int         depth;
} jparser_t;

static void jp_ws(jparser_t *p) {
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') p->pos++;
        else break;
    }
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static char *jp_parse_raw_str(jparser_t *p) {
    if (p->pos >= p->len || p->s[p->pos] != '"') return NULL;
    p->pos++;
    sbuf_t b;
    sb_init(&b, 64);
    while (p->pos < p->len) {
        unsigned char c = (unsigned char)p->s[p->pos++];
        if (c == '"') {
            if (b.oom) { sb_free(&b); return NULL; }
            return b.data;
        }
        if (c < 0x20u) { sb_free(&b); return NULL; }
        if (c == '\\') {
            if (p->pos >= p->len) { sb_free(&b); return NULL; }
            char e = p->s[p->pos++];
            switch (e) {
                case '"':  sb_putc(&b, '"');  break;
                case '\\': sb_putc(&b, '\\'); break;
                case '/':  sb_putc(&b, '/');  break;
                case 'b':  sb_putc(&b, '\b'); break;
                case 'f':  sb_putc(&b, '\f'); break;
                case 'n':  sb_putc(&b, '\n'); break;
                case 'r':  sb_putc(&b, '\r'); break;
                case 't':  sb_putc(&b, '\t'); break;
                case 'u': {
                    if (p->pos + 4u > p->len) { sb_free(&b); return NULL; }
                    uint32_t cp = 0;
                    for (int i = 0; i < 4; i++) {
                        int h = hex_nibble(p->s[p->pos++]);
                        if (h < 0) { sb_free(&b); return NULL; }
                        cp = (cp << 4) | (uint32_t)h;
                    }
                    if (cp == 0) { sb_free(&b); return NULL; } /* reject embedded NUL */
                    if (cp < 0x80u) {
                        sb_putc(&b, (char)cp);
                    } else if (cp < 0x800u) {
                        sb_putc(&b, (char)(0xC0u | (cp >> 6)));
                        sb_putc(&b, (char)(0x80u | (cp & 0x3Fu)));
                    } else {
                        sb_putc(&b, (char)(0xE0u | (cp >> 12)));
                        sb_putc(&b, (char)(0x80u | ((cp >> 6) & 0x3Fu)));
                        sb_putc(&b, (char)(0x80u | (cp & 0x3Fu)));
                    }
                    break;
                }
                default:
                    sb_free(&b);
                    return NULL;
            }
        } else {
            sb_putc(&b, (char)c);
        }
    }
    sb_free(&b);
    return NULL;
}

static jval_t *jp_parse_val(jparser_t *p);

static jval_t *jp_parse_num(jparser_t *p) {
    size_t start = p->pos;
    int is_float = 0;
    if (p->pos < p->len && p->s[p->pos] == '-') p->pos++;
    if (p->pos >= p->len) return NULL;
    if (p->s[p->pos] == '0') {
        p->pos++;
        if (p->pos < p->len && isdigit((unsigned char)p->s[p->pos])) return NULL;
    } else if (isdigit((unsigned char)p->s[p->pos])) {
        while (p->pos < p->len && isdigit((unsigned char)p->s[p->pos])) p->pos++;
    } else {
        return NULL;
    }
    if (p->pos < p->len && p->s[p->pos] == '.') {
        is_float = 1;
        p->pos++;
        if (p->pos >= p->len || !isdigit((unsigned char)p->s[p->pos])) return NULL;
        while (p->pos < p->len && isdigit((unsigned char)p->s[p->pos])) p->pos++;
    }
    if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
        is_float = 1;
        p->pos++;
        if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-')) p->pos++;
        if (p->pos >= p->len || !isdigit((unsigned char)p->s[p->pos])) return NULL;
        while (p->pos < p->len && isdigit((unsigned char)p->s[p->pos])) p->pos++;
    }
    size_t nlen = p->pos - start;
    if (nlen == 0 || nlen >= 128u) return NULL;
    char tmp[128];
    memcpy(tmp, p->s + start, nlen);
    tmp[nlen] = '\0';

    jval_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    if (!is_float) {
        errno = 0;
        char *endp = NULL;
        long long iv = strtoll(tmp, &endp, 10);
        if (errno == 0 && endp && *endp == '\0') {
            v->type = J_INT;
            v->ival = (int64_t)iv;
            v->fval = (double)iv;
            return v;
        }
    }
    errno = 0;
    char *endp = NULL;
    double dv = strtod(tmp, &endp);
    if (errno != 0 || !endp || *endp != '\0' || !isfinite(dv)) {
        free(v);
        return NULL;
    }
    v->type = J_FLOAT;
    v->fval = dv;
    return v;
}

static jval_t *jp_parse_val(jparser_t *p) {
    if (p->depth >= CP_MAX_JSON_DEPTH) return NULL;
    jp_ws(p);
    if (p->pos >= p->len) return NULL;
    char c = p->s[p->pos];

    if (c == '"') {
        char *s = jp_parse_raw_str(p);
        if (!s) return NULL;
        jval_t *v = calloc(1, sizeof(*v));
        if (!v) { free(s); return NULL; }
        v->type = J_STR;
        v->sval = s;
        return v;
    }
    if (c == '{') {
        p->pos++;
        p->depth++;
        jval_t *v = calloc(1, sizeof(*v));
        if (!v) { p->depth--; return NULL; }
        v->type = J_OBJ;
        jp_ws(p);
        if (p->pos < p->len && p->s[p->pos] == '}') {
            p->pos++;
            p->depth--;
            return v;
        }
        size_t cap = 8;
        v->kvs = calloc(cap, sizeof(jkv_t));
        if (!v->kvs) { jval_free(v); p->depth--; return NULL; }
        for (;;) {
            jp_ws(p);
            char *key = jp_parse_raw_str(p);
            if (!key) { jval_free(v); p->depth--; return NULL; }
            jp_ws(p);
            if (p->pos >= p->len || p->s[p->pos] != ':') {
                free(key); jval_free(v); p->depth--; return NULL;
            }
            p->pos++;
            jval_t *val = jp_parse_val(p);
            if (!val) { free(key); jval_free(v); p->depth--; return NULL; }
            if (v->count == cap) {
                size_t ncap = cap * 2u;
                jkv_t *nk = realloc(v->kvs, ncap * sizeof(jkv_t));
                if (!nk) { free(key); jval_free(val); jval_free(v); p->depth--; return NULL; }
                v->kvs = nk;
                cap = ncap;
            }
            v->kvs[v->count].key = key;
            v->kvs[v->count].val = val;
            v->count++;
            jp_ws(p);
            if (p->pos < p->len && p->s[p->pos] == ',') { p->pos++; continue; }
            if (p->pos < p->len && p->s[p->pos] == '}') { p->pos++; break; }
            jval_free(v); p->depth--; return NULL;
        }
        p->depth--;
        return v;
    }
    if (c == '[') {
        p->pos++;
        p->depth++;
        jval_t *v = calloc(1, sizeof(*v));
        if (!v) { p->depth--; return NULL; }
        v->type = J_ARR;
        jp_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ']') {
            p->pos++;
            p->depth--;
            return v;
        }
        size_t cap = 8;
        v->items = calloc(cap, sizeof(jval_t *));
        if (!v->items) { jval_free(v); p->depth--; return NULL; }
        for (;;) {
            jval_t *it = jp_parse_val(p);
            if (!it) { jval_free(v); p->depth--; return NULL; }
            if (v->count == cap) {
                size_t ncap = cap * 2u;
                jval_t **ni = realloc(v->items, ncap * sizeof(jval_t *));
                if (!ni) { jval_free(it); jval_free(v); p->depth--; return NULL; }
                v->items = ni;
                cap = ncap;
            }
            v->items[v->count++] = it;
            jp_ws(p);
            if (p->pos < p->len && p->s[p->pos] == ',') { p->pos++; continue; }
            if (p->pos < p->len && p->s[p->pos] == ']') { p->pos++; break; }
            jval_free(v); p->depth--; return NULL;
        }
        p->depth--;
        return v;
    }
    if (p->pos + 4u <= p->len && memcmp(p->s + p->pos, "true", 4) == 0) {
        p->pos += 4u;
        jval_t *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = J_BOOL; v->bval = 1;
        return v;
    }
    if (p->pos + 5u <= p->len && memcmp(p->s + p->pos, "false", 5) == 0) {
        p->pos += 5u;
        jval_t *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = J_BOOL; v->bval = 0;
        return v;
    }
    if (p->pos + 4u <= p->len && memcmp(p->s + p->pos, "null", 4) == 0) {
        p->pos += 4u;
        jval_t *v = calloc(1, sizeof(*v));
        if (!v) return NULL;
        v->type = J_NULL;
        return v;
    }
    if (c == '-' || isdigit((unsigned char)c)) return jp_parse_num(p);
    return NULL;
}

static jval_t *json_parse(const char *s, size_t len) {
    if (!s) return NULL;
    jparser_t p = { s, len, 0, 0 };
    jval_t *v = jp_parse_val(&p);
    if (!v) return NULL;
    jp_ws(&p);
    if (p.pos != p.len) { jval_free(v); return NULL; }
    return v;
}

static const jval_t *jobj_get(const jval_t *obj, const char *key) {
    if (!obj || obj->type != J_OBJ) return NULL;
    for (size_t i = obj->count; i > 0; i--) {
        if (strcmp(obj->kvs[i - 1].key, key) == 0) return obj->kvs[i - 1].val;
    }
    return NULL;
}

static int jobj_strict_i64(const jval_t *obj, const char *key, int64_t defv, int64_t minv, int64_t *out) {
    const jval_t *v = jobj_get(obj, key);
    if (!v || v->type == J_NULL) { *out = defv; return 0; }
    if (v->type != J_INT || v->ival < minv) return -1;
    *out = v->ival;
    return 0;
}

static int jobj_strict_double(const jval_t *obj, const char *key, double defv, double *out) {
    const jval_t *v = jobj_get(obj, key);
    if (!v || v->type == J_NULL) { *out = defv; return 0; }
    if (v->type != J_INT && v->type != J_FLOAT) return -1;
    double d = (v->type == J_INT) ? (double)v->ival : v->fval;
    if (!isfinite(d) || d < 0.0) return -1;
    *out = d;
    return 0;
}

static void jobj_copy_str(const jval_t *obj, const char *key, const char *defv, char *dst, size_t cap) {
    const jval_t *v = jobj_get(obj, key);
    const char *src = defv;
    if (v && v->type == J_STR && v->sval) src = v->sval;
    if (!src) src = "";
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1u;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ==================== Helpers & Crypto ==================== */

static void utc_now(char out[32]) {
    time_t t = time(NULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

static int is_valid_channel(const char *ch) {
    if (!ch || !ch[0]) return 0;
    size_t n = strlen(ch);
    if (n > 32u) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)ch[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int is_hex_lower(const char *s, size_t expect_len) {
    if (!s || strlen(s) != expect_len) return 0;
    for (size_t i = 0; i < expect_len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int is_digits_only(const char *s) {
    if (!s || !s[0]) return 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

static int hex_decode_lower(const char *hex, uint8_t *out, size_t out_len) {
    if (!is_hex_lower(hex, out_len * 2u)) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void to_hex_lower(const uint8_t *in, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2u]      = hx[in[i] >> 4];
        out[i * 2u + 1u] = hx[in[i] & 0x0Fu];
    }
    out[n * 2u] = '\0';
}

static int sha256_file_hex(const char *path, char hex_out[65], uint64_t *size_out) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return -1; }
    if (size_out) *size_out = (uint64_t)st.st_size;

    crypto_hash_sha256_state hst;
    crypto_hash_sha256_init(&hst);
    uint8_t buf[65536];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (r == 0) break;
        crypto_hash_sha256_update(&hst, buf, (unsigned long long)r);
    }
    close(fd);
    uint8_t digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_final(&hst, digest);
    to_hex_lower(digest, sizeof(digest), hex_out);
    return 0;
}

static int mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    size_t n = strlen(path);
    if (n == 0 || n >= sizeof(tmp)) return -1;
    memcpy(tmp, path, n + 1u);
    for (size_t i = 1; i < n; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int copy_file_atomic(const char *src_path, const char *dst_path) {
    int sfd = open(src_path, O_RDONLY | O_NOFOLLOW);
    if (sfd < 0) return -1;
    struct stat st;
    if (fstat(sfd, &st) != 0 || !S_ISREG(st.st_mode)) { close(sfd); return -1; }

    char tmp_path[PATH_MAX];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", dst_path) >= (int)sizeof(tmp_path)) {
        close(sfd);
        return -1;
    }
    int dfd = mkstemp(tmp_path);
    if (dfd < 0) { close(sfd); return -1; }
    (void)fchmod(dfd, 0644);

    uint8_t buf[65536];
    int ok = 1;
    for (;;) {
        ssize_t r = read(sfd, buf, sizeof(buf));
        if (r < 0) { if (errno == EINTR) continue; ok = 0; break; }
        if (r == 0) break;
        size_t off = 0;
        while (off < (size_t)r) {
            ssize_t w = write(dfd, buf + off, (size_t)r - off);
            if (w < 0) { if (errno == EINTR) continue; ok = 0; break; }
            off += (size_t)w;
        }
        if (!ok) break;
    }
    close(sfd);
    if (ok && fsync(dfd) != 0) ok = 0;
    close(dfd);
    if (!ok || rename(tmp_path, dst_path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    const char *slash = strrchr(dst_path, '/');
    if (slash && slash > dst_path) {
        char pdir[PATH_MAX];
        size_t dlen = (size_t)(slash - dst_path);
        if (dlen < sizeof(pdir)) {
            memcpy(pdir, dst_path, dlen);
            pdir[dlen] = '\0';
            int pfd = open(pdir, O_RDONLY | O_DIRECTORY);
            if (pfd >= 0) { (void)fsync(pfd); close(pfd); }
        }
    }
    return 0;
}

static int cp_load_event_file(const char *ev_path, fp_event_t *out_ev, char out_hash_hex[65]) {
    struct stat sb;
    if (lstat(ev_path, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size <= 0 || sb.st_size > (1 << 20)) {
        return -1;
    }
    FILE *f = fopen(ev_path, "rb");
    if (!f) return -1;
    size_t sz = (size_t)sb.st_size;
    uint8_t *buf = malloc(sz);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    if (rd != sz) { free(buf); return -1; }
    fp_err_t err = fp_event_decode(buf, sz, out_ev);
    free(buf);
    if (err != FP_OK) return -1;
    if (out_hash_hex) {
        to_hex_lower(out_ev->event_hash.bytes, FP_DNA_LEN, out_hash_hex);
    }
    return 0;
}

/* ==================== Control Plane State (SQLite3) ==================== */

typedef struct {
    char            data_dir[PATH_MAX];
    char            repo_dir[PATH_MAX];
    char            obj_dir[PATH_MAX];
    char            ev_dir[PATH_MAX];
    char            chan_dir[PATH_MAX];
    char            sbom_path[PATH_MAX];
    char            admin_token[128];
    int             require_signed_hb;
    int             require_enrolled;
    int             require_quorum;
    int             require_admin_read_auth;
    sqlite3        *db;
    pthread_mutex_t mu;
    pthread_mutex_t w_mu;
    pthread_cond_t  w_cv;
    _Atomic int     active_workers;
} cp_state_t;

static int db_table_exists(sqlite3 *db, const char *table_name) {
    sqlite3_stmt *s = NULL;
    int exists = 0;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?;",
                           -1, &s, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(s, 1, table_name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    if (rc == SQLITE_ROW) exists = 1;
    else if (rc != SQLITE_DONE) exists = -1;
    sqlite3_finalize(s);
    return exists;
}

static int db_table_has_col(sqlite3 *db, const char *table_name, const char *col_name) {
    char q[128];
    if (snprintf(q, sizeof(q), "PRAGMA table_info(%s);", table_name) >= (int)sizeof(q)) return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, q, -1, &s, NULL) != SQLITE_OK) return -1;
    int found = 0;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(s, 1);
        if (name && strcmp(name, col_name) == 0) { found = 1; break; }
    }
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) return -1;
    return found;
}

static int cp_state_init(cp_state_t *st, const char *data_dir, const char *sbom_path,
                         const char *explicit_tok, int require_signed_hb,
                         int require_enrolled, int require_quorum,
                         int require_admin_read_auth) {
    memset(st, 0, sizeof(*st));
    pthread_mutex_init(&st->mu, NULL);
    pthread_mutex_init(&st->w_mu, NULL);
    pthread_cond_init(&st->w_cv, NULL);
    st->require_signed_hb = require_signed_hb;
    st->require_enrolled = require_enrolled;
    st->require_quorum = require_quorum;
    st->require_admin_read_auth = require_admin_read_auth;

    if (mkdir_p(data_dir) != 0) return -1;
    if (!realpath(data_dir, st->data_dir)) {
        snprintf(st->data_dir, sizeof(st->data_dir), "%s", data_dir);
    }
    if (snprintf(st->repo_dir, sizeof(st->repo_dir), "%s/repo", st->data_dir) >= (int)sizeof(st->repo_dir) ||
        snprintf(st->obj_dir,  sizeof(st->obj_dir),  "%s/objects", st->repo_dir) >= (int)sizeof(st->obj_dir) ||
        snprintf(st->ev_dir,   sizeof(st->ev_dir),   "%s/events",  st->repo_dir) >= (int)sizeof(st->ev_dir) ||
        snprintf(st->chan_dir, sizeof(st->chan_dir), "%s/channels", st->repo_dir) >= (int)sizeof(st->chan_dir)) {
        return -1;
    }
    if (mkdir_p(st->repo_dir) != 0 || mkdir_p(st->obj_dir) != 0 ||
        mkdir_p(st->ev_dir) != 0   || mkdir_p(st->chan_dir) != 0) {
        return -1;
    }
    if (sbom_path && sbom_path[0]) {
        snprintf(st->sbom_path, sizeof(st->sbom_path), "%s", sbom_path);
    }

    /* Admin token */
    if (explicit_tok && explicit_tok[0]) {
        snprintf(st->admin_token, sizeof(st->admin_token), "%s", explicit_tok);
    } else {
        char tok_path[PATH_MAX];
        if (snprintf(tok_path, sizeof(tok_path), "%s/admin.token", st->data_dir) >= (int)sizeof(tok_path)) {
            return -1;
        }
        FILE *tf = fopen(tok_path, "r");
        int loaded = 0;
        if (tf) {
            if (fgets(st->admin_token, (int)sizeof(st->admin_token), tf)) {
                size_t l = strlen(st->admin_token);
                while (l > 0 && (st->admin_token[l - 1] == '\n' || st->admin_token[l - 1] == '\r' ||
                                 st->admin_token[l - 1] == ' '  || st->admin_token[l - 1] == '\t')) {
                    st->admin_token[--l] = '\0';
                }
                if (l > 0) loaded = 1;
            }
            fclose(tf);
        }
        if (!loaded) {
            uint8_t raw[24];
            randombytes_buf(raw, sizeof(raw));
            to_hex_lower(raw, sizeof(raw), st->admin_token);
            sodium_memzero(raw, sizeof(raw));
            int fd = open(tok_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
            if (fd < 0) return -1;
            char line[64];
            int ln = snprintf(line, sizeof(line), "%s\n", st->admin_token);
            if (ln > 0) {
                ssize_t wr = write(fd, line, (size_t)ln);
                (void)wr;
            }
            (void)fsync(fd);
            close(fd);
        }
    }

    /* Open SQLite3 state DB */
    char db_path[PATH_MAX];
    if (snprintf(db_path, sizeof(db_path), "%s/control_plane.db", st->data_dir) >= (int)sizeof(db_path)) {
        return -1;
    }
    if (sqlite3_open(db_path, &st->db) != SQLITE_OK) return -1;
    sqlite3_busy_timeout(st->db, 5000);
    if (sqlite3_exec(st->db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;", NULL, NULL, NULL) != SQLITE_OK) {
        return -1;
    }

    /* Schema versioning & safe migration (P1-06, P0-05) */
    int user_ver = 0;
    {
        sqlite3_stmt *vs = NULL;
        if (sqlite3_prepare_v2(st->db, "PRAGMA user_version;", -1, &vs, NULL) != SQLITE_OK) return -1;
        int rc = sqlite3_step(vs);
        if (rc == SQLITE_ROW) user_ver = sqlite3_column_int(vs, 0);
        sqlite3_finalize(vs);
        if (rc != SQLITE_ROW) return -1;
    }
    if (user_ver < 0 || user_ver > 2) {
        fprintf(stderr, "sf-cp: unsupported control_plane.db schema version %d\n", user_ver);
        return -1;
    }

    if (sqlite3_exec(st->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) return -1;

    if (user_ver < 2) {
        int has_app_tbl = db_table_exists(st->db, "approvals");
        if (has_app_tbl < 0) { (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL); return -1; }
        if (has_app_tbl == 1) {
            int has_ev_hash = db_table_has_col(st->db, "approvals", "event_hash");
            int has_app_pk  = db_table_has_col(st->db, "approvals", "approver_pubkey");
            if (has_ev_hash < 0 || has_app_pk < 0) {
                (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
                return -1;
            }
            if (has_ev_hash == 0) {
                /* Legacy v0 non-cryptographic approvals table: archive without granting quorum validity */
                int has_legacy = db_table_exists(st->db, "approvals_legacy_v0");
                if (has_legacy != 0) {
                    (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
                    return -1;
                }
                if (sqlite3_exec(st->db, "ALTER TABLE approvals RENAME TO approvals_legacy_v0;",
                                 NULL, NULL, NULL) != SQLITE_OK) {
                    (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
                    return -1;
                }
            } else if (has_app_pk == 0) {
                if (sqlite3_exec(st->db,
                                 "ALTER TABLE approvals ADD COLUMN approver_pubkey TEXT NOT NULL DEFAULT '';",
                                 NULL, NULL, NULL) != SQLITE_OK) {
                    (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
                    return -1;
                }
            }
        }
    }

    const char *schema =
        "CREATE TABLE IF NOT EXISTS devices ("
        "  device_id TEXT PRIMARY KEY,"
        "  ip TEXT NOT NULL,"
        "  channel TEXT NOT NULL,"
        "  outcome TEXT NOT NULL,"
        "  active_serial INTEGER NOT NULL,"
        "  active_dna TEXT NOT NULL,"
        "  attempted_serial INTEGER NOT NULL,"
        "  attempted_dna TEXT NOT NULL,"
        "  root_version INTEGER NOT NULL,"
        "  health_exit INTEGER NOT NULL,"
        "  bytes_downloaded INTEGER NOT NULL,"
        "  bytes_from_lan INTEGER NOT NULL,"
        "  bytes_resumed INTEGER NOT NULL,"
        "  elapsed_ms REAL NOT NULL,"
        "  detail TEXT NOT NULL,"
        "  auth_verified INTEGER NOT NULL,"
        "  device_pubkey TEXT NOT NULL,"
        "  last_seen_utc TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS audit_log ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  device_id TEXT NOT NULL,"
        "  ip TEXT NOT NULL,"
        "  channel TEXT NOT NULL,"
        "  outcome TEXT NOT NULL,"
        "  active_serial INTEGER NOT NULL,"
        "  detail TEXT NOT NULL,"
        "  auth_verified INTEGER NOT NULL,"
        "  last_seen_utc TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS enrolled_devices ("
        "  device_id TEXT PRIMARY KEY,"
        "  pubkey TEXT NOT NULL,"
        "  last_seq INTEGER NOT NULL DEFAULT 0,"
        "  enrolled_utc TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS approvers ("
        "  approver TEXT PRIMARY KEY,"
        "  pubkey TEXT NOT NULL UNIQUE,"
        "  added_utc TEXT NOT NULL"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_approvers_pubkey ON approvers(pubkey);"
        "CREATE TABLE IF NOT EXISTS approvals ("
        "  channel TEXT NOT NULL DEFAULT 'stable',"
        "  serial INTEGER NOT NULL,"
        "  approver TEXT NOT NULL,"
        "  approver_pubkey TEXT NOT NULL DEFAULT '',"
        "  event_hash TEXT NOT NULL DEFAULT '',"
        "  signature TEXT NOT NULL DEFAULT '',"
        "  approved_utc TEXT NOT NULL,"
        "  reason TEXT NOT NULL,"
        "  threshold INTEGER NOT NULL,"
        "  PRIMARY KEY (channel, serial, approver)"
        ");"
        "PRAGMA user_version = 2;";
    if (sqlite3_exec(st->db, schema, NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(st->db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }
    return 0;
}

static void cp_state_close(cp_state_t *st) {
    sodium_memzero(st->admin_token, sizeof(st->admin_token));
    if (st->db) { sqlite3_close(st->db); st->db = NULL; }
    pthread_cond_destroy(&st->w_cv);
    pthread_mutex_destroy(&st->w_mu);
    pthread_mutex_destroy(&st->mu);
}

static int check_admin_bearer(const cp_state_t *st, const char *auth) {
    if (!auth || strncmp(auth, "Bearer ", 7) != 0) return 0;
    const char *s = auth + 7;
    while (*s == ' ' || *s == '\t') s++;
    size_t slen = strlen(s);
    while (slen > 0 && (s[slen - 1] == ' ' || s[slen - 1] == '\t')) slen--;
    size_t tlen = strlen(st->admin_token);
    if (slen != tlen || tlen == 0) return 0;
    return sodium_memcmp(s, st->admin_token, tlen) == 0;
}

/* SEC-03/SEC-04: Propagate audit write errors fail-closed + retain 50,000 events */
static int db_append_audit(sqlite3 *db, const char *dev_id, const char *ip, const char *ch,
                           const char *outcome, int64_t active_serial, const char *detail,
                           int auth_verified, const char *utc) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
            db,
            "INSERT INTO audit_log(device_id,ip,channel,outcome,active_serial,detail,auth_verified,last_seen_utc) "
            "VALUES(?,?,?,?,?,?,?,?);",
            -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, dev_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, ch, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, outcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, active_serial);
    sqlite3_bind_text(stmt, 6, detail, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, auth_verified ? 1 : 0);
    sqlite3_bind_text(stmt, 8, utc, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    /* CP-01: Never prune governance/promotion/enrollment audit records during heartbeat rotation */
    (void)sqlite3_exec(
        db,
        "DELETE FROM audit_log "
        "WHERE channel NOT IN ('governance','enrollment') "
        "AND outcome NOT IN ('CHANNEL_SET','EMERGENCY_ROLLBACK','QUORUM_MET','DEVICE_ENROLLED','APPROVER_ADDED') "
        "AND id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 50000);",
        NULL, NULL, NULL);
    return 0;
}

static int cp_record_heartbeat(cp_state_t *st, const char *ip, const jval_t *body,
                               int auth_ok, const char *pk_hex, char out_dev[65],
                               int *out_http_status, char *err_msg, size_t err_cap) {
    *out_http_status = 400;
    snprintf(err_msg, err_cap, "invalid heartbeat field");
    if (!body || body->type != J_OBJ) return -1;
    char dev_id[65], channel[33], outcome[33], active_dna[65], att_dna[65], detail[257];
    jobj_copy_str(body, "device_id", "", dev_id, sizeof(dev_id));
    if (!dev_id[0]) {
        snprintf(err_msg, err_cap, "device_id required");
        return -1;
    }
    jobj_copy_str(body, "channel", "stable", channel, sizeof(channel));
    jobj_copy_str(body, "outcome", "UNKNOWN", outcome, sizeof(outcome));
    jobj_copy_str(body, "active_dna", "", active_dna, sizeof(active_dna));
    jobj_copy_str(body, "attempted_dna", "", att_dna, sizeof(att_dna));
    jobj_copy_str(body, "detail", "", detail, sizeof(detail));

    int has_hb_seq = 0;
    int64_t hb_seq = 0;
    const jval_t *sqv = jobj_get(body, "hb_seq");
    if (sqv) {
        if (sqv->type != J_INT || sqv->ival < 1) {
            snprintf(err_msg, err_cap, "hb_seq must be positive integer");
            return -1;
        }
        has_hb_seq = 1;
        hb_seq = sqv->ival;
    }

    int64_t active_serial = 0, att_serial = 0, root_ver = 0, health_exit = 0;
    int64_t b_dl = 0, b_lan = 0, b_res = 0;
    double elapsed_ms = 0.0;
    if (jobj_strict_i64(body, "active_serial", 0, 0, &active_serial) != 0 ||
        jobj_strict_i64(body, "attempted_serial", 0, 0, &att_serial) != 0 ||
        jobj_strict_i64(body, "root_version", 0, 0, &root_ver) != 0 ||
        jobj_strict_i64(body, "health_exit", 0, -255, &health_exit) != 0 ||
        jobj_strict_i64(body, "bytes_downloaded", 0, 0, &b_dl) != 0 ||
        jobj_strict_i64(body, "bytes_from_lan", 0, 0, &b_lan) != 0 ||
        jobj_strict_i64(body, "bytes_resumed", 0, 0, &b_res) != 0 ||
        jobj_strict_double(body, "elapsed_ms", 0.0, &elapsed_ms) != 0) {
        return -1;
    }

    char utc[32];
    utc_now(utc);
    char pk_trunc[65];
    snprintf(pk_trunc, sizeof(pk_trunc), "%.64s", pk_hex ? pk_hex : "");

    pthread_mutex_lock(&st->mu);
    if (sqlite3_exec(st->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(err_msg, err_cap, "database transaction begin failed");
        return -1;
    }

    /* Enforce device identity pinning & monotonic anti-replay counter */
    sqlite3_stmt *es = NULL;
    int enrolled = 0;
    char pinned_pk[65];
    int64_t last_seq = 0;
    pinned_pk[0] = '\0';
    if (sqlite3_prepare_v2(st->db,
                           "SELECT pubkey, last_seq FROM enrolled_devices WHERE device_id=?;",
                           -1, &es, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(err_msg, err_cap, "database query failed");
        return -1;
    }
    sqlite3_bind_text(es, 1, dev_id, -1, SQLITE_TRANSIENT);
    int erc = sqlite3_step(es);
    if (erc == SQLITE_ROW) {
        enrolled = 1;
        const char *pkc = (const char *)sqlite3_column_text(es, 0);
        snprintf(pinned_pk, sizeof(pinned_pk), "%.64s", pkc ? pkc : "");
        last_seq = sqlite3_column_int64(es, 1);
    }
    sqlite3_finalize(es);
    if (erc != SQLITE_ROW && erc != SQLITE_DONE) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(err_msg, err_cap, "database enrollment lookup failed");
        return -1;
    }

    if (enrolled) {
        if (!auth_ok || strlen(pk_trunc) != 64 || strlen(pinned_pk) != 64 ||
            sodium_memcmp(pk_trunc, pinned_pk, 64) != 0) {
            (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
            pthread_mutex_unlock(&st->mu);
            *out_http_status = 401;
            snprintf(err_msg, err_cap, "device identity mismatch: pubkey does not match enrolled key");
            return -1;
        }
        if (has_hb_seq) {
            if (hb_seq <= last_seq) {
                (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
                pthread_mutex_unlock(&st->mu);
                *out_http_status = 409;
                snprintf(err_msg, err_cap, "heartbeat replay detected (hb_seq=%lld <= last=%lld)",
                         (long long)hb_seq, (long long)last_seq);
                return -1;
            }
            sqlite3_stmt *us = NULL;
            int urc = sqlite3_prepare_v2(st->db,
                                         "UPDATE enrolled_devices SET last_seq=? WHERE device_id=?;",
                                         -1, &us, NULL);
            if (urc == SQLITE_OK) {
                sqlite3_bind_int64(us, 1, hb_seq);
                sqlite3_bind_text(us, 2, dev_id, -1, SQLITE_TRANSIENT);
                urc = sqlite3_step(us);
                sqlite3_finalize(us);
            }
            if (urc != SQLITE_DONE) {
                (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
                pthread_mutex_unlock(&st->mu);
                *out_http_status = 500;
                snprintf(err_msg, err_cap, "database heartbeat counter update failed");
                return -1;
            }
        } else if (last_seq > 0 || st->require_enrolled) {
            (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
            pthread_mutex_unlock(&st->mu);
            *out_http_status = 409;
            snprintf(err_msg, err_cap, "heartbeat replay protection active: monotonic hb_seq required");
            return -1;
        }
    } else {
        if (st->require_enrolled) {
            (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
            pthread_mutex_unlock(&st->mu);
            *out_http_status = 401;
            snprintf(err_msg, err_cap, "device not enrolled");
            return -1;
        }
        if (auth_ok && strlen(pk_trunc) == 64) {
            /* Pin first cryptographically authenticated device key (TOFU pinning) */
            sqlite3_stmt *is = NULL;
            int irc = sqlite3_prepare_v2(
                    st->db,
                    "INSERT INTO enrolled_devices(device_id,pubkey,last_seq,enrolled_utc) VALUES(?,?,?,?);",
                    -1, &is, NULL);
            if (irc == SQLITE_OK) {
                sqlite3_bind_text(is, 1, dev_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(is, 2, pk_trunc, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(is, 3, has_hb_seq ? hb_seq : 0);
                sqlite3_bind_text(is, 4, utc, -1, SQLITE_TRANSIENT);
                irc = sqlite3_step(is);
                sqlite3_finalize(is);
            }
            if (irc != SQLITE_DONE) {
                (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
                pthread_mutex_unlock(&st->mu);
                *out_http_status = 500;
                snprintf(err_msg, err_cap, "database device pinning failed");
                return -1;
            }
        }
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        st->db,
        "INSERT INTO devices("
        "device_id,ip,channel,outcome,active_serial,active_dna,attempted_serial,attempted_dna,"
        "root_version,health_exit,bytes_downloaded,bytes_from_lan,bytes_resumed,elapsed_ms,"
        "detail,auth_verified,device_pubkey,last_seen_utc) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(device_id) DO UPDATE SET "
        "ip=excluded.ip,channel=excluded.channel,outcome=excluded.outcome,"
        "active_serial=excluded.active_serial,active_dna=excluded.active_dna,"
        "attempted_serial=excluded.attempted_serial,attempted_dna=excluded.attempted_dna,"
        "root_version=excluded.root_version,health_exit=excluded.health_exit,"
        "bytes_downloaded=excluded.bytes_downloaded,bytes_from_lan=excluded.bytes_from_lan,"
        "bytes_resumed=excluded.bytes_resumed,elapsed_ms=excluded.elapsed_ms,"
        "detail=excluded.detail,auth_verified=excluded.auth_verified,"
        "device_pubkey=excluded.device_pubkey,last_seen_utc=excluded.last_seen_utc;",
        -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, dev_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, channel, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, outcome, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 5, active_serial);
        sqlite3_bind_text(stmt, 6, active_dna, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 7, att_serial);
        sqlite3_bind_text(stmt, 8, att_dna, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 9, root_ver);
        sqlite3_bind_int64(stmt, 10, health_exit);
        sqlite3_bind_int64(stmt, 11, b_dl);
        sqlite3_bind_int64(stmt, 12, b_lan);
        sqlite3_bind_int64(stmt, 13, b_res);
        sqlite3_bind_double(stmt, 14, elapsed_ms);
        sqlite3_bind_text(stmt, 15, detail, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 16, auth_ok ? 1 : 0);
        sqlite3_bind_text(stmt, 17, pk_trunc, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 18, utc, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    if (rc != SQLITE_DONE) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(err_msg, err_cap, "database heartbeat write failed");
        return -1;
    }
    if (db_append_audit(st->db, dev_id, ip, channel, outcome, active_serial, detail, auth_ok, utc) != 0) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(err_msg, err_cap, "database audit log write failed");
        return -1;
    }
    if (sqlite3_exec(st->db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(err_msg, err_cap, "database commit failed");
        return -1;
    }
    pthread_mutex_unlock(&st->mu);

    snprintf(out_dev, 65, "%s", dev_id);
    *out_http_status = 200;
    return 0;
}

static int cp_set_channel_serial(cp_state_t *st, const char *ch, int64_t serial,
                                 const char *reason, int is_emergency_rollback,
                                 char *msg, size_t msg_cap, int *out_http_status) {
    *out_http_status = 400;
    if (!is_valid_channel(ch)) {
        snprintf(msg, msg_cap, "invalid channel");
        return -1;
    }
    char src[PATH_MAX], cdir[PATH_MAX], dst[PATH_MAX];
    if (snprintf(src, sizeof(src), "%s/%lld.ev", st->ev_dir, (long long)serial) >= (int)sizeof(src)) {
        snprintf(msg, msg_cap, "path too long");
        return -1;
    }
    fp_event_t ev;
    char ev_hash_hex[65];
    if (cp_load_event_file(src, &ev, ev_hash_hex) != 0) {
        *out_http_status = 404;
        snprintf(msg, msg_cap, "event %lld.ev not found or invalid", (long long)serial);
        return -1;
    }
    if ((int64_t)ev.serial != serial) {
        *out_http_status = 400;
        snprintf(msg, msg_cap, "event file serial mismatch");
        return -1;
    }
    if (is_emergency_rollback && ev.action != FP_ACTION_ROLLBACK) {
        *out_http_status = 400;
        snprintf(msg, msg_cap, "emergency rollback requires a signed FP_ACTION_ROLLBACK event");
        return -1;
    }
    if (snprintf(cdir, sizeof(cdir), "%s/%s", st->chan_dir, ch) >= (int)sizeof(cdir) ||
        snprintf(dst, sizeof(dst), "%s/latest.ev", cdir) >= (int)sizeof(dst)) {
        snprintf(msg, msg_cap, "path too long");
        return -1;
    }

    /* Serialize monotonicity check, quorum verification, atomic file write, and audit log (SEC-03, P0-05) */
    pthread_mutex_lock(&st->mu);

    /* Enforce strict monotonicity on channel serial (agents ignore serial <= current!) */
    fp_event_t cur_ev;
    if (cp_load_event_file(dst, &cur_ev, NULL) == 0 && (uint64_t)serial <= cur_ev.serial) {
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 409;
        snprintf(msg, msg_cap,
                 "monotonic violation: serial %lld <= active channel '%s' serial %llu "
                 "(emit a new signed event with serial > %llu)",
                 (long long)serial, ch, (unsigned long long)cur_ev.serial,
                 (unsigned long long)cur_ev.serial);
        return -1;
    }

    /* Enforce cryptographic 2-of-N distinct-key approver quorum whenever approvers are registered or --require-quorum is set */
    int approver_count = 0;
    sqlite3_stmt *cs = NULL;
    if (sqlite3_prepare_v2(st->db, "SELECT COUNT(*) FROM approvers;", -1, &cs, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(msg, msg_cap, "database approver lookup failed");
        return -1;
    }
    int crc = sqlite3_step(cs);
    if (crc == SQLITE_ROW) approver_count = sqlite3_column_int(cs, 0);
    sqlite3_finalize(cs);
    if (crc != SQLITE_ROW && crc != SQLITE_DONE) {
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(msg, msg_cap, "database approver query failed");
        return -1;
    }
    if (st->require_quorum || approver_count > 0) {
        int verified_approvals = 0;
        if (sqlite3_prepare_v2(
                st->db,
                "SELECT COUNT(DISTINCT r.pubkey) FROM approvals a "
                "JOIN approvers r ON a.approver = r.approver AND a.approver_pubkey = r.pubkey "
                "WHERE a.channel=? AND a.serial=? AND a.event_hash=? AND length(a.approver_pubkey) = 64;",
                -1, &cs, NULL) != SQLITE_OK) {
            pthread_mutex_unlock(&st->mu);
            *out_http_status = 500;
            snprintf(msg, msg_cap, "database quorum lookup failed");
            return -1;
        }
        sqlite3_bind_text(cs, 1, ch, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(cs, 2, serial);
        sqlite3_bind_text(cs, 3, ev_hash_hex, -1, SQLITE_TRANSIENT);
        crc = sqlite3_step(cs);
        if (crc == SQLITE_ROW) verified_approvals = sqlite3_column_int(cs, 0);
        sqlite3_finalize(cs);
        if (crc != SQLITE_ROW && crc != SQLITE_DONE) {
            pthread_mutex_unlock(&st->mu);
            *out_http_status = 500;
            snprintf(msg, msg_cap, "database quorum query failed");
            return -1;
        }
        if (verified_approvals < 2) {
            pthread_mutex_unlock(&st->mu);
            *out_http_status = 403;
            snprintf(msg, msg_cap,
                     "quorum not met for channel '%s' serial %lld (%d/2 distinct Ed25519 keys)",
                     ch, (long long)serial, verified_approvals);
            return -1;
        }
    }

    /* SEC-05 + CP-02: Stage audit record inside SQLite transaction BEFORE flipping latest.ev;
     * if audit write fails, never publish latest.ev; if file write fails, rollback audit! */
    char utc[32], detail[256];
    utc_now(utc);
    snprintf(detail, sizeof(detail), "%s: channel '%s' -> serial #%lld", reason, ch, (long long)serial);
    if (sqlite3_exec(st->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(msg, msg_cap, "database transaction begin failed");
        return -1;
    }
    if (db_append_audit(st->db, "CONTROL_PLANE", "admin", ch,
                        is_emergency_rollback ? "EMERGENCY_ROLLBACK" : "CHANNEL_SET",
                        serial, detail, 1, utc) != 0) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(msg, msg_cap, "audit log write failed; channel not modified");
        return -1;
    }
    if (mkdir_p(cdir) != 0 || copy_file_atomic(src, dst) != 0) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(msg, msg_cap, "failed to write channel latest.ev");
        return -1;
    }
    if (sqlite3_exec(st->db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(st->db, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&st->mu);
        *out_http_status = 500;
        snprintf(msg, msg_cap, "channel updated but audit log commit failed");
        return -1;
    }
    pthread_mutex_unlock(&st->mu);
    snprintf(msg, msg_cap, "%s: channel '%s' promoted to serial %lld", reason, ch, (long long)serial);
    *out_http_status = 200;
    return 0;
}

/* ==================== JSON & HTML Builders ==================== */

static void append_devices_json(sqlite3 *db, sbuf_t *b, int *tot, int *healthy, int *rb, int *signed_d) {
    sb_putc(b, '[');
    sqlite3_stmt *stmt = NULL;
    int first = 1;
    if (sqlite3_prepare_v2(
            db,
            "SELECT device_id,ip,channel,outcome,active_serial,active_dna,attempted_serial,"
            "attempted_dna,root_version,health_exit,bytes_downloaded,bytes_from_lan,bytes_resumed,"
            "elapsed_ms,detail,auth_verified,device_pubkey,last_seen_utc FROM devices ORDER BY device_id;",
            -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) sb_putc(b, ',');
            first = 0;
            const char *did = (const char *)sqlite3_column_text(stmt, 0);
            const char *ip  = (const char *)sqlite3_column_text(stmt, 1);
            const char *ch  = (const char *)sqlite3_column_text(stmt, 2);
            const char *out = (const char *)sqlite3_column_text(stmt, 3);
            int64_t aser    = sqlite3_column_int64(stmt, 4);
            const char *ad  = (const char *)sqlite3_column_text(stmt, 5);
            int64_t tser    = sqlite3_column_int64(stmt, 6);
            const char *td  = (const char *)sqlite3_column_text(stmt, 7);
            int64_t rver    = sqlite3_column_int64(stmt, 8);
            int64_t hexit   = sqlite3_column_int64(stmt, 9);
            int64_t bdl     = sqlite3_column_int64(stmt, 10);
            int64_t blan    = sqlite3_column_int64(stmt, 11);
            int64_t bres    = sqlite3_column_int64(stmt, 12);
            double ems      = sqlite3_column_double(stmt, 13);
            const char *det = (const char *)sqlite3_column_text(stmt, 14);
            int auth        = sqlite3_column_int(stmt, 15);
            const char *pk  = (const char *)sqlite3_column_text(stmt, 16);
            const char *ut  = (const char *)sqlite3_column_text(stmt, 17);

            if (tot) (*tot)++;
            if (healthy && out && (strcmp(out, "UPDATED") == 0 || strcmp(out, "UP_TO_DATE") == 0)) (*healthy)++;
            if (rb && out && strcmp(out, "ROLLED_BACK") == 0) (*rb)++;
            if (signed_d && auth) (*signed_d)++;

            sb_puts(b, "{\"device_id\":"); sb_json_str(b, did);
            sb_puts(b, ",\"ip\":"); sb_json_str(b, ip);
            sb_puts(b, ",\"channel\":"); sb_json_str(b, ch);
            sb_puts(b, ",\"outcome\":"); sb_json_str(b, out);
            sb_printf(b, ",\"active_serial\":%lld,\"active_dna\":", (long long)aser);
            sb_json_str(b, ad);
            sb_printf(b, ",\"attempted_serial\":%lld,\"attempted_dna\":", (long long)tser);
            sb_json_str(b, td);
            sb_printf(b, ",\"root_version\":%lld,\"health_exit\":%lld,"
                         "\"bytes_downloaded\":%lld,\"bytes_from_lan\":%lld,\"bytes_resumed\":%lld,"
                         "\"elapsed_ms\":%.3f,\"detail\":",
                      (long long)rver, (long long)hexit, (long long)bdl, (long long)blan,
                      (long long)bres, ems);
            sb_json_str(b, det);
            sb_printf(b, ",\"auth_verified\":%s,\"device_pubkey\":", auth ? "true" : "false");
            sb_json_str(b, pk);
            sb_puts(b, ",\"last_seen_utc\":"); sb_json_str(b, ut);
            sb_putc(b, '}');
        }
        sqlite3_finalize(stmt);
    }
    sb_putc(b, ']');
}

/* SF-A06: Group approvals strictly by (channel, serial, event_hash) and count distinct verified approver pubkeys */
static void append_approvals_json(sqlite3 *db, sbuf_t *b, const char *filter_channel,
                                  int64_t filter_serial, const char *filter_event_hash) {
    int single = (filter_serial > 0 && filter_channel && filter_channel[0] &&
                  filter_event_hash && filter_event_hash[0]);
    if (!single) sb_putc(b, '[');
    sqlite3_stmt *s1 = NULL;
    const char *q1 = single
        ? "SELECT DISTINCT channel, serial, event_hash, threshold FROM approvals "
          "WHERE channel=? AND serial=? AND event_hash=? ORDER BY serial, channel, event_hash;"
        : "SELECT DISTINCT channel, serial, event_hash, threshold FROM approvals "
          "ORDER BY serial, channel, event_hash;";
    int first_s = 1;
    if (sqlite3_prepare_v2(db, q1, -1, &s1, NULL) == SQLITE_OK) {
        if (single) {
            sqlite3_bind_text(s1, 1, filter_channel, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s1, 2, filter_serial);
            sqlite3_bind_text(s1, 3, filter_event_hash, -1, SQLITE_TRANSIENT);
        }
        while (sqlite3_step(s1) == SQLITE_ROW) {
            if (!first_s && !single) sb_putc(b, ',');
            first_s = 0;
            const char *ch_s = (const char *)sqlite3_column_text(s1, 0);
            int64_t ser = sqlite3_column_int64(s1, 1);
            const char *eh_s = (const char *)sqlite3_column_text(s1, 2);
            int thr = sqlite3_column_int(s1, 3);
            if (!ch_s) ch_s = "";
            if (!eh_s) eh_s = "";

            sqlite3_stmt *s2 = NULL;
            sbuf_t app_map;
            sb_init(&app_map, 128);
            sb_putc(&app_map, '{');
            int listed = 0;
            if (sqlite3_prepare_v2(
                    db,
                    "SELECT a.approver, a.approved_utc, a.reason FROM approvals a "
                    "JOIN approvers r ON a.approver = r.approver AND a.approver_pubkey = r.pubkey "
                    "WHERE a.channel=? AND a.serial=? AND a.event_hash=? AND length(a.approver_pubkey) = 64 "
                    "ORDER BY a.approver;",
                    -1, &s2, NULL) == SQLITE_OK) {
                sqlite3_bind_text(s2, 1, ch_s, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(s2, 2, ser);
                sqlite3_bind_text(s2, 3, eh_s, -1, SQLITE_TRANSIENT);
                while (sqlite3_step(s2) == SQLITE_ROW) {
                    if (listed > 0) sb_putc(&app_map, ',');
                    sb_json_str(&app_map, (const char *)sqlite3_column_text(s2, 0));
                    sb_puts(&app_map, ":{\"approved_utc\":");
                    sb_json_str(&app_map, (const char *)sqlite3_column_text(s2, 1));
                    sb_puts(&app_map, ",\"reason\":");
                    sb_json_str(&app_map, (const char *)sqlite3_column_text(s2, 2));
                    sb_putc(&app_map, '}');
                    listed++;
                }
                sqlite3_finalize(s2);
            }
            sb_putc(&app_map, '}');

            int distinct_keys = 0;
            sqlite3_stmt *s3 = NULL;
            if (sqlite3_prepare_v2(
                    db,
                    "SELECT COUNT(DISTINCT r.pubkey) FROM approvals a "
                    "JOIN approvers r ON a.approver = r.approver AND a.approver_pubkey = r.pubkey "
                    "WHERE a.channel=? AND a.serial=? AND a.event_hash=? AND length(a.approver_pubkey) = 64;",
                    -1, &s3, NULL) == SQLITE_OK) {
                sqlite3_bind_text(s3, 1, ch_s, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(s3, 2, ser);
                sqlite3_bind_text(s3, 3, eh_s, -1, SQLITE_TRANSIENT);
                if (sqlite3_step(s3) == SQLITE_ROW) distinct_keys = sqlite3_column_int(s3, 0);
                sqlite3_finalize(s3);
            }

            sb_puts(b, "{\"channel\":");
            sb_json_str(b, ch_s);
            sb_printf(b, ",\"serial\":%lld,\"event_hash\":", (long long)ser);
            sb_json_str(b, eh_s);
            sb_printf(b, ",\"threshold\":%d,\"verified_keys\":%d,\"approvers\":%s,\"quorum_met\":%s}",
                      thr, distinct_keys, app_map.data ? app_map.data : "{}",
                      (distinct_keys >= thr) ? "true" : "false");
            sb_free(&app_map);
        }
        sqlite3_finalize(s1);
    }
    if (single && first_s) sb_puts(b, "null");
    if (!single) sb_putc(b, ']');
}

static int cmp_str_ptr(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void build_sbom_summary_json(const char *sbom_path, sbuf_t *b,
                                    char out_fmt[32], char out_ver[32], int *out_deps) {
    snprintf(out_fmt, 32, "None");
    out_ver[0] = '\0';
    *out_deps = 0;
    if (!sbom_path || !sbom_path[0]) { sb_puts(b, "null"); return; }

    FILE *f = fopen(sbom_path, "rb");
    if (!f) { sb_puts(b, "null"); return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0 || sz > (2 << 20)) { fclose(f); sb_puts(b, "{\"error\":\"unreadable\"}"); return; }
    rewind(f);
    char *raw = malloc((size_t)sz + 1u);
    if (!raw) { fclose(f); sb_puts(b, "null"); return; }
    size_t rd = fread(raw, 1, (size_t)sz, f);
    fclose(f);
    raw[rd] = '\0';

    jval_t *root = json_parse(raw, rd);
    free(raw);
    if (!root || root->type != J_OBJ) {
        jval_free(root);
        sb_puts(b, "{\"error\":\"unreadable\"}");
        return;
    }
    char fmt[32], spec[32], sn[96];
    jobj_copy_str(root, "bomFormat", "", fmt, sizeof(fmt));
    jobj_copy_str(root, "specVersion", "", spec, sizeof(spec));
    jobj_copy_str(root, "serialNumber", "", sn, sizeof(sn));
    const jval_t *comps = jobj_get(root, "components");
    int dep_cnt = (comps && comps->type == J_ARR) ? (int)comps->count : 0;

    snprintf(out_fmt, 32, "%s", fmt[0] ? fmt : "None");
    snprintf(out_ver, 32, "%s", spec);
    *out_deps = dep_cnt;

    sb_puts(b, "{\"bomFormat\":"); sb_json_str(b, fmt);
    sb_puts(b, ",\"specVersion\":"); sb_json_str(b, spec);
    sb_puts(b, ",\"serialNumber\":"); sb_json_str(b, sn);
    sb_printf(b, ",\"dependency_count\":%d}", dep_cnt);
    jval_free(root);
}

static void cp_build_cra_json(cp_state_t *st, sbuf_t *out) {
    char utc[32];
    utc_now(utc);

    /* Collect sorted *.ev files */
    char **ev_names = NULL;
    size_t ev_cnt = 0, ev_cap = 0;
    DIR *dir = opendir(st->ev_dir);
    if (dir) {
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            size_t n = strlen(de->d_name);
            if (n > 3u && strcmp(de->d_name + n - 3u, ".ev") == 0) {
                if (ev_cnt == ev_cap) {
                    size_t nc = ev_cap ? ev_cap * 2u : 16u;
                    char **nn = realloc(ev_names, nc * sizeof(char *));
                    if (!nn) break;
                    ev_names = nn;
                    ev_cap = nc;
                }
                ev_names[ev_cnt] = strdup(de->d_name);
                if (ev_names[ev_cnt]) ev_cnt++;
            }
        }
        closedir(dir);
    }
    if (ev_cnt > 1u) qsort(ev_names, ev_cnt, sizeof(char *), cmp_str_ptr);

    char root_path[PATH_MAX], root_sha[65];
    int root_present = 0;
    if (snprintf(root_path, sizeof(root_path), "%s/root.fpr", st->repo_dir) < (int)sizeof(root_path)) {
        root_present = (sha256_file_hex(root_path, root_sha, NULL) == 0);
    }

    sbuf_t body;
    sb_init(&body, 4096);
    sb_puts(&body, "{\"report_type\":\"EU_CRA_COMPLIANCE_AUDIT_REPORT\","
                   "\"regulation\":\"Regulation (EU) 2024/2847 (Cyber Resilience Act)\","
                   "\"generated_utc\":");
    sb_json_str(&body, utc);
    sb_puts(&body, ",\"product\":\"SealFrame Commercial Edge Control Plane v0.5.1 (C11)\","
                   "\"root_trust\":{\"root_fpr_present\":");
    sb_puts(&body, root_present ? "true" : "false");
    sb_puts(&body, ",\"root_fpr_sha256\":");
    if (root_present) sb_json_str(&body, root_sha);
    else sb_puts(&body, "null");

    sb_puts(&body, "},\"sbom_summary\":");
    char sfmt[32], sver[32];
    int sdeps = 0;
    build_sbom_summary_json(st->sbom_path, &body, sfmt, sver, &sdeps);

    sb_puts(&body, ",\"signed_events\":[");
    for (size_t i = 0; i < ev_cnt; i++) {
        char ep[PATH_MAX], esha[65];
        uint64_t esz = 0;
        int ok = 0;
        if (snprintf(ep, sizeof(ep), "%s/%s", st->ev_dir, ev_names[i]) < (int)sizeof(ep)) {
            ok = (sha256_file_hex(ep, esha, &esz) == 0);
        }
        if (i > 0) sb_putc(&body, ',');
        sb_puts(&body, "{\"file\":"); sb_json_str(&body, ev_names[i]);
        sb_printf(&body, ",\"size_bytes\":%llu,\"sha256\":", (unsigned long long)esz);
        if (ok) sb_json_str(&body, esha); else sb_puts(&body, "null");
        sb_putc(&body, '}');
        free(ev_names[i]);
    }
    free(ev_names);
    sb_putc(&body, ']');

    pthread_mutex_lock(&st->mu);
    sb_puts(&body, ",\"release_approvals\":");
    append_approvals_json(st->db, &body, NULL, 0, NULL);

    sbuf_t devs_buf;
    sb_init(&devs_buf, 1024);
    int tot = 0, healthy = 0, rb = 0, signed_d = 0;
    append_devices_json(st->db, &devs_buf, &tot, &healthy, &rb, &signed_d);

    sb_printf(&body, ",\"fleet_summary\":{\"total_devices\":%d,\"compliant_healthy\":%d,"
                     "\"auto_rolled_back\":%d,\"ed25519_authenticated_devices\":%d},\"devices\":%s",
              tot, healthy, rb, signed_d, devs_buf.data ? devs_buf.data : "[]");
    sb_free(&devs_buf);

    sb_puts(&body, ",\"recent_audit_trail\":[");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(
            st->db,
            "SELECT device_id,ip,channel,outcome,active_serial,detail,auth_verified,last_seen_utc "
            "FROM (SELECT * FROM audit_log ORDER BY id DESC LIMIT 50) ORDER BY id ASC;",
            -1, &stmt, NULL) == SQLITE_OK) {
        int first = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) sb_putc(&body, ',');
            first = 0;
            sb_puts(&body, "{\"device_id\":");
            sb_json_str(&body, (const char *)sqlite3_column_text(stmt, 0));
            sb_puts(&body, ",\"ip\":");
            sb_json_str(&body, (const char *)sqlite3_column_text(stmt, 1));
            sb_puts(&body, ",\"channel\":");
            sb_json_str(&body, (const char *)sqlite3_column_text(stmt, 2));
            sb_puts(&body, ",\"outcome\":");
            sb_json_str(&body, (const char *)sqlite3_column_text(stmt, 3));
            sb_printf(&body, ",\"active_serial\":%lld,\"detail\":",
                      (long long)sqlite3_column_int64(stmt, 4));
            sb_json_str(&body, (const char *)sqlite3_column_text(stmt, 5));
            sb_printf(&body, ",\"auth_verified\":%s,\"last_seen_utc\":",
                      sqlite3_column_int(stmt, 6) ? "true" : "false");
            sb_json_str(&body, (const char *)sqlite3_column_text(stmt, 7));
            sb_putc(&body, '}');
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&st->mu);
    sb_puts(&body, "]}");

    uint8_t digest[crypto_hash_sha256_BYTES];
    char rep_sha[65];
    crypto_hash_sha256(digest, (const uint8_t *)body.data, (unsigned long long)body.len);
    to_hex_lower(digest, sizeof(digest), rep_sha);

    /* Inject report_sha256 before final '}' */
    if (body.len > 0 && body.data[body.len - 1] == '}') {
        body.len--;
        body.data[body.len] = '\0';
        sb_puts(&body, ",\"report_sha256\":");
        sb_json_str(&body, rep_sha);
        sb_putc(&body, '}');
    }
    sb_putn(out, body.data, body.len);
    sb_free(&body);
}

static void cp_build_cra_html(cp_state_t *st, sbuf_t *out) {
    sbuf_t rep_json;
    sb_init(&rep_json, 4096);
    cp_build_cra_json(st, &rep_json);
    jval_t *rep = json_parse(rep_json.data, rep_json.len);
    sb_free(&rep_json);
    if (!rep) { sb_puts(out, "<html><body>Error generating report</body></html>"); return; }

    char prod[128], utc[64], rsha[80], fsha[80], sfmt[32], sver[32];
    jobj_copy_str(rep, "product", "SealFrame", prod, sizeof(prod));
    jobj_copy_str(rep, "generated_utc", "", utc, sizeof(utc));
    jobj_copy_str(rep, "report_sha256", "", rsha, sizeof(rsha));
    const jval_t *rt = jobj_get(rep, "root_trust");
    jobj_copy_str(rt, "root_fpr_sha256", "None", fsha, sizeof(fsha));
    const jval_t *sb = jobj_get(rep, "sbom_summary");
    jobj_copy_str(sb, "bomFormat", "None", sfmt, sizeof(sfmt));
    jobj_copy_str(sb, "specVersion", "", sver, sizeof(sver));
    int64_t sdeps = 0;
    (void)jobj_strict_i64(sb, "dependency_count", 0, 0, &sdeps);

    const jval_t *fs = jobj_get(rep, "fleet_summary");
    int64_t tot = 0, hlth = 0, rb = 0, sdev = 0;
    (void)jobj_strict_i64(fs, "total_devices", 0, 0, &tot);
    (void)jobj_strict_i64(fs, "compliant_healthy", 0, 0, &hlth);
    (void)jobj_strict_i64(fs, "auto_rolled_back", 0, 0, &rb);
    (void)jobj_strict_i64(fs, "ed25519_authenticated_devices", 0, 0, &sdev);

    sb_puts(out,
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<title>EU CRA Compliance Audit Report — SealFrame</title>"
        "<style>body{font:13px/1.5 system-ui,sans-serif;max-width:960px;margin:28px auto;color:#111}"
        "h1,h2{border-bottom:1px solid #ccc;padding-bottom:4px}"
        "table{width:100%;border-collapse:collapse;margin:12px 0}"
        "th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:12px}"
        "th{background:#f3f5f8}code{font-family:monospace;font-size:11px}"
        ".box{background:#f8fafc;border:1px solid #cbd5e1;padding:12px;border-radius:6px;margin:12px 0}"
        "@media print{.noprint{display:none}}</style></head><body>"
        "<div class=\"noprint\" style=\"margin-bottom:16px\"><button onclick=\"window.print()\">Print / Save PDF</button> "
        "<a href=\"/\">Back to Control Plane</a></div>"
        "<h1>EU Cyber Resilience Act (Regulation 2024/2847) — Audit Report</h1><div class=\"box\"><b>Product:</b> ");
    sb_html_esc(out, prod);
    sb_puts(out, "<br><b>Generated (UTC):</b> <code>"); sb_html_esc(out, utc);
    sb_puts(out, "</code><br><b>Report SHA-256:</b> <code>"); sb_html_esc(out, rsha);
    sb_puts(out, "</code><br><b>Root Trust FPR1 SHA-256:</b> <code>"); sb_html_esc(out, fsha);
    sb_puts(out, "</code><br><b>SBOM:</b> "); sb_html_esc(out, sfmt); sb_putc(out, ' '); sb_html_esc(out, sver);
    sb_printf(out, " (%lld runtime dependencies)</div>"
                   "<h2>1. Fleet Compliance Summary</h2>"
                   "<p>Total Devices: <b>%lld</b> | Healthy/Compliant: <b>%lld</b> | "
                   "Auto Rolled-Back: <b>%lld</b> | Ed25519 Authenticated: <b>%lld</b></p>"
                   "<table><thead><tr><th>Device</th><th>Channel</th><th>Outcome</th><th>Serial</th>"
                   "<th>Active DNA</th><th>Auth</th><th>Last Seen (UTC)</th></tr></thead><tbody>",
              (long long)sdeps, (long long)tot, (long long)hlth, (long long)rb, (long long)sdev);

    const jval_t *devs = jobj_get(rep, "devices");
    if (devs && devs->type == J_ARR && devs->count > 0) {
        for (size_t i = 0; i < devs->count; i++) {
            const jval_t *d = devs->items[i];
            char did[65], ch[33], oc[33], dna[65], ls[32];
            int64_t ser = 0;
            jobj_copy_str(d, "device_id", "", did, sizeof(did));
            jobj_copy_str(d, "channel", "", ch, sizeof(ch));
            jobj_copy_str(d, "outcome", "", oc, sizeof(oc));
            jobj_copy_str(d, "active_dna", "", dna, sizeof(dna));
            jobj_copy_str(d, "last_seen_utc", "", ls, sizeof(ls));
            (void)jobj_strict_i64(d, "active_serial", 0, 0, &ser);
            const jval_t *av = jobj_get(d, "auth_verified");
            int auth = (av && av->type == J_BOOL && av->bval);
            dna[16] = '\0';
            sb_puts(out, "<tr><td>"); sb_html_esc(out, did);
            sb_puts(out, "</td><td>"); sb_html_esc(out, ch);
            sb_puts(out, "</td><td><b>"); sb_html_esc(out, oc);
            sb_printf(out, "</b></td><td>#%lld</td><td><code>", (long long)ser);
            sb_html_esc(out, dna);
            sb_puts(out, "...</code></td><td>");
            sb_puts(out, auth ? "Ed25519 Verified" : "Unsigned");
            sb_puts(out, "</td><td>"); sb_html_esc(out, ls);
            sb_puts(out, "</td></tr>");
        }
    } else {
        sb_puts(out, "<tr><td colspan=\"7\">No devices recorded.</td></tr>");
    }

    sb_puts(out, "</tbody></table><h2>2. Immutable Signed Release Ledger</h2>"
                 "<table><thead><tr><th>Event File</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>");
    const jval_t *evs = jobj_get(rep, "signed_events");
    if (evs && evs->type == J_ARR && evs->count > 0) {
        for (size_t i = 0; i < evs->count; i++) {
            const jval_t *e = evs->items[i];
            char fn[64], sha[65];
            int64_t sz = 0;
            jobj_copy_str(e, "file", "", fn, sizeof(fn));
            jobj_copy_str(e, "sha256", "", sha, sizeof(sha));
            (void)jobj_strict_i64(e, "size_bytes", 0, 0, &sz);
            sb_puts(out, "<tr><td><code>"); sb_html_esc(out, fn);
            sb_printf(out, "</code></td><td>%lld B</td><td><code>", (long long)sz);
            sb_html_esc(out, sha);
            sb_puts(out, "</code></td></tr>");
        }
    } else {
        sb_puts(out, "<tr><td colspan=\"3\">No signed events.</td></tr>");
    }
    sb_puts(out, "</tbody></table></body></html>");
    jval_free(rep);
}

/* Split into <4095 B chunks for strict ISO C11 -pedantic compliance */
static const char *const DASHBOARD_CHUNKS[] = {
    "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
    "<title>SealFrame — Enterprise Edge Control Plane v0.5 (C11)</title>\n<style>\n"
    "  :root{--bg:#0b1020;--card:#131b31;--line:#233052;--txt:#e6ecf8;--mut:#92a3c7;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--acc:#38bdf8}\n"
    "  body{margin:0;font:14px/1.5 system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--txt);padding:24px}\n"
    "  .wrap{max-width:1180px;margin:0 auto}h1{margin:0 0 4px;font-size:22px;letter-spacing:.3px}\n"
    "  .sub{color:var(--mut);margin-bottom:18px}\n"
    "  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:18px}\n"
    "  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}\n"
    "  .kpi{font-size:26px;font-weight:700;margin-top:4px}\n"
    "  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:18px}\n"
    "  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);font-size:13px}\n"
    "  th{color:var(--mut);font-weight:600;background:#0f162a}\n"
    "  .pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}\n"
    "  .UPDATED,.UP_TO_DATE,.AUTH_OK{background:rgba(34,197,94,.16);color:var(--ok)}\n"
    "  .ROLLED_BACK{background:rgba(245,158,11,.18);color:var(--warn)}\n"
    "  .REJECTED,.REVOKED,.AUTH_NO{background:rgba(239,68,68,.18);color:var(--bad)}\n"
    "  .bar{display:flex;gap:10px;align-items:center;margin-bottom:16px;flex-wrap:wrap}\n"
    "  a.btn,button{background:var(--acc);color:#061224;border:0;padding:8px 14px;border-radius:7px;font-weight:700;cursor:pointer;text-decoration:none;font-size:13px}\n"
    "  button.danger{background:var(--bad);color:#fff}\n"
    "  input,select{background:#0f162a;border:1px solid var(--line);color:var(--txt);padding:7px 10px;border-radius:7px;font-size:13px}\n"
    "  code{font-family:ui-monospace,monospace;font-size:12px;color:#cbd5f5}\n"
    "</style></head><body><div class=\"wrap\">\n"
    "  <h1>SealFrame — Enterprise Edge Control Plane v0.5 (Pure C11)</h1>\n"
    "  <div class=\"sub\">Industrial B2B OTA &middot; Ed25519 Signed Telemetry &middot; Hybrid LAN/HTTP &middot; EU CRA Compliance</div>\n"
    "  <div class=\"bar\">\n"
    "    <button onclick=\"loadData()\">Refresh Fleet</button>\n"
    "    <a class=\"btn\" href=\"/api/v1/audit/cra\" target=\"_blank\">CRA Audit JSON</a>\n"
    "    <a class=\"btn\" href=\"/api/v1/audit/cra.html\" target=\"_blank\">Printable CRA Report (PDF/HTML)</a>\n"
    "  </div>\n  <div class=\"grid\" id=\"kpis\"></div>\n"
    "  <div class=\"card\" style=\"margin-bottom:18px\">\n"
    "    <div style=\"font-weight:700;margin-bottom:8px\">Authenticated Rollout &amp; Emergency Rollback (Bearer RBAC)</div>\n"
    "    <div class=\"bar\" style=\"margin:0\">\n"
    "      <input id=\"tok\" type=\"password\" placeholder=\"Admin Bearer Token\" style=\"width:240px\">\n"
    "      <select id=\"ch\"><option value=\"canary\">canary</option><option value=\"stable\">stable</option></select>\n"
    "      <input id=\"ser\" type=\"number\" min=\"1\" value=\"1\" style=\"width:90px\" placeholder=\"Serial\">\n"
    "      <button onclick=\"promote(false)\">Promote Serial</button>\n"
    "      <button class=\"danger\" onclick=\"promote(true)\">Emergency Rollback</button>\n"
    "      <span id=\"msg\" style=\"color:var(--mut);font-size:12px\"></span>\n"
    "    </div>\n  </div>\n"
    "  <table><thead><tr>\n"
    "    <th>Device</th><th>Auth</th><th>Channel</th><th>Outcome</th><th>Active</th>\n"
    "    <th>LAN / HTTP</th><th>Root</th><th>Detail</th><th>Last Seen (UTC)</th>\n"
    "  </tr></thead><tbody id=\"rows\"></tbody></table>\n</div>\n",

    "<script>\n"
    "function escHtml(v){\n"
    "  return String(v == null ? '' : v)\n"
    "    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')\n"
    "    .replace(/\"/g,'&quot;').replace(/'/g,'&#39;');\n"
    "}\n"
    "const OK_OUTCOMES = new Set(['UPDATED','UP_TO_DATE','ROLLED_BACK','REJECTED','REVOKED']);\n"
    "function safeClass(o){ return OK_OUTCOMES.has(o) ? o : 'REJECTED'; }\n"
    "async function promote(isRollback){\n"
    "  const tok = document.getElementById('tok').value.trim();\n"
    "  const ch = document.getElementById('ch').value;\n"
    "  const ser = parseInt(document.getElementById('ser').value, 10);\n"
    "  const ep = isRollback ? '/api/v1/emergency/rollback' : '/api/v1/channels/' + ch;\n"
    "  const body = isRollback ? {channel: ch, serial: ser} : {serial: ser};\n"
    "  const r = await fetch(ep, {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+tok}, body:JSON.stringify(body)});\n"
    "  const j = await r.json();\n"
    "  document.getElementById('msg').textContent = (r.ok ? 'OK: ' : 'DENIED: ') + (j.message || j.error || r.status);\n"
    "  loadData();\n"
    "}\n"
    "async function loadData(){\n"
    "  const tok = document.getElementById('tok').value.trim();\n"
    "  const hdrs = tok ? {'Authorization':'Bearer '+tok} : {};\n"
    "  const r = await fetch('/api/v1/audit/cra', {headers: hdrs});\n"
    "  if (r.status === 401){\n"
    "    document.getElementById('kpis').innerHTML = '';\n"
    "    document.getElementById('rows').innerHTML = '<tr><td colspan=\"9\" style=\"color:var(--warn)\">Admin Bearer token required: enter token above and click Refresh Fleet.</td></tr>';\n"
    "    return;\n"
    "  }\n"
    "  if (!r.ok){ document.getElementById('msg').textContent = 'HTTP ' + r.status; return; }\n"
    "  const d = await r.json();\n"
    "  document.getElementById('kpis').innerHTML = `\n"
    "    <div class=\"card\"><div class=\"sub\">Managed Devices</div><div class=\"kpi\">${Number(d.fleet_summary.total_devices)||0}</div></div>\n"
    "    <div class=\"card\"><div class=\"sub\">Healthy / Compliant</div><div class=\"kpi\" style=\"color:var(--ok)\">${Number(d.fleet_summary.compliant_healthy)||0}</div></div>\n"
    "    <div class=\"card\"><div class=\"sub\">Ed25519 Verified</div><div class=\"kpi\" style=\"color:var(--acc)\">${Number(d.fleet_summary.ed25519_authenticated_devices)||0}</div></div>\n"
    "    <div class=\"card\"><div class=\"sub\">Auto Rolled-Back</div><div class=\"kpi\" style=\"color:var(--warn)\">${Number(d.fleet_summary.auto_rolled_back)||0}</div></div>\n"
    "    <div class=\"card\"><div class=\"sub\">Signed Releases</div><div class=\"kpi\">${Number(d.signed_events.length)||0}</div></div>`;\n"
    "  document.getElementById('rows').innerHTML = d.devices.map(x => `<tr>\n"
    "    <td><strong>${escHtml(x.device_id)}</strong><br><code>${escHtml(x.ip)}</code></td>\n"
    "    <td><span class=\"pill ${x.auth_verified?'AUTH_OK':'AUTH_NO'}\">${x.auth_verified?'Ed25519 OK':'Unsigned'}</span></td>\n"
    "    <td><code>${escHtml(x.channel)}</code></td>\n"
    "    <td><span class=\"pill ${safeClass(x.outcome)}\">${escHtml(x.outcome)}</span></td>\n"
    "    <td>#${Number(x.active_serial)||0}<br><code>${escHtml((x.active_dna||'').slice(0,12))}...</code></td>\n"
    "    <td><code>LAN:${Number(x.bytes_from_lan)||0}B<br>HTTP:${Number(x.bytes_downloaded)||0}B</code></td>\n"
    "    <td>v${Number(x.root_version)||0}</td>\n"
    "    <td>${escHtml(x.detail)}</td>\n"
    "    <td><code>${escHtml(x.last_seen_utc)}</code></td>\n"
    "  </tr>`).join('') || '<tr><td colspan=\"9\" style=\"color:var(--mut)\">No edge agents reported yet.</td></tr>';\n"
    "}\nloadData(); setInterval(loadData, 5000);\n</script></body></html>\n",
    NULL
};

/* ==================== HTTP/1.1 Server Engine ==================== */

static int send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 206: return "Partial Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 413: return "Payload Too Large";
        case 416: return "Range Not Satisfiable";
        case 500: return "Internal Server Error";
        default:  return "Error";
    }
}

static void send_resp(int fd, int code, const char *ctype, const void *body, size_t len, const char *extra_hdr) {
    char hdr[1024];
    int n = snprintf(
        hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n"
        "%s\r\n",
        code, status_text(code), ctype, len, extra_hdr ? extra_hdr : "");
    if (n > 0 && (size_t)n < sizeof(hdr)) {
        if (send_all(fd, hdr, (size_t)n) == 0 && len > 0) {
            (void)send_all(fd, body, len);
        }
    }
}

static void send_text(int fd, int code, const char *msg) {
    send_resp(fd, code, "text/plain", msg, strlen(msg), NULL);
}

static void send_json(int fd, int code, const char *json) {
    send_resp(fd, code, "application/json", json, strlen(json), NULL);
}

static void serve_file_with_range(int fd, const char *path, const char *range_hdr) {
    int ffd = open(path, O_RDONLY | O_NOFOLLOW);
    if (ffd < 0) { send_text(fd, 404, "not found"); return; }
    struct stat st;
    if (fstat(ffd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(ffd);
        send_text(fd, 404, "not found");
        return;
    }
    uint64_t total = (uint64_t)st.st_size;
    uint64_t start = 0;
    uint64_t end = total > 0 ? total - 1u : 0u;
    int code = 200;
    char extra[256] = "Accept-Ranges: bytes\r\n";

    if (range_hdr && strncmp(range_hdr, "bytes=", 6) == 0) {
        const char *spec = range_hdr + 6;
        while (*spec == ' ') spec++;
        const char *dash = strchr(spec, '-');
        if (!dash || total == 0) {
            close(ffd);
            send_text(fd, 416, "range not satisfiable");
            return;
        }
        if (dash == spec) {
            close(ffd);
            send_text(fd, 416, "bad range");
            return;
        }
        char s1[32], s2[32];
        size_t l1 = (size_t)(dash - spec);
        size_t l2 = strlen(dash + 1);
        if (l1 >= sizeof(s1) || l2 >= sizeof(s2)) {
            close(ffd);
            send_text(fd, 416, "bad range");
            return;
        }
        memcpy(s1, spec, l1); s1[l1] = '\0';
        memcpy(s2, dash + 1, l2 + 1u);
        if (!is_digits_only(s1) || (l2 > 0 && !is_digits_only(s2))) {
            close(ffd);
            send_text(fd, 416, "bad range");
            return;
        }
        errno = 0;
        start = strtoull(s1, NULL, 10);
        if (errno != 0) { close(ffd); send_text(fd, 416, "bad range"); return; }
        if (l2 > 0) {
            errno = 0;
            end = strtoull(s2, NULL, 10);
            if (errno != 0) { close(ffd); send_text(fd, 416, "bad range"); return; }
        } else {
            end = total - 1u;
        }
        if (start >= total || end < start) {
            close(ffd);
            send_text(fd, 416, "range not satisfiable");
            return;
        }
        if (end >= total) end = total - 1u;
        code = 206;
        snprintf(extra, sizeof(extra), "Accept-Ranges: bytes\r\nContent-Range: bytes %llu-%llu/%llu\r\n",
                 (unsigned long long)start, (unsigned long long)end, (unsigned long long)total);
    }

    uint64_t length = (total > 0) ? (end - start + 1u) : 0u;
    char hdr[1024];
    int hn = snprintf(
        hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %llu\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n"
        "%s\r\n",
        code, status_text(code), (unsigned long long)length, extra);
    if (hn > 0 && send_all(fd, hdr, (size_t)hn) == 0) {
        uint8_t buf[65536];
        uint64_t off = start;
        uint64_t rem = length;
        while (rem > 0) {
            size_t want = rem > sizeof(buf) ? sizeof(buf) : (size_t)rem;
            ssize_t r = pread(ffd, buf, want, (off_t)off);
            if (r < 0) { if (errno == EINTR) continue; break; }
            if (r == 0) break;
            if (send_all(fd, buf, (size_t)r) != 0) break;
            off += (uint64_t)r;
            rem -= (uint64_t)r;
        }
    }
    close(ffd);
}

static int ascii_strncasecmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)tolower((unsigned char)a[i]);
        unsigned char cb = (unsigned char)tolower((unsigned char)b[i]);
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

static void trim_copy(const char *src, size_t len, char *dst, size_t cap) {
    while (len > 0 && (*src == ' ' || *src == '\t')) { src++; len--; }
    while (len > 0 && (src[len - 1] == ' ' || src[len - 1] == '\t' || src[len - 1] == '\r')) len--;
    if (len >= cap) len = cap - 1u;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

typedef struct {
    cp_state_t *st;
    int         cfd;
    char        ip[64];
} conn_ctx_t;

static void handle_client(cp_state_t *st, int cfd, const char *client_ip) {
    struct timeval tv = { 10, 0 };
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* 1. Read HTTP header */
    char hbuf[CP_MAX_HDR_BYTES + 1u];
    size_t hlen = 0;
    char *hdr_end = NULL;
    while (hlen < CP_MAX_HDR_BYTES) {
        ssize_t r = recv(cfd, hbuf + hlen, CP_MAX_HDR_BYTES - hlen, 0);
        if (r < 0) { if (errno == EINTR) continue; return; }
        if (r == 0) return;
        hlen += (size_t)r;
        hbuf[hlen] = '\0';
        hdr_end = strstr(hbuf, "\r\n\r\n");
        if (hdr_end) break;
    }
    if (!hdr_end) { send_text(cfd, 400, "bad request"); return; }

    size_t hdr_bytes = (size_t)(hdr_end - hbuf) + 4u;
    char *line_end = strstr(hbuf, "\r\n");
    if (!line_end || line_end > hdr_end) { send_text(cfd, 400, "bad request"); return; }

    /* Parse request line: METHOD PATH HTTP/1.x */
    char req_line[1024];
    size_t rl_len = (size_t)(line_end - hbuf);
    if (rl_len == 0 || rl_len >= sizeof(req_line)) { send_text(cfd, 400, "bad request"); return; }
    memcpy(req_line, hbuf, rl_len);
    req_line[rl_len] = '\0';

    char *sp1 = strchr(req_line, ' ');
    if (!sp1) { send_text(cfd, 400, "bad request"); return; }
    *sp1 = '\0';
    char *path_start = sp1 + 1;
    char *sp2 = strchr(path_start, ' ');
    if (!sp2 || strncmp(sp2 + 1, "HTTP/1.", 7) != 0) { send_text(cfd, 400, "bad request"); return; }
    *sp2 = '\0';
    char *qmark = strchr(path_start, '?');
    if (qmark) *qmark = '\0';

    const char *method = req_line;
    const char *path = path_start;
    if (path[0] != '/') { send_text(cfd, 400, "bad path"); return; }

    /* Parse headers */
    char hdr_clen[64] = "", hdr_range[128] = "", hdr_auth[256] = "";
    char hdr_pk[128] = "", hdr_sig[256] = "";
    int seen_clen = 0;

    char *cur = line_end + 2;
    while (cur < hdr_end) {
        char *next = strstr(cur, "\r\n");
        if (!next || next > hdr_end) break;
        char *colon = memchr(cur, ':', (size_t)(next - cur));
        if (colon) {
            size_t klen = (size_t)(colon - cur);
            const char *v = colon + 1;
            size_t vlen = (size_t)(next - v);
            if (klen == 14 && ascii_strncasecmp(cur, "Content-Length", 14) == 0) {
                if (seen_clen) { send_text(cfd, 400, "duplicate content-length"); return; }
                seen_clen = 1;
                trim_copy(v, vlen, hdr_clen, sizeof(hdr_clen));
            } else if (klen == 5 && ascii_strncasecmp(cur, "Range", 5) == 0) {
                trim_copy(v, vlen, hdr_range, sizeof(hdr_range));
            } else if (klen == 13 && ascii_strncasecmp(cur, "Authorization", 13) == 0) {
                trim_copy(v, vlen, hdr_auth, sizeof(hdr_auth));
            } else if ((klen == 18 && ascii_strncasecmp(cur, "X-SF-Device-PubKey", 18) == 0) ||
                       (klen == 18 && ascii_strncasecmp(cur, "X-FP-Device-PubKey", 18) == 0)) {
                if (!hdr_pk[0]) trim_copy(v, vlen, hdr_pk, sizeof(hdr_pk));
            } else if ((klen == 14 && ascii_strncasecmp(cur, "X-SF-Signature", 14) == 0) ||
                       (klen == 14 && ascii_strncasecmp(cur, "X-FP-Signature", 14) == 0)) {
                if (!hdr_sig[0]) trim_copy(v, vlen, hdr_sig, sizeof(hdr_sig));
            }
        }
        cur = next + 2;
    }

    /* ---------- GET ---------- */
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
            sbuf_t html;
            sb_init(&html, 4096);
            for (size_t i = 0; DASHBOARD_CHUNKS[i]; i++) sb_puts(&html, DASHBOARD_CHUNKS[i]);
            send_resp(cfd, 200, "text/html; charset=utf-8", html.data, html.len, NULL);
            sb_free(&html);
            return;
        }
        if (strcmp(path, "/api/v1/fleet") == 0) {
            if (st->require_admin_read_auth && !check_admin_bearer(st, hdr_auth)) {
                send_json(cfd, 401, "{\"ok\":false,\"error\":\"unauthorized: valid Bearer token required\"}");
                return;
            }
            sbuf_t jb;
            sb_init(&jb, 512);
            sb_puts(&jb, "{\"devices\":");
            pthread_mutex_lock(&st->mu);
            append_devices_json(st->db, &jb, NULL, NULL, NULL, NULL);
            pthread_mutex_unlock(&st->mu);
            sb_putc(&jb, '}');
            send_json(cfd, 200, jb.data);
            sb_free(&jb);
            return;
        }
        if (strcmp(path, "/api/v1/approvals") == 0) {
            if (st->require_admin_read_auth && !check_admin_bearer(st, hdr_auth)) {
                send_json(cfd, 401, "{\"ok\":false,\"error\":\"unauthorized: valid Bearer token required\"}");
                return;
            }
            sbuf_t jb;
            sb_init(&jb, 512);
            sb_puts(&jb, "{\"approvals\":");
            pthread_mutex_lock(&st->mu);
            append_approvals_json(st->db, &jb, NULL, 0, NULL);
            pthread_mutex_unlock(&st->mu);
            sb_putc(&jb, '}');
            send_json(cfd, 200, jb.data);
            sb_free(&jb);
            return;
        }
        if (strcmp(path, "/api/v1/audit/cra") == 0) {
            if (st->require_admin_read_auth && !check_admin_bearer(st, hdr_auth)) {
                send_json(cfd, 401, "{\"ok\":false,\"error\":\"unauthorized: valid Bearer token required\"}");
                return;
            }
            sbuf_t jb;
            sb_init(&jb, 4096);
            cp_build_cra_json(st, &jb);
            send_json(cfd, 200, jb.data);
            sb_free(&jb);
            return;
        }
        if (strcmp(path, "/api/v1/audit/cra.html") == 0) {
            if (st->require_admin_read_auth && !check_admin_bearer(st, hdr_auth)) {
                send_json(cfd, 401, "{\"ok\":false,\"error\":\"unauthorized: valid Bearer token required\"}");
                return;
            }
            sbuf_t hb;
            sb_init(&hb, 4096);
            cp_build_cra_html(st, &hb);
            send_resp(cfd, 200, "text/html; charset=utf-8", hb.data, hb.len, NULL);
            sb_free(&hb);
            return;
        }
        char fpath[PATH_MAX];
        if (strcmp(path, "/repo/root.fpr") == 0) {
            if (snprintf(fpath, sizeof(fpath), "%s/root.fpr", st->repo_dir) >= (int)sizeof(fpath)) {
                send_text(cfd, 404, "not found"); return;
            }
            serve_file_with_range(cfd, fpath, hdr_range);
            return;
        }
        if (strncmp(path, "/repo/roots/", 12) == 0) {
            const char *rest = path + 12;
            size_t rlen = strlen(rest);
            if (rlen > 4u && strcmp(rest + rlen - 4u, ".fpr") == 0) {
                char num[32];
                size_t nl = rlen - 4u;
                if (nl == 0 || nl >= sizeof(num)) { send_text(cfd, 400, "bad root version"); return; }
                memcpy(num, rest, nl); num[nl] = '\0';
                if (!is_digits_only(num)) { send_text(cfd, 400, "bad root version"); return; }
                if (snprintf(fpath, sizeof(fpath), "%s/roots/%s.fpr", st->repo_dir, num) >= (int)sizeof(fpath)) {
                    send_text(cfd, 404, "not found"); return;
                }
                serve_file_with_range(cfd, fpath, hdr_range);
                return;
            }
        }
        if (strcmp(path, "/repo/latest.ev") == 0) {
            /* SEC-05: Serve single authoritative stable channel pointer directly (zero dual-write split-brain) */
            if (snprintf(fpath, sizeof(fpath), "%s/stable/latest.ev", st->chan_dir) >= (int)sizeof(fpath)) {
                send_text(cfd, 404, "not found"); return;
            }
            struct stat lsb;
            if (stat(fpath, &lsb) != 0) {
                if (snprintf(fpath, sizeof(fpath), "%s/latest.ev", st->repo_dir) >= (int)sizeof(fpath)) {
                    send_text(cfd, 404, "not found"); return;
                }
            }
            serve_file_with_range(cfd, fpath, hdr_range);
            return;
        }
        if (strncmp(path, "/repo/channels/", 15) == 0) {
            const char *rest = path + 15;
            size_t rlen = strlen(rest);
            if (rlen > 10u && strcmp(rest + rlen - 10u, "/latest.ev") == 0) {
                char ch[64];
                size_t cl = rlen - 10u;
                if (cl == 0 || cl >= sizeof(ch)) { send_text(cfd, 400, "bad channel"); return; }
                memcpy(ch, rest, cl); ch[cl] = '\0';
                if (!is_valid_channel(ch)) { send_text(cfd, 400, "bad channel"); return; }
                if (snprintf(fpath, sizeof(fpath), "%s/%s/latest.ev", st->chan_dir, ch) >= (int)sizeof(fpath)) {
                    send_text(cfd, 404, "not found"); return;
                }
                serve_file_with_range(cfd, fpath, hdr_range);
                return;
            }
        }
        if (strncmp(path, "/repo/events/", 13) == 0) {
            const char *rest = path + 13;
            size_t rlen = strlen(rest);
            if (rlen > 3u && strcmp(rest + rlen - 3u, ".ev") == 0) {
                char num[32];
                size_t nl = rlen - 3u;
                if (nl == 0 || nl >= sizeof(num)) { send_text(cfd, 400, "bad serial"); return; }
                memcpy(num, rest, nl); num[nl] = '\0';
                if (!is_digits_only(num)) { send_text(cfd, 400, "bad serial"); return; }
                if (snprintf(fpath, sizeof(fpath), "%s/%s.ev", st->ev_dir, num) >= (int)sizeof(fpath)) {
                    send_text(cfd, 404, "not found"); return;
                }
                serve_file_with_range(cfd, fpath, hdr_range);
                return;
            }
        }
        if (strncmp(path, "/repo/objects/", 14) == 0) {
            const char *hex_id = path + 14;
            if (!is_hex_lower(hex_id, 64u)) { send_text(cfd, 400, "bad dna"); return; }
            if (snprintf(fpath, sizeof(fpath), "%s/%s", st->obj_dir, hex_id) >= (int)sizeof(fpath)) {
                send_text(cfd, 404, "not found"); return;
            }
            serve_file_with_range(cfd, fpath, hdr_range);
            return;
        }
        send_text(cfd, 404, "not found");
        return;
    }

    /* ---------- POST ---------- */
    if (strcmp(method, "POST") == 0) {
        size_t clen = 0;
        if (seen_clen) {
            if (!is_digits_only(hdr_clen)) { send_text(cfd, 400, "invalid content-length"); return; }
            errno = 0;
            unsigned long long v = strtoull(hdr_clen, NULL, 10);
            if (errno != 0 || v > CP_MAX_BODY_BYTES) { send_text(cfd, 413, "too large"); return; }
            clen = (size_t)v;
        }

        char *raw_body = malloc(clen > 0 ? clen + 1u : 3u);
        if (!raw_body) { send_text(cfd, 500, "oom"); return; }
        size_t got = 0;
        if (clen > 0) {
            size_t already = hlen - hdr_bytes;
            if (already > clen) already = clen;
            if (already > 0) { memcpy(raw_body, hbuf + hdr_bytes, already); got = already; }
            while (got < clen) {
                ssize_t r = recv(cfd, raw_body + got, clen - got, 0);
                if (r < 0) { if (errno == EINTR) continue; free(raw_body); return; }
                if (r == 0) { free(raw_body); send_text(cfd, 400, "truncated body"); return; }
                got += (size_t)r;
            }
            raw_body[clen] = '\0';
        } else {
            memcpy(raw_body, "{}", 3);
            clen = 2;
        }

        jval_t *body = json_parse(raw_body, clen);
        if (!body) {
            free(raw_body);
            send_text(cfd, 400, "invalid json");
            return;
        }
        if (body->type != J_OBJ) {
            jval_free(body);
            free(raw_body);
            send_text(cfd, 400, "json object required");
            return;
        }

        if (strcmp(path, "/api/v1/heartbeat") == 0) {
            for (char *p = hdr_pk; *p; p++) *p = (char)tolower((unsigned char)*p);
            for (char *p = hdr_sig; *p; p++) *p = (char)tolower((unsigned char)*p);
            int auth_ok = 0;
            if (hdr_pk[0] || hdr_sig[0]) {
                uint8_t pk[32], sig[64];
                if (hex_decode_lower(hdr_pk, pk, 32) == 0 &&
                    hex_decode_lower(hdr_sig, sig, 64) == 0 &&
                    crypto_sign_ed25519_verify_detached(sig, (const uint8_t *)raw_body,
                                                        (unsigned long long)clen, pk) == 0) {
                    auth_ok = 1;
                } else {
                    jval_free(body); free(raw_body);
                    send_json(cfd, 401, "{\"ok\":false,\"error\":\"invalid Ed25519 heartbeat signature\"}");
                    return;
                }
            } else if (st->require_signed_hb) {
                jval_free(body); free(raw_body);
                send_json(cfd, 401, "{\"ok\":false,\"error\":\"signed Ed25519 heartbeat required\"}");
                return;
            }
            char dev_id[65], err_msg[256];
            int http_rc = 400;
            if (cp_record_heartbeat(st, client_ip, body, auth_ok, hdr_pk, dev_id,
                                    &http_rc, err_msg, sizeof(err_msg)) != 0) {
                sbuf_t er;
                sb_init(&er, 256);
                sb_puts(&er, "{\"ok\":false,\"error\":");
                sb_json_str(&er, err_msg);
                sb_putc(&er, '}');
                send_json(cfd, http_rc, er.data);
                sb_free(&er);
                jval_free(body); free(raw_body);
                return;
            }
            sbuf_t resp;
            sb_init(&resp, 160);
            sb_puts(&resp, "{\"ok\":true,\"device\":");
            sb_json_str(&resp, dev_id);
            sb_printf(&resp, ",\"auth_verified\":%s}", auth_ok ? "true" : "false");
            send_json(cfd, 200, resp.data);
            sb_free(&resp);
            jval_free(body); free(raw_body);
            return;
        }

        if (strncmp(path, "/api/v1/channels/", 17) == 0 ||
            strcmp(path, "/api/v1/emergency/rollback") == 0 ||
            strcmp(path, "/api/v1/approvals") == 0 ||
            strcmp(path, "/api/v1/approvers") == 0 ||
            strcmp(path, "/api/v1/devices/enroll") == 0) {
            if (!check_admin_bearer(st, hdr_auth)) {
                jval_free(body); free(raw_body);
                send_json(cfd, 401, "{\"ok\":false,\"error\":\"unauthorized: valid Bearer token required\"}");
                return;
            }
            if (strcmp(path, "/api/v1/devices/enroll") == 0) {
                char dev_id[65], pk_hex[80];
                jobj_copy_str(body, "device_id", "", dev_id, sizeof(dev_id));
                jobj_copy_str(body, "pubkey", "", pk_hex, sizeof(pk_hex));
                for (char *p = pk_hex; *p; p++) *p = (char)tolower((unsigned char)*p);
                uint8_t pk_raw[32];
                if (!dev_id[0] || strlen(pk_hex) != 64 || hex_decode_lower(pk_hex, pk_raw, 32) != 0) {
                    jval_free(body); free(raw_body);
                    send_json(cfd, 400, "{\"ok\":false,\"error\":\"device_id and 64-hex Ed25519 pubkey required\"}");
                    return;
                }
                char utc[32];
                utc_now(utc);
                pthread_mutex_lock(&st->mu);
                sqlite3_stmt *stmt = NULL;
                int erc = sqlite3_prepare_v2(
                        st->db,
                        "INSERT INTO enrolled_devices(device_id,pubkey,last_seq,enrolled_utc) VALUES(?,?,0,?) "
                        "ON CONFLICT(device_id) DO UPDATE SET "
                        "last_seq = CASE WHEN enrolled_devices.pubkey = excluded.pubkey THEN enrolled_devices.last_seq ELSE 0 END, "
                        "pubkey=excluded.pubkey, enrolled_utc=excluded.enrolled_utc;",
                        -1, &stmt, NULL);
                if (erc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, dev_id, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, pk_hex, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 3, utc, -1, SQLITE_TRANSIENT);
                    erc = sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                if (erc != SQLITE_DONE) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 500, "{\"ok\":false,\"error\":\"database enrollment write failed\"}");
                    return;
                }
                char det[256];
                snprintf(det, sizeof(det), "Enrolled Ed25519 pubkey %.16s... for %s", pk_hex, dev_id);
                if (db_append_audit(st->db, dev_id, "admin", "enrollment", "DEVICE_ENROLLED", 0, det, 1, utc) != 0) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 500, "{\"ok\":false,\"error\":\"database audit write failed\"}");
                    return;
                }
                pthread_mutex_unlock(&st->mu);
                sbuf_t resp;
                sb_init(&resp, 192);
                sb_puts(&resp, "{\"ok\":true,\"device_id\":");
                sb_json_str(&resp, dev_id);
                sb_puts(&resp, ",\"pubkey\":");
                sb_json_str(&resp, pk_hex);
                sb_putc(&resp, '}');
                send_json(cfd, 200, resp.data);
                sb_free(&resp);
                jval_free(body); free(raw_body);
                return;
            }
            if (strcmp(path, "/api/v1/approvers") == 0) {
                char approver[65], pk_hex[80];
                jobj_copy_str(body, "approver", "", approver, sizeof(approver));
                jobj_copy_str(body, "pubkey", "", pk_hex, sizeof(pk_hex));
                for (char *p = pk_hex; *p; p++) *p = (char)tolower((unsigned char)*p);
                uint8_t pk_raw[32];
                if (!approver[0] || strlen(pk_hex) != 64 || hex_decode_lower(pk_hex, pk_raw, 32) != 0) {
                    jval_free(body); free(raw_body);
                    send_json(cfd, 400, "{\"ok\":false,\"error\":\"approver and 64-hex Ed25519 pubkey required\"}");
                    return;
                }
                char utc[32];
                utc_now(utc);
                pthread_mutex_lock(&st->mu);
                sqlite3_stmt *stmt = NULL;
                int arc = sqlite3_prepare_v2(
                        st->db,
                        "INSERT INTO approvers(approver,pubkey,added_utc) VALUES(?,?,?) "
                        "ON CONFLICT(approver) DO UPDATE SET pubkey=excluded.pubkey, added_utc=excluded.added_utc;",
                        -1, &stmt, NULL);
                if (arc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, approver, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 2, pk_hex, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 3, utc, -1, SQLITE_TRANSIENT);
                    arc = sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                if (arc == SQLITE_CONSTRAINT || arc == SQLITE_CONSTRAINT_UNIQUE) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 409, "{\"ok\":false,\"error\":\"approver pubkey already registered to another identity\"}");
                    return;
                }
                if (arc != SQLITE_DONE) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 500, "{\"ok\":false,\"error\":\"database approver write failed\"}");
                    return;
                }
                char det[256];
                snprintf(det, sizeof(det), "Registered Ed25519 approver %s (%.16s...)", approver, pk_hex);
                if (db_append_audit(st->db, "CONTROL_PLANE", "admin", "governance", "APPROVER_ADDED", 0, det, 1, utc) != 0) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 500, "{\"ok\":false,\"error\":\"database audit write failed\"}");
                    return;
                }
                pthread_mutex_unlock(&st->mu);
                sbuf_t resp;
                sb_init(&resp, 192);
                sb_puts(&resp, "{\"ok\":true,\"approver\":");
                sb_json_str(&resp, approver);
                sb_puts(&resp, ",\"pubkey\":");
                sb_json_str(&resp, pk_hex);
                sb_putc(&resp, '}');
                send_json(cfd, 200, resp.data);
                sb_free(&resp);
                jval_free(body); free(raw_body);
                return;
            }
            if (strcmp(path, "/api/v1/approvals") == 0) {
                const jval_t *sv = jobj_get(body, "serial");
                char ch[64], approver[65], reason[161], sig_hex[160];
                jobj_copy_str(body, "channel", "stable", ch, sizeof(ch));
                jobj_copy_str(body, "approver", "", approver, sizeof(approver));
                jobj_copy_str(body, "reason", "", reason, sizeof(reason));
                jobj_copy_str(body, "signature", "", sig_hex, sizeof(sig_hex));
                for (char *p = sig_hex; *p; p++) *p = (char)tolower((unsigned char)*p);
                if (!sv || sv->type != J_INT || sv->ival < 1 || !approver[0] || !is_valid_channel(ch)) {
                    jval_free(body); free(raw_body);
                    send_json(cfd, 400, "{\"ok\":false,\"error\":\"serial (int>=1), valid channel, and approver required\"}");
                    return;
                }
                int64_t serial = sv->ival;
                char ev_path[PATH_MAX], ev_hash_hex[65];
                fp_event_t ev;
                if (snprintf(ev_path, sizeof(ev_path), "%s/%lld.ev", st->ev_dir, (long long)serial) >= (int)sizeof(ev_path) ||
                    cp_load_event_file(ev_path, &ev, ev_hash_hex) != 0) {
                    jval_free(body); free(raw_body);
                    send_json(cfd, 404, "{\"ok\":false,\"error\":\"target event file not found or invalid\"}");
                    return;
                }
                /* Verify approver is registered & Ed25519 signature matches canonical approval payload */
                pthread_mutex_lock(&st->mu);
                char app_pk_hex[65];
                app_pk_hex[0] = '\0';
                sqlite3_stmt *stmt = NULL;
                int lrc = sqlite3_prepare_v2(st->db, "SELECT pubkey FROM approvers WHERE approver=?;",
                                             -1, &stmt, NULL);
                if (lrc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, approver, -1, SQLITE_TRANSIENT);
                    lrc = sqlite3_step(stmt);
                    if (lrc == SQLITE_ROW) {
                        const char *pkc = (const char *)sqlite3_column_text(stmt, 0);
                        snprintf(app_pk_hex, sizeof(app_pk_hex), "%.64s", pkc ? pkc : "");
                    }
                    sqlite3_finalize(stmt);
                }
                if (lrc != SQLITE_ROW && lrc != SQLITE_DONE) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 500, "{\"ok\":false,\"error\":\"database approver lookup failed\"}");
                    return;
                }
                if (strlen(app_pk_hex) != 64) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 403, "{\"ok\":false,\"error\":\"approver not registered in /api/v1/approvers\"}");
                    return;
                }
                uint8_t pk_raw[32], sig_raw[64];
                char canonical[256];
                int cl = snprintf(canonical, sizeof(canonical), "SF_APPROVAL_V1|%s|%lld|%s",
                                  ch, (long long)serial, ev_hash_hex);
                if (cl <= 0 || (size_t)cl >= sizeof(canonical) ||
                    strlen(sig_hex) != 128 ||
                    hex_decode_lower(app_pk_hex, pk_raw, 32) != 0 ||
                    hex_decode_lower(sig_hex, sig_raw, 64) != 0 ||
                    crypto_sign_ed25519_verify_detached(sig_raw, (const uint8_t *)canonical,
                                                        (unsigned long long)cl, pk_raw) != 0) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 401, "{\"ok\":false,\"error\":\"invalid Ed25519 approver signature\"}");
                    return;
                }

                int thr = 2;
                char utc[32];
                utc_now(utc);
                int wrc = sqlite3_prepare_v2(
                        st->db,
                        "INSERT OR REPLACE INTO approvals("
                        "channel,serial,approver,approver_pubkey,event_hash,signature,approved_utc,reason,threshold) "
                        "VALUES(?,?,?,?,?,?,?,?,?);", -1, &stmt, NULL);
                if (wrc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, ch, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int64(stmt, 2, serial);
                    sqlite3_bind_text(stmt, 3, approver, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 4, app_pk_hex, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 5, ev_hash_hex, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 6, sig_hex, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 7, utc, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(stmt, 8, reason, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 9, thr);
                    wrc = sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
                if (wrc != SQLITE_DONE) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 500, "{\"ok\":false,\"error\":\"database approval write failed\"}");
                    return;
                }
                int cnt = 0;
                if (sqlite3_prepare_v2(
                        st->db,
                        "SELECT COUNT(DISTINCT r.pubkey) FROM approvals a "
                        "JOIN approvers r ON a.approver = r.approver AND a.approver_pubkey = r.pubkey "
                        "WHERE a.channel=? AND a.serial=? AND a.event_hash=? AND length(a.approver_pubkey) = 64;",
                        -1, &stmt, NULL) == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, ch, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int64(stmt, 2, serial);
                    sqlite3_bind_text(stmt, 3, ev_hash_hex, -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(stmt) == SQLITE_ROW) cnt = sqlite3_column_int(stmt, 0);
                    sqlite3_finalize(stmt);
                }
                char dev_tag[96], det[320];
                snprintf(dev_tag, sizeof(dev_tag), "APPROVER:%s", approver);
                snprintf(det, sizeof(det), "Ed25519-verified approval %d/%d for %s#%lld: %s",
                         cnt, thr, ch, (long long)serial, reason);
                if (db_append_audit(st->db, dev_tag, "admin", ch,
                                    (cnt >= thr) ? "QUORUM_MET" : "APPROVED_PARTIAL",
                                    serial, det, 1, utc) != 0) {
                    pthread_mutex_unlock(&st->mu);
                    jval_free(body); free(raw_body);
                    send_json(cfd, 500, "{\"ok\":false,\"error\":\"database audit write failed\"}");
                    return;
                }
                sbuf_t resp;
                sb_init(&resp, 256);
                sb_puts(&resp, "{\"ok\":true,\"approval\":");
                append_approvals_json(st->db, &resp, ch, serial, ev_hash_hex);
                sb_putc(&resp, '}');
                pthread_mutex_unlock(&st->mu);
                send_json(cfd, 200, resp.data);
                sb_free(&resp);
                jval_free(body); free(raw_body);
                return;
            }
            if (strcmp(path, "/api/v1/emergency/rollback") == 0) {
                char ch[64];
                jobj_copy_str(body, "channel", "stable", ch, sizeof(ch));
                const jval_t *sv = jobj_get(body, "serial");
                if (!sv || sv->type != J_INT || sv->ival < 1) {
                    jval_free(body); free(raw_body);
                    send_json(cfd, 400, "{\"ok\":false,\"error\":\"serial must be positive int\"}");
                    return;
                }
                char msg[256];
                int http_rc = 400;
                int ok = (cp_set_channel_serial(st, ch, sv->ival, "EMERGENCY_ROLLBACK", 1,
                                                msg, sizeof(msg), &http_rc) == 0);
                sbuf_t resp;
                sb_init(&resp, 256);
                sb_printf(&resp, "{\"ok\":%s,\"message\":", ok ? "true" : "false");
                sb_json_str(&resp, msg);
                sb_putc(&resp, '}');
                send_json(cfd, http_rc, resp.data);
                sb_free(&resp);
                jval_free(body); free(raw_body);
                return;
            }
            /* /api/v1/channels/<ch> */
            const char *ch = path + 17;
            const jval_t *sv = jobj_get(body, "serial");
            if (!sv || sv->type != J_INT || sv->ival < 1) {
                jval_free(body); free(raw_body);
                send_json(cfd, 400, "{\"ok\":false,\"error\":\"serial must be positive int\"}");
                return;
            }
            char msg[256];
            int http_rc = 400;
            int ok = (cp_set_channel_serial(st, ch, sv->ival, "PROMOTION", 0,
                                            msg, sizeof(msg), &http_rc) == 0);
            sbuf_t resp;
            sb_init(&resp, 256);
            sb_printf(&resp, "{\"ok\":%s,\"message\":", ok ? "true" : "false");
            sb_json_str(&resp, msg);
            sb_putc(&resp, '}');
            send_json(cfd, http_rc, resp.data);
            sb_free(&resp);
            jval_free(body); free(raw_body);
            return;
        }

        jval_free(body);
        free(raw_body);
        send_text(cfd, 404, "not found");
        return;
    }

    send_text(cfd, 405, "method not allowed");
}

static void *worker_thread(void *arg) {
    conn_ctx_t *ctx = (conn_ctx_t *)arg;
    cp_state_t *st = ctx->st;
    handle_client(st, ctx->cfd, ctx->ip);
    close(ctx->cfd);
    free(ctx);
    pthread_mutex_lock(&st->w_mu);
    int prev = atomic_fetch_sub(&st->active_workers, 1);
    if (prev <= 1) {
        pthread_cond_broadcast(&st->w_cv);
    }
    pthread_mutex_unlock(&st->w_mu);
    return NULL;
}

/* ==================== CLI Entrypoint ==================== */

static void usage(void) {
    fprintf(stderr,
            "Usage: sf-cp --data-dir <dir> [--bind 127.0.0.1] [--port 8080] "
            "[--sbom <sbom.json>] [--admin-token <tok>] [--require-signed-heartbeat] "
            "[--require-enrolled] [--require-quorum] [--allow-insecure-dev]\n");
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (fp_init() != FP_OK) {
        fprintf(stderr, "sf-cp: crypto init failed\n");
        return 1;
    }

    /* Fail-closed secure defaults (P0-06): loopback bind, signed+enrolled heartbeats, 2-of-N quorum */
    const char *bind_addr = "127.0.0.1";
    uint16_t port = 8080;
    const char *data_dir = NULL;
    const char *sbom_path = NULL;
    const char *admin_tok = NULL;
    int require_signed_hb = 1;
    int require_enrolled = 1;
    int require_quorum = 1;
    int require_admin_read_auth = 1;
    int insecure_dev = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
            bind_addr = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            const char *ps = argv[++i];
            if (!is_digits_only(ps)) { fprintf(stderr, "invalid --port\n"); return 2; }
            unsigned long v = strtoul(ps, NULL, 10);
            if (v > 65535ul) { fprintf(stderr, "invalid --port\n"); return 2; }
            port = (uint16_t)v;
        } else if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(argv[i], "--sbom") == 0 && i + 1 < argc) {
            sbom_path = argv[++i];
        } else if (strcmp(argv[i], "--admin-token") == 0 && i + 1 < argc) {
            admin_tok = argv[++i];
        } else if (strcmp(argv[i], "--allow-insecure-dev") == 0) {
            insecure_dev = 1;
            require_signed_hb = 0;
            require_enrolled = 0;
            require_quorum = 0;
            require_admin_read_auth = 0;
        } else if (strcmp(argv[i], "--require-signed-heartbeat") == 0) {
            require_signed_hb = 1;
        } else if (strcmp(argv[i], "--require-enrolled") == 0) {
            require_enrolled = 1;
            require_signed_hb = 1;
        } else if (strcmp(argv[i], "--require-quorum") == 0) {
            require_quorum = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage();
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            usage();
            return 2;
        }
    }
    if (!data_dir || !data_dir[0]) {
        fprintf(stderr, "sf-cp: --data-dir is required\n");
        usage();
        return 2;
    }
    if (insecure_dev) {
        fprintf(stderr, "sf-cp: WARNING: --allow-insecure-dev active (signed_hb=%d enrolled=%d quorum=%d)\n",
                require_signed_hb, require_enrolled, require_quorum);
    }

    cp_state_t st;
    if (cp_state_init(&st, data_dir, sbom_path, admin_tok, require_signed_hb,
                      require_enrolled, require_quorum, require_admin_read_auth) != 0) {
        fprintf(stderr, "sf-cp: failed to initialize state in %s\n", data_dir);
        return 1;
    }

    uint16_t bound_port = 0;
    int lfd = fp_net_listen(bind_addr, port, &bound_port);
    if (lfd < 0) {
        fprintf(stderr, "sf-cp: failed to bind %s:%u\n", bind_addr, (unsigned)port);
        cp_state_close(&st);
        return 1;
    }
    atomic_store(&g_listen_fd, lfd);

    printf("sealframe-control-plane v0.5.1 (C11) listening on http://%s:%u (data=%s, sodium=OK)\n",
           bind_addr, (unsigned)bound_port, st.data_dir);
    fflush(stdout);

    while (!atomic_load(&g_stop)) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            if (atomic_load(&g_stop)) break;
            continue;
        }
        if (atomic_load(&st.active_workers) >= CP_MAX_WORKERS) {
            send_text(cfd, 500, "server busy");
            close(cfd);
            continue;
        }
        conn_ctx_t *ctx = calloc(1, sizeof(*ctx));
        if (!ctx) { close(cfd); continue; }
        ctx->st = &st;
        ctx->cfd = cfd;
        if (!inet_ntop(AF_INET, &peer.sin_addr, ctx->ip, sizeof(ctx->ip))) {
            snprintf(ctx->ip, sizeof(ctx->ip), "0.0.0.0");
        }
        atomic_fetch_add(&st.active_workers, 1);
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, worker_thread, ctx) != 0) {
            atomic_fetch_sub(&st.active_workers, 1);
            close(cfd);
            free(ctx);
        }
        pthread_attr_destroy(&attr);
    }

    int fd = atomic_exchange(&g_listen_fd, -1);
    if (fd >= 0) close(fd);
    /* Wait deterministically for all active workers to finish before closing DB/mutexes (SEC-04) */
    pthread_mutex_lock(&st.w_mu);
    while (atomic_load(&st.active_workers) > 0) {
        pthread_cond_wait(&st.w_cv, &st.w_mu);
    }
    pthread_mutex_unlock(&st.w_mu);
    cp_state_close(&st);
    return 0;
}
