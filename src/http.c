#define _POSIX_C_SOURCE 200809L

#include "fp_agent.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HTTP_MAX_HDR 8192u

typedef struct {
    char     host[256];
    uint16_t port;
    char     path[1024];
} parsed_url_t;

static int parse_http_url(const char *url, parsed_url_t *out) {
    if (!url || strncmp(url, "http://", 7) != 0) return -1;
    /* Reject CRLF, whitespace, or control chars (HTTP header/request smuggling defense) */
    for (const char *q = url; *q; q++) {
        unsigned char uc = (unsigned char)*q;
        if (uc <= 0x20u || uc == 0x7fu) return -1;
    }
    const char *p = url + 7;
    const char *slash = strchr(p, '/');
    const char *host_end = slash ? slash : p + strlen(p);
    const char *colon = NULL;
    for (const char *c = p; c < host_end; c++) {
        if (*c == ':') { colon = c; break; }
    }
    size_t hlen = colon ? (size_t)(colon - p) : (size_t)(host_end - p);
    if (hlen == 0 || hlen >= sizeof(out->host)) return -1;
    memcpy(out->host, p, hlen);
    out->host[hlen] = '\0';

    if (colon) {
        const char *ps = colon + 1;
        if (ps >= host_end) return -1;
        unsigned long pv = 0;
        for (const char *c = ps; c < host_end; c++) {
            if (*c < '0' || *c > '9') return -1;
            pv = pv * 10ul + (unsigned long)(*c - '0');
            if (pv > 65535ul) return -1;
        }
        if (pv == 0) return -1;
        out->port = (uint16_t)pv;
    } else {
        out->port = 80;
    }

    if (slash) {
        size_t plen = strlen(slash);
        if (plen >= sizeof(out->path)) return -1;
        memcpy(out->path, slash, plen + 1u);
    } else {
        out->path[0] = '/';
        out->path[1] = '\0';
    }
    return 0;
}

static int tcp_connect_host(const char *host, uint16_t port, int timeout_ms) {
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        if (rc != 0) {
            struct pollfd pfd = { fd, POLLOUT, 0 };
            int prc = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 10000);
            int so_err = 0;
            socklen_t slen = sizeof(so_err);
            if (prc <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) != 0 || so_err != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        if (flags >= 0) (void)fcntl(fd, F_SETFL, flags);
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static fp_err_t send_all_t(int fd, const uint8_t *buf, size_t len, int timeout_ms) {
    size_t sent = 0;
    while (sent < len) {
        struct pollfd pfd = { fd, POLLOUT, 0 };
        int prc = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 10000);
        if (prc <= 0) {
            if (prc < 0 && errno == EINTR) continue;
            return FP_ERR_IO;
        }
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return FP_ERR_IO;
        }
        if (n == 0) return FP_ERR_IO;
        sent += (size_t)n;
    }
    return FP_OK;
}

static ssize_t recv_some_t(int fd, uint8_t *buf, size_t cap, int timeout_ms) {
    for (;;) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : 10000);
        if (prc < 0) { if (errno == EINTR) continue; return -1; }
        if (prc == 0) return -1;
        ssize_t n = recv(fd, buf, cap, 0);
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

static int ci_prefix(const char *line, const char *prefix) {
    while (*prefix) {
        char a = *line++;
        char b = *prefix++;
        if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
        if (a != b) return 0;
    }
    return 1;
}

typedef struct {
    int      status_code;
    int      has_content_length;
    uint64_t content_length;
    int      has_content_range;
    uint64_t cr_start;
    uint64_t cr_end;
    uint64_t cr_total;
    size_t   hdr_len;
} http_hdr_info_t;

static int parse_u64_span(const char *s, const char *end, uint64_t *out) {
    if (!s || s >= end) return -1;
    uint64_t v = 0;
    for (const char *c = s; c < end; c++) {
        if (*c < '0' || *c > '9') return -1;
        if (v > (UINT64_MAX - (uint64_t)(*c - '0')) / 10u) return -1;
        v = v * 10u + (uint64_t)(*c - '0');
    }
    *out = v;
    return 0;
}

static int parse_content_range(const char *val, const char *endv,
                               uint64_t *out_start, uint64_t *out_end, uint64_t *out_total) {
    /* Strict RFC 9110 format: "bytes <start>-<end>/<total>" */
    while (val < endv && (*val == ' ' || *val == '\t')) val++;
    while (endv > val && (endv[-1] == ' ' || endv[-1] == '\t')) endv--;
    if ((size_t)(endv - val) < 10u || !ci_prefix(val, "bytes ")) return -1;
    val += 6;
    while (val < endv && (*val == ' ' || *val == '\t')) val++;
    const char *dash = memchr(val, '-', (size_t)(endv - val));
    if (!dash) return -1;
    const char *slash = memchr(dash + 1, '/', (size_t)(endv - (dash + 1)));
    if (!slash) return -1;
    uint64_t s = 0, e = 0, t = 0;
    if (parse_u64_span(val, dash, &s) != 0 ||
        parse_u64_span(dash + 1, slash, &e) != 0 ||
        parse_u64_span(slash + 1, endv, &t) != 0) {
        return -1;
    }
    if (e < s || t == 0 || e >= t) return -1;
    *out_start = s;
    *out_end = e;
    *out_total = t;
    return 0;
}

static fp_err_t read_http_headers(int fd, uint8_t *buf, size_t buf_cap,
                                  size_t *out_total_read, http_hdr_info_t *info,
                                  int timeout_ms) {
    memset(info, 0, sizeof(*info));
    size_t total = 0;
    const uint8_t *end_hdr = NULL;

    while (total < buf_cap) {
        ssize_t n = recv_some_t(fd, buf + total, buf_cap - total, timeout_ms);
        if (n <= 0) return FP_ERR_IO;
        total += (size_t)n;

        for (size_t i = 0; i + 3 < total; i++) {
            if (buf[i] == '\r' && buf[i + 1] == '\n' &&
                buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                end_hdr = buf + i + 4;
                break;
            }
        }
        if (end_hdr) break;
    }
    if (!end_hdr) return FP_ERR_BOUNDS;

    info->hdr_len = (size_t)(end_hdr - buf);
    *out_total_read = total;

    /* Parse status line: "HTTP/1.x NNN ..." (strict 3 ASCII digits) */
    if (info->hdr_len < 12 || memcmp(buf, "HTTP/1.", 7) != 0) return FP_ERR_INVALID;
    const char *sp = memchr(buf, ' ', info->hdr_len);
    if (!sp || (size_t)(sp - (const char *)buf) + 4 > info->hdr_len) return FP_ERR_INVALID;
    if (sp[1] < '1' || sp[1] > '5' || sp[2] < '0' || sp[2] > '9' || sp[3] < '0' || sp[3] > '9') {
        return FP_ERR_INVALID;
    }
    info->status_code = (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');

    /* Scan header lines for Content-Length (strict unsigned parse, reject conflicting duplicates) */
    const char *line = (const char *)buf;
    const char *limit = (const char *)end_hdr;
    while (line < limit) {
        const char *crlf = memchr(line, '\r', (size_t)(limit - line));
        if (!crlf || crlf == line) break;
        if (crlf + 1 >= limit || crlf[1] != '\n') return FP_ERR_INVALID;
        if (ci_prefix(line, "content-length:")) {
            const char *val = line + 15;
            while (val < crlf && (*val == ' ' || *val == '\t')) val++;
            const char *endv = crlf;
            while (endv > val && (endv[-1] == ' ' || endv[-1] == '\t')) endv--;
            if (val >= endv) return FP_ERR_INVALID;
            uint64_t cl = 0;
            for (const char *c = val; c < endv; c++) {
                if (*c < '0' || *c > '9') return FP_ERR_INVALID;
                if (cl > (UINT64_MAX - (uint64_t)(*c - '0')) / 10u) return FP_ERR_BOUNDS;
                cl = cl * 10u + (uint64_t)(*c - '0');
            }
            if (info->has_content_length && info->content_length != cl) {
                return FP_ERR_INVALID; /* Reject conflicting Content-Length smuggling */
            }
            info->content_length = cl;
            info->has_content_length = 1;
        } else if (ci_prefix(line, "content-range:")) {
            uint64_t cs = 0, ce = 0, ct = 0;
            if (parse_content_range(line + 14, crlf, &cs, &ce, &ct) != 0) {
                return FP_ERR_INVALID;
            }
            if (info->has_content_range &&
                (info->cr_start != cs || info->cr_end != ce || info->cr_total != ct)) {
                return FP_ERR_INVALID; /* Reject conflicting Content-Range headers */
            }
            info->cr_start = cs;
            info->cr_end = ce;
            info->cr_total = ct;
            info->has_content_range = 1;
        }
        line = crlf + 2;
    }
    return FP_OK;
}

void fp_http_resp_free(fp_http_resp_t *resp) {
    if (!resp) return;
    free(resp->body);
    memset(resp, 0, sizeof(*resp));
}

fp_err_t fp_http_get(const char *url, size_t max_bytes, int timeout_ms,
                     fp_http_resp_t *out_resp) {
    if (!url || !out_resp) return FP_ERR_INVALID;
    memset(out_resp, 0, sizeof(*out_resp));
    if (max_bytes == 0) max_bytes = (64u << 20);

    parsed_url_t u;
    if (parse_http_url(url, &u) != 0) return FP_ERR_INVALID;
    int fd = tcp_connect_host(u.host, u.port, timeout_ms);
    if (fd < 0) return FP_ERR_IO;

    char req[2048];
    int rlen = snprintf(req, sizeof(req),
                        "GET %s HTTP/1.1\r\n"
                        "Host: %s:%u\r\n"
                        "User-Agent: sf-agent/%d.%d\r\n"
                        "Connection: close\r\n\r\n",
                        u.path, u.host, (unsigned)u.port,
                        FP_VERSION_MAJOR, FP_VERSION_MINOR);
    if (rlen <= 0 || (size_t)rlen >= sizeof(req)) { close(fd); return FP_ERR_BOUNDS; }

    fp_err_t err = send_all_t(fd, (const uint8_t *)req, (size_t)rlen, timeout_ms);
    if (err != FP_OK) { close(fd); return err; }

    uint8_t hbuf[HTTP_MAX_HDR];
    size_t got = 0;
    http_hdr_info_t hinfo;
    err = read_http_headers(fd, hbuf, sizeof(hbuf), &got, &hinfo, timeout_ms);
    if (err != FP_OK) { close(fd); return err; }

    out_resp->status_code = hinfo.status_code;
    if (hinfo.has_content_length && hinfo.content_length > max_bytes) {
        close(fd);
        return FP_ERR_BOUNDS;
    }

    size_t init_cap = hinfo.has_content_length ? (size_t)hinfo.content_length : 4096u;
    if (init_cap == 0) init_cap = 1u;
    uint8_t *body = malloc(init_cap + 1u);
    if (!body) { close(fd); return FP_ERR_NOMEM; }

    size_t blen = got - hinfo.hdr_len;
    if (blen > max_bytes) { free(body); close(fd); return FP_ERR_BOUNDS; }
    if (blen > init_cap) {
        uint8_t *nb = realloc(body, blen + 1u);
        if (!nb) { free(body); close(fd); return FP_ERR_NOMEM; }
        body = nb;
        init_cap = blen;
    }
    if (blen > 0) memcpy(body, hbuf + hinfo.hdr_len, blen);

    for (;;) {
        if (hinfo.has_content_length && blen >= hinfo.content_length) break;
        uint8_t tmp[16384];
        ssize_t n = recv_some_t(fd, tmp, sizeof(tmp), timeout_ms);
        if (n < 0) { free(body); close(fd); return FP_ERR_IO; }
        if (n == 0) break;
        if (blen + (size_t)n > max_bytes) { free(body); close(fd); return FP_ERR_BOUNDS; }
        if (blen + (size_t)n > init_cap) {
            size_t ncap = init_cap * 2u;
            if (ncap < blen + (size_t)n) ncap = blen + (size_t)n;
            if (ncap > max_bytes) ncap = max_bytes;
            uint8_t *nb = realloc(body, ncap + 1u);
            if (!nb) { free(body); close(fd); return FP_ERR_NOMEM; }
            body = nb;
            init_cap = ncap;
        }
        memcpy(body + blen, tmp, (size_t)n);
        blen += (size_t)n;
    }
    close(fd);

    if (hinfo.has_content_length && blen != hinfo.content_length) {
        free(body);
        return FP_ERR_IO;
    }
    body[blen] = '\0';
    out_resp->body = body;
    out_resp->body_len = blen;
    return FP_OK;
}

fp_err_t fp_http_post_json_signed(const char *url, const char *json_body,
                                  const fp_keypair_t *device_kp,
                                  int timeout_ms, int *out_status) {
    if (!url || !json_body) return FP_ERR_INVALID;
    parsed_url_t u;
    if (parse_http_url(url, &u) != 0) return FP_ERR_INVALID;
    int fd = tcp_connect_host(u.host, u.port, timeout_ms);
    if (fd < 0) return FP_ERR_IO;

    size_t jlen = strlen(json_body);
    char auth_hdrs[384];
    auth_hdrs[0] = '\0';
    if (device_kp) {
        uint8_t sig[FP_SIG_LEN];
        unsigned long long siglen = 0;
        crypto_sign_ed25519_detached(sig, &siglen, (const uint8_t *)json_body,
                                     (unsigned long long)jlen, device_kp->sk);
        char pk_hex[FP_PK_LEN * 2 + 1];
        char sig_hex[FP_SIG_LEN * 2 + 1];
        fp_hex_encode(device_kp->pk, FP_PK_LEN, pk_hex);
        fp_hex_encode(sig, FP_SIG_LEN, sig_hex);
        snprintf(auth_hdrs, sizeof(auth_hdrs),
                 "X-FP-Device-PubKey: %s\r\n"
                 "X-FP-Signature: %s\r\n",
                 pk_hex, sig_hex);
    }

    char req[2560];
    int rlen = snprintf(req, sizeof(req),
                        "POST %s HTTP/1.1\r\n"
                        "Host: %s:%u\r\n"
                        "User-Agent: sf-agent/%d.%d\r\n"
                        "Content-Type: application/json\r\n"
                        "%s"
                        "Content-Length: %zu\r\n"
                        "Connection: close\r\n\r\n",
                        u.path, u.host, (unsigned)u.port,
                        FP_VERSION_MAJOR, FP_VERSION_MINOR,
                        auth_hdrs, jlen);
    if (rlen <= 0 || (size_t)rlen >= sizeof(req)) { close(fd); return FP_ERR_BOUNDS; }

    fp_err_t err = send_all_t(fd, (const uint8_t *)req, (size_t)rlen, timeout_ms);
    if (err == FP_OK && jlen > 0) {
        err = send_all_t(fd, (const uint8_t *)json_body, jlen, timeout_ms);
    }
    if (err != FP_OK) { close(fd); return err; }

    uint8_t hbuf[HTTP_MAX_HDR];
    size_t got = 0;
    http_hdr_info_t hinfo;
    err = read_http_headers(fd, hbuf, sizeof(hbuf), &got, &hinfo, timeout_ms);
    close(fd);
    if (err != FP_OK) return err;
    if (out_status) *out_status = hinfo.status_code;
    return (hinfo.status_code >= 200 && hinfo.status_code < 300) ? FP_OK : FP_ERR_IO;
}

fp_err_t fp_http_post_json(const char *url, const char *json_body,
                           int timeout_ms, int *out_status) {
    return fp_http_post_json_signed(url, json_body, NULL, timeout_ms, out_status);
}

static fp_err_t ensure_dir_h(const char *p) {
    if (mkdir(p, 0700) == 0 || errno == EEXIST) return FP_OK;
    return FP_ERR_IO;
}

static fp_err_t write_all_h(int fd, const uint8_t *buf, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = write(fd, buf + pos, len - pos);
        if (n < 0) { if (errno == EINTR) continue; return FP_ERR_IO; }
        pos += (size_t)n;
    }
    return FP_OK;
}

fp_err_t fp_http_pull_object(const char *url, const char *store_dir,
                             const fp_dna_t *expected_dna, uint64_t expected_size,
                             int timeout_ms, uint64_t *out_resumed_bytes) {
    if (!url || !store_dir || !expected_dna) return FP_ERR_INVALID;
    if (out_resumed_bytes) *out_resumed_bytes = 0;

    if (fp_store_has_object(store_dir, expected_dna, NULL)) {
        return FP_OK;
    }

    parsed_url_t u;
    if (parse_http_url(url, &u) != 0) return FP_ERR_INVALID;

    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(expected_dna->bytes, FP_DNA_LEN, hex);

    char stage_dir[PATH_MAX], obj_dir[PATH_MAX], stage_path[PATH_MAX], obj_path[PATH_MAX];
    int n1 = snprintf(stage_dir, sizeof(stage_dir), "%s/staging", store_dir);
    int n2 = snprintf(obj_dir, sizeof(obj_dir), "%s/objects", store_dir);
    int n3 = snprintf(stage_path, sizeof(stage_path), "%s/staging/%s.http", store_dir, hex);
    int n4 = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", store_dir, hex);
    if (n1 < 0 || (size_t)n1 >= sizeof(stage_dir) ||
        n2 < 0 || (size_t)n2 >= sizeof(obj_dir) ||
        n3 < 0 || (size_t)n3 >= sizeof(stage_path) ||
        n4 < 0 || (size_t)n4 >= sizeof(obj_path)) {
        return FP_ERR_BOUNDS;
    }

    if (ensure_dir_h(store_dir) != FP_OK || ensure_dir_h(stage_dir) != FP_OK ||
        ensure_dir_h(obj_dir) != FP_OK) {
        return FP_ERR_IO;
    }

    /* Check if a partial download exists for HTTP Range resume */
    uint64_t existing = 0;
    struct stat st;
    if (stat(stage_path, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
        if (expected_size == 0 || (uint64_t)st.st_size < expected_size) {
            existing = (uint64_t)st.st_size;
        } else if ((uint64_t)st.st_size == expected_size) {
            /* Already full size: check DNA directly! */
            fp_dna_t check;
            uint64_t csz = 0;
            if (fp_dna_compute_file(stage_path, &check, &csz) == FP_OK &&
                fp_dna_equal(&check, expected_dna)) {
                if (rename(stage_path, obj_path) == 0) {
                    if (out_resumed_bytes) *out_resumed_bytes = existing;
                    return FP_OK;
                }
            }
            unlink(stage_path);
            existing = 0;
        } else {
            unlink(stage_path);
            existing = 0;
        }
    }

    int fd = tcp_connect_host(u.host, u.port, timeout_ms);
    if (fd < 0) return FP_ERR_IO;

    char req[2048];
    int rlen;
    if (existing > 0) {
        rlen = snprintf(req, sizeof(req),
                        "GET %s HTTP/1.1\r\n"
                        "Host: %s:%u\r\n"
                        "User-Agent: sf-agent/%d.%d\r\n"
                        "Range: bytes=%llu-\r\n"
                        "Connection: close\r\n\r\n",
                        u.path, u.host, (unsigned)u.port,
                        FP_VERSION_MAJOR, FP_VERSION_MINOR,
                        (unsigned long long)existing);
    } else {
        rlen = snprintf(req, sizeof(req),
                        "GET %s HTTP/1.1\r\n"
                        "Host: %s:%u\r\n"
                        "User-Agent: sf-agent/%d.%d\r\n"
                        "Connection: close\r\n\r\n",
                        u.path, u.host, (unsigned)u.port,
                        FP_VERSION_MAJOR, FP_VERSION_MINOR);
    }
    if (rlen <= 0 || (size_t)rlen >= sizeof(req)) { close(fd); return FP_ERR_BOUNDS; }

    fp_err_t err = send_all_t(fd, (const uint8_t *)req, (size_t)rlen, timeout_ms);
    if (err != FP_OK) { close(fd); return err; }

    uint8_t hbuf[HTTP_MAX_HDR];
    size_t got = 0;
    http_hdr_info_t hinfo;
    err = read_http_headers(fd, hbuf, sizeof(hbuf), &got, &hinfo, timeout_ms);
    if (err != FP_OK) { close(fd); return err; }

    int sfd = -1;
    uint64_t range_expected_len = 0;
    if (existing > 0 && hinfo.status_code == 206) {
        /* SEC-06: Require strict Content-Range verification matching our exact resume offset! */
        if (!hinfo.has_content_range || hinfo.cr_start != existing ||
            (expected_size > 0 && hinfo.cr_total != expected_size)) {
            close(fd);
            return FP_ERR_INTEGRITY;
        }
        range_expected_len = (hinfo.cr_end - hinfo.cr_start) + 1u;
        if (hinfo.has_content_length && hinfo.content_length != range_expected_len) {
            close(fd);
            return FP_ERR_INTEGRITY;
        }
        sfd = open(stage_path, O_WRONLY | O_APPEND | O_NOFOLLOW, 0600);
        if (out_resumed_bytes) *out_resumed_bytes = existing;
    } else if (hinfo.status_code == 200) {
        existing = 0;
        sfd = open(stage_path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
    } else if (hinfo.status_code == 404) {
        close(fd);
        return FP_ERR_NOT_FOUND;
    } else {
        close(fd);
        return FP_ERR_IO;
    }
    if (sfd < 0) { close(fd); return FP_ERR_IO; }

    uint64_t written_this_req = 0;
    size_t init_body = got - hinfo.hdr_len;
    if (hinfo.has_content_length && expected_size > 0 &&
        (hinfo.content_length > expected_size || existing > expected_size - hinfo.content_length)) {
        err = FP_ERR_BOUNDS;
    } else if (init_body > 0) {
        if ((expected_size > 0 &&
             (init_body > expected_size || existing > expected_size - init_body)) ||
            (range_expected_len > 0 && init_body > range_expected_len)) {
            err = FP_ERR_BOUNDS;
        } else {
            err = write_all_h(sfd, hbuf + hinfo.hdr_len, init_body);
            written_this_req += init_body;
        }
    }

    uint8_t buf[16384];
    while (err == FP_OK) {
        if (hinfo.has_content_length && written_this_req >= hinfo.content_length) break;
        if (range_expected_len > 0 && written_this_req >= range_expected_len) break;
        ssize_t n = recv_some_t(fd, buf, sizeof(buf), timeout_ms);
        if (n < 0) { err = FP_ERR_IO; break; }
        if (n == 0) break;
        if ((expected_size > 0 &&
             ((uint64_t)n > expected_size - existing || written_this_req > expected_size - existing - (uint64_t)n)) ||
            (range_expected_len > 0 && ((uint64_t)n > range_expected_len || written_this_req > range_expected_len - (uint64_t)n))) {
            err = FP_ERR_BOUNDS;
            break;
        }
        err = write_all_h(sfd, buf, (size_t)n);
        written_this_req += (uint64_t)n;
    }
    close(fd);

    /* Preserve partial stage_path on truncated transfer rather than deleting valid resume prefix */
    if (err == FP_OK &&
        ((hinfo.has_content_length && written_this_req != hinfo.content_length) ||
         (range_expected_len > 0 && written_this_req != range_expected_len) ||
         (expected_size > 0 && existing + written_this_req < expected_size))) {
        err = FP_ERR_IO;
    }
    if (fsync(sfd) != 0 && err == FP_OK) err = FP_ERR_IO;
    close(sfd);
    if (err != FP_OK) return err; /* Keep partial stage_path for HTTP Range resume! */

    /* Fail-closed whole-file streaming BLAKE3 DNA verification before atomic commit */
    fp_dna_t actual_dna;
    uint64_t actual_sz = 0;
    err = fp_dna_compute_file(stage_path, &actual_dna, &actual_sz);
    if (err != FP_OK || !fp_dna_equal(&actual_dna, expected_dna) ||
        (expected_size > 0 && actual_sz != expected_size)) {
        unlink(stage_path); /* Corrupted or mismatched download: wipe immediately! */
        return FP_ERR_INTEGRITY;
    }

    if (rename(stage_path, obj_path) != 0) {
        unlink(stage_path);
        return FP_ERR_IO;
    }
    int dfd = open(obj_dir, O_RDONLY);
    if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
    return FP_OK;
}
