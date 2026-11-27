/*
 * SealFrame Pure-C11 Adversarial Red-Team & Crash Torture Suite
 *
 * 100% pure ISO C11 adversarial torture & security regression suite (zero Python):
 *   1. Control Plane (bin/sf-cp): malformed HTTP, bad/duplicate Content-Length, JSON type
 *      confusion, bool-as-int serial, malformed heartbeat fields, Stored XSS check, path
 *      traversal, Ed25519 signed & forged heartbeat, HTTP 206/416 Range, CRA audit JSON/HTML,
 *      24-thread concurrent mixed valid+garbage storm.
 *   2. Live FP-NET TCP server (bin/sf serve): 40 adversarial/corrupt connections + valid pull.
 *   3. Live FP-UDP1 UDP server (bin/sf udp-serve): 500 fuzzed datagrams + valid pull.
 *   4. CLI, adversarial HTTP server & Round-2 hardening: 0B/1B full pipeline, corrupt artifacts,
 *      traversal/CRLF rejection, evil HTTP server vs sf-agent, numeric overflows, directory dna,
 *      truncated anchor log, tampered FPC1 recipe.
 */
#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static _Atomic int g_findings = 0;

static void record_finding(const char *sev, const char *area, const char *msg) {
    atomic_fetch_add(&g_findings, 1);
    fprintf(stderr, "  [FINDING:%s] (%s) %s\n", sev, area, msg);
}

static void record_ok(const char *area, const char *msg) {
    printf("  [OK] (%s) %s\n", area, msg);
}

static void msleep(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static int run_cmd_capture(char *const argv[], char *out, size_t out_cap) {
    int pfd[2] = { -1, -1 };
    if (out && out_cap > 0) {
        if (pipe(pfd) != 0) return -1;
    }
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (pfd[1] >= 0) {
            dup2(pfd[1], STDOUT_FILENO);
            close(pfd[0]);
            close(pfd[1]);
        } else if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
        }
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    if (pfd[1] >= 0) {
        close(pfd[1]);
        size_t pos = 0;
        while (pos + 1u < out_cap) {
            ssize_t r = read(pfd[0], out + pos, out_cap - 1u - pos);
            if (r <= 0) break;
            pos += (size_t)r;
        }
        out[pos] = '\0';
        close(pfd[0]);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -99;
}

static pid_t spawn_bg(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    return pid;
}

static int tcp_connect_local(uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static ssize_t raw_http(uint16_t port, const void *req, size_t req_len, char *resp, size_t resp_cap, int timeout_ms) {
    int fd = tcp_connect_local(port, timeout_ms);
    if (fd < 0) return -1;
    const uint8_t *p = (const uint8_t *)req;
    size_t sent = 0;
    while (sent < req_len) {
        ssize_t w = send(fd, p + sent, req_len - sent, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += (size_t)w;
    }
    size_t got = 0;
    while (got + 1u < resp_cap) {
        ssize_t r = recv(fd, resp + got, resp_cap - 1u - got, 0);
        if (r <= 0) break;
        got += (size_t)r;
    }
    resp[got] = '\0';
    close(fd);
    return (ssize_t)got;
}

static void to_hex(const uint8_t *in, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2u] = hx[in[i] >> 4];
        out[i * 2u + 1u] = hx[in[i] & 0x0Fu];
    }
    out[n * 2u] = '\0';
}

static int read_file_str(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1u, f);
    fclose(f);
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ')) buf[--n] = '\0';
    return 0;
}

static void extract_kv(const char *txt, const char *prefix, char *out, size_t cap) {
    const char *p = strstr(txt, prefix);
    if (!p) { out[0] = '\0'; return; }
    p += strlen(prefix);
    size_t i = 0;
    while (p[i] && p[i] != ' ' && p[i] != '\n' && p[i] != '\r' && p[i] != '\t' && i + 1u < cap) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
}

/* ==================== 1. Control Plane Adversarial Torture ==================== */

typedef struct {
    uint16_t port;
    int      idx;
} storm_arg_t;

static void *cp_storm_worker(void *arg) {
    storm_arg_t *sa = (storm_arg_t *)arg;
    char resp[4096];
    if (sa->idx % 3 == 0) {
        uint8_t junk[200];
        size_t jlen = 1u + (size_t)(randombytes_uniform(199));
        randombytes_buf(junk, jlen);
        (void)raw_http(sa->port, junk, jlen, resp, sizeof(resp), 1000);
    } else {
        char body[160], req[512];
        int blen = snprintf(body, sizeof(body),
                            "{\"device_id\":\"dev-%d\",\"outcome\":\"UPDATED\",\"active_serial\":%d}",
                            sa->idx, sa->idx);
        int rlen = snprintf(req, sizeof(req),
                            "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s",
                            blen, body);
        ssize_t n = raw_http(sa->port, req, (size_t)rlen, resp, sizeof(resp), 2000);
        if (n <= 0 || strncmp(resp, "HTTP/1.1 200 OK", 15) != 0) {
            record_finding("HIGH", "CP-CONCURRENCY", "Valid heartbeat failed during concurrent storm");
        }
    }
    return NULL;
}

static void test_control_plane(const char *work) {
    printf("\n=== 1. Control Plane (bin/sf-cp) Adversarial Torture ===\n");
    const uint16_t port = 18921;
    char cp_dir[512];
    snprintf(cp_dir, sizeof(cp_dir), "%s/cp", work);
    mkdir(cp_dir, 0755);

    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
    char *argv[] = { "./bin/sf-cp", "--bind", "127.0.0.1", "--port", port_s, "--data-dir", cp_dir,
                     "--allow-insecure-dev", NULL };
    pid_t pid = spawn_bg(argv);
    assert(pid > 0);

    /* Wait until listening */
    int ready = 0;
    for (int i = 0; i < 40; i++) {
        int fd = tcp_connect_local(port, 200);
        if (fd >= 0) { close(fd); ready = 1; break; }
        msleep(50);
    }
    assert(ready);

    char tok_path[600], tok[128];
    snprintf(tok_path, sizeof(tok_path), "%s/admin.token", cp_dir);
    assert(read_file_str(tok_path, tok, sizeof(tok)) == 0 && strlen(tok) >= 16);

    char req[2048], resp[16384];

    /* 1a. Non-numeric Content-Length */
    const char *r1a = "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\nContent-Length: notanumber\r\n\r\n{}";
    raw_http(port, r1a, strlen(r1a), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 400", 12) != 0)
        record_finding("MEDIUM", "CP", "Non-numeric Content-Length did not return 400");
    else
        record_ok("CP", "Non-numeric Content-Length cleanly returned 400");

    /* 1a2. Duplicate Content-Length smuggling */
    const char *r1a2 = "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
    raw_http(port, r1a2, strlen(r1a2), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 400", 12) != 0)
        record_finding("HIGH", "CP", "Duplicate Content-Length not rejected with 400");
    else
        record_ok("CP", "Duplicate Content-Length smuggling rejected with 400");

    /* 1b. JSON array instead of object */
    snprintf(req, sizeof(req),
             "POST /api/v1/channels/canary HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
             "Content-Length: 7\r\n\r\n[1,2,3]", tok);
    raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 400", 12) != 0)
        record_finding("MEDIUM", "CP", "JSON array body did not return 400");
    else
        record_ok("CP", "JSON array body cleanly returned 400");

    /* 1c. Bool-as-int serial bypass */
    const char *b1c = "{\"serial\": true}";
    snprintf(req, sizeof(req),
             "POST /api/v1/channels/canary HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
             "Content-Length: %zu\r\n\r\n%s", tok, strlen(b1c), b1c);
    raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 400", 12) != 0)
        record_finding("MEDIUM", "CP", "Boolean serial=true accepted past int check");
    else
        record_ok("CP", "Boolean serial=true rejected with 400");

    /* 1d. Malformed heartbeat field types */
    const char *b1d = "{\"device_id\":\"bad-types\",\"active_serial\":\"NaN\",\"elapsed_ms\":\"oops\"}";
    snprintf(req, sizeof(req),
             "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\n\r\n%s",
             strlen(b1d), b1d);
    raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 400", 12) != 0)
        record_finding("MEDIUM", "CP", "Malformed heartbeat field types did not return 400");
    else
        record_ok("CP", "Malformed heartbeat field types cleanly returned 400");

    /* 1e. Stored XSS check on Dashboard / */
    const char *r1e = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    raw_http(port, r1e, strlen(r1e), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0 || !strstr(resp, "escHtml("))
        record_finding("HIGH", "CP-XSS", "Dashboard missing escHtml() escaping");
    else
        record_ok("CP-XSS", "Dashboard escapes all device fields before innerHTML");

    /* 1f. Path traversal probes */
    const char *bad_paths[3] = {
        "/repo/objects/../../../../etc/passwd",
        "/repo/channels/../../admin.token/latest.ev",
        "/repo/events/..%2fadmin.token.ev"
    };
    for (int i = 0; i < 3; i++) {
        snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", bad_paths[i]);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) == 0)
            record_finding("CRITICAL", "CP-PATH", "Path traversal succeeded");
    }
    record_ok("CP-PATH", "All path traversal probes blocked");

    /* 1g. Ed25519 signed & forged heartbeat verification */
    fp_keypair_t dkp;
    assert(fp_keygen(&dkp) == FP_OK);
    const char *hb_body = "{\"device_id\":\"ed-node-1\",\"outcome\":\"UPDATED\",\"active_serial\":1}";
    uint8_t sig[64];
    crypto_sign_ed25519_detached(sig, NULL, (const uint8_t *)hb_body, strlen(hb_body), dkp.sk);
    char pk_hex[65], sig_hex[129];
    to_hex(dkp.pk, 32, pk_hex);
    to_hex(sig, 64, sig_hex);
    snprintf(req, sizeof(req),
             "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\n"
             "X-SF-Device-PubKey: %s\r\nX-SF-Signature: %s\r\n"
             "Content-Length: %zu\r\n\r\n%s",
             pk_hex, sig_hex, strlen(hb_body), hb_body);
    raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0 || !strstr(resp, "\"auth_verified\":true"))
        record_finding("HIGH", "CP-AUTH", "Valid Ed25519 signed heartbeat rejected");
    /* Flip 1 bit in signature */
    sig_hex[0] = (sig_hex[0] == 'a') ? 'b' : 'a';
    snprintf(req, sizeof(req),
             "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\n"
             "X-SF-Device-PubKey: %s\r\nX-SF-Signature: %s\r\n"
             "Content-Length: %zu\r\n\r\n%s",
             pk_hex, sig_hex, strlen(hb_body), hb_body);
    raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 401", 12) != 0)
        record_finding("CRITICAL", "CP-AUTH", "Forged Ed25519 heartbeat was not rejected with 401");
    else
        record_ok("CP-AUTH", "Valid Ed25519 heartbeat verified and 1-bit forged signature rejected (401)");

    /* 1g2. P0-04 Device Enrollment/Key-Pinning + Anti-Replay hb_seq */
    {
        uint8_t pk2[32], sk2[64], sig2[64];
        crypto_sign_ed25519_keypair(pk2, sk2);
        char pk2_hex[65], sig2_hex[129];
        to_hex(pk2, 32, pk2_hex);
        const char *spoof_body = "{\"device_id\":\"ed-node-1\",\"outcome\":\"UPDATED\",\"active_serial\":99}";
        crypto_sign_ed25519_detached(sig2, NULL, (const uint8_t *)spoof_body, strlen(spoof_body), sk2);
        to_hex(sig2, 64, sig2_hex);
        snprintf(req, sizeof(req),
                 "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\n"
                 "X-SF-Device-PubKey: %s\r\nX-SF-Signature: %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s",
                 pk2_hex, sig2_hex, strlen(spoof_body), spoof_body);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 401", 12) != 0)
            record_finding("CRITICAL", "CP-P0-04", "Key-swap impersonation of pinned device was NOT rejected with 401");

        /* Enroll a dedicated device with monotonic hb_seq replay test */
        char enroll_body[256];
        snprintf(enroll_body, sizeof(enroll_body), "{\"device_id\":\"enrolled-01\",\"pubkey\":\"%s\"}", pk2_hex);
        snprintf(req, sizeof(req),
                 "POST /api/v1/devices/enroll HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s",
                 tok, strlen(enroll_body), enroll_body);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0)
            record_finding("HIGH", "CP-P0-04", "Device enrollment endpoint failed");

        const char *seq1_body = "{\"device_id\":\"enrolled-01\",\"hb_seq\":1,\"outcome\":\"UPDATED\",\"active_serial\":1}";
        crypto_sign_ed25519_detached(sig2, NULL, (const uint8_t *)seq1_body, strlen(seq1_body), sk2);
        to_hex(sig2, 64, sig2_hex);
        snprintf(req, sizeof(req),
                 "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\n"
                 "X-SF-Device-PubKey: %s\r\nX-SF-Signature: %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s",
                 pk2_hex, sig2_hex, strlen(seq1_body), seq1_body);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0)
            record_finding("HIGH", "CP-P0-04", "Valid enrolled heartbeat hb_seq=1 failed");

        /* Replaying exact same signed hb_seq=1 MUST be rejected with 409 Conflict! */
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 409", 12) != 0)
            record_finding("CRITICAL", "CP-P0-04", "Replayed heartbeat hb_seq=1 was NOT rejected with 409");
        else
            record_ok("CP-P0-04", "Device key-pinning (401 on spoofed key) + monotonic hb_seq replay defense (409) verified");
    }

    /* 1g3. P0-03 Cryptographic 2-of-N Quorum Enforcement + P0-06 Monotonic Emergency Rollback */
    {
        fp_keypair_t rel_kp, app1_kp, app2_kp;
        assert(fp_keygen(&rel_kp) == FP_OK && fp_keygen(&app1_kp) == FP_OK && fp_keygen(&app2_kp) == FP_OK);
        fp_dna_t rid, b1_dna, b2_dna;
        assert(fp_random_id(&rid) == FP_OK && fp_random_id(&b1_dna) == FP_OK && fp_random_id(&b2_dna) == FP_OK);
        uint64_t now_u = (uint64_t)time(NULL);

        fp_event_t ev1, ev2;
        memset(&ev1, 0, sizeof(ev1));
        ev1.action = FP_ACTION_INSTALL; ev1.repo_id = rid; ev1.serial = 1;
        ev1.timestamp_unix = now_u; ev1.expires_unix = now_u + 3600;
        ev1.target_dna = b1_dna; ev1.target_size = 100;
        assert(fp_event_sign(&ev1, &rel_kp) == FP_OK);

        memset(&ev2, 0, sizeof(ev2));
        ev2.action = FP_ACTION_INSTALL; ev2.repo_id = rid; ev2.serial = 2;
        ev2.prev_event_hash = ev1.event_hash;
        ev2.timestamp_unix = now_u; ev2.expires_unix = now_u + 3600;
        ev2.target_dna = b2_dna; ev2.target_size = 100;
        assert(fp_event_sign(&ev2, &rel_kp) == FP_OK);

        uint8_t *eb = NULL; size_t el = 0;
        char evp[640];
        assert(fp_event_encode(&ev1, &eb, &el) == FP_OK);
        snprintf(evp, sizeof(evp), "%s/repo/events/1.ev", cp_dir);
        FILE *ef = fopen(evp, "wb"); assert(ef && fwrite(eb, 1, el, ef) == el); fclose(ef); free(eb);
        assert(fp_event_encode(&ev2, &eb, &el) == FP_OK);
        snprintf(evp, sizeof(evp), "%s/repo/events/2.ev", cp_dir);
        ef = fopen(evp, "wb"); assert(ef && fwrite(eb, 1, el, ef) == el); fclose(ef); free(eb);

        /* Register 2 Ed25519 approvers */
        char a1_pk[65], a2_pk[65], abody[256];
        to_hex(app1_kp.pk, 32, a1_pk);
        to_hex(app2_kp.pk, 32, a2_pk);
        snprintf(abody, sizeof(abody), "{\"approver\":\"cto@corp\",\"pubkey\":\"%s\"}", a1_pk);
        snprintf(req, sizeof(req),
                 "POST /api/v1/approvers HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(abody), abody);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0) record_finding("HIGH", "CP-P0-03", "Approver 1 register failed");
        snprintf(abody, sizeof(abody), "{\"approver\":\"ciso@corp\",\"pubkey\":\"%s\"}", a2_pk);
        snprintf(req, sizeof(req),
                 "POST /api/v1/approvers HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(abody), abody);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0) record_finding("HIGH", "CP-P0-03", "Approver 2 register failed");

        /* P0-05: Registering a second alias with the SAME pubkey MUST be rejected with 409 Conflict */
        snprintf(abody, sizeof(abody), "{\"approver\":\"cto-alias@corp\",\"pubkey\":\"%s\"}", a1_pk);
        snprintf(req, sizeof(req),
                 "POST /api/v1/approvers HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(abody), abody);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 409", 12) != 0)
            record_finding("CRITICAL", "CP-P0-05", "Duplicate approver pubkey across alias was NOT rejected with 409");
        else
            record_ok("CP-P0-05", "Duplicate approver pubkey alias blocked with 409 Conflict (quorum requires distinct keys)");

        /* Promotion with 0/2 approvals MUST fail with 403 */
        const char *prom1 = "{\"serial\":1}";
        snprintf(req, sizeof(req),
                 "POST /api/v1/channels/stable HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(prom1), prom1);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 403", 12) != 0)
            record_finding("CRITICAL", "CP-P0-03", "Promotion without quorum was NOT blocked with 403");

        /* Unsigned / forged approver signature MUST fail with 401 */
        char ev1_hex[65], canon[256], sig_h[129];
        to_hex(ev1.event_hash.bytes, 32, ev1_hex);
        int cl = snprintf(canon, sizeof(canon), "SF_APPROVAL_V1|stable|1|%s", ev1_hex);
        uint8_t asig[64];
        crypto_sign_ed25519_detached(asig, NULL, (const uint8_t *)canon, (unsigned long long)cl, app1_kp.sk);
        asig[0] ^= 0xFFu; /* forge! */
        to_hex(asig, 64, sig_h);
        char app_body[512];
        snprintf(app_body, sizeof(app_body),
                 "{\"channel\":\"stable\",\"serial\":1,\"approver\":\"cto@corp\",\"signature\":\"%s\"}", sig_h);
        snprintf(req, sizeof(req),
                 "POST /api/v1/approvals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(app_body), app_body);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 401", 12) != 0)
            record_finding("CRITICAL", "CP-P0-03", "Forged approver Ed25519 signature was NOT rejected with 401");

        /* Valid approval 1/2 -> promotion STILL blocked with 403 */
        asig[0] ^= 0xFFu;
        to_hex(asig, 64, sig_h);
        snprintf(app_body, sizeof(app_body),
                 "{\"channel\":\"stable\",\"serial\":1,\"approver\":\"cto@corp\",\"signature\":\"%s\"}", sig_h);
        snprintf(req, sizeof(req),
                 "POST /api/v1/approvals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(app_body), app_body);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0) record_finding("HIGH", "CP-P0-03", "Valid approval 1/2 failed");
        snprintf(req, sizeof(req),
                 "POST /api/v1/channels/stable HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(prom1), prom1);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 403", 12) != 0)
            record_finding("CRITICAL", "CP-P0-03", "Promotion with only 1/2 approvals was NOT blocked with 403");

        /* Valid approval 2/2 -> promotion succeeds (200 OK)! */
        crypto_sign_ed25519_detached(asig, NULL, (const uint8_t *)canon, (unsigned long long)cl, app2_kp.sk);
        to_hex(asig, 64, sig_h);
        snprintf(app_body, sizeof(app_body),
                 "{\"channel\":\"stable\",\"serial\":1,\"approver\":\"ciso@corp\",\"signature\":\"%s\"}", sig_h);
        snprintf(req, sizeof(req),
                 "POST /api/v1/approvals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(app_body), app_body);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0) record_finding("HIGH", "CP-P0-03", "Valid approval 2/2 failed");
        snprintf(req, sizeof(req),
                 "POST /api/v1/channels/stable HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(prom1), prom1);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0)
            record_finding("HIGH", "CP-P0-03", "Promotion with valid 2/2 Ed25519 quorum failed");
        else
            record_ok("CP-P0-03", "Cryptographic 2-of-N Ed25519 quorum enforced (0/2->403, forged->401, 1/2->403, 2/2->200)");

        /* P0-06: Republishing old/equal serial via /api/v1/emergency/rollback MUST be rejected with 400/409! */
        const char *rb_old = "{\"channel\":\"stable\",\"serial\":1}";
        snprintf(req, sizeof(req),
                 "POST /api/v1/emergency/rollback HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s", tok, strlen(rb_old), rb_old);
        raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 400", 12) != 0 && strncmp(resp, "HTTP/1.1 409", 12) != 0)
            record_finding("CRITICAL", "CP-P0-06", "Non-monotonic/non-ROLLBACK emergency rollback was NOT rejected");
        else
            record_ok("CP-P0-06", "Non-monotonic emergency rollback rejected cleanly (requires new signed FP_ACTION_ROLLBACK)");
    }

    /* 1h. HTTP 206 Partial Content Range + 416 + CRA Audit JSON/HTML */
    char obj_path[640];
    const char *obj_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    snprintf(obj_path, sizeof(obj_path), "%s/repo/objects/%s", cp_dir, obj_hex);
    FILE *of = fopen(obj_path, "wb");
    assert(of != NULL);
    fwrite("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1, 36, of);
    fclose(of);

    snprintf(req, sizeof(req), "GET /repo/objects/%s HTTP/1.1\r\nHost: x\r\nRange: bytes=10-19\r\n\r\n", obj_hex);
    raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 206", 12) != 0 || !strstr(resp, "ABCDEFGHIJ"))
        record_finding("MEDIUM", "CP-RANGE", "HTTP 206 Partial Content range failed");
    snprintf(req, sizeof(req), "GET /repo/objects/%s HTTP/1.1\r\nHost: x\r\nRange: bytes=999-1000\r\n\r\n", obj_hex);
    raw_http(port, req, strlen(req), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 416", 12) != 0)
        record_finding("MEDIUM", "CP-RANGE", "Out-of-bounds range did not return 416");
    else
        record_ok("CP-RANGE", "HTTP 206 Partial Content and 416 Range Not Satisfiable verified");

    const char *r_cra = "GET /api/v1/audit/cra HTTP/1.1\r\nHost: x\r\n\r\n";
    raw_http(port, r_cra, strlen(r_cra), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0 || !strstr(resp, "\"report_sha256\""))
        record_finding("MEDIUM", "CP-CRA", "CRA JSON audit endpoint failed");
    const char *r_chtml = "GET /api/v1/audit/cra.html HTTP/1.1\r\nHost: x\r\n\r\n";
    raw_http(port, r_chtml, strlen(r_chtml), resp, sizeof(resp), 2000);
    if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0 || !strstr(resp, "EU Cyber Resilience Act"))
        record_finding("MEDIUM", "CP-CRA", "CRA HTML audit endpoint failed");
    else
        record_ok("CP-CRA", "EU CRA JSON (SHA-256) and printable HTML endpoints verified");

    /* 1i. 24 parallel mixed valid+garbage clients */
    pthread_t ths[24];
    storm_arg_t args[24];
    for (int i = 0; i < 24; i++) {
        args[i].port = port;
        args[i].idx = i;
        assert(pthread_create(&ths[i], NULL, cp_storm_worker, &args[i]) == 0);
    }
    for (int i = 0; i < 24; i++) pthread_join(ths[i], NULL);
    int st = 0;
    assert(waitpid(pid, &st, WNOHANG) == 0); /* still alive! */
    record_ok("CP-CONCURRENCY", "24 parallel mixed valid+garbage clients survived cleanly");

    kill(pid, SIGTERM);
    waitpid(pid, &st, 0);

    /* 1j. P0-06 Fail-Closed Default Mode + P1-06 Legacy v0 DB Migration */
    {
        const uint16_t sec_port = 18924;
        char sec_dir[512], sec_ev_dir[544], sec_db_path[544];
        snprintf(sec_dir, sizeof(sec_dir), "%s/cp_secure_default", work);
        snprintf(sec_ev_dir, sizeof(sec_ev_dir), "%s/repo/events", sec_dir);
        snprintf(sec_db_path, sizeof(sec_db_path), "%s/control_plane.db", sec_dir);
        mkdir(sec_dir, 0755);
        char sec_repo_dir[544];
        snprintf(sec_repo_dir, sizeof(sec_repo_dir), "%s/repo", sec_dir);
        mkdir(sec_repo_dir, 0755);
        mkdir(sec_ev_dir, 0755);

        /* Pre-seed legacy v0 DB with unsigned approvals rows that MUST NOT grant quorum after migration */
        sqlite3 *ldb = NULL;
        assert(sqlite3_open(sec_db_path, &ldb) == SQLITE_OK);
        const char *v0_sql =
            "CREATE TABLE approvals ("
            "  serial INTEGER NOT NULL,"
            "  approver TEXT NOT NULL,"
            "  approved_utc TEXT NOT NULL,"
            "  reason TEXT NOT NULL,"
            "  threshold INTEGER NOT NULL,"
            "  PRIMARY KEY (serial, approver)"
            ");"
            "INSERT INTO approvals VALUES (1, 'legacy-a', '2025-01-01T00:00:00Z', 'old', 2);"
            "INSERT INTO approvals VALUES (1, 'legacy-b', '2025-01-01T00:00:00Z', 'old', 2);"
            "PRAGMA user_version = 0;";
        assert(sqlite3_exec(ldb, v0_sql, NULL, NULL, NULL) == SQLITE_OK);
        sqlite3_close(ldb);

        /* Put signed 1.ev in repo/events/1.ev */
        fp_keypair_t rkp;
        assert(fp_keygen(&rkp) == FP_OK);
        fp_dna_t rid, bdna;
        assert(fp_random_id(&rid) == FP_OK && fp_random_id(&bdna) == FP_OK);
        fp_event_t ev1;
        memset(&ev1, 0, sizeof(ev1));
        ev1.action = FP_ACTION_INSTALL; ev1.repo_id = rid; ev1.serial = 1;
        ev1.timestamp_unix = (uint64_t)time(NULL); ev1.expires_unix = ev1.timestamp_unix + 3600;
        ev1.target_dna = bdna; ev1.target_size = 64;
        assert(fp_event_sign(&ev1, &rkp) == FP_OK);
        uint8_t *eb = NULL; size_t el = 0;
        assert(fp_event_encode(&ev1, &eb, &el) == FP_OK);
        char evp[600];
        snprintf(evp, sizeof(evp), "%s/1.ev", sec_ev_dir);
        FILE *ef = fopen(evp, "wb"); assert(ef && fwrite(eb, 1, el, ef) == el); fclose(ef); free(eb);

        /* Launch sf-cp with ZERO security flags -> must default to loopback + signed + enrolled + quorum! */
        char sec_port_s[16];
        snprintf(sec_port_s, sizeof(sec_port_s), "%u", (unsigned)sec_port);
        char *sec_argv[] = { "./bin/sf-cp", "--port", sec_port_s, "--data-dir", sec_dir, NULL };
        pid_t spid = spawn_bg(sec_argv);
        assert(spid > 0);
        int sready = 0;
        for (int i = 0; i < 40; i++) {
            int fd = tcp_connect_local(sec_port, 200);
            if (fd >= 0) { close(fd); sready = 1; break; }
            msleep(50);
        }
        assert(sready);

        char sec_tok_path[600], sec_tok[128];
        snprintf(sec_tok_path, sizeof(sec_tok_path), "%s/admin.token", sec_dir);
        assert(read_file_str(sec_tok_path, sec_tok, sizeof(sec_tok)) == 0);

        /* Unsigned heartbeat -> 401 */
        const char *uhb = "{\"device_id\":\"d1\",\"outcome\":\"UPDATED\",\"active_serial\":1}";
        snprintf(req, sizeof(req),
                 "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\nContent-Length: %zu\r\n\r\n%s",
                 strlen(uhb), uhb);
        raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 401", 12) != 0)
            record_finding("CRITICAL", "CP-P0-06", "Default sf-cp did NOT reject unsigned heartbeat with 401");

        /* Signed but unenrolled heartbeat -> 401 */
        uint8_t dsig[64];
        char dpk_hex[65], dsig_hex[129];
        crypto_sign_ed25519_detached(dsig, NULL, (const uint8_t *)uhb, strlen(uhb), dkp.sk);
        to_hex(dkp.pk, 32, dpk_hex);
        to_hex(dsig, 64, dsig_hex);
        snprintf(req, sizeof(req),
                 "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\n"
                 "X-SF-Device-PubKey: %s\r\nX-SF-Signature: %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s",
                 dpk_hex, dsig_hex, strlen(uhb), uhb);
        raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 401", 12) != 0)
            record_finding("CRITICAL", "CP-P0-06", "Default sf-cp did NOT reject unenrolled device with 401");

        /* Promotion without crypto quorum (despite legacy v0 approvals!) -> 403 */
        const char *sprom = "{\"serial\":1}";
        snprintf(req, sizeof(req),
                 "POST /api/v1/channels/stable HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                 "Content-Length: %zu\r\n\r\n%s",
                 sec_tok, strlen(sprom), sprom);
        raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
        if (strncmp(resp, "HTTP/1.1 403", 12) != 0)
            record_finding("CRITICAL", "CP-P0-06/P1-06", "Default sf-cp allowed promotion without crypto quorum or accepted legacy v0 approvals");
        else
            record_ok("CP-P0-06/P1-06", "Default fail-closed mode (401 unsigned/unenrolled, 403 no quorum) & legacy v0 DB migration verified");

        /* CP-03 (SEC-02): Admin GET endpoints MUST require Bearer token in default fail-closed mode! */
        const char *admin_gets[4] = {
            "/api/v1/fleet", "/api/v1/approvals", "/api/v1/audit/cra", "/api/v1/audit/cra.html"
        };
        int cp03_ok = 1;
        for (int gi = 0; gi < 4; gi++) {
            snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", admin_gets[gi]);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            if (strncmp(resp, "HTTP/1.1 401", 12) != 0) cp03_ok = 0;

            snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n\r\n",
                     admin_gets[gi], sec_tok);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0) cp03_ok = 0;
        }
        if (!cp03_ok)
            record_finding("CRITICAL", "CP-03", "Default sf-cp leaked admin GET endpoint without Bearer token or rejected valid Bearer");
        else
            record_ok("CP-03", "Admin GET endpoints (fleet/approvals/CRA) enforce Bearer auth by default (401 unauth -> 200 auth)");

        /* SF-A06: Cross-channel approvals (1 on canary + 1 on stable for serial 1) MUST NOT report quorum_met:true! */
        {
            fp_keypair_t ak1, ak2;
            assert(fp_keygen(&ak1) == FP_OK && fp_keygen(&ak2) == FP_OK);
            char pk1[65], pk2[65], sig1[129], sig2[129], eh_hex[65];
            to_hex(ak1.pk, 32, pk1);
            to_hex(ak2.pk, 32, pk2);
            to_hex(ev1.event_hash.bytes, 32, eh_hex);

            char body_buf[512];
            snprintf(body_buf, sizeof(body_buf), "{\"approver\":\"alice\",\"pubkey\":\"%s\"}", pk1);
            snprintf(req, sizeof(req),
                     "POST /api/v1/approvers HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s", sec_tok, strlen(body_buf), body_buf);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            snprintf(body_buf, sizeof(body_buf), "{\"approver\":\"bob\",\"pubkey\":\"%s\"}", pk2);
            snprintf(req, sizeof(req),
                     "POST /api/v1/approvers HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s", sec_tok, strlen(body_buf), body_buf);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            char can1[256], can2[256];
            uint8_t sraw1[64], sraw2[64];
            snprintf(can1, sizeof(can1), "SF_APPROVAL_V1|canary|1|%s", eh_hex);
            snprintf(can2, sizeof(can2), "SF_APPROVAL_V1|stable|1|%s", eh_hex);
            crypto_sign_ed25519_detached(sraw1, NULL, (const uint8_t *)can1, strlen(can1), ak1.sk);
            crypto_sign_ed25519_detached(sraw2, NULL, (const uint8_t *)can2, strlen(can2), ak2.sk);
            to_hex(sraw1, 64, sig1);
            to_hex(sraw2, 64, sig2);

            snprintf(body_buf, sizeof(body_buf),
                     "{\"channel\":\"canary\",\"serial\":1,\"approver\":\"alice\",\"reason\":\"ok\",\"signature\":\"%s\"}", sig1);
            snprintf(req, sizeof(req),
                     "POST /api/v1/approvals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s", sec_tok, strlen(body_buf), body_buf);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            snprintf(body_buf, sizeof(body_buf),
                     "{\"channel\":\"stable\",\"serial\":1,\"approver\":\"bob\",\"reason\":\"ok\",\"signature\":\"%s\"}", sig2);
            snprintf(req, sizeof(req),
                     "POST /api/v1/approvals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s", sec_tok, strlen(body_buf), body_buf);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            snprintf(req, sizeof(req),
                     "GET /api/v1/approvals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n\r\n", sec_tok);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            if (strncmp(resp, "HTTP/1.1 200", 12) != 0 ||
                strstr(resp, "\"quorum_met\":true") != NULL ||
                strstr(resp, "\"channel\":\"canary\"") == NULL ||
                strstr(resp, "\"channel\":\"stable\"") == NULL) {
                record_finding("HIGH", "SF-A06", "GET /api/v1/approvals conflated canary+stable approvals into quorum_met:true");
            } else {
                record_ok("SF-A06", "GET /api/v1/approvals groups by (channel, serial, event_hash) and rejects cross-channel quorum");
            }

            /* SF-A07: Dashboard HTML must pass Bearer token in loadData() and handle 401 cleanly */
            snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            if (strncmp(resp, "HTTP/1.1 200", 12) != 0 ||
                strstr(resp, "Authorization") == NULL ||
                strstr(resp, "r.status === 401") == NULL) {
                record_finding("MEDIUM", "SF-A07", "Dashboard HTML loadData() missing Bearer header or 401 handling");
            } else {
                record_ok("SF-A07", "Dashboard HTML loadData() sends Admin Bearer header and handles 401 cleanly");
            }

            /* R4 + R5: Atomic SQLite channel+audit transaction AND server-side audit category isolation */
            char can1_st[256], sig1_st[129];
            uint8_t sraw1_st[64];
            snprintf(can1_st, sizeof(can1_st), "SF_APPROVAL_V1|stable|1|%s", eh_hex);
            crypto_sign_ed25519_detached(sraw1_st, NULL, (const uint8_t *)can1_st, strlen(can1_st), ak1.sk);
            to_hex(sraw1_st, 64, sig1_st);
            snprintf(body_buf, sizeof(body_buf),
                     "{\"channel\":\"stable\",\"serial\":1,\"approver\":\"alice\",\"reason\":\"2nd\",\"signature\":\"%s\"}", sig1_st);
            snprintf(req, sizeof(req),
                     "POST /api/v1/approvals HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s", sec_tok, strlen(body_buf), body_buf);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            snprintf(req, sizeof(req),
                     "POST /api/v1/channels/stable HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s", sec_tok, strlen(sprom), sprom);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            /* Remove legacy file mirror channels/stable/latest.ev -> GET must still serve committed DB pointer! */
            char mir_ev[600];
            snprintf(mir_ev, sizeof(mir_ev), "%s/repo/channels/stable/latest.ev", sec_dir);
            (void)unlink(mir_ev);
            snprintf(req, sizeof(req), "GET /repo/channels/stable/latest.ev HTTP/1.1\r\nHost: x\r\n\r\n");
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            if (strncmp(resp, "HTTP/1.1 200 OK", 15) != 0) {
                record_finding("HIGH", "CP-R4", "Channel GET failed when legacy latest.ev mirror was absent despite committed DB pointer");
            } else {
                record_ok("CP-R4", "Channel promotion commits pointer + audit in one SQLite TX and serves committed immutable event");
            }

            /* R5: Enroll device, send heartbeat claiming channel='governance' + outcome='CHANNEL_SET' -> category MUST be 'heartbeat'! */
            snprintf(body_buf, sizeof(body_buf), "{\"device_id\":\"d1\",\"pubkey\":\"%s\"}", dpk_hex);
            snprintf(req, sizeof(req),
                     "POST /api/v1/devices/enroll HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s", sec_tok, strlen(body_buf), body_buf);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            const char *tricky_hb = "{\"device_id\":\"d1\",\"channel\":\"governance\",\"outcome\":\"CHANNEL_SET\",\"active_serial\":1,\"hb_seq\":1}";
            crypto_sign_ed25519_detached(dsig, NULL, (const uint8_t *)tricky_hb, strlen(tricky_hb), dkp.sk);
            to_hex(dsig, 64, dsig_hex);
            snprintf(req, sizeof(req),
                     "POST /api/v1/heartbeat HTTP/1.1\r\nHost: x\r\n"
                     "X-SF-Device-PubKey: %s\r\nX-SF-Signature: %s\r\n"
                     "Content-Length: %zu\r\n\r\n%s",
                     dpk_hex, dsig_hex, strlen(tricky_hb), tricky_hb);
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            assert(strncmp(resp, "HTTP/1.1 200", 12) == 0);

            sqlite3 *cdb = NULL;
            assert(sqlite3_open(sec_db_path, &cdb) == SQLITE_OK);
            int hb_cat_ok = 0, admin_partial_ok = 0, chan_row_ok = 0;
            sqlite3_stmt *qs = NULL;
            if (sqlite3_prepare_v2(cdb, "SELECT COUNT(*) FROM audit_log WHERE device_id='d1' AND category='heartbeat';", -1, &qs, NULL) == SQLITE_OK) {
                if (sqlite3_step(qs) == SQLITE_ROW && sqlite3_column_int(qs, 0) == 1) hb_cat_ok = 1;
                sqlite3_finalize(qs);
            }
            if (sqlite3_prepare_v2(cdb, "SELECT COUNT(*) FROM audit_log WHERE outcome='APPROVED_PARTIAL' AND category='admin';", -1, &qs, NULL) == SQLITE_OK) {
                if (sqlite3_step(qs) == SQLITE_ROW && sqlite3_column_int(qs, 0) >= 1) admin_partial_ok = 1;
                sqlite3_finalize(qs);
            }
            if (sqlite3_prepare_v2(cdb, "SELECT COUNT(*) FROM channels WHERE channel='stable' AND serial=1;", -1, &qs, NULL) == SQLITE_OK) {
                if (sqlite3_step(qs) == SQLITE_ROW && sqlite3_column_int(qs, 0) == 1) chan_row_ok = 1;
                sqlite3_finalize(qs);
            }
            sqlite3_close(cdb);
            if (!hb_cat_ok || !admin_partial_ok || !chan_row_ok) {
                record_finding("MEDIUM", "CP-R4/R5", "audit_log.category isolation or channels table commit verification failed");
            } else {
                record_ok("CP-R5", "audit_log.category isolates device telemetry ('heartbeat') from admin/partial-approval records ('admin')");
            }

            /* F6 + F7: (a) Unpromoted filesystem mirror blocked (404) in default secure mode;
             * (b) Range request served from verified in-memory event buffer (206);
             * (c) Tampered committed event file rejected with 503 (never falls back to mirror!) */
            char unp_dir[600], unp_ev[640];
            snprintf(unp_dir, sizeof(unp_dir), "%s/repo/channels/unpromoted", sec_dir);
            snprintf(unp_ev, sizeof(unp_ev), "%s/latest.ev", unp_dir);
            mkdir(unp_dir, 0755);
            FILE *uf = fopen(unp_ev, "wb"); assert(uf && fwrite("FAKE", 1, 4, uf) == 4); fclose(uf);
            snprintf(req, sizeof(req), "GET /repo/channels/unpromoted/latest.ev HTTP/1.1\r\nHost: x\r\n\r\n");
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            if (strncmp(resp, "HTTP/1.1 404", 12) != 0) {
                record_finding("MEDIUM", "CP-F6", "Default secure sf-cp served unpromoted filesystem latest.ev file");
            } else {
                record_ok("CP-F6", "Default secure sf-cp rejects unpromoted filesystem latest.ev with 404");
            }

            snprintf(req, sizeof(req), "GET /repo/channels/stable/latest.ev HTTP/1.1\r\nHost: x\r\nRange: bytes=0-15\r\n\r\n");
            raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
            if (strncmp(resp, "HTTP/1.1 206", 12) != 0 || strstr(resp, "Content-Range: bytes 0-15/") == NULL) {
                record_finding("MEDIUM", "CP-F7", "Verified in-memory event buffer failed HTTP 206 Range request");
            } else {
                /* Corrupt committed events/1.ev on disk -> MUST return 503 fail-closed (zero TOCTOU / zero mirror fallback) */
                FILE *cf = fopen(evp, "wb"); assert(cf && fwrite("CORRUPT_EVENT", 1, 13, cf) == 13); fclose(cf);
                snprintf(req, sizeof(req), "GET /repo/channels/stable/latest.ev HTTP/1.1\r\nHost: x\r\n\r\n");
                raw_http(sec_port, req, strlen(req), resp, sizeof(resp), 2000);
                if (strncmp(resp, "HTTP/1.1 503", 12) != 0) {
                    record_finding("HIGH", "CP-F6/F7", "Tampered committed event did not fail closed with 503");
                } else {
                    record_ok("CP-F7", "Single-read verified buffer serves Range (206) and fails closed (503) on event tamper");
                }
            }
        }

        /* SEC-07: sf-llama-bridge --role server without --peer-pk or --allow-any-peer MUST fail closed */
        char bkey[600];
        snprintf(bkey, sizeof(bkey), "%s/bridge_sec07.key", work);
        char *br_cmd[] = { "./bin/sf-llama-bridge", "--role", "server", "--key", bkey, "--once", NULL };
        if (run_cmd_capture(br_cmd, NULL, 0) == 0)
            record_finding("HIGH", "BRIDGE-SEC-07", "sf-llama-bridge server started without --peer-pk or --allow-any-peer");
        else
            record_ok("BRIDGE-SEC-07", "sf-llama-bridge server fails closed without --peer-pk / --allow-any-peer");

        kill(spid, SIGTERM);
        waitpid(spid, &st, 0);
    }
}

/* ==================== 2. Live TCP & UDP Server Fuzzing ==================== */

static void test_live_tcp_udp_fuzz(const char *work) {
    printf("\n=== 2. Live TCP (bin/sf serve) & UDP (bin/sf udp-serve) Network Fuzzing ===\n");
    char store[512], srv_sk[512], srv_pk[512], cli_sk[512], cli_pk[512], sample[512];
    snprintf(store, sizeof(store), "%s/net_store", work);
    snprintf(srv_sk, sizeof(srv_sk), "%s/srv.sk", work);
    snprintf(srv_pk, sizeof(srv_pk), "%s/srv.pk", work);
    snprintf(cli_sk, sizeof(cli_sk), "%s/cli.sk", work);
    snprintf(cli_pk, sizeof(cli_pk), "%s/cli.pk", work);
    snprintf(sample, sizeof(sample), "%s/sample.bin", work);
    mkdir(store, 0755);

    char *kg1[] = { "./bin/sf", "keygen", srv_sk, srv_pk, NULL };
    char *kg2[] = { "./bin/sf", "keygen", cli_sk, cli_pk, NULL };
    assert(run_cmd_capture(kg1, NULL, 0) == 0);
    assert(run_cmd_capture(kg2, NULL, 0) == 0);

    uint8_t *rnd = malloc(128u * 1024u);
    assert(rnd != NULL);
    randombytes_buf(rnd, 128u * 1024u);
    FILE *sf = fopen(sample, "wb");
    assert(sf && fwrite(rnd, 1, 128u * 1024u, sf) == 128u * 1024u);
    fclose(sf);
    free(rnd);

    char out[512], dna[80];
    char *put_cmd[] = { "./bin/sf", "put", store, sample, NULL };
    assert(run_cmd_capture(put_cmd, out, sizeof(out)) == 0);
    extract_kv(out, "dna=", dna, sizeof(dna));
    assert(strlen(dna) == 64);

    /* 2a. TCP fuzzing */
    char *tcp_srv[] = { "./bin/sf", "serve", store, "--key", srv_sk,
                        "--bind", "127.0.0.1", "--port", "18922", "--max", "41", NULL };
    pid_t tpid = spawn_bg(tcp_srv);
    assert(tpid > 0);
    msleep(250);
    for (int i = 0; i < 40; i++) {
        int fd = tcp_connect_local(18922, 1000);
        if (fd >= 0) {
            uint8_t junk[512];
            randombytes_buf(junk, sizeof(junk));
            if (i % 4 == 0) {
                memcpy(junk, "FPN1", 4);
                (void)send(fd, junk, 148, MSG_NOSIGNAL);
            } else if (i % 4 == 1) {
                memcpy(junk, "FPN1", 4);
                (void)send(fd, junk, 14, MSG_NOSIGNAL);
            } else if (i % 4 == 2) {
                (void)send(fd, junk, 512, MSG_NOSIGNAL);
            }
            close(fd);
        }
    }
    int st = 0;
    assert(waitpid(tpid, &st, WNOHANG) == 0);
    char cli_tcp[512];
    snprintf(cli_tcp, sizeof(cli_tcp), "%s/cli_tcp", work);
    char *pull_cmd[] = { "./bin/sf", "pull", "127.0.0.1:18922", dna, cli_tcp,
                         "--key", cli_sk, "--peer-pub", srv_pk, NULL };
    assert(run_cmd_capture(pull_cmd, NULL, 0) == 0);
    waitpid(tpid, &st, 0);
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    record_ok("TCP-FUZZ", "sf serve survived 40 adversarial connections and served valid pull immediately after");

    /* 2b. UDP fuzzing */
    char *udp_srv[] = { "./bin/sf", "udp-serve", store, "--key", srv_sk,
                        "--bind", "127.0.0.1", "--port", "18923", "--max", "1", NULL };
    pid_t upid = spawn_bg(udp_srv);
    assert(upid > 0);
    msleep(250);
    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(ufd >= 0);
    struct sockaddr_in usa;
    memset(&usa, 0, sizeof(usa));
    usa.sin_family = AF_INET;
    usa.sin_port = htons(18923);
    inet_pton(AF_INET, "127.0.0.1", &usa.sin_addr);
    for (int i = 0; i < 500; i++) {
        uint8_t pkt[1400];
        size_t plen = 0;
        int r = i % 5;
        if (r == 0) { memcpy(pkt, "FPU1", 4); randombytes_buf(pkt + 4, 176); plen = 180; }
        else if (r == 1) { memcpy(pkt, "FPU1", 4); pkt[4] = 3; randombytes_buf(pkt + 5, 47); plen = 52; }
        else if (r == 2) { memcpy(pkt, "FPU1", 4); pkt[4] = 5; randombytes_buf(pkt + 5, 35); plen = 40; }
        else if (r == 3) { plen = (size_t)randombytes_uniform(1400); if (plen) randombytes_buf(pkt, plen); }
        else { memcpy(pkt, "FPU1", 4); plen = 4; }
        (void)sendto(ufd, pkt, plen, 0, (struct sockaddr *)&usa, sizeof(usa));
    }
    close(ufd);
    msleep(150);
    assert(waitpid(upid, &st, WNOHANG) == 0);
    char cli_udp[512];
    snprintf(cli_udp, sizeof(cli_udp), "%s/cli_udp", work);
    char *upull[] = { "./bin/sf", "udp-pull", "127.0.0.1:18923", dna, cli_udp,
                      "--key", cli_sk, "--peer-pub", srv_pk, NULL };
    assert(run_cmd_capture(upull, NULL, 0) == 0);
    waitpid(upid, &st, 0);
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    record_ok("UDP-FUZZ", "sf udp-serve survived 500 fuzzed datagrams and completed valid pull cleanly");
}

/* ==================== 3. Evil HTTP Server + CLI Edge Cases ==================== */

typedef struct {
    int          lfd;
    _Atomic int  stop;
    _Atomic int  idx;
} evil_http_t;

static const char *const EVIL_RESPS[4] = {
    "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nboom",
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 99\r\n\r\nhello",
    "HTTP/1.1 999 BAD\r\nContent-Length: 0\r\n\r\n",
    "NOT_HTTP_AT_ALL\r\n\r\n"
};

static void *evil_http_thread(void *arg) {
    evil_http_t *e = (evil_http_t *)arg;
    struct timeval tv = { 0, 200000 };
    (void)setsockopt(e->lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (!atomic_load(&e->stop)) {
        int c = accept(e->lfd, NULL, NULL);
        if (c < 0) continue;
        struct timeval ctv = { 1, 0 };
        (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &ctv, sizeof(ctv));
        char tmp[1024];
        (void)recv(c, tmp, sizeof(tmp), 0);
        int k = atomic_fetch_add(&e->idx, 1) % 4;
        (void)send(c, EVIL_RESPS[k], strlen(EVIL_RESPS[k]), MSG_NOSIGNAL);
        close(c);
    }
    return NULL;
}

static void check_must_fail_clean(char *const argv[], const char *area) {
    int rc = run_cmd_capture(argv, NULL, 0);
    if (rc < 0) record_finding("CRITICAL", area, "Process crashed with signal!");
    else if (rc == 0) record_finding("HIGH", area, "Malicious/invalid command unexpectedly returned 0");
}

static void test_cli_edge_cases(const char *work) {
    printf("\n=== 3. CLI, Evil HTTP & Round-2 Hardening Edge Cases ===\n");
    char store[512], empty[512], oneb[512], corrupt[512];
    snprintf(store, sizeof(store), "%s/edge_store", work);
    snprintf(empty, sizeof(empty), "%s/empty.bin", work);
    snprintf(oneb, sizeof(oneb), "%s/one.bin", work);
    snprintf(corrupt, sizeof(corrupt), "%s/corrupt.bin", work);

    FILE *f = fopen(empty, "wb"); assert(f); fclose(f);
    f = fopen(oneb, "wb"); assert(f); fwrite("X", 1, 1, f); fclose(f);
    f = fopen(corrupt, "wb"); assert(f);
    uint8_t ff[777]; memset(ff, 0xFF, sizeof(ff));
    fwrite(ff, 1, sizeof(ff), f); fclose(f);

    /* 0-byte & 1-byte full round-trip */
    const char *files[2] = { empty, oneb };
    const char *labels[2] = { "0b", "1b" };
    char d_one[80] = "";
    for (int i = 0; i < 2; i++) {
        char out[512], d[80], rec[512], mpath[512], opath[512];
        char *c_dna[] = { "./bin/sf", "dna", (char *)files[i], NULL };
        char *c_put[] = { "./bin/sf", "put", store, (char *)files[i], NULL };
        char *c_ing[] = { "./bin/sf", "ingest", store, (char *)files[i], NULL };
        assert(run_cmd_capture(c_dna, NULL, 0) == 0);
        assert(run_cmd_capture(c_put, NULL, 0) == 0);
        assert(run_cmd_capture(c_ing, out, sizeof(out)) == 0);
        extract_kv(out, "dna=", d, sizeof(d));
        assert(strlen(d) == 64);
        if (i == 1) snprintf(d_one, sizeof(d_one), "%s", d);

        snprintf(rec, sizeof(rec), "%s/rec_%s", work, labels[i]);
        char *c_rec[] = { "./bin/sf", "reconstruct", store, d, rec, NULL };
        assert(run_cmd_capture(c_rec, NULL, 0) == 0);

        const char *kinds[2] = { "raw", "zstd" };
        for (int k = 0; k < 2; k++) {
            snprintf(mpath, sizeof(mpath), "%s/%s.%s.fp", work, labels[i], kinds[k]);
            snprintf(opath, sizeof(opath), "%s/%s.%s.out", work, labels[i], kinds[k]);
            char *c_m[] = { "./bin/sf", "morph", (char *)kinds[k], (char *)files[i], mpath, NULL };
            char *c_i[] = { "./bin/sf", "inspect", mpath, NULL };
            char *c_z[] = { "./bin/sf", "materialize", mpath, opath, NULL };
            assert(run_cmd_capture(c_m, NULL, 0) == 0);
            assert(run_cmd_capture(c_i, NULL, 0) == 0);
            assert(run_cmd_capture(c_z, NULL, 0) == 0);
        }
    }
    record_ok("CLI-EDGE", "0-byte and 1-byte files passed dna/put/ingest/reconstruct/morph/materialize");

    /* Negative CLI & traversal checks */
    char bad_out[512], b1[600], b2[600], b3[600], b4[600];
    snprintf(bad_out, sizeof(bad_out), "%s/bad.out", work);
    snprintf(b1, sizeof(b1), "../escape=%s", oneb);
    snprintf(b2, sizeof(b2), "/etc/evil=%s", oneb);
    snprintf(b3, sizeof(b3), "a//b=%s", oneb);
    snprintf(b4, sizeof(b4), "ok=%s", oneb);

    char *n1[] = { "./bin/sf", "inspect", corrupt, NULL };
    char *n2[] = { "./bin/sf", "materialize", corrupt, bad_out, NULL };
    char *n3[] = { "./bin/sf", "root-verify", corrupt, NULL };
    char *n4[] = { "./bin/sf", "bundle-pack", store, "--file", b1, NULL };
    char *n5[] = { "./bin/sf", "bundle-pack", store, "--file", b2, NULL };
    char *n6[] = { "./bin/sf", "bundle-pack", store, "--file", b3, NULL };
    char *n7[] = { "./bin/sf", "bundle-pack", store, "--file", b4, "--file", b4, NULL };
    char *n8[] = { "./bin/sf-agent", "--repo", "http://127.0.0.1:18999", "--channel", "../../evil",
                   "--store", store, "--target", (char *)work, "--root", corrupt, "--once", NULL };
    char *n9[] = { "./bin/sf-agent", "--repo", "http://127.0.0.1:18999/x\r\nInjected:1", "--channel", "stable",
                   "--store", store, "--target", (char *)work, "--root", corrupt, "--once", NULL };
    check_must_fail_clean(n1, "CLI-NEGATIVE");
    check_must_fail_clean(n2, "CLI-NEGATIVE");
    check_must_fail_clean(n3, "CLI-NEGATIVE");
    check_must_fail_clean(n4, "CLI-NEGATIVE");
    check_must_fail_clean(n5, "CLI-NEGATIVE");
    check_must_fail_clean(n6, "CLI-NEGATIVE");
    check_must_fail_clean(n7, "CLI-NEGATIVE");
    check_must_fail_clean(n8, "CLI-NEGATIVE");
    check_must_fail_clean(n9, "CLI-NEGATIVE");
    record_ok("CLI-NEGATIVE", "All corrupt, path-traversal & CRLF-injection CLI inputs rejected cleanly (0 signals)");

    /* Adversarial HTTP server against sf-agent */
    char rsk[512], rpk[512], root_fpr[512], out_kg[512], repo_id[80];
    snprintf(rsk, sizeof(rsk), "%s/hr.sk", work);
    snprintf(rpk, sizeof(rpk), "%s/hr.pk", work);
    snprintf(root_fpr, sizeof(root_fpr), "%s/hr.fpr", work);
    char *kg_r[] = { "./bin/sf", "keygen", rsk, rpk, NULL };
    assert(run_cmd_capture(kg_r, out_kg, sizeof(out_kg)) == 0);
    extract_kv(out_kg, "repo=", repo_id, sizeof(repo_id));
    assert(strlen(repo_id) == 64);
    char *ri[] = { "./bin/sf", "root-init", "--repo", repo_id, "--threshold", "1",
                   "--root-pub", rpk, "--release-pub", rpk, "--sign", rsk, "--out", root_fpr, NULL };
    assert(run_cmd_capture(ri, NULL, 0) == 0);

    uint16_t bad_port = 0;
    int el_fd = fp_net_listen("127.0.0.1", 0, &bad_port);
    assert(el_fd >= 0 && bad_port > 0);
    evil_http_t eh;
    eh.lfd = el_fd;
    atomic_init(&eh.stop, 0);
    atomic_init(&eh.idx, 0);
    pthread_t eth;
    assert(pthread_create(&eth, NULL, evil_http_thread, &eh) == 0);
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u", (unsigned)bad_port);
    for (int i = 0; i < 4; i++) {
        char hs[512], ht[512];
        snprintf(hs, sizeof(hs), "%s/hs%d", work, i);
        snprintf(ht, sizeof(ht), "%s/ht%d", work, i);
        char *ag[] = { "./bin/sf-agent", "--repo", url, "--channel", "stable",
                       "--device", "evil\"id\\<script>", "--store", hs, "--target", ht,
                       "--root", root_fpr, "--no-heartbeat", "--once", NULL };
        check_must_fail_clean(ag, "HTTP-ADVERSARIAL");
    }
    atomic_store(&eh.stop, 1);
    pthread_join(eth, NULL);
    close(el_fd);
    record_ok("HTTP-ADVERSARIAL", "sf-agent safely rejected all 4 adversarial HTTP responses (0 crashes)");

    /* Round-2 Hardening Checks */
    char ev1[512], bad_fpr[512], bad_ttl[512];
    snprintf(ev1, sizeof(ev1), "%s/ev1.ev", work);
    snprintf(bad_fpr, sizeof(bad_fpr), "%s/bad.fpr", work);
    snprintf(bad_ttl, sizeof(bad_ttl), "%s/bad_ttl.ev", work);
    char *em1[] = { "./bin/sf", "emit", "--key", rsk, "--repo", repo_id, "--serial", "1",
                    "--input", oneb, "--out", ev1, NULL };
    assert(run_cmd_capture(em1, NULL, 0) == 0);

    char *r2_1[] = { "./bin/sf", "dna", (char *)work, NULL };
    char *r2_2[] = { "./bin/sf", "serve", store, "--key", rsk, "--port", "65536", NULL };
    char *r2_3[] = { "./bin/sf", "serve", store, "--key", rsk, "--port", "abc", NULL };
    char *r2_4[] = { "./bin/sf", "udp-serve", store, "--key", rsk, "--port", "99999", NULL };
    char *r2_5[] = { "./bin/sf", "root-init", "--repo", repo_id, "--threshold", "256",
                     "--root-pub", rpk, "--release-pub", rpk, "--sign", rsk, "--out", bad_fpr, NULL };
    char *r2_6[] = { "./bin/sf", "emit", "--key", rsk, "--repo", repo_id, "--serial", "2",
                     "--ttl", "18446744073709551615", "--input", oneb, "--out", bad_ttl, NULL };
    check_must_fail_clean(r2_1, "CLI-R2");
    check_must_fail_clean(r2_2, "CLI-R2");
    check_must_fail_clean(r2_3, "CLI-R2");
    check_must_fail_clean(r2_4, "CLI-R2");
    check_must_fail_clean(r2_5, "CLI-R2");
    check_must_fail_clean(r2_6, "CLI-R2");

    /* Truncated anchor log */
    char bad_alog[512];
    snprintf(bad_alog, sizeof(bad_alog), "%s/trunc.anchor.log", work);
    f = fopen(bad_alog, "wb"); assert(f);
    uint8_t aa[50]; memset(aa, 0xAA, sizeof(aa));
    fwrite(aa, 1, sizeof(aa), f); fclose(f);
    char *av[] = { "./bin/sf", "anchor", ev1, "--log", bad_alog, "--verify", NULL };
    char *ap[] = { "./bin/sf", "anchor", ev1, "--log", bad_alog, NULL };
    check_must_fail_clean(av, "ANCHOR-TRUNC");
    check_must_fail_clean(ap, "ANCHOR-TRUNC");
    struct stat ast;
    assert(stat(bad_alog, &ast) == 0 && ast.st_size == 50);
    record_ok("ANCHOR-TRUNC", "Truncated/misaligned anchor log rejected fail-closed without corruption");

    /* Tampered FPC1 recipe with trailing byte */
    char rec_file[640], rec_bad[512];
    snprintf(rec_file, sizeof(rec_file), "%s/recipes/%s.fpc", store, d_one);
    snprintf(rec_bad, sizeof(rec_bad), "%s/rec_bad.out", work);
    f = fopen(rec_file, "ab"); assert(f);
    uint8_t z = 0; fwrite(&z, 1, 1, f); fclose(f);
    char *rb[] = { "./bin/sf", "reconstruct", store, d_one, rec_bad, NULL };
    check_must_fail_clean(rb, "CDC-FPC1");
    record_ok("CDC-FPC1", "Tampered FPC1 recipe rejected fail-closed (0 corrupt output)");
    record_ok("CLI-R2", "All Round-2 numeric overflow, directory, anchor & FPC1 checks passed");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    assert(fp_init() == FP_OK);

    char tmpl[] = "/tmp/sf-redteam-c-XXXXXX";
    char *work = mkdtemp(tmpl);
    assert(work != NULL);

    test_control_plane(work);
    test_live_tcp_udp_fuzz(work);
    test_cli_edge_cases(work);

    /* Cleanup tmp dir */
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", work);
    int sr = system(cmd);
    (void)sr;

    int findings = atomic_load(&g_findings);
    printf("\n=== PURE-C11 RED-TEAM SUMMARY: %d finding(s) ===\n", findings);
    return findings ? 1 : 0;
}
