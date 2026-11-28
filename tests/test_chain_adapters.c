/*
 * SealFrame Anchor Adapters Unit & Live JSON-RPC Integration Tests (Pure ISO C11)
 *
 * Verifies:
 *   1. Cryptographic & Encoding primitives:
 *      - Keryx OPoI Phase-2 fixed-point MLP BIT-EXACT match against keryx-node opoi.rs nonce=42 vector!
 *      - Base64 encoder (used by RFC 6455 WebSocket handshake)
 *   2. Live HTTP/1.1 JSON-RPC 2.0 end-to-end tests across supported adapters:
 *      - SF_CHAIN_GENERIC (sealframe_anchorPublish / sealframe_anchorVerify / submitDerivation)
 *      - SF_CHAIN_KERYX   (keryx_submitAnchor 76B SF1+OPoI payload / keryx_verifyAnchor / fraud-proof)
 *   3. Pure-C11 RFC 6455 WebSocket wRPC-JSON client (sf_keryx_wrpc_call)
 */
#define _POSIX_C_SOURCE 200809L

#include "sealframe.h"
#include "sealframe_chain.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ==================== Multi-Protocol In-Process Mock JSON-RPC 2.0 Server ==================== */

typedef struct {
    int             lfd;
    _Atomic int     stop;
    pthread_mutex_t mu;
    char            generic_comm[65];
    char            keryx_comm[65];
    char            keryx_tag[17];
    int             derivations_verified;
    int             evil_mode; /* A8-SEC-04 (CHAIN-01): 1=wrong id, 2=empty tx_id, 3=spoofed substring */
    uint8_t         expected_signer_pk[32];
} mock_rpc_t;

static void extract_str(const char *src, const char *key, char *dst, size_t cap) {
    dst[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(src, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1u < cap) dst[i++] = *p++;
    dst[i] = '\0';
}

static void send_http_json(int fd, const char *body) {
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                     strlen(body));
    (void)send(fd, hdr, (size_t)n, MSG_NOSIGNAL);
    (void)send(fd, body, strlen(body), MSG_NOSIGNAL);
}

static void *mock_rpc_thread(void *arg) {
    mock_rpc_t *m = (mock_rpc_t *)arg;
    struct timeval tv = { 0, 100000 };
    (void)setsockopt(m->lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (!atomic_load(&m->stop)) {
        int c = accept(m->lfd, NULL, NULL);
        if (c < 0) continue;
        struct timeval ctv = { 2, 0 };
        (void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &ctv, sizeof(ctv));

        char buf[16384];
        size_t got = 0;
        while (got + 1u < sizeof(buf)) {
            ssize_t r = recv(c, buf + got, sizeof(buf) - 1u - got, 0);
            if (r <= 0) break;
            got += (size_t)r;
            buf[got] = '\0';
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) {
                const char *cl = strstr(buf, "Content-Length:");
                if (cl) {
                    size_t need = (size_t)strtoul(cl + 15, NULL, 10);
                    if (got - (size_t)(sep - buf + 4) >= need) break;
                } else break;
            }
        }
        buf[got] = '\0';
        /* Handle RFC 6455 WebSocket Upgrade for sf_keryx_wrpc_call() test */
        if (strncmp(buf, "GET ", 4) == 0 && strstr(buf, "Upgrade: websocket") != NULL) {
            const char *hs =
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: mock==\r\n\r\n";
            (void)send(c, hs, strlen(hs), MSG_NOSIGNAL);
            /* Read client masked text frame */
            uint8_t fh[2];
            if (recv(c, fh, 2, MSG_WAITALL) == 2) {
                size_t plen = fh[1] & 0x7Fu;
                uint8_t mask[4];
                if (recv(c, mask, 4, MSG_WAITALL) == 4 && plen < 2048u) {
                    char payload[2048];
                    if (recv(c, payload, plen, MSG_WAITALL) == (ssize_t)plen) {
                        for (size_t i = 0; i < plen; i++) payload[i] ^= (char)mask[i & 3];
                        payload[plen] = '\0';
                        const char *reply = "{\"id\":1,\"result\":{\"networkName\":\"keryx-simnet\",\"virtualDaaScore\":42}}";
                        size_t rlen = strlen(reply);
                        uint8_t out_f[2] = { 0x81u, (uint8_t)rlen };
                        (void)send(c, out_f, 2, MSG_NOSIGNAL);
                        (void)send(c, reply, rlen, MSG_NOSIGNAL);
                    }
                }
            }
            close(c);
            continue;
        }
        const char *body = strstr(buf, "\r\n\r\n");
        if (!body) { close(c); continue; }
        body += 4;

        char method[64];
        extract_str(body, "method", method, sizeof(method));
        pthread_mutex_lock(&m->mu);

        if (m->evil_mode == 1) {
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":999,\"result\":\"gen_tx_bad_id\"}");
        } else if (m->evil_mode == 2) {
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\"}");
        } else if (m->evil_mode == 3) {
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"verified\":\"true\",\"note\":\"\\\"verified\\\":true\"}}");
        } else if (m->evil_mode == 4) {
            /* A9-SEC-01: Duplicate JSON key (parser differential attack) */
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"verified\":false,\"verified\":true}}");
        } else if (m->evil_mode == 5) {
            /* A9-SEC-01: Leading-zero number (invalid RFC 8259) */
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":01,\"result\":\"gen_tx_leadzero\"}");
        } else if (m->evil_mode == 6) {
            /* A9-SEC-02: Semantically rejected derivation result (`false`) */
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":false}");
        } else if (m->evil_mode == 7) {
            /* A9-SEC-02: Empty object `{}` derivation result */
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}");
        } else if (m->evil_mode == 8) {
            /* A9-SEC-03: Truncated HTTP body (Content-Length > actual bytes sent) */
            const char *trunc =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 200\r\n"
                "Connection: close\r\n\r\n"
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"short\"}";
            (void)send(c, trunc, strlen(trunc), MSG_NOSIGNAL);
        } else if (strcmp(method, "sealframe_anchorPublish") == 0) {
            extract_str(body, "commitment", m->generic_comm, sizeof(m->generic_comm));
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"gen_tx_0001\"}");
        } else if (strcmp(method, "sealframe_anchorVerify") == 0) {
            char q[65];
            extract_str(body, "commitment", q, sizeof(q));
            if (m->generic_comm[0] && strcmp(q, m->generic_comm) == 0)
                send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"verified\":true}}");
            else
                send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"verified\":false}}");
        } else if (strcmp(method, "keryx_submitAnchor") == 0) {
            char payload[256];
            extract_str(body, "commitment", m->keryx_comm, sizeof(m->keryx_comm));
            extract_str(body, "opoi_tag", m->keryx_tag, sizeof(m->keryx_tag));
            extract_str(body, "payload", payload, sizeof(payload));
            /* Verify 76-byte payload = 152 hex chars starting with "53463100" ("SF1\0") */
            if (strlen(payload) == 152u && strncmp(payload, "53463100", 8) == 0 &&
                strncmp(payload + 8, m->keryx_comm, 64) == 0 &&
                strncmp(payload + 72, m->keryx_tag, 16) == 0) {
                send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"keryx_dag_tx_99\"}");
            } else {
                send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":\"bad keryx payload\"}");
            }
        } else if (strcmp(method, "keryx_verifyAnchor") == 0) {
            char q[65];
            extract_str(body, "commitment", q, sizeof(q));
            if (m->keryx_comm[0] && strcmp(q, m->keryx_comm) == 0)
                send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"anchored\":true}}");
            else
                send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"anchored\":false}}");
        } else if (strcmp(method, "sealframe_submitDerivation") == 0 ||
                   strcmp(method, "keryx_submitOpoiFraudProof") == 0) {
            char fpd_hex[1024];
            extract_str(body, "fpd1_hex", fpd_hex, sizeof(fpd_hex));
            size_t blen = strlen(fpd_hex) / 2u;
            uint8_t fpd_bin[512];
            if (blen > 0 && blen <= sizeof(fpd_bin) &&
                fp_hex_decode(fpd_hex, fpd_bin, blen) == FP_OK) {
                fp_derivation_t drv;
                if (fp_derivation_decode(fpd_bin, blen, &drv) == FP_OK &&
                    fp_derivation_verify(&drv, m->expected_signer_pk) == FP_OK) {
                    m->derivations_verified++;
                    send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":\"slashed_ok\"}");
                } else {
                    send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":\"bad fpd1 sig\"}");
                }
            } else {
                send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":\"bad fpd1 hex\"}");
            }
        } else {
            send_http_json(c, "{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":\"unknown method\"}");
        }

        pthread_mutex_unlock(&m->mu);
        close(c);
    }
    return NULL;
}

int main(void) {
    assert(fp_init() == FP_OK);

    /* --- 1. Keryx OPoI Phase-2 BIT-EXACT Regression Vector (nonce=42 from keryx-node opoi.rs) --- */
    {
        static const uint8_t EXPECTED_NONCE42[32] = {
            182, 147, 169, 135, 251, 232, 129,  16,
            221, 172,  47, 152,   9,  81, 226, 160,
              1,  54, 235,  28, 221, 139, 125, 111,
            176, 173, 146,  73, 168, 229, 102, 209
        };
        uint8_t got[32];
        sf_keryx_opoi_forward_nonce(42ull, got);
        assert(memcmp(got, EXPECTED_NONCE42, 32) == 0);

        uint8_t t1[8], t2[8];
        char h1[17], h2[17];
        sf_keryx_opoi_tag(UINT64_C(0xDEADBEEFCAFE1337), t1, h1);
        sf_keryx_opoi_tag(UINT64_C(0xDEADBEEFCAFE1337), t2, h2);
        assert(memcmp(t1, t2, 8) == 0 && strlen(h1) == 16 && strcmp(h1, h2) == 0);
        printf("[PASS] Keryx OPoI Phase-2 fixed-point MLP bit-exact (nonce=42 matches keryx-node 32/32 bytes, tag=%s)\n", h1);
    }

    /* --- 2. Base64 Helper (RFC 6455 WebSocket Handshake) --- */
    {
        char b64[64];
        const uint8_t msg[5] = { 'h', 'e', 'l', 'l', 'o' };
        assert(sf_base64_encode(msg, 5, b64, sizeof(b64)) > 0 && strcmp(b64, "aGVsbG8=") == 0);
        printf("[PASS] Base64 encoder verified ('%s')\n", b64);
    }

    /* --- 3. Live JSON-RPC 2.0 Integration (Generic JSON-RPC 2.0 & Keryx BlockDAG/OPoI) --- */
    fp_keypair_t kp;
    assert(fp_keygen(&kp) == FP_OK);

    fp_dna_t target_dna, other_dna, parent_dna, op_dna;
    assert(fp_dna_compute((const uint8_t *)"inference-output-v1", 19, &target_dna) == FP_OK);
    assert(fp_dna_compute((const uint8_t *)"tampered-output-v2", 18, &other_dna) == FP_OK);
    assert(fp_dna_compute((const uint8_t *)"prompt-input", 12, &parent_dna) == FP_OK);
    assert(fp_dna_compute((const uint8_t *)"model-stage-0..8", 16, &op_dna) == FP_OK);

    fp_event_t ev, ev_bad;
    memset(&ev, 0, sizeof(ev));
    ev.version = 1; ev.action = FP_ACTION_INSTALL;
    memcpy(ev.repo_id.bytes, kp.pk, 32);
    ev.serial = 7;
    ev.timestamp_unix = (uint64_t)time(NULL);
    ev.expires_unix = ev.timestamp_unix + 3600u;
    ev.target_dna = target_dna;
    ev.target_size = 19;
    snprintf(ev.reason, sizeof(ev.reason), "chain-anchor-test");
    assert(fp_event_sign(&ev, &kp) == FP_OK);

    ev_bad = ev;
    ev_bad.serial = 999;
    ev_bad.target_dna = other_dna;
    assert(fp_event_sign(&ev_bad, &kp) == FP_OK);

    fp_anchor_commitment_t comm, comm_bad;
    assert(fp_anchor_compute(&ev, &comm) == FP_OK);
    assert(fp_anchor_compute(&ev_bad, &comm_bad) == FP_OK);

    fp_derivation_t drv;
    memset(&drv, 0, sizeof(drv));
    drv.version = 1;
    drv.parent_dna = parent_dna;
    drv.op_dna = op_dna;
    drv.result_dna = target_dna;
    drv.result_size = 19;
    drv.timestamp_unix = (uint64_t)time(NULL);
    assert(fp_derivation_sign(&drv, &kp) == FP_OK);

    uint16_t port = 0;
    int lfd = fp_net_listen("127.0.0.1", 0, &port);
    assert(lfd >= 0 && port > 0);
    mock_rpc_t rpc;
    memset(&rpc, 0, sizeof(rpc));
    rpc.lfd = lfd;
    atomic_init(&rpc.stop, 0);
    pthread_mutex_init(&rpc.mu, NULL);
    memcpy(rpc.expected_signer_pk, kp.pk, 32);

    pthread_t th;
    assert(pthread_create(&th, NULL, mock_rpc_thread, &rpc) == 0);

    char rpc_url[64];
    snprintf(rpc_url, sizeof(rpc_url), "http://127.0.0.1:%u", (unsigned)port);

    const sf_chain_kind_t kinds[2] = { SF_CHAIN_GENERIC, SF_CHAIN_KERYX };
    const char *names[2] = { "Generic JSON-RPC 2.0", "Keryx (BlockDAG/OPoI)" };

    for (int i = 0; i < 2; i++) {
        sf_chain_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.kind = kinds[i];
        cfg.rpc_url = rpc_url;
        cfg.contract_addr = "keryx:qpzry9x8";
        cfg.signer_kp = &kp;
        cfg.keryx_nonce = UINT64_C(0xDEADBEEFCAFE1337);
        cfg.io_timeout_ms = 5000;

        sf_chain_ctx_t ctx;
        fp_anchor_ops_t ops;
        assert(sf_chain_adapter_init(&ctx, &cfg, &ops) == FP_OK);

        /* Publish -> Verify OK -> Tampered/Unanchored rejected -> Signed FPD1 Derivation verified */
        assert(ops.publish(ops.user_ctx, &comm) == FP_OK);
        assert(strlen(ctx.last_tx_id) > 0);
        assert(ops.verify(ops.user_ctx, &comm) == FP_OK);
        assert(ops.verify(ops.user_ctx, &comm_bad) == FP_ERR_INTEGRITY);
        assert(sf_chain_submit_derivation(&ctx, &drv, &other_dna) == FP_OK);

        printf("[PASS] %-24s -> publish(tx=%s) + verify(OK) + tamper(REJECT) + FPD1(VERIFIED)\n",
               names[i], ctx.last_tx_id);
    }

    assert(rpc.derivations_verified == 2);

    /* --- 3b. A8-SEC-04 (CHAIN-01): Strict JSON-RPC 2.0 negative tests (wrong id, empty tx_id, spoofed substring) --- */
    {
        sf_chain_cfg_t ecfg;
        memset(&ecfg, 0, sizeof(ecfg));
        ecfg.kind = SF_CHAIN_GENERIC;
        ecfg.rpc_url = rpc_url;
        ecfg.io_timeout_ms = 5000;
        sf_chain_ctx_t ectx;
        fp_anchor_ops_t eops;
        assert(sf_chain_adapter_init(&ectx, &ecfg, &eops) == FP_OK);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 1; pthread_mutex_unlock(&rpc.mu);
        assert(eops.publish(eops.user_ctx, &comm) == FP_ERR_INTEGRITY);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 2; pthread_mutex_unlock(&rpc.mu);
        assert(eops.publish(eops.user_ctx, &comm) == FP_ERR_INTEGRITY);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 3; pthread_mutex_unlock(&rpc.mu);
        assert(eops.verify(eops.user_ctx, &comm) == FP_ERR_INTEGRITY);

        /* A9-SEC-01/02/03: Duplicate JSON keys, leading-zero numbers, false/{} derivation result, truncated HTTP body */
        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 4; pthread_mutex_unlock(&rpc.mu);
        assert(eops.verify(eops.user_ctx, &comm) == FP_ERR_INTEGRITY);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 5; pthread_mutex_unlock(&rpc.mu);
        assert(eops.publish(eops.user_ctx, &comm) == FP_ERR_INTEGRITY);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 6; pthread_mutex_unlock(&rpc.mu);
        assert(sf_chain_submit_derivation(&ectx, &drv, &other_dna) == FP_ERR_INTEGRITY);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 7; pthread_mutex_unlock(&rpc.mu);
        assert(sf_chain_submit_derivation(&ectx, &drv, &other_dna) == FP_ERR_INTEGRITY);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 8; pthread_mutex_unlock(&rpc.mu);
        assert(eops.publish(eops.user_ctx, &comm) == FP_ERR_IO);

        pthread_mutex_lock(&rpc.mu); rpc.evil_mode = 0; pthread_mutex_unlock(&rpc.mu);
        printf("[PASS] A8-SEC-04 & A9-SEC-01/02/03 (RPC-01/02/03): Strict RFC 8259 JSON, dup-key, semantic derivation & HTTP framing verified!\n");
    }

    /* --- 4. Pure-C11 RFC 6455 WebSocket wRPC-JSON client test --- */
    {
        char ws_url[64], ws_resp[512];
        snprintf(ws_url, sizeof(ws_url), "ws://127.0.0.1:%u/", (unsigned)port);
        assert(sf_keryx_wrpc_call(ws_url, "getBlockDagInfo", "{}", 5000, ws_resp, sizeof(ws_resp)) == FP_OK);
        assert(strstr(ws_resp, "\"networkName\":\"keryx-simnet\"") != NULL);
        printf("[PASS] Pure-C11 RFC 6455 WebSocket wRPC-JSON client verified (%s)\n", ws_resp);
    }

    atomic_store(&rpc.stop, 1);
    pthread_join(th, NULL);
    close(lfd);
    pthread_mutex_destroy(&rpc.mu);
    sodium_memzero(&kp, sizeof(kp));

    printf("ALL ANCHOR ADAPTER TESTS PASSED (Generic JSON-RPC 2.0 & Keryx).\n");
    return 0;
}
