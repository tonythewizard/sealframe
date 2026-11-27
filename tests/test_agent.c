#define _POSIX_C_SOURCE 200809L

#include "fp.h"
#include "fp_agent.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Minimal embedded HTTP/1.1 Range test server (zero external deps, ASan-friendly!) */
typedef struct {
    int         listen_fd;
    const char *repo_dir;
    _Atomic int stop;
    _Atomic int corrupt_next_obj;
    _Atomic int bad_range_next;
    _Atomic int heartbeats_received;
    _Atomic int signed_heartbeats_verified;
} mini_http_t;

typedef struct {
    int                 fd;
    fp_net_server_cfg_t cfg;
} lan_srv_t;

static void *lan_srv_thread(void *arg) {
    lan_srv_t *s = (lan_srv_t *)arg;
    (void)fp_net_serve_fd(s->fd, &s->cfg);
    close(s->fd);
    return NULL;
}

static void send_http_simple(int cfd, int code, const char *ct, const uint8_t *body, size_t len,
                             const char *extra) {
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
                        "HTTP/1.1 %d OK\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %zu\r\n"
                        "%s"
                        "Connection: close\r\n\r\n",
                        code, ct, len, extra ? extra : "");
    (void)send(cfd, hdr, (size_t)hlen, 0);
    if (len > 0) (void)send(cfd, body, len, 0);
}

static void *mini_http_thread(void *arg) {
    mini_http_t *s = (mini_http_t *)arg;
    while (!s->stop) {
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) break;
        char req[4096];
        size_t total = 0;
        while (total < sizeof(req) - 1u) {
            ssize_t n = recv(cfd, req + total, sizeof(req) - 1u - total, 0);
            if (n <= 0) break;
            total += (size_t)n;
            req[total] = '\0';
            const char *hdr_end = strstr(req, "\r\n\r\n");
            if (hdr_end) {
                const char *cl = strstr(req, "Content-Length: ");
                size_t want = cl ? (size_t)strtoul(cl + 16, NULL, 10) : 0;
                size_t have = total - (size_t)((hdr_end + 4) - req);
                if (have >= want) break;
            }
        }
        if (total == 0) { close(cfd); continue; }

        if (strncmp(req, "POST /api/v1/heartbeat ", 23) == 0) {
            s->heartbeats_received++;
            const char *pkh = strstr(req, "X-FP-Device-PubKey: ");
            const char *sigh = strstr(req, "X-FP-Signature: ");
            const char *body = strstr(req, "\r\n\r\n");
            if (pkh && sigh && body) {
                char pk_str[65], sig_str[129];
                memcpy(pk_str, pkh + 20, 64); pk_str[64] = '\0';
                memcpy(sig_str, sigh + 16, 128); sig_str[128] = '\0';
                uint8_t pk[32], sig[64];
                if (fp_hex_decode(pk_str, pk, 32) == FP_OK &&
                    fp_hex_decode(sig_str, sig, 64) == FP_OK) {
                    body += 4;
                    if (crypto_sign_ed25519_verify_detached(sig, (const uint8_t *)body,
                                                            (unsigned long long)strlen(body), pk) == 0) {
                        s->signed_heartbeats_verified++;
                    }
                }
            }
            const char *ok = "{\"ok\":true}";
            send_http_simple(cfd, 200, "application/json", (const uint8_t *)ok, strlen(ok), NULL);
            close(cfd);
            continue;
        }
        if (strncmp(req, "GET /repo/", 10) != 0) {
            send_http_simple(cfd, 404, "text/plain", (const uint8_t *)"no", 2, NULL);
            close(cfd);
            continue;
        }

        const char *pstart = req + 10;
        const char *pend = strchr(pstart, ' ');
        if (!pend) { close(cfd); continue; }
        char rel[512];
        size_t rlen = (size_t)(pend - pstart);
        if (rlen >= sizeof(rel) || strstr(pstart, "..")) { close(cfd); continue; }
        memcpy(rel, pstart, rlen);
        rel[rlen] = '\0';

        char fpath[1024];
        snprintf(fpath, sizeof(fpath), "%s/%s", s->repo_dir, rel);
        FILE *f = fopen(fpath, "rb");
        if (!f) {
            send_http_simple(cfd, 404, "text/plain", (const uint8_t *)"404", 3, NULL);
            close(cfd);
            continue;
        }
        struct stat st;
        fstat(fileno(f), &st);
        size_t fsz = (size_t)st.st_size;
        uint8_t *data = malloc(fsz > 0 ? fsz : 1u);
        assert(data != NULL);
        if (fsz > 0) assert(fread(data, 1, fsz, f) == fsz);
        fclose(f);

        if (s->corrupt_next_obj && strncmp(rel, "objects/", 8) == 0 && fsz > 0) {
            data[fsz / 2] ^= 0xFFu;
            s->corrupt_next_obj = 0;
        }

        const char *rng = strstr(req, "Range: bytes=");
        if (rng && fsz > 0) {
            unsigned long off = strtoul(rng + 13, NULL, 10);
            if (off < fsz) {
                char extra[128];
                if (s->bad_range_next) {
                    s->bad_range_next = 0;
                    /* SEC-06 adversarial test: lie about start offset in Content-Range! */
                    snprintf(extra, sizeof(extra), "Content-Range: bytes 0-%zu/%zu\r\n",
                             fsz - off - 1u, fsz);
                } else {
                    snprintf(extra, sizeof(extra), "Content-Range: bytes %lu-%zu/%zu\r\n",
                             off, fsz - 1u, fsz);
                }
                send_http_simple(cfd, 206, "application/octet-stream", data + off, fsz - off, extra);
                free(data);
                close(cfd);
                continue;
            }
        }
        send_http_simple(cfd, 200, "application/octet-stream", data, fsz, NULL);
        free(data);
        close(cfd);
    }
    return NULL;
}

static void write_bytes_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    if (len > 0) assert(fwrite(buf, 1, len, f) == len);
    fclose(f);
}

static void build_release_bundle(const char *repo_dir, const char *cfg_text,
                                 const uint8_t *cs, size_t cs_len,
                                 fp_dna_t *out_bdna, uint64_t *out_bsize) {
    fp_bundle_t b;
    memset(&b, 0, sizeof(b));
    b.version = 1;
    b.entry_count = 2;

    b.entries[0].role = FP_ROLE_FILE;
    b.entries[0].mode = 0644;
    b.entries[0].size = strlen(cfg_text);
    snprintf(b.entries[0].path, sizeof(b.entries[0].path), "app.cfg");
    assert(fp_store_put_object(repo_dir, (const uint8_t *)cfg_text, strlen(cfg_text),
                               &b.entries[0].dna) == FP_OK);

    b.entries[1].role = FP_ROLE_SQLITE_CHANGESET;
    b.entries[1].mode = 0;
    b.entries[1].size = cs_len;
    snprintf(b.entries[1].path, sizeof(b.entries[1].path), "settings");
    assert(fp_store_put_object(repo_dir, cs, cs_len, &b.entries[1].dna) == FP_OK);

    assert(fp_bundle_pack(repo_dir, &b, out_bdna) == FP_OK);
    assert(fp_store_has_object(repo_dir, out_bdna, out_bsize));
}

int main(void) {
    assert(fp_init() == FP_OK);

    char rtmpl[] = "/tmp/fp-ag-repo-XXXXXX";
    char etmpl[] = "/tmp/fp-ag-edge-XXXXXX";
    char *repo = mkdtemp(rtmpl);
    char *edge = mkdtemp(etmpl);
    assert(repo && edge);

    char ev_dir[512], ch_dir[512], ch_stable[512];
    snprintf(ev_dir, sizeof(ev_dir), "%s/events", repo);
    snprintf(ch_dir, sizeof(ch_dir), "%s/channels", repo);
    snprintf(ch_stable, sizeof(ch_stable), "%s/channels/stable", repo);
    assert(mkdir(ev_dir, 0700) == 0 && mkdir(ch_dir, 0700) == 0 && mkdir(ch_stable, 0700) == 0);

    /* 1. Create 2-of-3 Ed25519 Root Multi-Sig + Release key */
    fp_keypair_t rk[3], rel_kp, evil_kp;
    for (int i = 0; i < 3; i++) assert(fp_keygen(&rk[i]) == FP_OK);
    assert(fp_keygen(&rel_kp) == FP_OK);
    assert(fp_keygen(&evil_kp) == FP_OK);
    fp_dna_t repo_id;
    assert(fp_random_id(&repo_id) == FP_OK);

    uint64_t now = (uint64_t)time(NULL);
    fp_root_doc_t root;
    memset(&root, 0, sizeof(root));
    root.version = 1;
    root.root_version = 1;
    root.repo_id = repo_id;
    root.timestamp_unix = now - 10;
    root.expires_unix = now + 86400;
    root.root_threshold = 2;
    root.root_key_count = 3;
    for (int i = 0; i < 3; i++) memcpy(root.root_keys[i], rk[i].pk, FP_PK_LEN);
    memcpy(root.release_pk, rel_kp.pk, FP_PK_LEN);
    assert(fp_root_add_sig(&root, &rk[0]) == FP_OK);
    assert(fp_root_add_sig(&root, &rk[2]) == FP_OK);

    uint8_t *root_enc = NULL; size_t root_len = 0;
    assert(fp_root_encode(&root, &root_enc, &root_len) == FP_OK);
    char repo_root_p[512], edge_root_p[512];
    snprintf(repo_root_p, sizeof(repo_root_p), "%s/root.fpr", repo);
    snprintf(edge_root_p, sizeof(edge_root_p), "%s/pinned_root.fpr", edge);
    write_bytes_file(repo_root_p, root_enc, root_len);
    write_bytes_file(edge_root_p, root_enc, root_len);
    free(root_enc);

    /* 2. Capture SQLite changesets for v1, v2 (bad health), v3 (good) */
    char ref_db_p[512], edge_db_p[512];
    snprintf(ref_db_p, sizeof(ref_db_p), "%s/ref.db", repo);
    snprintf(edge_db_p, sizeof(edge_db_p), "%s/app.db", edge);

    fp_sql_ctx_t *rdb = NULL, *edb = NULL;
    assert(fp_sql_open(ref_db_p, &rdb) == FP_OK);
    assert(fp_sql_open(edge_db_p, &edb) == FP_OK);
    const char *schema = "CREATE TABLE settings(id INTEGER PRIMARY KEY, val TEXT);";
    assert(fp_sql_exec(rdb, schema) == FP_OK);
    assert(fp_sql_exec(edb, schema) == FP_OK);

    uint8_t *cs1 = NULL, *cs2 = NULL, *cs3 = NULL;
    size_t cs1_l = 0, cs2_l = 0, cs3_l = 0;
    assert(fp_sql_capture_changeset(rdb, "settings",
           "INSERT INTO settings(id,val) VALUES(1,'v1-healthy');", &cs1, &cs1_l) == FP_OK);
    fp_dna_t db_dig_v1;
    assert(fp_sql_state_digest(rdb, "settings", &db_dig_v1) == FP_OK);

    assert(fp_sql_capture_changeset(rdb, "settings",
           "UPDATE settings SET val='v2-broken' WHERE id=1;", &cs2, &cs2_l) == FP_OK);

    /* Capture v3 incrementally on top of v2 (linear causal chain e1 -> e2 -> e3, P0-01) */
    assert(fp_sql_capture_changeset(rdb, "settings",
           "UPDATE settings SET val='v3-fixed' WHERE id=1;", &cs3, &cs3_l) == FP_OK);
    fp_dna_t db_dig_v3;
    assert(fp_sql_state_digest(rdb, "settings", &db_dig_v3) == FP_OK);
    fp_sql_close(rdb);
    fp_sql_close(edb);

    fp_dna_t b1_dna, b2_dna, b3_dna;
    uint64_t b1_sz = 0, b2_sz = 0, b3_sz = 0;
    build_release_bundle(repo, "STATUS=OK\nVERSION=1\n", cs1, cs1_l, &b1_dna, &b1_sz);
    build_release_bundle(repo, "STATUS=CRASH\nVERSION=2\n", cs2, cs2_l, &b2_dna, &b2_sz);
    build_release_bundle(repo, "STATUS=OK\nVERSION=3\n", cs3, cs3_l, &b3_dna, &b3_sz);
    free(cs1); free(cs2); free(cs3);

    /* 3. Start embedded HTTP/1.1 Range server */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd >= 0);
    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(lfd, 16) == 0);
    socklen_t alen = sizeof(addr);
    assert(getsockname(lfd, (struct sockaddr *)&addr, &alen) == 0);
    uint16_t port = ntohs(addr.sin_port);

    mini_http_t srv;
    memset(&srv, 0, sizeof(srv));
    srv.listen_fd = lfd;
    srv.repo_dir = repo;
    pthread_t th;
    assert(pthread_create(&th, NULL, mini_http_thread, &srv) == 0);

    char base_url[128], edge_store[512], edge_target[512], health_cmd[768];
    snprintf(base_url, sizeof(base_url), "http://127.0.0.1:%u", (unsigned)port);
    snprintf(edge_store, sizeof(edge_store), "%s/store", edge);
    snprintf(edge_target, sizeof(edge_target), "%s/live", edge);
    snprintf(health_cmd, sizeof(health_cmd), "grep -q 'STATUS=OK' '%s/current/app.cfg'", edge_target);

    /* Test A: HTTP 206 Partial Content Range Resume + DNA tamper rejection */
    {
        uint8_t blob[65536];
        for (size_t i = 0; i < sizeof(blob); i++) blob[i] = (uint8_t)(i * 37u + 11u);
        fp_dna_t bdna;
        assert(fp_store_put_object(repo, blob, sizeof(blob), &bdna) == FP_OK);
        char hex[65], ourl[256], sdir[600], spath[768];
        fp_hex_encode(bdna.bytes, FP_DNA_LEN, hex);
        snprintf(ourl, sizeof(ourl), "%s/repo/objects/%s", base_url, hex);
        snprintf(sdir, sizeof(sdir), "%s/staging", edge_store);
        assert(mkdir(edge_store, 0700) == 0 && mkdir(sdir, 0700) == 0);
        snprintf(spath, sizeof(spath), "%s/%s.http", sdir, hex);
        /* Pre-stage first 30,000 bytes -> SEC-06: mismatched Content-Range MUST fail closed first! */
        write_bytes_file(spath, blob, 30000);
        uint64_t resumed = 0;
        srv.bad_range_next = 1;
        assert(fp_http_pull_object(ourl, edge_store, &bdna, sizeof(blob), 5000, &resumed) == FP_ERR_INTEGRITY);
        assert(!fp_store_has_object(edge_store, &bdna, NULL));

        /* Now with valid Content-Range -> MUST resume via HTTP 206 cleanly! */
        assert(fp_http_pull_object(ourl, edge_store, &bdna, sizeof(blob), 5000, &resumed) == FP_OK);
        assert(resumed == 30000);
        printf("[PASS] HTTP/1.1 206 Partial Content Range resume + SEC-06 Content-Range offset verification\n");

        /* Corrupted HTTP body MUST fail closed with FP_ERR_INTEGRITY */
        blob[0] ^= 0xAAu;
        fp_dna_t bdna2;
        assert(fp_store_put_object(repo, blob, sizeof(blob), &bdna2) == FP_OK);
        fp_hex_encode(bdna2.bytes, FP_DNA_LEN, hex);
        snprintf(ourl, sizeof(ourl), "%s/repo/objects/%s", base_url, hex);
        srv.corrupt_next_obj = 1;
        assert(fp_http_pull_object(ourl, edge_store, &bdna2, sizeof(blob), 5000, &resumed) == FP_ERR_INTEGRITY);
        assert(!fp_store_has_object(edge_store, &bdna2, NULL));
        printf("[PASS] Tampered HTTP object rejected fail-closed (FP_ERR_INTEGRITY, 0 bytes committed)\n");
    }

    /* Test B: Release v1 (healthy) */
    fp_event_t e1;
    memset(&e1, 0, sizeof(e1));
    e1.action = FP_ACTION_INSTALL; e1.repo_id = repo_id; e1.serial = 1;
    e1.timestamp_unix = now - 5; e1.expires_unix = now + 3600;
    e1.target_dna = b1_dna; e1.target_size = b1_sz;
    assert(fp_event_sign(&e1, &rel_kp) == FP_OK);
    uint8_t *eb = NULL; size_t el = 0;
    assert(fp_event_encode(&e1, &eb, &el) == FP_OK);
    char p1[600], p_lat[600];
    snprintf(p1, sizeof(p1), "%s/1.ev", ev_dir);
    snprintf(p_lat, sizeof(p_lat), "%s/latest.ev", ch_stable);
    write_bytes_file(p1, eb, el);
    write_bytes_file(p_lat, eb, el);
    free(eb);

    /* Spawn a real encrypted LAN FP-NET peer holding the repo objects (serves v1's 3 objects, then exits
     * so v2/v3 exercise automatic fallback to HTTP/1.1 Range!) */
    fp_keypair_t dev_kp, lan_kp;
    assert(fp_keygen(&dev_kp) == FP_OK && fp_keygen(&lan_kp) == FP_OK);
    uint16_t lan_port = 0;
    lan_srv_t lan_srv;
    memset(&lan_srv, 0, sizeof(lan_srv));
    lan_srv.fd = fp_net_listen("127.0.0.1", 0, &lan_port);
    assert(lan_srv.fd >= 0);
    lan_srv.cfg.bind_addr = "127.0.0.1";
    lan_srv.cfg.port = lan_port;
    lan_srv.cfg.store_dir = repo;
    lan_srv.cfg.server_kp = &lan_kp;
    lan_srv.cfg.allowed_peer_pk = dev_kp.pk;
    lan_srv.cfg.max_requests = 3; /* manifest + app.cfg + changeset for v1 */
    pthread_t lan_th;
    assert(pthread_create(&lan_th, NULL, lan_srv_thread, &lan_srv) == 0);

    fp_agent_cfg_t acfg;
    memset(&acfg, 0, sizeof(acfg));
    acfg.device_id = "edge-test-01";
    acfg.repo_url = base_url;
    acfg.channel = "stable";
    acfg.store_dir = edge_store;
    acfg.target_dir = edge_target;
    acfg.db_path = edge_db_p;
    acfg.root_path = edge_root_p;
    acfg.health_cmd = health_cmd;
    acfg.health_timeout_sec = 5;
    acfg.report_heartbeat = 1;
    acfg.device_kp = &dev_kp;
    acfg.lan_peer_host = "127.0.0.1";
    acfg.lan_peer_port = lan_port;
    acfg.lan_peer_pk = lan_kp.pk;

    fp_agent_report_t rep;
    assert(fp_agent_sync_once(&acfg, &rep) == FP_OK);
    pthread_join(lan_th, NULL);
    assert(rep.outcome == FP_AGENT_UPDATED && rep.active_serial == 1 && rep.health_exit_code == 0);
    assert(rep.bytes_from_lan > 0 && rep.bytes_downloaded == 0);
    assert(fp_sql_open(edge_db_p, &edb) == FP_OK);
    fp_dna_t live_dig;
    assert(fp_sql_state_digest(edb, "settings", &live_dig) == FP_OK);
    fp_sql_close(edb);
    assert(fp_dna_equal(&live_dig, &db_dig_v1));
    printf("[PASS] sf-agent v1 rollout: 2-of-3 Multi-Sig + Hybrid LAN FP-NET (%llu B LAN, 0 B HTTP!) + health=0\n",
           (unsigned long long)rep.bytes_from_lan);

    /* Test C: Release v2-broken -> health-check FAILS -> AUTOMATIC ROLLBACK to v1! */
    fp_event_t e2;
    memset(&e2, 0, sizeof(e2));
    e2.action = FP_ACTION_INSTALL; e2.repo_id = repo_id; e2.serial = 2;
    e2.prev_event_hash = e1.event_hash;
    e2.timestamp_unix = now - 3; e2.expires_unix = now + 3600;
    e2.target_dna = b2_dna; e2.target_size = b2_sz;
    assert(fp_event_sign(&e2, &rel_kp) == FP_OK);
    assert(fp_event_encode(&e2, &eb, &el) == FP_OK);
    snprintf(p1, sizeof(p1), "%s/2.ev", ev_dir);
    write_bytes_file(p1, eb, el);
    write_bytes_file(p_lat, eb, el);
    free(eb);

    assert(fp_agent_sync_once(&acfg, &rep) == FP_OK);
    assert(rep.outcome == FP_AGENT_ROLLED_BACK && rep.active_serial == 1 && rep.health_exit_code != 0);
    /* Verify BOTH app.cfg AND SQLite DB were rolled back bit-exact to v1! */
    assert(fp_agent_run_health_check(health_cmd, 5) == 0);
    assert(fp_sql_open(edge_db_p, &edb) == FP_OK);
    assert(fp_sql_state_digest(edb, "settings", &live_dig) == FP_OK);
    fp_sql_close(edb);
    assert(fp_dna_equal(&live_dig, &db_dig_v1));
    printf("[PASS] sf-agent v2-broken auto-rollback: files + SQLite inverted bit-exact to v1!\n");

    /* Repeat sync while v2-broken is still live -> must NOT loop/re-break */
    assert(fp_agent_sync_once(&acfg, &rep) == FP_OK);
    assert(rep.outcome == FP_AGENT_ROLLED_BACK && rep.active_serial == 1);

    /* Test D: Release v3-fixed (chained after e2) -> walks e2->e3 and upgrades cleanly! */
    fp_event_t e3;
    memset(&e3, 0, sizeof(e3));
    e3.action = FP_ACTION_INSTALL; e3.repo_id = repo_id; e3.serial = 3;
    e3.prev_event_hash = e2.event_hash;
    e3.timestamp_unix = now - 1; e3.expires_unix = now + 3600;
    e3.target_dna = b3_dna; e3.target_size = b3_sz;
    assert(fp_event_sign(&e3, &rel_kp) == FP_OK);
    assert(fp_event_encode(&e3, &eb, &el) == FP_OK);
    snprintf(p1, sizeof(p1), "%s/3.ev", ev_dir);
    write_bytes_file(p1, eb, el);
    write_bytes_file(p_lat, eb, el);
    free(eb);

    assert(fp_agent_sync_once(&acfg, &rep) == FP_OK);
    assert(rep.outcome == FP_AGENT_UPDATED && rep.active_serial == 3 && rep.health_exit_code == 0);
    assert(fp_sql_open(edge_db_p, &edb) == FP_OK);
    assert(fp_sql_state_digest(edb, "settings", &live_dig) == FP_OK);
    fp_sql_close(edb);
    assert(fp_dna_equal(&live_dig, &db_dig_v3));
    assert(srv.heartbeats_received >= 4);
    assert(srv.signed_heartbeats_verified == srv.heartbeats_received);
    printf("[PASS] sf-agent v3-fixed recovery: HTTP fallback + chain e2->e3 + %d/%d Ed25519-signed heartbeats!\n",
           srv.signed_heartbeats_verified, srv.heartbeats_received);

    /* Test E: Forged event signed by evil key -> REJECTED fail-closed! */
    fp_event_t e4_evil = e3;
    e4_evil.serial = 4; e4_evil.prev_event_hash = e3.event_hash;
    assert(fp_event_sign(&e4_evil, &evil_kp) == FP_OK);
    assert(fp_event_encode(&e4_evil, &eb, &el) == FP_OK);
    write_bytes_file(p_lat, eb, el);
    free(eb);
    assert(fp_agent_sync_once(&acfg, &rep) == FP_ERR_SIGNATURE);
    assert(rep.outcome == FP_AGENT_REJECTED && rep.active_serial == 3);
    printf("[PASS] Forged event signed by unauthorized key rejected fail-closed (FP_ERR_SIGNATURE)\n");

    /* Test F: Watchdog SIGKILL on hung health-check command */
    assert(fp_agent_run_health_check("sleep 10", 1) == -1);
    printf("[PASS] Health-check watchdog cleanly terminated hung process after 1s timeout\n");

    /* Test G (P0-06): Explicit monotonic signed FP_ACTION_ROLLBACK event (serial=4 -> back to v1!) */
    fp_event_t e4_rb;
    memset(&e4_rb, 0, sizeof(e4_rb));
    e4_rb.action = FP_ACTION_ROLLBACK; e4_rb.repo_id = repo_id; e4_rb.serial = 4;
    e4_rb.prev_event_hash = e3.event_hash;
    e4_rb.timestamp_unix = now; e4_rb.expires_unix = now + 3600;
    e4_rb.target_dna = b1_dna; e4_rb.target_size = b1_sz;
    snprintf(e4_rb.reason, sizeof(e4_rb.reason), "emergency fleet rollback to v1");
    assert(fp_event_sign(&e4_rb, &rel_kp) == FP_OK);
    assert(fp_event_encode(&e4_rb, &eb, &el) == FP_OK);
    snprintf(p1, sizeof(p1), "%s/4.ev", ev_dir);
    write_bytes_file(p1, eb, el);
    write_bytes_file(p_lat, eb, el);
    free(eb);

    assert(fp_agent_sync_once(&acfg, &rep) == FP_OK);
    assert(rep.outcome == FP_AGENT_ROLLED_BACK && rep.active_serial == 4 && rep.health_exit_code == 0);
    assert(fp_sql_open(edge_db_p, &edb) == FP_OK);
    assert(fp_sql_state_digest(edb, "settings", &live_dig) == FP_OK);
    fp_sql_close(edb);
    assert(fp_dna_equal(&live_dig, &db_dig_v1));
    printf("[PASS] P0-06 monotonic FP_ACTION_ROLLBACK (serial=4 -> v1): files + SQLite rolled back bit-exact\n");

    /* Test H (P0-05): FP_ACTION_REVOKE physically deactivates <target_dir>/current & writes .sf_revoked */
    fp_event_t e5_rev;
    memset(&e5_rev, 0, sizeof(e5_rev));
    e5_rev.action = FP_ACTION_REVOKE; e5_rev.repo_id = repo_id; e5_rev.serial = 5;
    e5_rev.prev_event_hash = e4_rb.event_hash;
    e5_rev.timestamp_unix = now; e5_rev.expires_unix = now + 3600;
    e5_rev.target_dna = b1_dna; e5_rev.target_size = 0;
    snprintf(e5_rev.reason, sizeof(e5_rev.reason), "CVE emergency revoke");
    assert(fp_event_sign(&e5_rev, &rel_kp) == FP_OK);
    assert(fp_event_encode(&e5_rev, &eb, &el) == FP_OK);
    snprintf(p1, sizeof(p1), "%s/5.ev", ev_dir);
    write_bytes_file(p1, eb, el);
    write_bytes_file(p_lat, eb, el);
    free(eb);

    assert(fp_agent_sync_once(&acfg, &rep) == FP_OK);
    assert(rep.outcome == FP_AGENT_REVOKED && rep.active_serial == 5);
    char cur_link[600], rev_marker[600];
    snprintf(cur_link, sizeof(cur_link), "%s/current", edge_target);
    snprintf(rev_marker, sizeof(rev_marker), "%s/.sf_revoked", edge_target);
    struct stat st_chk;
    assert(lstat(cur_link, &st_chk) != 0); /* current symlink MUST be removed! */
    assert(lstat(rev_marker, &st_chk) == 0);
    printf("[PASS] P0-05 FP_ACTION_REVOKE physically removed live target symlink & created .sf_revoked\n");

    /* Test I (P0-02): Initial install health-check failure MUST return non-OK & deactivate target */
    {
        char etmpl2[] = "/tmp/fp-ag-edge2-XXXXXX";
        char *edge2 = mkdtemp(etmpl2);
        assert(edge2 != NULL);
        char e2_store[512], e2_target[512], e2_db[512], e2_hcmd[768];
        snprintf(e2_store, sizeof(e2_store), "%s/store", edge2);
        snprintf(e2_target, sizeof(e2_target), "%s/live", edge2);
        snprintf(e2_db, sizeof(e2_db), "%s/app.db", edge2);
        snprintf(e2_hcmd, sizeof(e2_hcmd), "grep -q 'STATUS=OK' '%s/current/app.cfg'", e2_target);

        /* Put broken v2 as serial 1 on a fresh channel 'badinit' */
        char ch_bad[512], p_bad_lat[600];
        snprintf(ch_bad, sizeof(ch_bad), "%s/channels/badinit", repo);
        assert(mkdir(ch_bad, 0700) == 0);
        fp_sql_ctx_t *edb2 = NULL;
        assert(fp_sql_open(e2_db, &edb2) == FP_OK);
        assert(fp_sql_exec(edb2, schema) == FP_OK);
        assert(fp_sql_exec(edb2, "INSERT INTO settings(id,val) VALUES(1,'v1-healthy');") == FP_OK);
        fp_sql_close(edb2);

        fp_event_t e_bad1;
        memset(&e_bad1, 0, sizeof(e_bad1));
        e_bad1.action = FP_ACTION_INSTALL; e_bad1.repo_id = repo_id; e_bad1.serial = 1;
        e_bad1.timestamp_unix = now; e_bad1.expires_unix = now + 3600;
        e_bad1.target_dna = b2_dna; e_bad1.target_size = b2_sz;
        assert(fp_event_sign(&e_bad1, &rel_kp) == FP_OK);
        assert(fp_event_encode(&e_bad1, &eb, &el) == FP_OK);
        snprintf(p_bad_lat, sizeof(p_bad_lat), "%s/latest.ev", ch_bad);
        write_bytes_file(p_bad_lat, eb, el);
        free(eb);

        fp_agent_cfg_t acfg2 = acfg;
        acfg2.device_id = "edge-init-fail";
        acfg2.channel = "badinit";
        acfg2.store_dir = e2_store;
        acfg2.target_dir = e2_target;
        acfg2.db_path = e2_db;
        acfg2.health_cmd = e2_hcmd;
        acfg2.lan_peer_host = NULL;
        acfg2.lan_peer_port = 0;

        fp_err_t ierr = fp_agent_sync_once(&acfg2, &rep);
        assert(ierr != FP_OK);
        assert(rep.outcome == FP_AGENT_INITIAL_INSTALL_FAILED && rep.active_serial == 0);
        snprintf(cur_link, sizeof(cur_link), "%s/current", e2_target);
        assert(lstat(cur_link, &st_chk) != 0);

        /* V-03: Subsequent sync on the same failed initial serial MUST keep failing closed (not ROLLED_BACK + OK) */
        fp_err_t ierr2 = fp_agent_sync_once(&acfg2, &rep);
        assert(ierr2 != FP_OK);
        assert(rep.outcome == FP_AGENT_INITIAL_INSTALL_FAILED && rep.active_serial == 0);
        printf("[PASS] P0-02/V-03 initial install health failure stays fail-closed across repeated syncs\n");
    }

    /* Test J (P1-04): Offline recovery from EXPIRED pinned root v1 across multi-step v1->v2->v3
     * rotation with historical release keys & expired intermediate event! */
    {
        char r2tmpl[] = "/tmp/fp-ag-hist-repo-XXXXXX";
        char e3tmpl[] = "/tmp/fp-ag-hist-edge-XXXXXX";
        char *hrepo = mkdtemp(r2tmpl);
        char *hedge = mkdtemp(e3tmpl);
        assert(hrepo && hedge);

        char h_ev[512], h_ch[512], h_st[512], h_roots[512];
        snprintf(h_ev, sizeof(h_ev), "%s/events", hrepo);
        snprintf(h_ch, sizeof(h_ch), "%s/channels", hrepo);
        snprintf(h_st, sizeof(h_st), "%s/channels/stable", hrepo);
        snprintf(h_roots, sizeof(h_roots), "%s/roots", hrepo);
        assert(mkdir(h_ev, 0700) == 0 && mkdir(h_ch, 0700) == 0 &&
               mkdir(h_st, 0700) == 0 && mkdir(h_roots, 0700) == 0);

        fp_keypair_t hrk[3], hrel1, hrel2, hrel3;
        for (int i = 0; i < 3; i++) assert(fp_keygen(&hrk[i]) == FP_OK);
        assert(fp_keygen(&hrel1) == FP_OK && fp_keygen(&hrel2) == FP_OK && fp_keygen(&hrel3) == FP_OK);
        fp_dna_t hrid;
        assert(fp_random_id(&hrid) == FP_OK);

        /* Root v1: EXPIRED (simulating device offline for months!) */
        fp_root_doc_t rv1;
        memset(&rv1, 0, sizeof(rv1));
        rv1.version = 1; rv1.root_version = 1; rv1.repo_id = hrid;
        rv1.timestamp_unix = now - 7200; rv1.expires_unix = now - 3600; /* EXPIRED! */
        rv1.root_threshold = 2; rv1.root_key_count = 3;
        for (int i = 0; i < 3; i++) memcpy(rv1.root_keys[i], hrk[i].pk, FP_PK_LEN);
        memcpy(rv1.release_pk, hrel1.pk, FP_PK_LEN);
        assert(fp_root_add_sig(&rv1, &hrk[0]) == FP_OK && fp_root_add_sig(&rv1, &hrk[1]) == FP_OK);

        /* Root v2: historical intermediate root (also expired, rotated release_pk -> hrel2) */
        fp_root_doc_t rv2 = rv1;
        rv2.root_version = 2; rv2.sig_count = 0;
        rv2.timestamp_unix = now - 3500; rv2.expires_unix = now - 1000;
        memcpy(rv2.release_pk, hrel2.pk, FP_PK_LEN);
        assert(fp_root_add_sig(&rv2, &hrk[0]) == FP_OK && fp_root_add_sig(&rv2, &hrk[2]) == FP_OK);

        /* Root v3: fresh active root (rotated release_pk -> hrel3) */
        fp_root_doc_t rv3 = rv2;
        rv3.root_version = 3; rv3.sig_count = 0;
        rv3.timestamp_unix = now - 60; rv3.expires_unix = now + 86400;
        memcpy(rv3.release_pk, hrel3.pk, FP_PK_LEN);
        assert(fp_root_add_sig(&rv3, &hrk[1]) == FP_OK && fp_root_add_sig(&rv3, &hrk[2]) == FP_OK);

        uint8_t *rb = NULL; size_t rl = 0;
        char rp[600], hedge_root[600];
        assert(fp_root_encode(&rv1, &rb, &rl) == FP_OK);
        snprintf(hedge_root, sizeof(hedge_root), "%s/pinned_root.fpr", hedge);
        write_bytes_file(hedge_root, rb, rl);
        free(rb);

        assert(fp_root_encode(&rv2, &rb, &rl) == FP_OK);
        snprintf(rp, sizeof(rp), "%s/2.fpr", h_roots);
        write_bytes_file(rp, rb, rl);
        free(rb);

        assert(fp_root_encode(&rv3, &rb, &rl) == FP_OK);
        snprintf(rp, sizeof(rp), "%s/3.fpr", h_roots);
        write_bytes_file(rp, rb, rl);
        snprintf(rp, sizeof(rp), "%s/root.fpr", hrepo);
        write_bytes_file(rp, rb, rl);
        free(rb);

        /* Bundle 1 & 2 (file-only) */
        fp_bundle_t hb1, hb2;
        memset(&hb1, 0, sizeof(hb1)); memset(&hb2, 0, sizeof(hb2));
        hb1.version = 1; hb1.entry_count = 1; hb1.entries[0].role = FP_ROLE_FILE;
        hb1.entries[0].mode = 0644; hb1.entries[0].size = 10;
        snprintf(hb1.entries[0].path, sizeof(hb1.entries[0].path), "app.cfg");
        assert(fp_store_put_object(hrepo, (const uint8_t *)"STATUS=OK\n", 10, &hb1.entries[0].dna) == FP_OK);
        fp_dna_t hbd1, hbd2; uint64_t hbs1 = 0, hbs2 = 0;
        assert(fp_bundle_pack(hrepo, &hb1, &hbd1) == FP_OK);
        assert(fp_store_has_object(hrepo, &hbd1, &hbs1));

        hb2 = hb1;
        hb2.entries[0].size = 14;
        assert(fp_store_put_object(hrepo, (const uint8_t *)"STATUS=OK_V3!\n", 14, &hb2.entries[0].dna) == FP_OK);
        assert(fp_bundle_pack(hrepo, &hb2, &hbd2) == FP_OK);
        assert(fp_store_has_object(hrepo, &hbd2, &hbs2));

        /* Event 1: historical & expired, signed by OLD release key hrel2! */
        fp_event_t he1, he2;
        memset(&he1, 0, sizeof(he1)); memset(&he2, 0, sizeof(he2));
        he1.action = FP_ACTION_INSTALL; he1.repo_id = hrid; he1.serial = 1;
        he1.timestamp_unix = now - 3000; he1.expires_unix = now - 1500; /* expired intermediate! */
        he1.target_dna = hbd1; he1.target_size = hbs1;
        assert(fp_event_sign(&he1, &hrel2) == FP_OK);
        assert(fp_event_encode(&he1, &eb, &el) == FP_OK);
        snprintf(rp, sizeof(rp), "%s/1.ev", h_ev);
        write_bytes_file(rp, eb, el);
        free(eb);

        /* Event 2: fresh latest event signed by NEW release key hrel3! */
        he2.action = FP_ACTION_INSTALL; he2.repo_id = hrid; he2.serial = 2;
        he2.prev_event_hash = he1.event_hash;
        he2.timestamp_unix = now - 10; he2.expires_unix = now + 3600;
        he2.target_dna = hbd2; he2.target_size = hbs2;
        assert(fp_event_sign(&he2, &hrel3) == FP_OK);
        assert(fp_event_encode(&he2, &eb, &el) == FP_OK);
        snprintf(rp, sizeof(rp), "%s/2.ev", h_ev);
        write_bytes_file(rp, eb, el);
        snprintf(rp, sizeof(rp), "%s/latest.ev", h_st);
        write_bytes_file(rp, eb, el);
        free(eb);

        /* Point mini HTTP server at hrepo temporarily */
        srv.repo_dir = hrepo;
        char hstore[512], htarget[512], hhcmd[768];
        snprintf(hstore, sizeof(hstore), "%s/store", hedge);
        snprintf(htarget, sizeof(htarget), "%s/live", hedge);
        snprintf(hhcmd, sizeof(hhcmd), "grep -q 'STATUS=OK_V3!' '%s/current/app.cfg'", htarget);

        fp_agent_cfg_t hcfg;
        memset(&hcfg, 0, sizeof(hcfg));
        hcfg.device_id = "edge-offline-recover";
        hcfg.repo_url = base_url;
        hcfg.channel = "stable";
        hcfg.store_dir = hstore;
        hcfg.target_dir = htarget;
        hcfg.root_path = hedge_root;
        hcfg.health_cmd = hhcmd;
        hcfg.health_timeout_sec = 5;

        assert(fp_agent_sync_once(&hcfg, &rep) == FP_OK);
        assert(rep.outcome == FP_AGENT_UPDATED && rep.root_version == 3 && rep.active_serial == 2);
        printf("[PASS] P1-04 offline recovery: expired root v1 -> v2 -> v3 + historical key chain synced cleanly!\n");

        /* Test K (P1-01 + P0-04): Offline recovery of interrupted revoke completes BEFORE any network access */
        char h_rev_pend[600], h_cur[600], h_rev[600];
        snprintf(h_rev_pend, sizeof(h_rev_pend), "%s/.sf_revoke_pending", htarget);
        snprintf(h_cur, sizeof(h_cur), "%s/current", htarget);
        snprintf(h_rev, sizeof(h_rev), "%s/.sf_revoked", htarget);
        write_bytes_file(h_rev_pend, (const uint8_t *)"REVOKE_PENDING 3\n", 17);
        hcfg.repo_url = "http://127.0.0.1:1"; /* unreachable! */
        fp_err_t off_err = fp_agent_sync_once(&hcfg, &rep);
        assert(off_err != FP_OK); /* network fetch fails, AFTER offline recovery finishes! */
        assert(lstat(h_cur, &st_chk) != 0);
        assert(lstat(h_rev, &st_chk) == 0);
        assert(lstat(h_rev_pend, &st_chk) != 0);
        printf("[PASS] P1-01/P0-04 offline revoke recovery completed before network access\n");

        /* Test L (TX-01 + TX-04/05 + P1-02 + TX-03 + TX-08 + TRUST-01): Full 3rd-audit gate coverage */
        {
            char l_otap[600];
            snprintf(l_otap, sizeof(l_otap), "%s/.sf_ota_state", htarget);

            /* P1-02: Corrupted .sf_ota_state MUST fail closed (FP_ERR_INTEGRITY) WITHOUT deleting evidence */
            write_bytes_file(l_otap, (const uint8_t *)"SFOTA1 CORRUPT_GARBAGE\n", 23);
            hcfg.repo_url = base_url;
            assert(fp_agent_sync_once(&hcfg, &rep) == FP_ERR_INTEGRITY);
            assert(lstat(l_otap, &st_chk) == 0);
            assert(unlink(l_otap) == 0);

            /* TX-01 & TX-04/05: HEALTH_PENDING written BEFORE apply (current already at hbd2) ->
             * offline recovery clears .sf_ota_state cleanly without FP_ERR_CHAIN loop; repeat 25x idempotent! */
            assert(fp_bundle_apply(hstore, &hbd2, htarget, NULL, 2, 0) == FP_OK);
            char hbd1_hex[65], hbd2_hex[65], oline[256];
            fp_hex_encode(hbd1.bytes, FP_DNA_LEN, hbd1_hex);
            fp_hex_encode(hbd2.bytes, FP_DNA_LEN, hbd2_hex);
            int oln = snprintf(oline, sizeof(oline), "SFOTA1 HEALTH_PENDING 9 %s 1 %s 9\n", hbd1_hex, hbd2_hex);
            for (int r = 0; r < 25; r++) {
                write_bytes_file(l_otap, (const uint8_t *)oline, (size_t)oln);
                assert(fp_agent_sync_once(&hcfg, &rep) == FP_OK);
                assert(lstat(l_otap, &st_chk) != 0);
            }
            printf("[PASS] TX-01/TX-04/TX-05/P1-02: Pre-apply HEALTH_PENDING idempotent 25x & corrupt .sf_ota_state fail-closed\n");

            /* TX-03 (P0-03): Offline LEDGER_PENDING recovery commits pending_events/3.ev with NO network! */
            fp_event_t he3;
            memset(&he3, 0, sizeof(he3));
            he3.action = FP_ACTION_REVOKE; he3.repo_id = hrid; he3.serial = 3;
            he3.prev_event_hash = he2.event_hash;
            he3.timestamp_unix = now; he3.expires_unix = now + 3600;
            he3.target_dna = hbd1; he3.target_size = 0; /* revoke historical hbd1 */
            snprintf(he3.reason, sizeof(he3.reason), "test-revoke-historical");
            assert(fp_event_sign(&he3, &hrel3) == FP_OK);
            assert(fp_event_encode(&he3, &eb, &el) == FP_OK);
            char pdir[600], pev[640];
            snprintf(pdir, sizeof(pdir), "%s/pending_events", hstore);
            (void)mkdir(pdir, 0700);
            snprintf(pev, sizeof(pev), "%s/3.ev", pdir);
            write_bytes_file(pev, eb, el);
            free(eb);
            oln = snprintf(oline, sizeof(oline), "SFOTA1 LEDGER_PENDING 3 %s 1 %s 3\n", hbd2_hex, hbd2_hex);
            write_bytes_file(l_otap, (const uint8_t *)oline, (size_t)oln);
            hcfg.repo_url = "http://127.0.0.1:1"; /* completely offline! */
            (void)fp_agent_sync_once(&hcfg, &rep);
            fp_store_state_t pst;
            assert(fp_store_load_state(hstore, &pst) == FP_OK && pst.serial == 3);
            assert(lstat(l_otap, &st_chk) != 0);
            printf("[PASS] TX-03 (P0-03): Offline LEDGER_PENDING committed serial=3 cleanly with zero network\n");

            /* TX-08 (P0-04): Signed INSTALL targeting revoked hbd1 -> rejected in preflight BEFORE mutation! */
            fp_event_t he4;
            memset(&he4, 0, sizeof(he4));
            he4.action = FP_ACTION_INSTALL; he4.repo_id = hrid; he4.serial = 4;
            he4.prev_event_hash = he3.event_hash;
            he4.timestamp_unix = now; he4.expires_unix = now + 3600;
            he4.target_dna = hbd1; he4.target_size = hbs1; /* REVOKED! */
            assert(fp_event_sign(&he4, &hrel3) == FP_OK);
            assert(fp_event_encode(&he4, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/4.ev", h_ev);
            write_bytes_file(rp, eb, el);
            snprintf(rp, sizeof(rp), "%s/latest.ev", h_st);
            write_bytes_file(rp, eb, el);
            free(eb);
            hcfg.repo_url = base_url;
            assert(fp_agent_sync_once(&hcfg, &rep) == FP_ERR_REVOKED);
            assert(fp_store_load_state(hstore, &pst) == FP_OK && pst.serial == 3);
            printf("[PASS] TX-08 (P0-04): Signed event targeting revoked DNA rejected in preflight before mutation\n");

            /* TRUST-01 (P1-04): 40-step root rotation chain (v3 -> v43, exceeding old 32-slot array!) */
            fp_root_doc_t prev_r = rv3;
            for (uint64_t rv = 4; rv <= 43; rv++) {
                fp_root_doc_t nr = prev_r;
                nr.root_version = rv;
                nr.sig_count = 0;
                nr.timestamp_unix = prev_r.timestamp_unix + 1u;
                nr.expires_unix = now + 86400;
                assert(fp_root_add_sig(&nr, &hrk[0]) == FP_OK && fp_root_add_sig(&nr, &hrk[1]) == FP_OK);
                assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                snprintf(rp, sizeof(rp), "%s/%llu.fpr", h_roots, (unsigned long long)rv);
                write_bytes_file(rp, rb, rl);
                if (rv == 43) {
                    snprintf(rp, sizeof(rp), "%s/root.fpr", hrepo);
                    write_bytes_file(rp, rb, rl);
                }
                free(rb);
                prev_r = nr;
            }
            /* Point latest.ev back to serial=3 (up-to-date) so sync finishes cleanly after walking 40 rotations */
            assert(fp_event_encode(&he3, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/latest.ev", h_st);
            write_bytes_file(rp, eb, el);
            free(eb);
            assert(fp_agent_sync_once(&hcfg, &rep) == FP_OK);
            assert(rep.root_version == 43);
            printf("[PASS] TRUST-01 (P1-04): 40-step verified root rotation chain (v3 -> v43) synced cleanly!\n");
        }

        /* Test M (4th Audit: P0-02 SQLite multi-event catch-up, SF-A02/P0-05 mixed INSTALL+REVOKE & double-REVOKE, SF-A05/P0-04) */
        {
            char m4tmpl[] = "/tmp/fp-ag-m4-XXXXXX";
            char *mdir = mkdtemp(m4tmpl);
            assert(mdir != NULL);
            char mrepo[256], mev[300], mchan[300], mst[340], mroots[300], medge[256];
            char mstore[300], mtarget[300], msrc_dbp[300], mdst_dbp[300], mroot_p[300], mhcmd[512];
            snprintf(mrepo, sizeof(mrepo), "%s/repo", mdir);
            snprintf(mev, sizeof(mev), "%s/events", mrepo);
            snprintf(mchan, sizeof(mchan), "%s/channels", mrepo);
            snprintf(mst, sizeof(mst), "%s/stable", mchan);
            snprintf(mroots, sizeof(mroots), "%s/roots", mrepo);
            snprintf(medge, sizeof(medge), "%s/edge", mdir);
            snprintf(mstore, sizeof(mstore), "%s/store", medge);
            snprintf(mtarget, sizeof(mtarget), "%s/live", medge);
            snprintf(msrc_dbp, sizeof(msrc_dbp), "%s/src.db", mdir);
            snprintf(mdst_dbp, sizeof(mdst_dbp), "%s/dst.db", medge);
            snprintf(mroot_p, sizeof(mroot_p), "%s/root.fpr", medge);
            assert(mkdir(mrepo, 0755) == 0 && mkdir(mev, 0755) == 0);
            assert(mkdir(mchan, 0755) == 0 && mkdir(mst, 0755) == 0 && mkdir(mroots, 0755) == 0);
            assert(mkdir(medge, 0755) == 0);

            fp_keypair_t mrk, mrel;
            assert(fp_keygen(&mrk) == FP_OK && fp_keygen(&mrel) == FP_OK);
            fp_dna_t mrid;
            assert(fp_random_id(&mrid) == FP_OK);
            fp_root_doc_t mr;
            memset(&mr, 0, sizeof(mr));
            mr.version = 1; mr.root_version = 1; mr.root_threshold = 1; mr.repo_id = mrid;
            mr.timestamp_unix = now - 60; mr.expires_unix = now + 86400;
            mr.root_key_count = 1; memcpy(mr.root_keys[0], mrk.pk, FP_PK_LEN);
            memcpy(mr.release_pk, mrel.pk, FP_PK_LEN);
            assert(fp_root_add_sig(&mr, &mrk) == FP_OK);
            assert(fp_root_encode(&mr, &rb, &rl) == FP_OK);
            write_bytes_file(mroot_p, rb, rl);
            snprintf(rp, sizeof(rp), "%s/root.fpr", mrepo);
            write_bytes_file(rp, rb, rl);
            free(rb);

            fp_sql_ctx_t *msrc = NULL, *mdst = NULL;
            assert(fp_sql_open(msrc_dbp, &msrc) == FP_OK && fp_sql_open(mdst_dbp, &mdst) == FP_OK);
            assert(fp_sql_exec(msrc, "CREATE TABLE cfg(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
            assert(fp_sql_exec(mdst, "CREATE TABLE cfg(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);

            const char *msqls[4] = {
                "INSERT INTO cfg VALUES (1, 10);",
                "INSERT INTO cfg VALUES (2, 20);",
                "INSERT INTO cfg VALUES (3, 30);",
                "INSERT INTO cfg VALUES (4, 40);"
            };
            const char *mcfgs[4] = { "V=1\n", "V=2\n", "V=3\n", "V=4\n" };
            fp_dna_t mbdnas[4], mdigs[4];
            uint64_t mbsz[4];
            for (int i = 0; i < 4; i++) {
                uint8_t *cs = NULL; size_t csl = 0;
                assert(fp_sql_capture_changeset(msrc, "cfg", msqls[i], &cs, &csl) == FP_OK);
                assert(fp_sql_state_digest(msrc, "cfg", &mdigs[i]) == FP_OK);
                fp_bundle_t mb;
                memset(&mb, 0, sizeof(mb));
                mb.version = 1; mb.entry_count = 2;
                mb.entries[0].role = FP_ROLE_FILE; mb.entries[0].mode = 0644; mb.entries[0].size = 4;
                snprintf(mb.entries[0].path, sizeof(mb.entries[0].path), "ver.txt");
                assert(fp_store_put_object(mrepo, (const uint8_t *)mcfgs[i], 4, &mb.entries[0].dna) == FP_OK);
                mb.entries[1].role = FP_ROLE_SQLITE_CHANGESET; mb.entries[1].size = csl;
                snprintf(mb.entries[1].path, sizeof(mb.entries[1].path), "cfg");
                assert(fp_store_put_object(mrepo, cs, csl, &mb.entries[1].dna) == FP_OK);
                free(cs);
                assert(fp_bundle_pack(mrepo, &mb, &mbdnas[i]) == FP_OK);
                assert(fp_store_has_object(mrepo, &mbdnas[i], &mbsz[i]));
            }
            fp_sql_close(msrc);
            fp_sql_close(mdst);

            /* Emit events 1 (INSTALL V1), 2 (INSTALL V2), 3 (INSTALL V3) */
            fp_event_t mev1, mev2, mev3, mev4, mev5, mev6, mev7;
            memset(&mev1, 0, sizeof(mev1)); memset(&mev2, 0, sizeof(mev2)); memset(&mev3, 0, sizeof(mev3));
            mev1.action = FP_ACTION_INSTALL; mev1.repo_id = mrid; mev1.serial = 1;
            mev1.timestamp_unix = now; mev1.expires_unix = now + 3600;
            mev1.target_dna = mbdnas[0]; mev1.target_size = mbsz[0];
            assert(fp_event_sign(&mev1, &mrel) == FP_OK);
            assert(fp_event_encode(&mev1, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/1.ev", mev); write_bytes_file(rp, eb, el);
            snprintf(rp, sizeof(rp), "%s/latest.ev", mst); write_bytes_file(rp, eb, el);
            free(eb);

            srv.repo_dir = mrepo;
            snprintf(mhcmd, sizeof(mhcmd), "test -f '%s/current/ver.txt'", mtarget);
            fp_agent_cfg_t mcfg;
            memset(&mcfg, 0, sizeof(mcfg));
            mcfg.device_id = "edge-m4"; mcfg.repo_url = base_url; mcfg.channel = "stable";
            mcfg.store_dir = mstore; mcfg.target_dir = mtarget; mcfg.db_path = mdst_dbp;
            mcfg.root_path = mroot_p; mcfg.health_cmd = mhcmd; mcfg.health_timeout_sec = 5;

            /* Sync serial 1 (V1) */
            assert(fp_agent_sync_once(&mcfg, &rep) == FP_OK && rep.active_serial == 1);

            /* Publish serial 2 (V2) AND serial 3 (V3) while agent is offline -> single sync MUST replay V2 then V3! */
            mev2.action = FP_ACTION_INSTALL; mev2.repo_id = mrid; mev2.serial = 2;
            mev2.prev_event_hash = mev1.event_hash; mev2.timestamp_unix = now; mev2.expires_unix = now + 3600;
            mev2.target_dna = mbdnas[1]; mev2.target_size = mbsz[1];
            assert(fp_event_sign(&mev2, &mrel) == FP_OK);
            assert(fp_event_encode(&mev2, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/2.ev", mev); write_bytes_file(rp, eb, el);
            free(eb);

            mev3.action = FP_ACTION_INSTALL; mev3.repo_id = mrid; mev3.serial = 3;
            mev3.prev_event_hash = mev2.event_hash; mev3.timestamp_unix = now; mev3.expires_unix = now + 3600;
            mev3.target_dna = mbdnas[2]; mev3.target_size = mbsz[2];
            assert(fp_event_sign(&mev3, &mrel) == FP_OK);
            assert(fp_event_encode(&mev3, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/3.ev", mev); write_bytes_file(rp, eb, el);
            snprintf(rp, sizeof(rp), "%s/latest.ev", mst); write_bytes_file(rp, eb, el);
            free(eb);

            assert(fp_agent_sync_once(&mcfg, &rep) == FP_OK && rep.active_serial == 3);
            assert(fp_sql_open(mdst_dbp, &mdst) == FP_OK);
            fp_dna_t cur_mdig;
            assert(fp_sql_state_digest(mdst, "cfg", &cur_mdig) == FP_OK && fp_dna_equal(&cur_mdig, &mdigs[2]));
            fp_sql_close(mdst);
            printf("[PASS] P0-02: Offline multi-event SQLite catch-up (V1->V2->V3) applied every intermediate changeset\n");

            /* SF-A02 / P0-05 Case 1: Catch up across [INSTALL V4, REVOKE V2] -> MUST deploy V4 (NOT deactivate!) */
            memset(&mev4, 0, sizeof(mev4)); memset(&mev5, 0, sizeof(mev5));
            mev4.action = FP_ACTION_INSTALL; mev4.repo_id = mrid; mev4.serial = 4;
            mev4.prev_event_hash = mev3.event_hash; mev4.timestamp_unix = now; mev4.expires_unix = now + 3600;
            mev4.target_dna = mbdnas[3]; mev4.target_size = mbsz[3];
            assert(fp_event_sign(&mev4, &mrel) == FP_OK);
            assert(fp_event_encode(&mev4, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/4.ev", mev); write_bytes_file(rp, eb, el);
            free(eb);

            mev5.action = FP_ACTION_REVOKE; mev5.repo_id = mrid; mev5.serial = 5;
            mev5.prev_event_hash = mev4.event_hash; mev5.timestamp_unix = now; mev5.expires_unix = now + 3600;
            mev5.target_dna = mbdnas[1]; mev5.target_size = 0; /* revoke old V2 while V4 is active! */
            snprintf(mev5.reason, sizeof(mev5.reason), "revoke-old-v2");
            assert(fp_event_sign(&mev5, &mrel) == FP_OK);
            assert(fp_event_encode(&mev5, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/5.ev", mev); write_bytes_file(rp, eb, el);
            snprintf(rp, sizeof(rp), "%s/latest.ev", mst); write_bytes_file(rp, eb, el);
            free(eb);

            assert(fp_agent_sync_once(&mcfg, &rep) == FP_OK);
            assert(rep.outcome == FP_AGENT_UPDATED && rep.active_serial == 5);
            assert(fp_dna_equal(&rep.active_bundle_dna, &mbdnas[3]));
            char mcur[640], mrev[640];
            snprintf(mcur, sizeof(mcur), "%s/current", mtarget);
            snprintf(mrev, sizeof(mrev), "%s/.sf_revoked", mtarget);
            assert(lstat(mcur, &st_chk) == 0 && lstat(mrev, &st_chk) != 0);
            assert(fp_sql_open(mdst_dbp, &mdst) == FP_OK);
            assert(fp_sql_state_digest(mdst, "cfg", &cur_mdig) == FP_OK && fp_dna_equal(&cur_mdig, &mdigs[3]));
            fp_sql_close(mdst);
            printf("[PASS] SF-A02/P0-05 (1): Catch-up [INSTALL V4 + REVOKE V2] deployed V4 without deactivating live target\n");

            /* SF-A02 / P0-05 Case 2: Double revoke [REVOKE V4 (current!), REVOKE V1 (old)] -> MUST deactivate live target! */
            memset(&mev6, 0, sizeof(mev6)); memset(&mev7, 0, sizeof(mev7));
            mev6.action = FP_ACTION_REVOKE; mev6.repo_id = mrid; mev6.serial = 6;
            mev6.prev_event_hash = mev5.event_hash; mev6.timestamp_unix = now; mev6.expires_unix = now + 3600;
            mev6.target_dna = mbdnas[3]; mev6.target_size = 0; /* revoke ACTIVE V4! */
            snprintf(mev6.reason, sizeof(mev6.reason), "revoke-active-v4");
            assert(fp_event_sign(&mev6, &mrel) == FP_OK);
            assert(fp_event_encode(&mev6, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/6.ev", mev); write_bytes_file(rp, eb, el);
            free(eb);

            mev7.action = FP_ACTION_REVOKE; mev7.repo_id = mrid; mev7.serial = 7;
            mev7.prev_event_hash = mev6.event_hash; mev7.timestamp_unix = now; mev7.expires_unix = now + 3600;
            mev7.target_dna = mbdnas[0]; mev7.target_size = 0; /* revoke old V1 after revoking V4 */
            snprintf(mev7.reason, sizeof(mev7.reason), "revoke-old-v1");
            assert(fp_event_sign(&mev7, &mrel) == FP_OK);
            assert(fp_event_encode(&mev7, &eb, &el) == FP_OK);
            snprintf(rp, sizeof(rp), "%s/7.ev", mev); write_bytes_file(rp, eb, el);
            snprintf(rp, sizeof(rp), "%s/latest.ev", mst); write_bytes_file(rp, eb, el);
            free(eb);

            assert(fp_agent_sync_once(&mcfg, &rep) == FP_OK);
            assert(rep.outcome == FP_AGENT_REVOKED && rep.active_serial == 7);
            assert(lstat(mcur, &st_chk) != 0 && lstat(mrev, &st_chk) == 0);
            printf("[PASS] SF-A02/P0-05 (2): Double revoke [REVOKE active V4 + REVOKE old V1] deactivated live target!\n");

            /* Test N (Differential Audit 20611c4: R1 intermediate crash recovery, R2 rejected+revoke, R3 explicit rollback crash) */
            {
                char ntmpl[] = "/tmp/fp-ag-m5-XXXXXX";
                char *ndir = mkdtemp(ntmpl);
                assert(ndir != NULL);
                char nrepo[256], nev[300], nchan[300], nst[340], nedge[256], nstore[300], ntarget[300];
                char nsrc_dbp[300], ndst_dbp[300], nroot_p[300], nhcmd[512], notap[360], ncur[360], nunh[360];
                snprintf(nrepo, sizeof(nrepo), "%s/repo", ndir);
                snprintf(nev, sizeof(nev), "%s/events", nrepo);
                snprintf(nchan, sizeof(nchan), "%s/channels", nrepo);
                snprintf(nst, sizeof(nst), "%s/stable", nchan);
                snprintf(nedge, sizeof(nedge), "%s/edge", ndir);
                snprintf(nstore, sizeof(nstore), "%s/store", nedge);
                snprintf(ntarget, sizeof(ntarget), "%s/live", nedge);
                snprintf(nsrc_dbp, sizeof(nsrc_dbp), "%s/src.db", ndir);
                snprintf(ndst_dbp, sizeof(ndst_dbp), "%s/dst.db", nedge);
                snprintf(nroot_p, sizeof(nroot_p), "%s/root.fpr", nedge);
                snprintf(notap, sizeof(notap), "%s/.sf_ota_state", ntarget);
                snprintf(ncur, sizeof(ncur), "%s/current", ntarget);
                snprintf(nunh, sizeof(nunh), "%s/.sf_unhealthy", ntarget);
                assert(mkdir(nrepo, 0755) == 0 && mkdir(nev, 0755) == 0 &&
                       mkdir(nchan, 0755) == 0 && mkdir(nst, 0755) == 0 && mkdir(nedge, 0755) == 0);

                fp_keypair_t nrk, nrel;
                assert(fp_keygen(&nrk) == FP_OK && fp_keygen(&nrel) == FP_OK);
                fp_dna_t nrid;
                assert(fp_random_id(&nrid) == FP_OK);
                fp_root_doc_t nr;
                memset(&nr, 0, sizeof(nr));
                nr.version = 1; nr.root_version = 1; nr.root_threshold = 1; nr.repo_id = nrid;
                nr.timestamp_unix = now - 60; nr.expires_unix = now + 86400;
                nr.root_key_count = 1; memcpy(nr.root_keys[0], nrk.pk, FP_PK_LEN);
                memcpy(nr.release_pk, nrel.pk, FP_PK_LEN);
                assert(fp_root_add_sig(&nr, &nrk) == FP_OK);
                assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                write_bytes_file(nroot_p, rb, rl);
                snprintf(rp, sizeof(rp), "%s/root.fpr", nrepo); write_bytes_file(rp, rb, rl);
                free(rb);

                fp_sql_ctx_t *nsrc = NULL, *ndst = NULL;
                assert(fp_sql_open(nsrc_dbp, &nsrc) == FP_OK && fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                assert(fp_sql_exec(nsrc, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
                assert(fp_sql_exec(ndst, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
                fp_dna_t n_empty_dig;
                assert(fp_sql_state_digest(nsrc, "kv", &n_empty_dig) == FP_OK);

                const char *nsqls[3] = {
                    "INSERT INTO kv VALUES (1, 10);",
                    "INSERT INTO kv VALUES (2, 20);",
                    "INSERT INTO kv VALUES (3, 30);"
                };
                const char *ncfgs[3] = { "OK=1\n", "FAIL=1\n", "OK=3\n" };
                fp_dna_t nbdnas[3], ndigs[3];
                uint64_t nbsz[3];
                for (int i = 0; i < 3; i++) {
                    uint8_t *cs = NULL; size_t csl = 0;
                    assert(fp_sql_capture_changeset(nsrc, "kv", nsqls[i], &cs, &csl) == FP_OK);
                    assert(fp_sql_state_digest(nsrc, "kv", &ndigs[i]) == FP_OK);
                    fp_bundle_t nb;
                    memset(&nb, 0, sizeof(nb));
                    nb.version = 1; nb.entry_count = 2;
                    nb.entries[0].role = FP_ROLE_FILE; nb.entries[0].mode = 0644; nb.entries[0].size = strlen(ncfgs[i]);
                    snprintf(nb.entries[0].path, sizeof(nb.entries[0].path), "app.cfg");
                    assert(fp_store_put_object(nrepo, (const uint8_t *)ncfgs[i], strlen(ncfgs[i]), &nb.entries[0].dna) == FP_OK);
                    assert(fp_store_put_object(nstore, (const uint8_t *)ncfgs[i], strlen(ncfgs[i]), NULL) == FP_OK);
                    nb.entries[1].role = FP_ROLE_SQLITE_CHANGESET; nb.entries[1].size = csl;
                    snprintf(nb.entries[1].path, sizeof(nb.entries[1].path), "kv");
                    assert(fp_store_put_object(nrepo, cs, csl, &nb.entries[1].dna) == FP_OK);
                    assert(fp_store_put_object(nstore, cs, csl, NULL) == FP_OK);
                    free(cs);
                    fp_dna_t tmp_d;
                    assert(fp_bundle_pack(nrepo, &nb, &nbdnas[i]) == FP_OK);
                    assert(fp_bundle_pack(nstore, &nb, &tmp_d) == FP_OK && fp_dna_equal(&tmp_d, &nbdnas[i]));
                    assert(fp_store_has_object(nrepo, &nbdnas[i], &nbsz[i]));
                }
                fp_sql_close(nsrc);

                char h0[65], h1[65], h2[65], hzero[65];
                fp_hex_encode(nbdnas[0].bytes, FP_DNA_LEN, h0);
                fp_hex_encode(nbdnas[1].bytes, FP_DNA_LEN, h1);
                fp_hex_encode(nbdnas[2].bytes, FP_DNA_LEN, h2);
                memset(hzero, '0', 64); hzero[64] = '\0';

                fp_agent_cfg_t ncfg;
                memset(&ncfg, 0, sizeof(ncfg));
                ncfg.device_id = "edge-m5"; ncfg.repo_url = "http://127.0.0.1:1"; ncfg.channel = "stable";
                ncfg.store_dir = nstore; ncfg.target_dir = ntarget; ncfg.db_path = ndst_dbp;
                ncfg.root_path = nroot_p; ncfg.health_cmd = nhcmd; ncfg.health_timeout_sec = 5;
                snprintf(nhcmd, sizeof(nhcmd), "grep -q 'OK=' '%s/current/app.cfg'", ntarget);

                /* R1 (Case 1 — Initial install crashed after intermediate V1 of V1->V2):
                 * offline recovery MUST revert SQLite to empty baseline AND unlink current! */
                assert(fp_bundle_apply(nstore, &nbdnas[0], ntarget, ndst, 1, 0) == FP_OK);
                fp_sql_close(ndst);
                char oline[256];
                int oln = snprintf(oline, sizeof(oline), "SFOTA1 HEALTH_PENDING 2 %s 0 %s 1\n", h1, hzero);
                write_bytes_file(notap, (const uint8_t *)oline, (size_t)oln);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(lstat(notap, &st_chk) != 0);
                assert(lstat(ncur, &st_chk) != 0);
                assert(fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                fp_dna_t ndig_now;
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &n_empty_dig));

                /* R1 + F5 (Case 2 — Upgrade V1 -> [V2, V3] crashed after intermediate V2!):
                 * offline recovery MUST revert BOTH files AND SQLite back to V1 without FP_ERR_CHAIN
                 * AND MUST NOT quarantine never-executed serial 3! */
                assert(fp_bundle_apply(nstore, &nbdnas[0], ntarget, ndst, 1, 0) == FP_OK);
                assert(fp_bundle_apply(nstore, &nbdnas[1], ntarget, ndst, 2, 0) == FP_OK);
                fp_sql_close(ndst);
                oln = snprintf(oline, sizeof(oline), "SFOTA1 HEALTH_PENDING 3 %s 1 %s 2\n", h2, h0);
                write_bytes_file(notap, (const uint8_t *)oline, (size_t)oln);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(lstat(notap, &st_chk) != 0);
                assert(fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &ndigs[0]));
                /* F5: Ensure intermediate crash did NOT quarantine never-executed serial 3! */
                char nfailp[360];
                snprintf(nfailp, sizeof(nfailp), "%s/.failed_serial", nstore);
                assert(lstat(nfailp, &st_chk) != 0);
                /* Repeat offline recovery -> idempotent! */
                fp_sql_close(ndst);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &ndigs[0]));
                printf("[PASS] R1/F5: Offline recovery from intermediate SQLite crashes exact, idempotent & does not quarantine untested final serial\n");

                /* R3 + F2: Explicit rollback crash recovery (ROLLBACK_HEALTH_PENDING after V2->V1)
                 * MUST commit local ledger offline to serial=3 & V1 even when repository is unreachable! */
                fp_event_t rb_e1, rb_e2, rb_e3;
                memset(&rb_e1, 0, sizeof(rb_e1)); memset(&rb_e2, 0, sizeof(rb_e2)); memset(&rb_e3, 0, sizeof(rb_e3));
                rb_e1.action = FP_ACTION_INSTALL; rb_e1.repo_id = nrid; rb_e1.serial = 1;
                rb_e1.timestamp_unix = now - 30; rb_e1.expires_unix = now + 3600;
                rb_e1.target_dna = nbdnas[0]; rb_e1.target_size = nbsz[0];
                assert(fp_event_sign(&rb_e1, &nrel) == FP_OK);
                assert(fp_store_apply_event_with_root(nstore, &rb_e1, &nr, 0, NULL, 0) == FP_OK);

                rb_e2.action = FP_ACTION_INSTALL; rb_e2.repo_id = nrid; rb_e2.serial = 2;
                rb_e2.prev_event_hash = rb_e1.event_hash; rb_e2.timestamp_unix = now - 20; rb_e2.expires_unix = now + 3600;
                rb_e2.target_dna = nbdnas[1]; rb_e2.target_size = nbsz[1];
                assert(fp_event_sign(&rb_e2, &nrel) == FP_OK);
                assert(fp_store_apply_event_with_root(nstore, &rb_e2, &nr, 0, NULL, 0) == FP_OK);

                rb_e3.action = FP_ACTION_ROLLBACK; rb_e3.repo_id = nrid; rb_e3.serial = 3;
                rb_e3.prev_event_hash = rb_e2.event_hash; rb_e3.timestamp_unix = now - 10; rb_e3.expires_unix = now + 3600;
                rb_e3.target_dna = nbdnas[0]; rb_e3.target_size = nbsz[0];
                snprintf(rb_e3.reason, sizeof(rb_e3.reason), "offline-rb-f2");
                assert(fp_event_sign(&rb_e3, &nrel) == FP_OK);
                assert(fp_event_encode(&rb_e3, &eb, &el) == FP_OK);
                char npdir[340], npev[380];
                snprintf(npdir, sizeof(npdir), "%s/pending_events", nstore);
                (void)mkdir(npdir, 0700);
                snprintf(npev, sizeof(npev), "%s/3.ev", npdir);
                write_bytes_file(npev, eb, el);
                free(eb);

                assert(fp_bundle_apply(nstore, &nbdnas[1], ntarget, ndst, 2, 0) == FP_OK);
                assert(fp_bundle_rollback(nstore, &nbdnas[1], &nbdnas[0], ntarget, ndst) == FP_OK);
                fp_sql_close(ndst);
                /* 3a + F2: Healthy target V1 -> offline recovery validates V1 AND commits local ledger to serial=3/V1! */
                oln = snprintf(oline, sizeof(oline), "SFOTA1 ROLLBACK_HEALTH_PENDING 3 %s 1 %s 3\n", h0, h1);
                write_bytes_file(notap, (const uint8_t *)oline, (size_t)oln);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(lstat(notap, &st_chk) != 0);
                assert(lstat(ncur, &st_chk) == 0);
                assert(fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &ndigs[0]));
                fp_sql_close(ndst);
                fp_store_state_t f2st;
                assert(fp_store_load_state(nstore, &f2st) == FP_OK);
                assert(f2st.serial == 3 && f2st.has_current == 1 && fp_dna_equal(&f2st.current_dna, &nbdnas[0]));
                /* Second offline restart stays concordant at serial=3 / V1 */
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(fp_store_load_state(nstore, &f2st) == FP_OK && f2st.serial == 3 && fp_dna_equal(&f2st.current_dna, &nbdnas[0]));
                /* 3b: Unhealthy rollback target -> offline recovery durably deactivates target & creates .sf_unhealthy */
                ncfg.health_cmd = "false";
                write_bytes_file(notap, (const uint8_t *)oline, (size_t)oln);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(lstat(notap, &st_chk) != 0);
                assert(lstat(ncur, &st_chk) != 0 && lstat(nunh, &st_chk) == 0);
                printf("[PASS] R3/F2: ROLLBACK_HEALTH_PENDING offline recovery commits ledger (serial=3/V1) & deactivates unhealthy target\n");

                /* R2: Rejected release V2 (serial=2) followed by historical REVOKE (serial=3) MUST NOT promote V2! */
                char r2tmpl_e[] = "/tmp/fp-ag-r2-XXXXXX";
                char *r2edge = mkdtemp(r2tmpl_e);
                assert(r2edge != NULL);
                char r2store[300], r2target[300], r2dbp[300], r2root[300], r2hcmd[512];
                snprintf(r2store, sizeof(r2store), "%s/store", r2edge);
                snprintf(r2target, sizeof(r2target), "%s/live", r2edge);
                snprintf(r2dbp, sizeof(r2dbp), "%s/dst.db", r2edge);
                snprintf(r2root, sizeof(r2root), "%s/root.fpr", r2edge);
                snprintf(r2hcmd, sizeof(r2hcmd), "grep -q 'OK=' '%s/current/app.cfg'", r2target);
                assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                write_bytes_file(r2root, rb, rl);
                free(rb);
                assert(fp_sql_open(r2dbp, &ndst) == FP_OK);
                assert(fp_sql_exec(ndst, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
                fp_sql_close(ndst);

                fp_event_t ne1, ne2, ne3;
                memset(&ne1, 0, sizeof(ne1)); memset(&ne2, 0, sizeof(ne2)); memset(&ne3, 0, sizeof(ne3));
                ne1.action = FP_ACTION_INSTALL; ne1.repo_id = nrid; ne1.serial = 1;
                ne1.timestamp_unix = now; ne1.expires_unix = now + 3600;
                ne1.target_dna = nbdnas[0]; ne1.target_size = nbsz[0];
                assert(fp_event_sign(&ne1, &nrel) == FP_OK);
                assert(fp_event_encode(&ne1, &eb, &el) == FP_OK);
                snprintf(rp, sizeof(rp), "%s/1.ev", nev); write_bytes_file(rp, eb, el);
                snprintf(rp, sizeof(rp), "%s/latest.ev", nst); write_bytes_file(rp, eb, el);
                free(eb);

                srv.repo_dir = nrepo;
                fp_agent_cfg_t r2cfg;
                memset(&r2cfg, 0, sizeof(r2cfg));
                r2cfg.device_id = "edge-r2"; r2cfg.repo_url = base_url; r2cfg.channel = "stable";
                r2cfg.store_dir = r2store; r2cfg.target_dir = r2target; r2cfg.db_path = r2dbp;
                r2cfg.root_path = r2root; r2cfg.health_cmd = r2hcmd; r2cfg.health_timeout_sec = 5;
                assert(fp_agent_sync_once(&r2cfg, &rep) == FP_OK && rep.active_serial == 1);

                /* Serial 2: INSTALL V2 (FAIL=1 -> fails health check -> auto-rolls back to V1, failed_serial=2) */
                ne2.action = FP_ACTION_INSTALL; ne2.repo_id = nrid; ne2.serial = 2;
                ne2.prev_event_hash = ne1.event_hash; ne2.timestamp_unix = now; ne2.expires_unix = now + 3600;
                ne2.target_dna = nbdnas[1]; ne2.target_size = nbsz[1];
                assert(fp_event_sign(&ne2, &nrel) == FP_OK);
                assert(fp_event_encode(&ne2, &eb, &el) == FP_OK);
                snprintf(rp, sizeof(rp), "%s/2.ev", nev); write_bytes_file(rp, eb, el);
                snprintf(rp, sizeof(rp), "%s/latest.ev", nst); write_bytes_file(rp, eb, el);
                free(eb);
                assert(fp_agent_sync_once(&r2cfg, &rep) == FP_OK && rep.outcome == FP_AGENT_ROLLED_BACK && rep.active_serial == 1);

                /* Serial 3: REVOKE unrelated historical DNA (nbdnas[2]) -> simulated target is STILL failed V2! */
                ne3.action = FP_ACTION_REVOKE; ne3.repo_id = nrid; ne3.serial = 3;
                ne3.prev_event_hash = ne2.event_hash; ne3.timestamp_unix = now; ne3.expires_unix = now + 3600;
                ne3.target_dna = nbdnas[2]; ne3.target_size = 0;
                snprintf(ne3.reason, sizeof(ne3.reason), "revoke-unrelated");
                assert(fp_event_sign(&ne3, &nrel) == FP_OK);
                assert(fp_event_encode(&ne3, &eb, &el) == FP_OK);
                snprintf(rp, sizeof(rp), "%s/3.ev", nev); write_bytes_file(rp, eb, el);
                snprintf(rp, sizeof(rp), "%s/latest.ev", nst); write_bytes_file(rp, eb, el);
                free(eb);
                assert(fp_agent_sync_once(&r2cfg, &rep) == FP_OK);
                assert(rep.outcome == FP_AGENT_ROLLED_BACK && rep.active_serial == 1);
                assert(fp_dna_equal(&rep.active_bundle_dna, &nbdnas[0]));
                fp_store_state_t r2st;
                assert(fp_store_load_state(r2store, &r2st) == FP_OK && r2st.serial == 1);
                assert(fp_sql_open(r2dbp, &ndst) == FP_OK);
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &ndigs[0]));
                fp_sql_close(ndst);
                printf("[PASS] R2: Historical REVOKE after rejected V2 stays ROLLED_BACK on V1 (ledger/DB/telemetry concordant)\n");

                /* F1: REVOKE of the PHYSICALLY ACTIVE V1 while replacement V2 is rejected (failed_serial=2)
                 * MUST deactivate live target (never keep revoked V1 running or return FP_OK)! */
                fp_event_t ne4;
                memset(&ne4, 0, sizeof(ne4));
                ne4.action = FP_ACTION_REVOKE; ne4.repo_id = nrid; ne4.serial = 4;
                ne4.prev_event_hash = ne3.event_hash; ne4.timestamp_unix = now; ne4.expires_unix = now + 3600;
                ne4.target_dna = nbdnas[0]; ne4.target_size = 0; /* REVOKE active V1! */
                snprintf(ne4.reason, sizeof(ne4.reason), "revoke-active-v1");
                assert(fp_event_sign(&ne4, &nrel) == FP_OK);
                assert(fp_event_encode(&ne4, &eb, &el) == FP_OK);
                snprintf(rp, sizeof(rp), "%s/4.ev", nev); write_bytes_file(rp, eb, el);
                snprintf(rp, sizeof(rp), "%s/latest.ev", nst); write_bytes_file(rp, eb, el);
                free(eb);
                char r2cur[360], r2rev[360];
                snprintf(r2cur, sizeof(r2cur), "%s/current", r2target);
                snprintf(r2rev, sizeof(r2rev), "%s/.sf_revoked", r2target);
                assert(fp_agent_sync_once(&r2cfg, &rep) == FP_ERR_POLICY);
                assert(rep.outcome == FP_AGENT_REVOKED && rep.active_serial == 0);
                assert(lstat(r2cur, &st_chk) != 0 && lstat(r2rev, &st_chk) == 0);
                /* Repeated sync after restart keeps target deactivated & reports REVOKED */
                assert(fp_agent_sync_once(&r2cfg, &rep) == FP_ERR_POLICY);
                assert(rep.outcome == FP_AGENT_REVOKED && rep.active_serial == 0);
                assert(lstat(r2cur, &st_chk) != 0);
                printf("[PASS] F1: Signed REVOKE of active V1 while replacement V2 is rejected deactivates target fail-closed\n");

                /* F3 + F4: (a) [ROLLBACK V3->V1 + trailing REVOKE V2] uses rollback path; (b) >64 SQLite steps rejected preflight! */
                {
                    char f3tmpl[] = "/tmp/fp-ag-f34-XXXXXX";
                    char *f3dir = mkdtemp(f3tmpl);
                    assert(f3dir != NULL);
                    char f3repo[256], f3ev[300], f3ch[300], f3st[340], f3edge[256];
                    char f3store[300], f3target[300], f3src[300], f3dst[300], f3root[300], f3hcmd[512];
                    snprintf(f3repo, sizeof(f3repo), "%s/repo", f3dir);
                    snprintf(f3ev, sizeof(f3ev), "%s/events", f3repo);
                    snprintf(f3ch, sizeof(f3ch), "%s/channels", f3repo);
                    snprintf(f3st, sizeof(f3st), "%s/stable", f3ch);
                    snprintf(f3edge, sizeof(f3edge), "%s/edge", f3dir);
                    snprintf(f3store, sizeof(f3store), "%s/store", f3edge);
                    snprintf(f3target, sizeof(f3target), "%s/live", f3edge);
                    snprintf(f3src, sizeof(f3src), "%s/src.db", f3dir);
                    snprintf(f3dst, sizeof(f3dst), "%s/dst.db", f3edge);
                    snprintf(f3root, sizeof(f3root), "%s/root.fpr", f3edge);
                    snprintf(f3hcmd, sizeof(f3hcmd), "test -f '%s/current/v.cfg'", f3target);
                    assert(mkdir(f3repo, 0755) == 0 && mkdir(f3ev, 0755) == 0 &&
                           mkdir(f3ch, 0755) == 0 && mkdir(f3st, 0755) == 0 && mkdir(f3edge, 0755) == 0);

                    assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                    write_bytes_file(f3root, rb, rl);
                    snprintf(rp, sizeof(rp), "%s/root.fpr", f3repo); write_bytes_file(rp, rb, rl);
                    free(rb);

                    fp_sql_ctx_t *s3 = NULL, *d3 = NULL;
                    assert(fp_sql_open(f3src, &s3) == FP_OK && fp_sql_open(f3dst, &d3) == FP_OK);
                    assert(fp_sql_exec(s3, "CREATE TABLE t(id INTEGER PRIMARY KEY, x INTEGER);") == FP_OK);
                    assert(fp_sql_exec(d3, "CREATE TABLE t(id INTEGER PRIMARY KEY, x INTEGER);") == FP_OK);
                    fp_sql_close(d3);

                    fp_dna_t fbd[3], fdig[3];
                    uint64_t fbsz[3];
                    for (int i = 0; i < 3; i++) {
                        char q[64], c[32];
                        snprintf(q, sizeof(q), "INSERT INTO t VALUES (%d, %d);", i + 1, (i + 1) * 10);
                        snprintf(c, sizeof(c), "VER=%d\n", i + 1);
                        uint8_t *cs = NULL; size_t csl = 0;
                        assert(fp_sql_capture_changeset(s3, "t", q, &cs, &csl) == FP_OK);
                        assert(fp_sql_state_digest(s3, "t", &fdig[i]) == FP_OK);
                        fp_bundle_t fb;
                        memset(&fb, 0, sizeof(fb));
                        fb.version = 1; fb.entry_count = 2;
                        fb.entries[0].role = FP_ROLE_FILE; fb.entries[0].mode = 0644; fb.entries[0].size = strlen(c);
                        snprintf(fb.entries[0].path, sizeof(fb.entries[0].path), "v.cfg");
                        assert(fp_store_put_object(f3repo, (const uint8_t *)c, strlen(c), &fb.entries[0].dna) == FP_OK);
                        fb.entries[1].role = FP_ROLE_SQLITE_CHANGESET; fb.entries[1].size = csl;
                        snprintf(fb.entries[1].path, sizeof(fb.entries[1].path), "t");
                        assert(fp_store_put_object(f3repo, cs, csl, &fb.entries[1].dna) == FP_OK);
                        free(cs);
                        assert(fp_bundle_pack(f3repo, &fb, &fbd[i]) == FP_OK);
                        assert(fp_store_has_object(f3repo, &fbd[i], &fbsz[i]));
                    }

                    /* Events 1..3: INSTALL V1, V2, V3 */
                    fp_event_t fe[5];
                    memset(fe, 0, sizeof(fe));
                    for (int i = 0; i < 3; i++) {
                        fe[i].action = FP_ACTION_INSTALL; fe[i].repo_id = nrid; fe[i].serial = (uint64_t)(i + 1);
                        if (i > 0) fe[i].prev_event_hash = fe[i - 1].event_hash;
                        fe[i].timestamp_unix = now; fe[i].expires_unix = now + 3600;
                        fe[i].target_dna = fbd[i]; fe[i].target_size = fbsz[i];
                        assert(fp_event_sign(&fe[i], &nrel) == FP_OK);
                        assert(fp_event_encode(&fe[i], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/%d.ev", f3ev, i + 1); write_bytes_file(rp, eb, el);
                        if (i == 2) { snprintf(rp, sizeof(rp), "%s/latest.ev", f3st); write_bytes_file(rp, eb, el); }
                        free(eb);
                    }
                    srv.repo_dir = f3repo;
                    fp_agent_cfg_t f3cfg;
                    memset(&f3cfg, 0, sizeof(f3cfg));
                    f3cfg.device_id = "edge-f34"; f3cfg.repo_url = base_url; f3cfg.channel = "stable";
                    f3cfg.store_dir = f3store; f3cfg.target_dir = f3target; f3cfg.db_path = f3dst;
                    f3cfg.root_path = f3root; f3cfg.health_cmd = f3hcmd; f3cfg.health_timeout_sec = 5;
                    assert(fp_agent_sync_once(&f3cfg, &rep) == FP_OK && rep.active_serial == 3);

                    /* F3: Emit [4: ROLLBACK V3->V1, 5: REVOKE V2] -> single sync MUST treat as explicit rollback! */
                    fe[3].action = FP_ACTION_ROLLBACK; fe[3].repo_id = nrid; fe[3].serial = 4;
                    fe[3].prev_event_hash = fe[2].event_hash; fe[3].timestamp_unix = now; fe[3].expires_unix = now + 3600;
                    fe[3].target_dna = fbd[0]; fe[3].target_size = fbsz[0];
                    snprintf(fe[3].reason, sizeof(fe[3].reason), "rb-v1");
                    assert(fp_event_sign(&fe[3], &nrel) == FP_OK);
                    assert(fp_event_encode(&fe[3], &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/4.ev", f3ev); write_bytes_file(rp, eb, el); free(eb);

                    fe[4].action = FP_ACTION_REVOKE; fe[4].repo_id = nrid; fe[4].serial = 5;
                    fe[4].prev_event_hash = fe[3].event_hash; fe[4].timestamp_unix = now; fe[4].expires_unix = now + 3600;
                    fe[4].target_dna = fbd[1]; fe[4].target_size = 0;
                    snprintf(fe[4].reason, sizeof(fe[4].reason), "revoke-old-v2");
                    assert(fp_event_sign(&fe[4], &nrel) == FP_OK);
                    assert(fp_event_encode(&fe[4], &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/5.ev", f3ev); write_bytes_file(rp, eb, el);
                    snprintf(rp, sizeof(rp), "%s/latest.ev", f3st); write_bytes_file(rp, eb, el); free(eb);

                    assert(fp_agent_sync_once(&f3cfg, &rep) == FP_OK);
                    assert(rep.outcome == FP_AGENT_ROLLED_BACK && rep.active_serial == 5);
                    assert(fp_dna_equal(&rep.active_bundle_dna, &fbd[0]));
                    assert(fp_sql_open(f3dst, &d3) == FP_OK);
                    fp_dna_t f3dig_now;
                    assert(fp_sql_state_digest(d3, "t", &f3dig_now) == FP_OK && fp_dna_equal(&f3dig_now, &fdig[0]));
                    fp_sql_close(d3);
                    printf("[PASS] F3: [ROLLBACK V3->V1 + trailing REVOKE V2] keeps rollback direction & exact SQLite digest\n");

                    /* F4: 65 incremental SQLite installs (>64 rollback step limit) MUST fail closed preflight with FP_ERR_BOUNDS
                     * leaving V1 completely untouched! */
                    fp_dna_t prev_eh = fe[4].event_hash;
                    for (uint64_t k = 0; k < 65; k++) {
                        uint64_t ser = 6u + k;
                        char q[64], c[32];
                        snprintf(q, sizeof(q), "INSERT INTO t VALUES (%llu, %llu);",
                                 (unsigned long long)(100u + k), (unsigned long long)k);
                        snprintf(c, sizeof(c), "STEP=%llu\n", (unsigned long long)k);
                        uint8_t *cs = NULL; size_t csl = 0;
                        assert(fp_sql_capture_changeset(s3, "t", q, &cs, &csl) == FP_OK);
                        fp_bundle_t fb;
                        memset(&fb, 0, sizeof(fb));
                        fb.version = 1; fb.entry_count = 2;
                        fb.entries[0].role = FP_ROLE_FILE; fb.entries[0].mode = 0644; fb.entries[0].size = strlen(c);
                        snprintf(fb.entries[0].path, sizeof(fb.entries[0].path), "v.cfg");
                        assert(fp_store_put_object(f3repo, (const uint8_t *)c, strlen(c), &fb.entries[0].dna) == FP_OK);
                        fb.entries[1].role = FP_ROLE_SQLITE_CHANGESET; fb.entries[1].size = csl;
                        snprintf(fb.entries[1].path, sizeof(fb.entries[1].path), "t");
                        assert(fp_store_put_object(f3repo, cs, csl, &fb.entries[1].dna) == FP_OK);
                        free(cs);
                        fp_dna_t kd; uint64_t ksz = 0;
                        assert(fp_bundle_pack(f3repo, &fb, &kd) == FP_OK);
                        assert(fp_store_has_object(f3repo, &kd, &ksz));

                        fp_event_t ke;
                        memset(&ke, 0, sizeof(ke));
                        ke.action = FP_ACTION_INSTALL; ke.repo_id = nrid; ke.serial = ser;
                        ke.prev_event_hash = prev_eh; ke.timestamp_unix = now; ke.expires_unix = now + 3600;
                        ke.target_dna = kd; ke.target_size = ksz;
                        assert(fp_event_sign(&ke, &nrel) == FP_OK);
                        assert(fp_event_encode(&ke, &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/%llu.ev", f3ev, (unsigned long long)ser); write_bytes_file(rp, eb, el);
                        if (k == 64) { snprintf(rp, sizeof(rp), "%s/latest.ev", f3st); write_bytes_file(rp, eb, el); }
                        free(eb);
                        prev_eh = ke.event_hash;
                    }
                    fp_sql_close(s3);

                    assert(fp_agent_sync_once(&f3cfg, &rep) == FP_ERR_BOUNDS);
                    assert(fp_sql_open(f3dst, &d3) == FP_OK);
                    assert(fp_sql_state_digest(d3, "t", &f3dig_now) == FP_OK && fp_dna_equal(&f3dig_now, &fdig[0]));
                    fp_sql_close(d3);
                    printf("[PASS] F4: 65-step SQLite catch-up rejected preflight (FP_ERR_BOUNDS) with zero mutation to V1\n");
                }

                /* Test O (6th Audit P0-01/03/04/05/06 & P1-01):
                 * TX-01 independent rows after failed V2, TX-02/03 first health FAIL after REVOKE V1 + offline crash,
                 * TX-05 mixed ROLLBACK->INSTALL preflight reject, TX-07 LEDGER_PENDING missing current, TX-08 HEALTH_PENDING vs HEALTH_RUNNING */
                {
                    char otmpl[] = "/tmp/fp-ag-m7-XXXXXX";
                    char *odir = mkdtemp(otmpl);
                    assert(odir != NULL);
                    char orepo[256], oev[300], och[300], ost[340], oedge[256];
                    char ostore[300], otarget[300], osrc[300], odst[300], oroot[300], ohcmd[512];
                    snprintf(orepo, sizeof(orepo), "%s/repo", odir);
                    snprintf(oev, sizeof(oev), "%s/events", orepo);
                    snprintf(och, sizeof(och), "%s/channels", orepo);
                    snprintf(ost, sizeof(ost), "%s/stable", och);
                    snprintf(oedge, sizeof(oedge), "%s/edge", odir);
                    snprintf(ostore, sizeof(ostore), "%s/store", oedge);
                    snprintf(otarget, sizeof(otarget), "%s/live", oedge);
                    snprintf(osrc, sizeof(osrc), "%s/src.db", odir);
                    snprintf(odst, sizeof(odst), "%s/dst.db", oedge);
                    snprintf(oroot, sizeof(oroot), "%s/root.fpr", oedge);
                    snprintf(ohcmd, sizeof(ohcmd), "grep -q 'OK=1' '%s/current/app.cfg'", otarget);
                    assert(mkdir(orepo, 0755) == 0 && mkdir(oev, 0755) == 0 &&
                           mkdir(och, 0755) == 0 && mkdir(ost, 0755) == 0 && mkdir(oedge, 0755) == 0);

                    assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                    write_bytes_file(oroot, rb, rl);
                    snprintf(rp, sizeof(rp), "%s/root.fpr", orepo); write_bytes_file(rp, rb, rl);
                    free(rb);

                    fp_sql_ctx_t *os = NULL, *od = NULL;
                    assert(fp_sql_open(osrc, &os) == FP_OK && fp_sql_open(odst, &od) == FP_OK);
                    assert(fp_sql_exec(os, "CREATE TABLE ab(k TEXT PRIMARY KEY, v INTEGER);") == FP_OK);
                    assert(fp_sql_exec(od, "CREATE TABLE ab(k TEXT PRIMARY KEY, v INTEGER);") == FP_OK);
                    fp_sql_close(od);

                    /* TX-01 (P0-01): V1=(A:100,B:100) -> V2(A:200, FAIL=1) -> V3(B:300, OK=1) -> MUST yield exact (200,300)! */
                    const char *osqls[4] = {
                        "INSERT INTO ab VALUES ('A', 100); INSERT INTO ab VALUES ('B', 100);",
                        "UPDATE ab SET v=200 WHERE k='A';",
                        "UPDATE ab SET v=300 WHERE k='B';",
                        "UPDATE ab SET v=400 WHERE k='B';"
                    };
                    const char *ocfgs[4] = { "OK=1\nV=1\n", "FAIL=1\nV=2\n", "OK=1\nV=3\n", "OK=1\nV=4\n" };
                    fp_dna_t obd[4], odig[4];
                    uint64_t obsz[4];
                    for (int i = 0; i < 4; i++) {
                        uint8_t *cs = NULL; size_t csl = 0;
                        assert(fp_sql_capture_changeset(os, "ab", osqls[i], &cs, &csl) == FP_OK);
                        assert(fp_sql_state_digest(os, "ab", &odig[i]) == FP_OK);
                        fp_bundle_t ob;
                        memset(&ob, 0, sizeof(ob));
                        ob.version = 1; ob.entry_count = 2;
                        ob.entries[0].role = FP_ROLE_FILE; ob.entries[0].mode = 0644; ob.entries[0].size = strlen(ocfgs[i]);
                        snprintf(ob.entries[0].path, sizeof(ob.entries[0].path), "app.cfg");
                        assert(fp_store_put_object(orepo, (const uint8_t *)ocfgs[i], strlen(ocfgs[i]), &ob.entries[0].dna) == FP_OK);
                        ob.entries[1].role = FP_ROLE_SQLITE_CHANGESET; ob.entries[1].size = csl;
                        snprintf(ob.entries[1].path, sizeof(ob.entries[1].path), "ab");
                        assert(fp_store_put_object(orepo, cs, csl, &ob.entries[1].dna) == FP_OK);
                        free(cs);
                        assert(fp_bundle_pack(orepo, &ob, &obd[i]) == FP_OK);
                        assert(fp_store_has_object(orepo, &obd[i], &obsz[i]));
                    }
                    fp_sql_close(os);

                    fp_event_t oe1, oe2, oe3;
                    memset(&oe1, 0, sizeof(oe1)); memset(&oe2, 0, sizeof(oe2)); memset(&oe3, 0, sizeof(oe3));
                    oe1.action = FP_ACTION_INSTALL; oe1.repo_id = nrid; oe1.serial = 1;
                    oe1.timestamp_unix = now; oe1.expires_unix = now + 3600;
                    oe1.target_dna = obd[0]; oe1.target_size = obsz[0];
                    assert(fp_event_sign(&oe1, &nrel) == FP_OK);
                    assert(fp_event_encode(&oe1, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/1.ev", oev); write_bytes_file(rp, eb, el);
                    snprintf(rp, sizeof(rp), "%s/latest.ev", ost); write_bytes_file(rp, eb, el); free(eb);

                    srv.repo_dir = orepo;
                    fp_agent_cfg_t ocfg;
                    memset(&ocfg, 0, sizeof(ocfg));
                    ocfg.device_id = "edge-m7"; ocfg.repo_url = base_url; ocfg.channel = "stable";
                    ocfg.store_dir = ostore; ocfg.target_dir = otarget; ocfg.db_path = odst;
                    ocfg.root_path = oroot; ocfg.health_cmd = ohcmd; ocfg.health_timeout_sec = 5;
                    assert(fp_agent_sync_once(&ocfg, &rep) == FP_OK && rep.active_serial == 1);

                    /* V2 fails health -> auto-rolls back to V1 */
                    oe2.action = FP_ACTION_INSTALL; oe2.repo_id = nrid; oe2.serial = 2;
                    oe2.prev_event_hash = oe1.event_hash; oe2.timestamp_unix = now; oe2.expires_unix = now + 3600;
                    oe2.target_dna = obd[1]; oe2.target_size = obsz[1];
                    assert(fp_event_sign(&oe2, &nrel) == FP_OK);
                    assert(fp_event_encode(&oe2, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/2.ev", oev); write_bytes_file(rp, eb, el);
                    snprintf(rp, sizeof(rp), "%s/latest.ev", ost); write_bytes_file(rp, eb, el); free(eb);
                    assert(fp_agent_sync_once(&ocfg, &rep) == FP_OK && rep.outcome == FP_AGENT_ROLLED_BACK);

                    /* V3 (B=300, health=true) MUST replay V2's SQL migration (A=200) + V3 (B=300) -> exact odig[2]! */
                    oe3.action = FP_ACTION_INSTALL; oe3.repo_id = nrid; oe3.serial = 3;
                    oe3.prev_event_hash = oe2.event_hash; oe3.timestamp_unix = now; oe3.expires_unix = now + 3600;
                    oe3.target_dna = obd[2]; oe3.target_size = obsz[2];
                    assert(fp_event_sign(&oe3, &nrel) == FP_OK);
                    assert(fp_event_encode(&oe3, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/3.ev", oev); write_bytes_file(rp, eb, el);
                    snprintf(rp, sizeof(rp), "%s/latest.ev", ost); write_bytes_file(rp, eb, el); free(eb);
                    ocfg.health_cmd = "true";
                    assert(fp_agent_sync_once(&ocfg, &rep) == FP_OK && rep.active_serial == 3);
                    assert(fp_sql_open(odst, &od) == FP_OK);
                    fp_dna_t odig_now;
                    assert(fp_sql_state_digest(od, "ab", &odig_now) == FP_OK && fp_dna_equal(&odig_now, &odig[2]));
                    fp_sql_close(od);
                    printf("[PASS] TX-01 (P0-01): Failed intermediate V2(A=200) NOT skipped on V3(B=300) -> exact SQL digest (200,300)!\n");

                    /* TX-05 (P0-04): Mixed [ROLLBACK V3->V1, INSTALL V4] with SQLite MUST fail closed pre-mutation! */
                    fp_event_t oe4, oe5;
                    memset(&oe4, 0, sizeof(oe4)); memset(&oe5, 0, sizeof(oe5));
                    oe4.action = FP_ACTION_ROLLBACK; oe4.repo_id = nrid; oe4.serial = 4;
                    oe4.prev_event_hash = oe3.event_hash; oe4.timestamp_unix = now; oe4.expires_unix = now + 3600;
                    oe4.target_dna = obd[0]; oe4.target_size = obsz[0];
                    snprintf(oe4.reason, sizeof(oe4.reason), "mix-rb");
                    assert(fp_event_sign(&oe4, &nrel) == FP_OK);
                    assert(fp_event_encode(&oe4, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/4.ev", oev); write_bytes_file(rp, eb, el); free(eb);

                    oe5.action = FP_ACTION_INSTALL; oe5.repo_id = nrid; oe5.serial = 5;
                    oe5.prev_event_hash = oe4.event_hash; oe5.timestamp_unix = now; oe5.expires_unix = now + 3600;
                    oe5.target_dna = obd[3]; oe5.target_size = obsz[3];
                    assert(fp_event_sign(&oe5, &nrel) == FP_OK);
                    assert(fp_event_encode(&oe5, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/5.ev", oev); write_bytes_file(rp, eb, el);
                    snprintf(rp, sizeof(rp), "%s/latest.ev", ost); write_bytes_file(rp, eb, el); free(eb);

                    assert(fp_agent_sync_once(&ocfg, &rep) == FP_ERR_POLICY);
                    assert(fp_sql_open(odst, &od) == FP_OK);
                    assert(fp_sql_state_digest(od, "ab", &odig_now) == FP_OK && fp_dna_equal(&odig_now, &odig[2]));
                    fp_sql_close(od);
                    printf("[PASS] TX-05 (P0-04): Mixed [ROLLBACK->INSTALL] SQLite chain rejected preflight (FP_ERR_POLICY), V3 intact\n");

                    /* TX-08 (P1-01): Crash in HEALTH_PENDING AFTER target reached (before watchdog) -> rollback WITHOUT quarantine! */
                    char ootap[360], ofailp[360], ocur[360], orev[360], ob2h[65], ob3h[65];
                    snprintf(ootap, sizeof(ootap), "%s/.sf_ota_state", otarget);
                    snprintf(ofailp, sizeof(ofailp), "%s/agent_failed_serial", ostore);
                    snprintf(ocur, sizeof(ocur), "%s/current", otarget);
                    snprintf(orev, sizeof(orev), "%s/.sf_revoked", otarget);
                    fp_hex_encode(obd[2].bytes, FP_DNA_LEN, ob2h);
                    fp_hex_encode(obd[3].bytes, FP_DNA_LEN, ob3h);
                    /* Stage V4 locally & simulate crash right BEFORE watchdog (state=HEALTH_PENDING, not HEALTH_RUNNING) */
                    assert(fp_store_put_object(ostore, (const uint8_t *)ocfgs[3], strlen(ocfgs[3]), NULL) == FP_OK);
                    {
                        uint8_t *b4b = NULL; size_t b4l = 0;
                        assert(fp_store_get_object(orepo, &obd[3], (1u << 20), &b4b, &b4l) == FP_OK);
                        fp_bundle_t b4;
                        assert(fp_bundle_decode(b4b, b4l, &b4) == FP_OK);
                        assert(fp_store_put_object(ostore, b4b, b4l, NULL) == FP_OK);
                        free(b4b);
                        for (uint16_t j = 0; j < b4.entry_count; j++) {
                            uint8_t *eb2 = NULL; size_t el2 = 0;
                            assert(fp_store_get_object(orepo, &b4.entries[j].dna, (1u << 20), &eb2, &el2) == FP_OK);
                            assert(fp_store_put_object(ostore, eb2, el2, NULL) == FP_OK);
                            free(eb2);
                        }
                    }
                    assert(fp_sql_open(odst, &od) == FP_OK);
                    assert(fp_bundle_apply(ostore, &obd[3], otarget, od, 4, 0) == FP_OK);
                    fp_sql_close(od);
                    oln = snprintf(oline, sizeof(oline), "SFOTA1 HEALTH_PENDING 4 %s 1 %s 4\n", ob3h, ob2h);
                    write_bytes_file(ootap, (const uint8_t *)oline, (size_t)oln);
                    ocfg.repo_url = "http://127.0.0.1:1";
                    (void)fp_agent_sync_once(&ocfg, &rep);
                    assert(lstat(ootap, &st_chk) != 0);
                    assert(lstat(ofailp, &st_chk) != 0); /* ZERO false quarantine on pre-watchdog crash! */
                    printf("[PASS] TX-08 (P1-01): Pre-watchdog crash on final DNA reverted cleanly without false quarantine\n");

                    /* TX-07 (P0-06): LEDGER_PENDING with missing `current` symlink MUST fail closed & preserve .sf_ota_state! */
                    assert(unlink(ocur) == 0);
                    oln = snprintf(oline, sizeof(oline), "SFOTA1 LEDGER_PENDING 3 %s 1 %s 3\n", ob2h, ob2h);
                    write_bytes_file(ootap, (const uint8_t *)oline, (size_t)oln);
                    assert(fp_agent_sync_once(&ocfg, &rep) == FP_ERR_INTEGRITY);
                    assert(lstat(ootap, &st_chk) == 0); /* Evidence preserved! */
                    assert(unlink(ootap) == 0);
                    printf("[PASS] TX-07 (P0-06): LEDGER_PENDING with missing current symlink rejected fail-closed (evidence preserved)\n");

                    /* TX-02 & TX-03 (P0-03 & P0-05): [REVOKE active V1, INSTALL V2(FAIL)] -> FIRST health FAIL MUST NOT reactivate V1! */
                    char p03tmpl[] = "/tmp/fp-ag-p03-XXXXXX";
                    char *p03dir = mkdtemp(p03tmpl);
                    assert(p03dir != NULL);
                    char p03repo[256], p03ev[300], p03ch[300], p03st[340], p03edge[256];
                    char p03store[300], p03target[300], p03root[300], p03cur[360], p03rev[360], p03hcmd[512];
                    snprintf(p03repo, sizeof(p03repo), "%s/repo", p03dir);
                    snprintf(p03ev, sizeof(p03ev), "%s/events", p03repo);
                    snprintf(p03ch, sizeof(p03ch), "%s/channels", p03repo);
                    snprintf(p03st, sizeof(p03st), "%s/stable", p03ch);
                    snprintf(p03edge, sizeof(p03edge), "%s/edge", p03dir);
                    snprintf(p03store, sizeof(p03store), "%s/store", p03edge);
                    snprintf(p03target, sizeof(p03target), "%s/live", p03edge);
                    snprintf(p03root, sizeof(p03root), "%s/root.fpr", p03edge);
                    snprintf(p03cur, sizeof(p03cur), "%s/current", p03target);
                    snprintf(p03rev, sizeof(p03rev), "%s/.sf_revoked", p03target);
                    snprintf(p03hcmd, sizeof(p03hcmd), "grep -q 'OK=1' '%s/current/app.cfg'", p03target);
                    assert(mkdir(p03repo, 0755) == 0 && mkdir(p03ev, 0755) == 0 &&
                           mkdir(p03ch, 0755) == 0 && mkdir(p03st, 0755) == 0 && mkdir(p03edge, 0755) == 0);
                    assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                    write_bytes_file(p03root, rb, rl);
                    snprintf(rp, sizeof(rp), "%s/root.fpr", p03repo); write_bytes_file(rp, rb, rl); free(rb);

                    fp_bundle_t pb1, pb2;
                    memset(&pb1, 0, sizeof(pb1)); memset(&pb2, 0, sizeof(pb2));
                    pb1.version = 1; pb1.entry_count = 1; pb1.entries[0].role = FP_ROLE_FILE;
                    pb1.entries[0].mode = 0644; pb1.entries[0].size = 5;
                    snprintf(pb1.entries[0].path, sizeof(pb1.entries[0].path), "app.cfg");
                    assert(fp_store_put_object(p03repo, (const uint8_t *)"OK=1\n", 5, &pb1.entries[0].dna) == FP_OK);
                    pb2 = pb1; pb2.entries[0].size = 7;
                    assert(fp_store_put_object(p03repo, (const uint8_t *)"FAIL=1\n", 7, &pb2.entries[0].dna) == FP_OK);
                    fp_dna_t pbd1, pbd2; uint64_t pbs1 = 0, pbs2 = 0;
                    assert(fp_bundle_pack(p03repo, &pb1, &pbd1) == FP_OK && fp_store_has_object(p03repo, &pbd1, &pbs1));
                    assert(fp_bundle_pack(p03repo, &pb2, &pbd2) == FP_OK && fp_store_has_object(p03repo, &pbd2, &pbs2));

                    fp_event_t pe1, pe2, pe3;
                    memset(&pe1, 0, sizeof(pe1)); memset(&pe2, 0, sizeof(pe2)); memset(&pe3, 0, sizeof(pe3));
                    pe1.action = FP_ACTION_INSTALL; pe1.repo_id = nrid; pe1.serial = 1;
                    pe1.timestamp_unix = now; pe1.expires_unix = now + 3600;
                    pe1.target_dna = pbd1; pe1.target_size = pbs1;
                    assert(fp_event_sign(&pe1, &nrel) == FP_OK);
                    assert(fp_event_encode(&pe1, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/1.ev", p03ev); write_bytes_file(rp, eb, el);
                    snprintf(rp, sizeof(rp), "%s/latest.ev", p03st); write_bytes_file(rp, eb, el); free(eb);

                    srv.repo_dir = p03repo;
                    fp_agent_cfg_t p03cfg;
                    memset(&p03cfg, 0, sizeof(p03cfg));
                    p03cfg.device_id = "edge-p03"; p03cfg.repo_url = base_url; p03cfg.channel = "stable";
                    p03cfg.store_dir = p03store; p03cfg.target_dir = p03target;
                    p03cfg.root_path = p03root; p03cfg.health_cmd = p03hcmd; p03cfg.health_timeout_sec = 5;
                    assert(fp_agent_sync_once(&p03cfg, &rep) == FP_OK && rep.active_serial == 1);

                    /* Now emit [2: REVOKE V1, 3: INSTALL V2(FAIL)] -> V2 has NEVER been tried before! */
                    pe2.action = FP_ACTION_REVOKE; pe2.repo_id = nrid; pe2.serial = 2;
                    pe2.prev_event_hash = pe1.event_hash; pe2.timestamp_unix = now; pe2.expires_unix = now + 3600;
                    pe2.target_dna = pbd1; pe2.target_size = 0;
                    snprintf(pe2.reason, sizeof(pe2.reason), "compromised-v1");
                    assert(fp_event_sign(&pe2, &nrel) == FP_OK);
                    assert(fp_event_encode(&pe2, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/2.ev", p03ev); write_bytes_file(rp, eb, el); free(eb);

                    pe3.action = FP_ACTION_INSTALL; pe3.repo_id = nrid; pe3.serial = 3;
                    pe3.prev_event_hash = pe2.event_hash; pe3.timestamp_unix = now; pe3.expires_unix = now + 3600;
                    pe3.target_dna = pbd2; pe3.target_size = pbs2;
                    assert(fp_event_sign(&pe3, &nrel) == FP_OK);
                    assert(fp_event_encode(&pe3, &eb, &el) == FP_OK);
                    snprintf(rp, sizeof(rp), "%s/3.ev", p03ev); write_bytes_file(rp, eb, el);
                    snprintf(rp, sizeof(rp), "%s/latest.ev", p03st); write_bytes_file(rp, eb, el); free(eb);

                    /* FIRST health FAIL on V2 MUST deactivate live target (NEVER roll back to revoked V1!) */
                    assert(fp_agent_sync_once(&p03cfg, &rep) == FP_ERR_POLICY);
                    assert(rep.outcome == FP_AGENT_REVOKED && rep.active_serial == 0);
                    assert(lstat(p03cur, &st_chk) != 0 && lstat(p03rev, &st_chk) == 0);

                    /* Offline crash recovery (TX-03): even if HEALTH_PENDING points prev=V1, durable deny-set blocks V1 offline! */
                    char p1h[65], p2h[65], p03otap[360];
                    fp_hex_encode(pbd1.bytes, FP_DNA_LEN, p1h);
                    fp_hex_encode(pbd2.bytes, FP_DNA_LEN, p2h);
                    snprintf(p03otap, sizeof(p03otap), "%s/.sf_ota_state", p03target);
                    oln = snprintf(oline, sizeof(oline), "SFOTA1 HEALTH_PENDING 3 %s 1 %s 2\n", p2h, p1h);
                    write_bytes_file(p03otap, (const uint8_t *)oline, (size_t)oln);
                    p03cfg.repo_url = "http://127.0.0.1:1"; /* completely offline! */
                    (void)fp_agent_sync_once(&p03cfg, &rep);
                    assert(lstat(p03otap, &st_chk) != 0);
                    assert(lstat(p03cur, &st_chk) != 0 && lstat(p03rev, &st_chk) == 0);
                    printf("[PASS] TX-02/TX-03 (P0-03/P0-05): Monotonic deny-set prevents V1 reactivation on first health FAIL & offline crash!\n");

                    /* A7-P0-02/03/04/05 & A7-P1-02: 7th Audit Regression Suite (REV-01/02, REV-05, REV-06, TX-01) */
                    {
                        char a7tmpl[] = "/tmp/fp-ag-a7-XXXXXX";
                        char *a7dir = mkdtemp(a7tmpl);
                        assert(a7dir != NULL);

                        /* --- REV-01 / REV-02 / A7-P1-02: Immediate pre-download fencing + boot fence + UP_TO_DATE deny-set --- */
                        char r1repo[256], r1ev[300], r1ch[300], r1st[340], r1edge[256];
                        char r1store[300], r1target[300], r1root[300], r1cur[360], r1rev[360];
                        snprintf(r1repo, sizeof(r1repo), "%s/r1_repo", a7dir);
                        snprintf(r1ev, sizeof(r1ev), "%s/events", r1repo);
                        snprintf(r1ch, sizeof(r1ch), "%s/channels", r1repo);
                        snprintf(r1st, sizeof(r1st), "%s/stable", r1ch);
                        snprintf(r1edge, sizeof(r1edge), "%s/r1_edge", a7dir);
                        snprintf(r1store, sizeof(r1store), "%s/store", r1edge);
                        snprintf(r1target, sizeof(r1target), "%s/live", r1edge);
                        snprintf(r1root, sizeof(r1root), "%s/root.fpr", r1edge);
                        snprintf(r1cur, sizeof(r1cur), "%s/current", r1target);
                        snprintf(r1rev, sizeof(r1rev), "%s/.sf_revoked", r1target);
                        assert(mkdir(r1repo, 0755) == 0 && mkdir(r1ev, 0755) == 0 &&
                               mkdir(r1ch, 0755) == 0 && mkdir(r1st, 0755) == 0 && mkdir(r1edge, 0755) == 0);
                        assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                        write_bytes_file(r1root, rb, rl);
                        snprintf(rp, sizeof(rp), "%s/root.fpr", r1repo); write_bytes_file(rp, rb, rl); free(rb);

                        fp_bundle_t fb1, fb2;
                        memset(&fb1, 0, sizeof(fb1)); memset(&fb2, 0, sizeof(fb2));
                        fb1.version = 1; fb1.entry_count = 1; fb1.entries[0].role = FP_ROLE_FILE;
                        fb1.entries[0].mode = 0644; fb1.entries[0].size = 5;
                        snprintf(fb1.entries[0].path, sizeof(fb1.entries[0].path), "app.cfg");
                        assert(fp_store_put_object(r1repo, (const uint8_t *)"OK=1\n", 5, &fb1.entries[0].dna) == FP_OK);
                        fb2 = fb1; fb2.entries[0].size = 5;
                        assert(fp_store_put_object(r1repo, (const uint8_t *)"OK=2\n", 5, &fb2.entries[0].dna) == FP_OK);
                        fp_dna_t fbd1, fbd2; uint64_t fbs1 = 0, fbs2 = 0;
                        assert(fp_bundle_pack(r1repo, &fb1, &fbd1) == FP_OK && fp_store_has_object(r1repo, &fbd1, &fbs1));
                        assert(fp_bundle_pack(r1repo, &fb2, &fbd2) == FP_OK && fp_store_has_object(r1repo, &fbd2, &fbs2));

                        fp_event_t fe1, fe2, fe3;
                        memset(&fe1, 0, sizeof(fe1)); memset(&fe2, 0, sizeof(fe2)); memset(&fe3, 0, sizeof(fe3));
                        fe1.action = FP_ACTION_INSTALL; fe1.repo_id = nrid; fe1.serial = 1;
                        fe1.timestamp_unix = now; fe1.expires_unix = now + 3600;
                        fe1.target_dna = fbd1; fe1.target_size = fbs1;
                        assert(fp_event_sign(&fe1, &nrel) == FP_OK);
                        assert(fp_event_encode(&fe1, &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/1.ev", r1ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", r1st); write_bytes_file(rp, eb, el); free(eb);

                        srv.repo_dir = r1repo;
                        fp_agent_cfg_t r1cfg;
                        memset(&r1cfg, 0, sizeof(r1cfg));
                        r1cfg.device_id = "edge-r1"; r1cfg.repo_url = base_url; r1cfg.channel = "stable";
                        r1cfg.store_dir = r1store; r1cfg.target_dir = r1target;
                        r1cfg.root_path = r1root; r1cfg.health_cmd = "true"; r1cfg.health_timeout_sec = 5;
                        assert(fp_agent_sync_once(&r1cfg, &rep) == FP_OK && rep.active_serial == 1);
                        assert(lstat(r1cur, &st_chk) == 0);

                        /* Publish [2: REVOKE V1, 3: INSTALL V2] and DELETE V2 object from repo -> 404 on download! */
                        fe2.action = FP_ACTION_REVOKE; fe2.repo_id = nrid; fe2.serial = 2;
                        fe2.prev_event_hash = fe1.event_hash; fe2.timestamp_unix = now; fe2.expires_unix = now + 3600;
                        fe2.target_dna = fbd1; fe2.target_size = 0;
                        snprintf(fe2.reason, sizeof(fe2.reason), "fence-v1");
                        assert(fp_event_sign(&fe2, &nrel) == FP_OK);
                        assert(fp_event_encode(&fe2, &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/2.ev", r1ev); write_bytes_file(rp, eb, el); free(eb);

                        fe3.action = FP_ACTION_INSTALL; fe3.repo_id = nrid; fe3.serial = 3;
                        fe3.prev_event_hash = fe2.event_hash; fe3.timestamp_unix = now; fe3.expires_unix = now + 3600;
                        fe3.target_dna = fbd2; fe3.target_size = fbs2;
                        assert(fp_event_sign(&fe3, &nrel) == FP_OK);
                        assert(fp_event_encode(&fe3, &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/3.ev", r1ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", r1st); write_bytes_file(rp, eb, el); free(eb);

                        char fbd2h[65], del_obj[400];
                        fp_hex_encode(fbd2.bytes, FP_DNA_LEN, fbd2h);
                        snprintf(del_obj, sizeof(del_obj), "%s/objects/%s", r1repo, fbd2h);
                        assert(unlink(del_obj) == 0);

                        /* Download of V2 fails (404), BUT V1 MUST ALREADY BE FENCED (current removed + .sf_revoked)! */
                        assert(fp_agent_sync_once(&r1cfg, &rep) != FP_OK);
                        assert(lstat(r1cur, &st_chk) != 0 && lstat(r1rev, &st_chk) == 0);

                        /* REV-02: Recreate symlink to revoked V1 manually with NO .sf_ota_state -> offline boot fence MUST remove it! */
                        char fbd1h[65], frel[128];
                        fp_hex_encode(fbd1.bytes, FP_DNA_LEN, fbd1h);
                        snprintf(frel, sizeof(frel), "gen/%s", fbd1h);
                        assert(symlink(frel, r1cur) == 0);
                        r1cfg.repo_url = "http://127.0.0.1:1";
                        (void)fp_agent_sync_once(&r1cfg, &rep);
                        assert(lstat(r1cur, &st_chk) != 0 && lstat(r1rev, &st_chk) == 0);

                        /* A7-P1-02: UP_TO_DATE branch when latest_ev.serial <= st.serial AND st.current_dna is in deny-set! */
                        assert(fp_event_encode(&fe1, &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", r1st); write_bytes_file(rp, eb, el); free(eb);
                        r1cfg.repo_url = base_url;
                        assert(fp_agent_sync_once(&r1cfg, &rep) == FP_ERR_POLICY);
                        assert(rep.outcome == FP_AGENT_REVOKED && rep.active_serial == 0);
                        printf("[PASS] A7-P0-02/A7-P1-02 (REV-01/REV-02): Pre-download fencing, offline boot fence & UP_TO_DATE deny-set verified!\n");

                        /* --- REV-05 (A7-P0-03) & REV-06 (A7-P0-04) & TX-01 (A7-P0-05) --- */
                        char s7repo[256], s7ev[300], s7ch[300], s7st[340], s7edge[256];
                        char s7store[300], s7target[300], s7root[300], s7src[300], s7dst[300];
                        char s7cur[360], s7rev[360], s7hcmd[512];
                        snprintf(s7repo, sizeof(s7repo), "%s/s7_repo", a7dir);
                        snprintf(s7ev, sizeof(s7ev), "%s/events", s7repo);
                        snprintf(s7ch, sizeof(s7ch), "%s/channels", s7repo);
                        snprintf(s7st, sizeof(s7st), "%s/stable", s7ch);
                        snprintf(s7edge, sizeof(s7edge), "%s/s7_edge", a7dir);
                        snprintf(s7store, sizeof(s7store), "%s/store", s7edge);
                        snprintf(s7target, sizeof(s7target), "%s/live", s7edge);
                        snprintf(s7root, sizeof(s7root), "%s/root.fpr", s7edge);
                        snprintf(s7src, sizeof(s7src), "%s/src.db", a7dir);
                        snprintf(s7dst, sizeof(s7dst), "%s/dst.db", s7edge);
                        snprintf(s7cur, sizeof(s7cur), "%s/current", s7target);
                        snprintf(s7rev, sizeof(s7rev), "%s/.sf_revoked", s7target);
                        snprintf(s7hcmd, sizeof(s7hcmd), "grep -q 'OK=1' '%s/current/app.cfg'", s7target);
                        assert(mkdir(s7repo, 0755) == 0 && mkdir(s7ev, 0755) == 0 &&
                               mkdir(s7ch, 0755) == 0 && mkdir(s7st, 0755) == 0 && mkdir(s7edge, 0755) == 0);
                        assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                        write_bytes_file(s7root, rb, rl);
                        snprintf(rp, sizeof(rp), "%s/root.fpr", s7repo); write_bytes_file(rp, rb, rl); free(rb);

                        fp_sql_ctx_t *s7s = NULL, *s7d = NULL;
                        assert(fp_sql_open(s7src, &s7s) == FP_OK && fp_sql_open(s7dst, &s7d) == FP_OK);
                        assert(fp_sql_exec(s7s, "CREATE TABLE t7(id INTEGER PRIMARY KEY, val TEXT);") == FP_OK);
                        assert(fp_sql_exec(s7d, "CREATE TABLE t7(id INTEGER PRIMARY KEY, val TEXT);") == FP_OK);
                        fp_sql_close(s7d);

                        /* Build 4 SQLite+file bundles:
                         * V1(OK, id=1), V2(revoked intermediate, id=2), V3(OK for REV-05), V4(FAIL for REV-06), V5(OK for REV-06) */
                        const char *s7sql[5] = {
                            "INSERT INTO t7 VALUES (1, 'v1');",
                            "INSERT INTO t7 VALUES (2, 'v2-mid');",
                            "INSERT INTO t7 VALUES (3, 'v3-ok');",
                            "INSERT INTO t7 VALUES (4, 'v4-fail');",
                            "INSERT INTO t7 VALUES (5, 'v5-ok');"
                        };
                        const char *s7cfg[5] = { "OK=1\nV=1\n", "FAIL=1\nV=2\n", "OK=1\nV=3\n", "FAIL=1\nV=4\n", "OK=1\nV=5\n" };
                        fp_dna_t s7bd[5], s7dig[5];
                        uint64_t s7bsz[5];
                        for (int i = 0; i < 5; i++) {
                            uint8_t *cs = NULL; size_t csl = 0;
                            assert(fp_sql_capture_changeset(s7s, "t7", s7sql[i], &cs, &csl) == FP_OK);
                            assert(fp_sql_state_digest(s7s, "t7", &s7dig[i]) == FP_OK);
                            fp_bundle_t b;
                            memset(&b, 0, sizeof(b));
                            b.version = 1; b.entry_count = 2;
                            b.entries[0].role = FP_ROLE_FILE; b.entries[0].mode = 0644; b.entries[0].size = strlen(s7cfg[i]);
                            snprintf(b.entries[0].path, sizeof(b.entries[0].path), "app.cfg");
                            assert(fp_store_put_object(s7repo, (const uint8_t *)s7cfg[i], strlen(s7cfg[i]), &b.entries[0].dna) == FP_OK);
                            b.entries[1].role = FP_ROLE_SQLITE_CHANGESET; b.entries[1].size = csl;
                            snprintf(b.entries[1].path, sizeof(b.entries[1].path), "t7");
                            assert(fp_store_put_object(s7repo, cs, csl, &b.entries[1].dna) == FP_OK);
                            free(cs);
                            assert(fp_bundle_pack(s7repo, &b, &s7bd[i]) == FP_OK);
                            assert(fp_store_has_object(s7repo, &s7bd[i], &s7bsz[i]));
                        }
                        fp_sql_close(s7s);

                        /* Event 1: INSTALL V1 */
                        fp_event_t se[9];
                        memset(se, 0, sizeof(se));
                        se[1].action = FP_ACTION_INSTALL; se[1].repo_id = nrid; se[1].serial = 1;
                        se[1].timestamp_unix = now; se[1].expires_unix = now + 3600;
                        se[1].target_dna = s7bd[0]; se[1].target_size = s7bsz[0];
                        assert(fp_event_sign(&se[1], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[1], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/1.ev", s7ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", s7st); write_bytes_file(rp, eb, el); free(eb);

                        srv.repo_dir = s7repo;
                        fp_agent_cfg_t s7acfg;
                        memset(&s7acfg, 0, sizeof(s7acfg));
                        s7acfg.device_id = "edge-s7"; s7acfg.repo_url = base_url; s7acfg.channel = "stable";
                        s7acfg.store_dir = s7store; s7acfg.target_dir = s7target; s7acfg.db_path = s7dst;
                        s7acfg.root_path = s7root; s7acfg.health_cmd = s7hcmd; s7acfg.health_timeout_sec = 5;
                        assert(fp_agent_sync_once(&s7acfg, &rep) == FP_OK && rep.active_serial == 1);

                        /* REV-05 (A7-P0-03): [2: INSTALL V2 (revoked!), 3: REVOKE V2, 4: INSTALL V3 (OK)] ->
                         * V3 succeeds with exact SQL digest (V1+V2+V3), AND gen/<V2> is NEVER created! */
                        se[2].action = FP_ACTION_INSTALL; se[2].repo_id = nrid; se[2].serial = 2;
                        se[2].prev_event_hash = se[1].event_hash; se[2].timestamp_unix = now; se[2].expires_unix = now + 3600;
                        se[2].target_dna = s7bd[1]; se[2].target_size = s7bsz[1];
                        assert(fp_event_sign(&se[2], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[2], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/2.ev", s7ev); write_bytes_file(rp, eb, el); free(eb);

                        se[3].action = FP_ACTION_REVOKE; se[3].repo_id = nrid; se[3].serial = 3;
                        se[3].prev_event_hash = se[2].event_hash; se[3].timestamp_unix = now; se[3].expires_unix = now + 3600;
                        se[3].target_dna = s7bd[1]; se[3].target_size = 0;
                        snprintf(se[3].reason, sizeof(se[3].reason), "revoked-intermediate-v2");
                        assert(fp_event_sign(&se[3], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[3], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/3.ev", s7ev); write_bytes_file(rp, eb, el); free(eb);

                        se[4].action = FP_ACTION_INSTALL; se[4].repo_id = nrid; se[4].serial = 4;
                        se[4].prev_event_hash = se[3].event_hash; se[4].timestamp_unix = now; se[4].expires_unix = now + 3600;
                        se[4].target_dna = s7bd[2]; se[4].target_size = s7bsz[2];
                        assert(fp_event_sign(&se[4], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[4], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/4.ev", s7ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", s7st); write_bytes_file(rp, eb, el); free(eb);

                        assert(fp_agent_sync_once(&s7acfg, &rep) == FP_OK && rep.active_serial == 4);
                        char v2_hex[65], v2_gen[400];
                        fp_hex_encode(s7bd[1].bytes, FP_DNA_LEN, v2_hex);
                        snprintf(v2_gen, sizeof(v2_gen), "%s/gen/%s", s7target, v2_hex);
                        assert(lstat(v2_gen, &st_chk) != 0); /* Intermediate revoked V2 NEVER materialized! */
                        assert(fp_sql_open(s7dst, &s7d) == FP_OK);
                        fp_dna_t s7dig_now;
                        assert(fp_sql_state_digest(s7d, "t7", &s7dig_now) == FP_OK && fp_dna_equal(&s7dig_now, &s7dig[2]));
                        fp_sql_close(s7d);
                        printf("[PASS] A7-P0-03 (REV-05): Intermediate revoked V2 replayed SQL-only (gen/<V2> never created, V3 SQL exact)!\n");

                        /* REV-06 (A7-P0-04): Active V3 revoked + V4(SQL, health FAIL) -> SQLite reverted to V3 WITHOUT
                         * reactivating V3, then V5(SQL, health OK) advances cleanly without FP_ERR_CHAIN! */
                        se[5].action = FP_ACTION_REVOKE; se[5].repo_id = nrid; se[5].serial = 5;
                        se[5].prev_event_hash = se[4].event_hash; se[5].timestamp_unix = now; se[5].expires_unix = now + 3600;
                        se[5].target_dna = s7bd[2]; se[5].target_size = 0;
                        snprintf(se[5].reason, sizeof(se[5].reason), "revoke-v3");
                        assert(fp_event_sign(&se[5], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[5], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/5.ev", s7ev); write_bytes_file(rp, eb, el); free(eb);

                        se[6].action = FP_ACTION_INSTALL; se[6].repo_id = nrid; se[6].serial = 6;
                        se[6].prev_event_hash = se[5].event_hash; se[6].timestamp_unix = now; se[6].expires_unix = now + 3600;
                        se[6].target_dna = s7bd[3]; se[6].target_size = s7bsz[3];
                        assert(fp_event_sign(&se[6], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[6], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/6.ev", s7ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", s7st); write_bytes_file(rp, eb, el); free(eb);

                        assert(fp_agent_sync_once(&s7acfg, &rep) == FP_ERR_POLICY);
                        assert(rep.outcome == FP_AGENT_REVOKED && rep.active_serial == 0);
                        assert(lstat(s7cur, &st_chk) != 0 && lstat(s7rev, &st_chk) == 0);
                        assert(fp_sql_open(s7dst, &s7d) == FP_OK);
                        uint64_t pseq7 = 0; char pdna7[65], v3_hex[65];
                        fp_hex_encode(s7bd[2].bytes, FP_DNA_LEN, v3_hex);
                        assert(fp_sql_get_progress(s7d, &pseq7, pdna7) == FP_OK && pseq7 == 4 && strcmp(pdna7, v3_hex) == 0);
                        assert(fp_sql_state_digest(s7d, "t7", &s7dig_now) == FP_OK && fp_dna_equal(&s7dig_now, &s7dig[2]));
                        fp_sql_close(s7d);

                        /* Now publish 7: INSTALL V5 (OK) -> MUST advance cleanly from (4, V3) -> V4(sql-only) -> V5(full) with exact digest! */
                        se[7].action = FP_ACTION_INSTALL; se[7].repo_id = nrid; se[7].serial = 7;
                        se[7].prev_event_hash = se[6].event_hash; se[7].timestamp_unix = now; se[7].expires_unix = now + 3600;
                        se[7].target_dna = s7bd[4]; se[7].target_size = s7bsz[4];
                        assert(fp_event_sign(&se[7], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[7], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/7.ev", s7ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", s7st); write_bytes_file(rp, eb, el); free(eb);

                        assert(fp_agent_sync_once(&s7acfg, &rep) == FP_OK && rep.outcome == FP_AGENT_UPDATED && rep.active_serial == 7);
                        assert(lstat(s7cur, &st_chk) == 0 && lstat(s7rev, &st_chk) != 0);
                        assert(fp_sql_open(s7dst, &s7d) == FP_OK);
                        assert(fp_sql_state_digest(s7d, "t7", &s7dig_now) == FP_OK && fp_dna_equal(&s7dig_now, &s7dig[4]));
                        fp_sql_close(s7d);
                        printf("[PASS] A7-P0-04 (REV-06): Failed V4 on revoked V3 reverted SQLite cleanly & V5 advanced without FP_ERR_CHAIN!\n");

                        /* TX-01 (A7-P0-05): LEDGER_PENDING with st.serial < ol.serial MUST NOT mutate state.bin when
                         * material invariants fail OR when a pending_events/<N>.ev file is missing! */
                        char pdir7[360], pev8[400], ota7[360], v5_hex[65];
                        fp_hex_encode(s7bd[4].bytes, FP_DNA_LEN, v5_hex);
                        snprintf(pdir7, sizeof(pdir7), "%s/pending_events", s7store);
                        (void)mkdir(pdir7, 0700);
                        /* Create signed event 8 (historical REVOKE of V1) and omit event 9 to test pre-validation! */
                        se[8].action = FP_ACTION_REVOKE; se[8].repo_id = nrid; se[8].serial = 8;
                        se[8].prev_event_hash = se[7].event_hash; se[8].timestamp_unix = now; se[8].expires_unix = now + 3600;
                        se[8].target_dna = s7bd[0]; se[8].target_size = 0;
                        snprintf(se[8].reason, sizeof(se[8].reason), "hist-v1");
                        assert(fp_event_sign(&se[8], &nrel) == FP_OK);
                        assert(fp_event_encode(&se[8], &eb, &el) == FP_OK);
                        snprintf(pev8, sizeof(pev8), "%s/8.ev", pdir7);
                        write_bytes_file(pev8, eb, el);
                        free(eb);

                        /* Case 1: Missing `current` with st.serial(7) < ol.serial(8) -> fails closed AND st.serial stays 7! */
                        assert(unlink(s7cur) == 0);
                        snprintf(ota7, sizeof(ota7), "%s/.sf_ota_state", s7target);
                        oln = snprintf(oline, sizeof(oline), "SFOTA1 LEDGER_PENDING 8 %s 1 %s 8 8\n", v5_hex, v5_hex);
                        write_bytes_file(ota7, (const uint8_t *)oline, (size_t)oln);
                        s7acfg.repo_url = "http://127.0.0.1:1";
                        assert(fp_agent_sync_once(&s7acfg, &rep) == FP_ERR_INTEGRITY);
                        fp_store_state_t st7;
                        assert(fp_store_load_state(s7store, &st7) == FP_OK && st7.serial == 7);

                        /* Case 2: Valid `current` -> gen/V5, but ol.serial=9 and 9.ev missing -> fails closed AND st.serial stays 7 (8.ev NOT committed)! */
                        snprintf(frel, sizeof(frel), "gen/%s", v5_hex);
                        assert(symlink(frel, s7cur) == 0);
                        oln = snprintf(oline, sizeof(oline), "SFOTA1 LEDGER_PENDING 9 %s 1 %s 8 9\n", v5_hex, v5_hex);
                        write_bytes_file(ota7, (const uint8_t *)oline, (size_t)oln);
                        assert(fp_agent_sync_once(&s7acfg, &rep) == FP_ERR_NOT_FOUND);
                        assert(fp_store_load_state(s7store, &st7) == FP_OK && st7.serial == 7);
                        assert(unlink(ota7) == 0 && unlink(pev8) == 0);
                        printf("[PASS] A7-P0-05 (TX-01): LEDGER_PENDING pre-validates invariants & full pending_events chain (zero state.bin drift)!\n");

                        /* A8-P0-05 (TX-02): Committed REVOKE V1(SQL) -> `!st.has_current` but SQLite still at V1!
                         * When V2(SQL) fails watchdog, SQLite MUST restore V1 (NOT wipe to empty!), then V3(SQL) succeeds! */
                        char t2repo[256], t2ev[300], t2ch[300], t2st[340], t2edge[256];
                        char t2store[300], t2target[300], t2root[300], t2src[300], t2dst[300];
                        char t2cur[360], t2rev[360], t2hcmd[512], t2ota[360];
                        snprintf(t2repo, sizeof(t2repo), "%s/t2_repo", a7dir);
                        snprintf(t2ev, sizeof(t2ev), "%s/events", t2repo);
                        snprintf(t2ch, sizeof(t2ch), "%s/channels", t2repo);
                        snprintf(t2st, sizeof(t2st), "%s/stable", t2ch);
                        snprintf(t2edge, sizeof(t2edge), "%s/t2_edge", a7dir);
                        snprintf(t2store, sizeof(t2store), "%s/store", t2edge);
                        snprintf(t2target, sizeof(t2target), "%s/live", t2edge);
                        snprintf(t2root, sizeof(t2root), "%s/root.fpr", t2edge);
                        snprintf(t2src, sizeof(t2src), "%s/t2_src.db", a7dir);
                        snprintf(t2dst, sizeof(t2dst), "%s/t2_dst.db", t2edge);
                        snprintf(t2cur, sizeof(t2cur), "%s/current", t2target);
                        snprintf(t2rev, sizeof(t2rev), "%s/.sf_revoked", t2target);
                        snprintf(t2ota, sizeof(t2ota), "%s/.sf_ota_state", t2target);
                        snprintf(t2hcmd, sizeof(t2hcmd), "grep -q 'OK=1' '%s/current/app.cfg'", t2target);
                        assert(mkdir(t2repo, 0755) == 0 && mkdir(t2ev, 0755) == 0 &&
                               mkdir(t2ch, 0755) == 0 && mkdir(t2st, 0755) == 0 && mkdir(t2edge, 0755) == 0);
                        assert(fp_root_encode(&nr, &rb, &rl) == FP_OK);
                        write_bytes_file(t2root, rb, rl);
                        snprintf(rp, sizeof(rp), "%s/root.fpr", t2repo); write_bytes_file(rp, rb, rl); free(rb);

                        fp_sql_ctx_t *t2s = NULL, *t2d = NULL;
                        assert(fp_sql_open(t2src, &t2s) == FP_OK && fp_sql_open(t2dst, &t2d) == FP_OK);
                        assert(fp_sql_exec(t2s, "CREATE TABLE kv2(k TEXT PRIMARY KEY, v INTEGER);") == FP_OK);
                        assert(fp_sql_exec(t2d, "CREATE TABLE kv2(k TEXT PRIMARY KEY, v INTEGER);") == FP_OK);
                        fp_sql_close(t2d);

                        const char *t2sql[3] = {
                            "INSERT INTO kv2 VALUES ('A', 100);",
                            "INSERT INTO kv2 VALUES ('B', 200);",
                            "UPDATE kv2 SET v=300 WHERE k='A';"
                        };
                        const char *t2cfg[3] = { "OK=1\nV=1\n", "FAIL=1\nV=2\n", "OK=1\nV=3\n" };
                        fp_dna_t t2bd[3], t2dig[3];
                        uint64_t t2bsz[3];
                        for (int i = 0; i < 3; i++) {
                            uint8_t *cs = NULL; size_t csl = 0;
                            assert(fp_sql_capture_changeset(t2s, "kv2", t2sql[i], &cs, &csl) == FP_OK);
                            assert(fp_sql_state_digest(t2s, "kv2", &t2dig[i]) == FP_OK);
                            fp_bundle_t b;
                            memset(&b, 0, sizeof(b));
                            b.version = 1; b.entry_count = 2;
                            b.entries[0].role = FP_ROLE_FILE; b.entries[0].mode = 0644; b.entries[0].size = strlen(t2cfg[i]);
                            snprintf(b.entries[0].path, sizeof(b.entries[0].path), "app.cfg");
                            assert(fp_store_put_object(t2repo, (const uint8_t *)t2cfg[i], strlen(t2cfg[i]), &b.entries[0].dna) == FP_OK);
                            b.entries[1].role = FP_ROLE_SQLITE_CHANGESET; b.entries[1].size = csl;
                            snprintf(b.entries[1].path, sizeof(b.entries[1].path), "kv2");
                            assert(fp_store_put_object(t2repo, cs, csl, &b.entries[1].dna) == FP_OK);
                            free(cs);
                            assert(fp_bundle_pack(t2repo, &b, &t2bd[i]) == FP_OK);
                            assert(fp_store_has_object(t2repo, &t2bd[i], &t2bsz[i]));
                        }
                        fp_sql_close(t2s);

                        fp_event_t te[5];
                        memset(te, 0, sizeof(te));
                        te[1].action = FP_ACTION_INSTALL; te[1].repo_id = nrid; te[1].serial = 1;
                        te[1].timestamp_unix = now; te[1].expires_unix = now + 3600;
                        te[1].target_dna = t2bd[0]; te[1].target_size = t2bsz[0];
                        assert(fp_event_sign(&te[1], &nrel) == FP_OK);
                        assert(fp_event_encode(&te[1], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/1.ev", t2ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", t2st); write_bytes_file(rp, eb, el); free(eb);

                        srv.repo_dir = t2repo;
                        fp_agent_cfg_t t2acfg;
                        memset(&t2acfg, 0, sizeof(t2acfg));
                        t2acfg.device_id = "edge-t2"; t2acfg.repo_url = base_url; t2acfg.channel = "stable";
                        t2acfg.store_dir = t2store; t2acfg.target_dir = t2target; t2acfg.db_path = t2dst;
                        t2acfg.root_path = t2root; t2acfg.health_cmd = t2hcmd; t2acfg.health_timeout_sec = 5;
                        assert(fp_agent_sync_once(&t2acfg, &rep) == FP_OK && rep.active_serial == 1);

                        /* Event 2: REVOKE V1 committed (`st.has_current == 0`, SQLite stays at V1!) */
                        te[2].action = FP_ACTION_REVOKE; te[2].repo_id = nrid; te[2].serial = 2;
                        te[2].prev_event_hash = te[1].event_hash; te[2].timestamp_unix = now; te[2].expires_unix = now + 3600;
                        te[2].target_dna = t2bd[0]; te[2].target_size = 0;
                        snprintf(te[2].reason, sizeof(te[2].reason), "revoke-v1-keep-db");
                        assert(fp_event_sign(&te[2], &nrel) == FP_OK);
                        assert(fp_event_encode(&te[2], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/2.ev", t2ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", t2st); write_bytes_file(rp, eb, el); free(eb);
                        assert(fp_agent_sync_once(&t2acfg, &rep) == FP_OK && rep.outcome == FP_AGENT_REVOKED);
                        assert(lstat(t2cur, &st_chk) != 0);

                        /* Event 3: INSTALL V2(SQL, FAIL=1) -> fails watchdog, MUST restore SQLite to V1 (NOT wipe!) */
                        te[3].action = FP_ACTION_INSTALL; te[3].repo_id = nrid; te[3].serial = 3;
                        te[3].prev_event_hash = te[2].event_hash; te[3].timestamp_unix = now; te[3].expires_unix = now + 3600;
                        te[3].target_dna = t2bd[1]; te[3].target_size = t2bsz[1];
                        assert(fp_event_sign(&te[3], &nrel) == FP_OK);
                        assert(fp_event_encode(&te[3], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/3.ev", t2ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", t2st); write_bytes_file(rp, eb, el); free(eb);
                        assert(fp_agent_sync_once(&t2acfg, &rep) == FP_ERR_POLICY && rep.outcome == FP_AGENT_REVOKED);
                        assert(lstat(t2cur, &st_chk) != 0 && lstat(t2rev, &st_chk) == 0);
                        assert(fp_sql_open(t2dst, &t2d) == FP_OK);
                        fp_dna_t t2dig_now;
                        assert(fp_sql_state_digest(t2d, "kv2", &t2dig_now) == FP_OK && fp_dna_equal(&t2dig_now, &t2dig[0]));
                        fp_sql_close(t2d);

                        /* Event 4: INSTALL V3(SQL, UPDATE A=300, OK=1) -> succeeds cleanly with exact (V1+V2+V3)! */
                        te[4].action = FP_ACTION_INSTALL; te[4].repo_id = nrid; te[4].serial = 4;
                        te[4].prev_event_hash = te[3].event_hash; te[4].timestamp_unix = now; te[4].expires_unix = now + 3600;
                        te[4].target_dna = t2bd[2]; te[4].target_size = t2bsz[2];
                        assert(fp_event_sign(&te[4], &nrel) == FP_OK);
                        assert(fp_event_encode(&te[4], &eb, &el) == FP_OK);
                        snprintf(rp, sizeof(rp), "%s/4.ev", t2ev); write_bytes_file(rp, eb, el);
                        snprintf(rp, sizeof(rp), "%s/latest.ev", t2st); write_bytes_file(rp, eb, el); free(eb);
                        assert(fp_agent_sync_once(&t2acfg, &rep) == FP_OK && rep.outcome == FP_AGENT_UPDATED && rep.active_serial == 4);
                        assert(fp_sql_open(t2dst, &t2d) == FP_OK);
                        assert(fp_sql_state_digest(t2d, "kv2", &t2dig_now) == FP_OK && fp_dna_equal(&t2dig_now, &t2dig[2]));
                        fp_sql_close(t2d);

                        /* A8-P0-04 (REV-04) & A8-P1-03 (TX-05): Boot fence runs even with corrupted .sf_ota_state,
                         * AND invalid range `start > serial` in .sf_ota_state is rejected fail-closed! */
                        char t2v1h[65];
                        fp_hex_encode(t2bd[0].bytes, FP_DNA_LEN, t2v1h);
                        assert(unlink(t2cur) == 0);
                        snprintf(frel, sizeof(frel), "gen/%s", t2v1h);
                        assert(symlink(frel, t2cur) == 0);
                        oln = snprintf(oline, sizeof(oline), "SFOTA1 HEALTH_PENDING 4 %s 1 %s 9 4\n", t2v1h, t2v1h);
                        write_bytes_file(t2ota, (const uint8_t *)oline, (size_t)oln);
                        t2acfg.repo_url = "http://127.0.0.1:1";
                        assert(fp_agent_sync_once(&t2acfg, &rep) == FP_ERR_INTEGRITY); /* start=9 > serial=4 rejected! */
                        assert(lstat(t2cur, &st_chk) != 0); /* Boot fence STILL removed revoked `current` BEFORE journal fail! */
                        assert(unlink(t2ota) == 0);
                        printf("[PASS] A8-P0-04/05 & A8-P1-03 (TX-02/REV-04/TX-05): SQL baseline preserved across revoke+fail, boot fence before journal & strict parser!\n");
                    }
                }
            }
        }
    }

    srv.stop = 1;
    shutdown(lfd, SHUT_RDWR);
    close(lfd);
    pthread_join(th, NULL);
    printf("ALL PHASE 2 EDGE AGENT TESTS PASSED.\n");
    return 0;
}
