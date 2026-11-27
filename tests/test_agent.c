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

    /* Capture v3 relative to v1 (since v2 will be rolled back to v1!) */
    fp_sql_close(rdb);
    unlink(ref_db_p);
    assert(fp_sql_open(ref_db_p, &rdb) == FP_OK);
    assert(fp_sql_exec(rdb, schema) == FP_OK);
    assert(fp_sql_exec(rdb, "INSERT INTO settings(id,val) VALUES(1,'v1-healthy');") == FP_OK);
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

                /* R1 (Case 2 — Upgrade V1 -> [V2, V3] crashed after intermediate V2!):
                 * offline recovery MUST revert BOTH files AND SQLite back to V1 without FP_ERR_CHAIN! */
                assert(fp_bundle_apply(nstore, &nbdnas[0], ntarget, ndst, 1, 0) == FP_OK);
                assert(fp_bundle_apply(nstore, &nbdnas[1], ntarget, ndst, 2, 0) == FP_OK);
                fp_sql_close(ndst);
                oln = snprintf(oline, sizeof(oline), "SFOTA1 HEALTH_PENDING 3 %s 1 %s 2\n", h2, h0);
                write_bytes_file(notap, (const uint8_t *)oline, (size_t)oln);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(lstat(notap, &st_chk) != 0);
                assert(fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &ndigs[0]));
                /* Repeat offline recovery -> idempotent! */
                fp_sql_close(ndst);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &ndigs[0]));
                printf("[PASS] R1: Offline recovery from intermediate multi-step SQLite crashes (initial & upgrade) exact & idempotent\n");

                /* R3: Explicit rollback crash recovery (ROLLBACK_HEALTH_PENDING after V2->V1) */
                assert(fp_bundle_apply(nstore, &nbdnas[1], ntarget, ndst, 2, 0) == FP_OK);
                assert(fp_bundle_rollback(nstore, &nbdnas[1], &nbdnas[0], ntarget, ndst) == FP_OK);
                fp_sql_close(ndst);
                /* 3a: Healthy target V1 -> offline recovery validates V1 and clears journal (no FP_ERR_CHAIN!) */
                oln = snprintf(oline, sizeof(oline), "SFOTA1 ROLLBACK_HEALTH_PENDING 3 %s 1 %s 3\n", h0, h1);
                write_bytes_file(notap, (const uint8_t *)oline, (size_t)oln);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(lstat(notap, &st_chk) != 0);
                assert(lstat(ncur, &st_chk) == 0);
                assert(fp_sql_open(ndst_dbp, &ndst) == FP_OK);
                assert(fp_sql_state_digest(ndst, "kv", &ndig_now) == FP_OK && fp_dna_equal(&ndig_now, &ndigs[0]));
                fp_sql_close(ndst);
                /* 3b: Unhealthy rollback target -> offline recovery durably deactivates target & creates .sf_unhealthy */
                ncfg.health_cmd = "false";
                write_bytes_file(notap, (const uint8_t *)oline, (size_t)oln);
                (void)fp_agent_sync_once(&ncfg, &rep);
                assert(lstat(notap, &st_chk) != 0);
                assert(lstat(ncur, &st_chk) != 0 && lstat(nunh, &st_chk) == 0);
                printf("[PASS] R3: ROLLBACK_HEALTH_PENDING offline recovery converges (healthy->keep, unhealthy->deactivate)\n");

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
