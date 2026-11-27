#define _POSIX_C_SOURCE 200809L

#include "fp_agent.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static uint64_t now_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

const char *fp_agent_outcome_name(fp_agent_outcome_t o) {
    switch (o) {
        case FP_AGENT_UP_TO_DATE:  return "UP_TO_DATE";
        case FP_AGENT_UPDATED:     return "UPDATED";
        case FP_AGENT_ROLLED_BACK: return "ROLLED_BACK";
        case FP_AGENT_REVOKED:     return "REVOKED";
        case FP_AGENT_REJECTED:    return "REJECTED";
        default:                   return "UNKNOWN";
    }
}

static fp_err_t read_file_small(const char *path, size_t max_len,
                                uint8_t **out_buf, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return errno == ENOENT ? FP_ERR_NOT_FOUND : FP_ERR_IO;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size > max_len) {
        fclose(f);
        return FP_ERR_BOUNDS;
    }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = malloc(sz > 0 ? sz : 1u);
    if (!buf) { fclose(f); return FP_ERR_NOMEM; }
    if (sz > 0 && fread(buf, 1, sz, f) != sz) {
        free(buf); fclose(f); return FP_ERR_IO;
    }
    fclose(f);
    *out_buf = buf;
    *out_len = sz;
    return FP_OK;
}

static fp_err_t write_file_atomic(const char *path, const uint8_t *buf, size_t len) {
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return FP_ERR_BOUNDS;
    int fd = mkstemp(tmp);
    if (fd < 0) return FP_ERR_IO;
    size_t pos = 0;
    while (pos < len) {
        ssize_t w = write(fd, buf + pos, len - pos);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp); return FP_ERR_IO;
        }
        pos += (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return FP_ERR_IO; }
    close(fd);
    if (rename(tmp, path) != 0) { unlink(tmp); return FP_ERR_IO; }
    return FP_OK;
}

static uint64_t load_failed_serial(const char *store_dir) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/agent_failed_serial", store_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return (uint64_t)v;
}

static void save_failed_serial(const char *store_dir, uint64_t serial) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/agent_failed_serial", store_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return;
    if (serial == 0) { unlink(path); return; }
    char buf[32];
    int bl = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)serial);
    if (bl > 0) (void)write_file_atomic(path, (const uint8_t *)buf, (size_t)bl);
}

int fp_agent_run_health_check(const char *cmd, int timeout_sec) {
    if (!cmd || cmd[0] == '\0') return 0;
    if (timeout_sec <= 0) timeout_sec = 15;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        (void)setpgid(0, 0);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    uint64_t deadline = now_mono_ns() + (uint64_t)timeout_sec * 1000000000ull;
    for (;;) {
        int status = 0;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return -1;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (now_mono_ns() >= deadline) {
            (void)kill(-pid, SIGKILL);
            (void)kill(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            return -1;
        }
        struct timespec ts = { 0, 50000000L }; /* 50 ms poll */
        nanosleep(&ts, NULL);
    }
}

static fp_err_t fetch_object_hybrid(const fp_agent_cfg_t *cfg,
                                    const fp_dna_t *dna, uint64_t expected_size,
                                    int timeout_ms,
                                    uint64_t *io_http_dl, uint64_t *io_lan_dl,
                                    uint64_t *io_resumed) {
    if (fp_store_has_object(cfg->store_dir, dna, NULL)) {
        return FP_OK;
    }

    /* 1. Try encrypted LAN FP-NET peer FIRST (Delta/Merkle, saves WAN bandwidth!) */
    if (cfg->lan_peer_host && cfg->lan_peer_host[0] && cfg->lan_peer_port > 0 &&
        cfg->lan_peer_pk && cfg->device_kp) {
        fp_net_pull_cfg_t ncfg;
        memset(&ncfg, 0, sizeof(ncfg));
        ncfg.host = cfg->lan_peer_host;
        ncfg.port = cfg->lan_peer_port;
        ncfg.store_dir = cfg->store_dir;
        ncfg.client_kp = cfg->device_kp;
        ncfg.expected_srv_pk = cfg->lan_peer_pk;
        ncfg.target_dna = *dna;
        ncfg.io_timeout_ms = timeout_ms > 3000 ? 3000 : timeout_ms;
        ncfg.max_output = (size_t)UINT64_C(68719476736);

        fp_net_stats_t nst;
        memset(&nst, 0, sizeof(nst));
        if (fp_net_pull(&ncfg, &nst) == FP_OK) {
            *io_lan_dl += nst.wire_bytes;
            *io_resumed += nst.resumed_chunks * FP_CHUNK_SIZE;
            return FP_OK;
        }
        /* LAN peer unavailable or missing object -> fall back transparently to HTTP Range */
    }

    /* 2. HTTP/1.1 Range fallback with BLAKE3 DNA verification */
    char hex[65], url[1536];
    fp_hex_encode(dna->bytes, FP_DNA_LEN, hex);
    int n = snprintf(url, sizeof(url), "%s/repo/objects/%s", cfg->repo_url, hex);
    if (n < 0 || (size_t)n >= sizeof(url)) return FP_ERR_BOUNDS;

    uint64_t res = 0;
    fp_err_t err = fp_http_pull_object(url, cfg->store_dir, dna, expected_size, timeout_ms, &res);
    if (err != FP_OK) return err;
    *io_resumed += res;
    if (expected_size > res) *io_http_dl += (expected_size - res);
    return FP_OK;
}

static fp_err_t download_bundle_and_entries(const fp_agent_cfg_t *cfg,
                                            const fp_dna_t *bundle_dna,
                                            uint64_t bundle_size,
                                            int timeout_ms,
                                            uint64_t *io_downloaded,
                                            uint64_t *io_lan_dl,
                                            uint64_t *io_resumed) {
    fp_err_t err = fetch_object_hybrid(cfg, bundle_dna, bundle_size, timeout_ms,
                                       io_downloaded, io_lan_dl, io_resumed);
    if (err != FP_OK) return err;

    uint8_t *mbuf = NULL;
    size_t mlen = 0;
    err = fp_store_get_object(cfg->store_dir, bundle_dna, (16u << 20), &mbuf, &mlen);
    if (err != FP_OK) return err;

    fp_bundle_t b;
    err = fp_bundle_decode(mbuf, mlen, &b);
    free(mbuf);
    if (err != FP_OK) return err;

    for (uint16_t i = 0; i < b.entry_count; i++) {
        const fp_bundle_entry_t *e = &b.entries[i];
        err = fetch_object_hybrid(cfg, &e->dna, e->size, timeout_ms,
                                  io_downloaded, io_lan_dl, io_resumed);
        if (err != FP_OK) return err;
    }
    return FP_OK;
}

static int valid_channel_name(const char *ch) {
    if (!ch || ch[0] == '\0') return 0;
    size_t len = strnlen(ch, 33u);
    if (len == 0 || len > 32u) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = ch[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return 0;
    }
    return 1;
}

static void json_sanitize_str(const char *src, char *dst, size_t dst_cap) {
    if (!dst || dst_cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t ci = 0;
    for (size_t i = 0; src[i] && ci + 1u < dst_cap; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[ci++] = (c == '"' || c == '\\' || c < 0x20u || c == 0x7fu) ? ' ' : (char)c;
    }
    dst[ci] = '\0';
}

static void send_heartbeat_best_effort(const fp_agent_cfg_t *cfg, const fp_agent_report_t *rep) {
    if (!cfg->report_heartbeat) return;
    char url[1536];
    int n = snprintf(url, sizeof(url), "%s/api/v1/heartbeat", cfg->repo_url);
    if (n < 0 || (size_t)n >= sizeof(url)) return;

    char act_hex[65], att_hex[65];
    fp_hex_encode(rep->active_bundle_dna.bytes, FP_DNA_LEN, act_hex);
    fp_hex_encode(rep->attempted_bundle_dna.bytes, FP_DNA_LEN, att_hex);

    /* Sanitize ALL string fields for safe JSON encoding */
    char clean_dev[128], clean_ch[64], clean_detail[256];
    json_sanitize_str(cfg->device_id ? cfg->device_id : "edge-node", clean_dev, sizeof(clean_dev));
    json_sanitize_str(cfg->channel ? cfg->channel : "stable", clean_ch, sizeof(clean_ch));
    json_sanitize_str(rep->detail, clean_detail, sizeof(clean_detail));

    char body[1536];
    int bl = snprintf(body, sizeof(body),
                      "{\"device_id\":\"%s\",\"channel\":\"%s\",\"outcome\":\"%s\","
                      "\"active_serial\":%llu,\"active_dna\":\"%s\","
                      "\"attempted_serial\":%llu,\"attempted_dna\":\"%s\","
                      "\"root_version\":%llu,\"health_exit\":%d,"
                      "\"bytes_downloaded\":%llu,\"bytes_from_lan\":%llu,\"bytes_resumed\":%llu,"
                      "\"elapsed_ms\":%.2f,\"detail\":\"%s\"}",
                      clean_dev, clean_ch,
                      fp_agent_outcome_name(rep->outcome),
                      (unsigned long long)rep->active_serial, act_hex,
                      (unsigned long long)rep->attempted_serial, att_hex,
                      (unsigned long long)rep->root_version, rep->health_exit_code,
                      (unsigned long long)rep->bytes_downloaded,
                      (unsigned long long)rep->bytes_from_lan,
                      (unsigned long long)rep->bytes_resumed,
                      (double)rep->elapsed_ns / 1e6, clean_detail);
    if (bl > 0 && (size_t)bl < sizeof(body)) {
        int status = 0;
        (void)fp_http_post_json_signed(url, body, cfg->device_kp,
                                       cfg->io_timeout_ms > 0 ? cfg->io_timeout_ms : 5000,
                                       &status);
    }
}

fp_err_t fp_agent_sync_once(const fp_agent_cfg_t *cfg, fp_agent_report_t *out_report) {
    if (!cfg || !cfg->repo_url || !cfg->store_dir || !cfg->target_dir || !cfg->root_path) {
        return FP_ERR_INVALID;
    }
    uint64_t t0 = now_mono_ns();
    int timeout_ms = cfg->io_timeout_ms > 0 ? cfg->io_timeout_ms : 10000;
    const char *channel = (cfg->channel && cfg->channel[0]) ? cfg->channel : "stable";
    if (!valid_channel_name(channel)) {
        return FP_ERR_INVALID;
    }

    fp_agent_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.outcome = FP_AGENT_REJECTED;

    /* 1. Load & verify pinned local Root Multi-Sig (FPR1) */
    uint8_t *rbuf = NULL;
    size_t rlen = 0;
    fp_err_t err = read_file_small(cfg->root_path, (1u << 20), &rbuf, &rlen);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "cannot load pinned root.fpr (%s)", fp_strerror(err));
        goto done;
    }
    fp_root_doc_t root;
    err = fp_root_decode(rbuf, rlen, &root);
    free(rbuf);
    uint64_t now_unix = (uint64_t)time(NULL);
    if (err == FP_OK) err = fp_root_verify_self(&root, now_unix);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "pinned root.fpr invalid (%s)", fp_strerror(err));
        goto done;
    }
    rep.root_version = root.root_version;

    /* 2. Check remote root.fpr for verified Multi-Sig Root rotation */
    {
        char rurl[1536];
        snprintf(rurl, sizeof(rurl), "%s/repo/root.fpr", cfg->repo_url);
        fp_http_resp_t hresp;
        if (fp_http_get(rurl, (1u << 20), timeout_ms, &hresp) == FP_OK) {
            if (hresp.status_code == 200 && hresp.body_len > 0) {
                fp_root_doc_t remote_root;
                if (fp_root_decode(hresp.body, hresp.body_len, &remote_root) == FP_OK &&
                    remote_root.root_version > root.root_version) {
                    if (fp_root_verify_rotation(&root, &remote_root, now_unix) == FP_OK) {
                        if (write_file_atomic(cfg->root_path, hresp.body, hresp.body_len) == FP_OK) {
                            root = remote_root;
                            rep.root_version = root.root_version;
                        }
                    } else {
                        fp_http_resp_free(&hresp);
                        err = FP_ERR_SIGNATURE;
                        snprintf(rep.detail, sizeof(rep.detail), "rejected untrusted remote root rotation");
                        goto done;
                    }
                }
            }
            fp_http_resp_free(&hresp);
        }
    }

    /* 3. Load current local Store state */
    fp_store_state_t st;
    err = fp_store_load_state(cfg->store_dir, &st);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "store state load failed (%s)", fp_strerror(err));
        goto done;
    }
    rep.active_serial = st.serial;
    rep.active_bundle_dna = st.current_dna;

    /* 4. Fetch latest signed release event for this device's channel */
    char ev_url[1536];
    snprintf(ev_url, sizeof(ev_url), "%s/repo/channels/%s/latest.ev", cfg->repo_url, channel);
    fp_http_resp_t ev_resp;
    err = fp_http_get(ev_url, (1u << 20), timeout_ms, &ev_resp);
    if (err != FP_OK || ev_resp.status_code == 404) {
        fp_http_resp_free(&ev_resp);
        snprintf(ev_url, sizeof(ev_url), "%s/repo/latest.ev", cfg->repo_url);
        err = fp_http_get(ev_url, (1u << 20), timeout_ms, &ev_resp);
    }
    if (err != FP_OK || ev_resp.status_code != 200) {
        fp_http_resp_free(&ev_resp);
        err = (err != FP_OK) ? err : FP_ERR_NOT_FOUND;
        snprintf(rep.detail, sizeof(rep.detail), "failed to fetch latest.ev");
        goto done;
    }

    fp_event_t latest_ev;
    err = fp_event_decode(ev_resp.body, ev_resp.body_len, &latest_ev);
    fp_http_resp_free(&ev_resp);
    if (err == FP_OK) err = fp_event_verify_with_root(&latest_ev, &root, now_unix);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "rejected invalid/untrusted latest.ev (%s)", fp_strerror(err));
        goto done;
    }

    rep.attempted_serial = latest_ev.serial;
    rep.attempted_bundle_dna = latest_ev.target_dna;

    if (latest_ev.serial <= st.serial) {
        rep.outcome = FP_AGENT_UP_TO_DATE;
        snprintf(rep.detail, sizeof(rep.detail), "up to date at serial %llu", (unsigned long long)st.serial);
        err = FP_OK;
        goto done;
    }

    uint64_t failed_serial = load_failed_serial(cfg->store_dir);
    if (latest_ev.serial == failed_serial) {
        rep.outcome = FP_AGENT_ROLLED_BACK;
        snprintf(rep.detail, sizeof(rep.detail), "skipping previously failed serial %llu",
                 (unsigned long long)failed_serial);
        err = FP_OK;
        goto done;
    }

    /* 5. Build & verify full signed event chain from (st.serial + 1) .. latest_ev.serial */
    uint64_t chain_len = latest_ev.serial - st.serial;
    if (chain_len > 64u) {
        err = FP_ERR_BOUNDS;
        snprintf(rep.detail, sizeof(rep.detail), "event chain gap too large (%llu)", (unsigned long long)chain_len);
        goto done;
    }
    fp_event_t *chain = calloc((size_t)chain_len, sizeof(fp_event_t));
    if (!chain) { err = FP_ERR_NOMEM; goto done; }

    fp_dna_t expected_prev = st.last_event_hash;
    for (uint64_t i = 0; i < chain_len; i++) {
        uint64_t s = st.serial + 1u + i;
        if (s == latest_ev.serial) {
            chain[i] = latest_ev;
        } else {
            char curl[1536];
            snprintf(curl, sizeof(curl), "%s/repo/events/%llu.ev", cfg->repo_url, (unsigned long long)s);
            fp_http_resp_t cr;
            err = fp_http_get(curl, (1u << 20), timeout_ms, &cr);
            if (err != FP_OK || cr.status_code != 200) {
                fp_http_resp_free(&cr);
                free(chain);
                err = FP_ERR_CHAIN;
                snprintf(rep.detail, sizeof(rep.detail), "missing intermediate event %llu", (unsigned long long)s);
                goto done;
            }
            err = fp_event_decode(cr.body, cr.body_len, &chain[i]);
            fp_http_resp_free(&cr);
            if (err == FP_OK) err = fp_event_verify_with_root(&chain[i], &root, now_unix);
            if (err != FP_OK) {
                free(chain);
                snprintf(rep.detail, sizeof(rep.detail), "invalid intermediate event %llu (%s)",
                         (unsigned long long)s, fp_strerror(err));
                goto done;
            }
        }
        if (chain[i].serial != s || !fp_dna_equal(&chain[i].prev_event_hash, &expected_prev)) {
            free(chain);
            err = FP_ERR_CHAIN;
            snprintf(rep.detail, sizeof(rep.detail), "broken hash chain at serial %llu", (unsigned long long)s);
            goto done;
        }
        expected_prev = chain[i].event_hash;
    }

    /* 6. Handle REVOKE action immediately */
    if (latest_ev.action == FP_ACTION_REVOKE) {
        for (uint64_t i = 0; i < chain_len; i++) {
            if (chain[i].action != FP_ACTION_REVOKE) {
                /* Ensure bundle manifest exists so store chain advances cleanly */
                char h[65], u[1536];
                fp_hex_encode(chain[i].target_dna.bytes, FP_DNA_LEN, h);
                snprintf(u, sizeof(u), "%s/repo/objects/%s", cfg->repo_url, h);
                uint64_t r = 0;
                (void)fp_http_pull_object(u, cfg->store_dir, &chain[i].target_dna, chain[i].target_size, timeout_ms, &r);
            }
            err = fp_store_apply_event_with_root(cfg->store_dir, &chain[i], &root, now_unix, NULL, 0);
            if (err != FP_OK) { free(chain); snprintf(rep.detail, sizeof(rep.detail), "revoke apply failed"); goto done; }
        }
        free(chain);
        save_failed_serial(cfg->store_dir, 0);
        rep.outcome = FP_AGENT_REVOKED;
        rep.active_serial = latest_ev.serial;
        memset(&rep.active_bundle_dna, 0, sizeof(rep.active_bundle_dna));
        snprintf(rep.detail, sizeof(rep.detail), "revoked DNA per serial %llu", (unsigned long long)latest_ev.serial);
        err = FP_OK;
        goto done;
    }

    /* 7. Download target Particle Bundle + all missing payload objects (LAN FP-NET -> HTTP Range) */
    err = download_bundle_and_entries(cfg, &latest_ev.target_dna, latest_ev.target_size,
                                      timeout_ms, &rep.bytes_downloaded, &rep.bytes_from_lan,
                                      &rep.bytes_resumed);
    if (err != FP_OK) {
        free(chain);
        snprintf(rep.detail, sizeof(rep.detail), "artifact download/verify failed (%s)", fp_strerror(err));
        goto done;
    }

    /* Also ensure any intermediate chain manifest objects are resident before commit */
    for (uint64_t i = 0; i + 1 < chain_len; i++) {
        if (chain[i].action != FP_ACTION_REVOKE &&
            !fp_store_has_object(cfg->store_dir, &chain[i].target_dna, NULL)) {
            char h[65], u[1536];
            fp_hex_encode(chain[i].target_dna.bytes, FP_DNA_LEN, h);
            snprintf(u, sizeof(u), "%s/repo/objects/%s", cfg->repo_url, h);
            uint64_t r = 0;
            err = fp_http_pull_object(u, cfg->store_dir, &chain[i].target_dna,
                                      chain[i].target_size, timeout_ms, &r);
            if (err != FP_OK) {
                free(chain);
                snprintf(rep.detail, sizeof(rep.detail), "intermediate manifest fetch failed");
                goto done;
            }
        }
    }

    /* 8. Open optional SQLite DB & apply Particle Bundle atomically */
    fp_sql_ctx_t *sql = NULL;
    if (cfg->db_path && cfg->db_path[0]) {
        err = fp_sql_open(cfg->db_path, &sql);
        if (err != FP_OK) {
            free(chain);
            snprintf(rep.detail, sizeof(rep.detail), "cannot open SQLite DB (%s)", fp_strerror(err));
            goto done;
        }
    }

    err = fp_bundle_apply(cfg->store_dir, &latest_ev.target_dna, cfg->target_dir,
                          sql, latest_ev.serial, 0);
    if (err != FP_OK) {
        fp_sql_close(sql);
        free(chain);
        snprintf(rep.detail, sizeof(rep.detail), "bundle apply failed (%s)", fp_strerror(err));
        goto done;
    }

    /* 9. Run Application Health-Check with Watchdog -> AUTO-ROLLBACK ON FAILURE! */
    int hrc = fp_agent_run_health_check(cfg->health_cmd, cfg->health_timeout_sec);
    rep.health_exit_code = hrc;
    if (hrc != 0) {
        if (st.has_current) {
            fp_err_t rerr = fp_bundle_rollback(cfg->store_dir, &latest_ev.target_dna,
                                               &st.current_dna, cfg->target_dir, sql);
            if (rerr == FP_OK) {
                snprintf(rep.detail, sizeof(rep.detail),
                         "health-check failed (exit=%d) on serial %llu -> auto-rolled back to serial %llu",
                         hrc, (unsigned long long)latest_ev.serial, (unsigned long long)st.serial);
            } else {
                snprintf(rep.detail, sizeof(rep.detail),
                         "health-check failed (exit=%d), rollback error (%s)", hrc, fp_strerror(rerr));
            }
        } else {
            snprintf(rep.detail, sizeof(rep.detail),
                     "initial health-check failed (exit=%d) on serial %llu",
                     hrc, (unsigned long long)latest_ev.serial);
        }
        fp_sql_close(sql);
        free(chain);
        save_failed_serial(cfg->store_dir, latest_ev.serial);
        rep.outcome = FP_AGENT_ROLLED_BACK;
        rep.active_serial = st.serial;
        rep.active_bundle_dna = st.current_dna;
        err = FP_OK;
        goto done;
    }
    fp_sql_close(sql);

    /* 10. Health-check PASSED -> commit full verified event chain atomically to Store */
    for (uint64_t i = 0; i < chain_len; i++) {
        err = fp_store_apply_event_with_root(cfg->store_dir, &chain[i], &root, now_unix, NULL, 0);
        if (err != FP_OK) {
            uint64_t bad_s = chain[i].serial;
            free(chain);
            snprintf(rep.detail, sizeof(rep.detail), "store state commit failed at serial %llu (%s)",
                     (unsigned long long)bad_s, fp_strerror(err));
            goto done;
        }
    }
    free(chain);
    save_failed_serial(cfg->store_dir, 0);

    rep.outcome = FP_AGENT_UPDATED;
    rep.active_serial = latest_ev.serial;
    rep.active_bundle_dna = latest_ev.target_dna;
    snprintf(rep.detail, sizeof(rep.detail),
             "updated cleanly to serial %llu (health=0, root_v=%llu)",
             (unsigned long long)latest_ev.serial, (unsigned long long)root.root_version);
    err = FP_OK;

done:
    rep.elapsed_ns = now_mono_ns() - t0;
    send_heartbeat_best_effort(cfg, &rep);
    if (out_report) *out_report = rep;
    return err;
}
