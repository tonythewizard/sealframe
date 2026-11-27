#define _POSIX_C_SOURCE 200809L

#include "fp_agent.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
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
        case FP_AGENT_UP_TO_DATE:             return "UP_TO_DATE";
        case FP_AGENT_UPDATED:                return "UPDATED";
        case FP_AGENT_ROLLED_BACK:            return "ROLLED_BACK";
        case FP_AGENT_REVOKED:                return "REVOKED";
        case FP_AGENT_REJECTED:               return "REJECTED";
        case FP_AGENT_ROLLBACK_FAILED:        return "ROLLBACK_FAILED";
        case FP_AGENT_INITIAL_INSTALL_FAILED: return "INITIAL_INSTALL_FAILED";
        default:                              return "UNKNOWN";
    }
}

static fp_err_t sync_parent_dir(const char *path) {
    if (!path || !path[0]) return FP_ERR_INVALID;
    char dir[PATH_MAX];
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(dir, sizeof(dir), ".");
    } else if (slash == path) {
        snprintf(dir, sizeof(dir), "/");
    } else {
        size_t dlen = (size_t)(slash - path);
        if (dlen >= sizeof(dir)) return FP_ERR_BOUNDS;
        memcpy(dir, path, dlen);
        dir[dlen] = '\0';
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return FP_ERR_IO;
    int rc = fsync(dfd);
    close(dfd);
    return rc == 0 ? FP_OK : FP_ERR_IO;
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
    return sync_parent_dir(path);
}

static fp_err_t deactivate_live_target(const char *target_dir, const char *marker_name,
                                       const char *marker_text) {
    if (!target_dir || !target_dir[0]) return FP_ERR_INVALID;
    char cur[PATH_MAX];
    int n = snprintf(cur, sizeof(cur), "%s/current", target_dir);
    if (n < 0 || (size_t)n >= sizeof(cur)) return FP_ERR_BOUNDS;
    int unlinked = 0;
    if (unlink(cur) == 0) {
        unlinked = 1;
    } else if (errno != ENOENT) {
        return FP_ERR_IO;
    }
    if (unlinked) {
        fp_err_t serr = sync_parent_dir(cur);
        if (serr != FP_OK) return serr;
    }
    if (marker_name && marker_name[0]) {
        char mpath[PATH_MAX];
        n = snprintf(mpath, sizeof(mpath), "%s/%s", target_dir, marker_name);
        if (n < 0 || (size_t)n >= sizeof(mpath)) return FP_ERR_BOUNDS;
        const char *body = marker_text ? marker_text : "deactivated\n";
        fp_err_t werr = write_file_atomic(mpath, (const uint8_t *)body, strlen(body));
        if (werr != FP_OK) return werr;
    }
    return FP_OK;
}

static void clear_revoked_marker(const char *target_dir) {
    if (!target_dir || !target_dir[0]) return;
    char mpath[PATH_MAX];
    int n = snprintf(mpath, sizeof(mpath), "%s/.sf_revoked", target_dir);
    if (n > 0 && (size_t)n < sizeof(mpath)) {
        if (unlink(mpath) == 0) (void)sync_parent_dir(mpath);
    }
}

/* P0-06: End-to-end OTA transaction lock (strict ordering: .sf_agent_tx.lock -> .sf_lifecycle.lock -> store .lock) */
static int acquire_agent_tx_lock(const char *target_dir) {
    if (!target_dir || !target_dir[0]) return -1;
    (void)mkdir(target_dir, 0755);
    char lpath[PATH_MAX];
    if (snprintf(lpath, sizeof(lpath), "%s/.sf_agent_tx.lock", target_dir) >= (int)sizeof(lpath)) {
        return -1;
    }
    int fd = open(lpath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    while (flock(fd, LOCK_EX) != 0) {
        if (errno == EINTR) continue;
        close(fd);
        return -1;
    }
    return fd;
}

static void release_agent_tx_lock(int fd) {
    if (fd >= 0) {
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
}

/* SEC-05: Serialized (flock) + durable monotonic heartbeat sequence; returns 0 on persistence failure */
static uint64_t next_heartbeat_seq(const char *store_dir) {
    if (!store_dir || !store_dir[0]) return 0;
    (void)mkdir(store_dir, 0700);
    char lpath[PATH_MAX], path[PATH_MAX];
    int nl = snprintf(lpath, sizeof(lpath), "%s/.agent_hb.lock", store_dir);
    int np = snprintf(path, sizeof(path), "%s/agent_hb_seq", store_dir);
    if (nl < 0 || (size_t)nl >= sizeof(lpath) || np < 0 || (size_t)np >= sizeof(path)) return 0;

    int lfd = open(lpath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lfd < 0) return 0;
    while (flock(lfd, LOCK_EX) != 0) {
        if (errno == EINTR) continue;
        close(lfd);
        return 0;
    }

    unsigned long long seq = 0;
    FILE *f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%llu", &seq) != 1) seq = 0;
        fclose(f);
    }
    if (seq == UINT64_MAX) {
        (void)flock(lfd, LOCK_UN); close(lfd);
        return 0;
    }
    seq++;
    char buf[32];
    int bl = snprintf(buf, sizeof(buf), "%llu\n", seq);
    fp_err_t werr = (bl > 0) ? write_file_atomic(path, (const uint8_t *)buf, (size_t)bl) : FP_ERR_BOUNDS;
    (void)flock(lfd, LOCK_UN);
    close(lfd);
    return (werr == FP_OK) ? (uint64_t)seq : 0;
}

/* V-03: Persist failed serial AND whether a prior healthy generation existed (`had_prev`) */
static uint64_t load_failed_serial(const char *store_dir, int *out_had_prev) {
    if (out_had_prev) *out_had_prev = 1;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/agent_failed_serial", store_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    int hp = 1;
    int got = fscanf(f, "%llu %d", &v, &hp);
    fclose(f);
    if (got < 1) return 0;
    if (out_had_prev) *out_had_prev = (got >= 2) ? (hp ? 1 : 0) : 1;
    return (uint64_t)v;
}

static void save_failed_serial(const char *store_dir, uint64_t serial, int had_prev) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/agent_failed_serial", store_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return;
    if (serial == 0) {
        if (unlink(path) == 0) sync_parent_dir(path);
        return;
    }
    char buf[48];
    int bl = snprintf(buf, sizeof(buf), "%llu %d\n", (unsigned long long)serial, had_prev ? 1 : 0);
    if (bl > 0) (void)write_file_atomic(path, (const uint8_t *)buf, (size_t)bl);
}

/* P1-04: Dynamic verified historical root chain (supports 64+ rotations; verifies continuity up to active_root) */
typedef struct {
    fp_root_doc_t *items;
    size_t         count;
    size_t         cap;
} root_vec_t;

static void root_vec_free(root_vec_t *v) {
    if (!v) return;
    free(v->items);
    v->items = NULL;
    v->count = 0;
    v->cap = 0;
}

static fp_err_t root_vec_push_unique(root_vec_t *v, const fp_root_doc_t *rd) {
    for (size_t i = 0; i < v->count; i++) {
        if (v->items[i].root_version == rd->root_version) return FP_OK;
    }
    if (v->count == v->cap) {
        size_t nc = v->cap ? v->cap * 2u : 16u;
        fp_root_doc_t *ni = realloc(v->items, nc * sizeof(*ni));
        if (!ni) return FP_ERR_NOMEM;
        v->items = ni;
        v->cap = nc;
    }
    v->items[v->count++] = *rd;
    return FP_OK;
}

static void persist_hist_root(const char *store_dir, uint64_t ver, const uint8_t *raw, size_t len) {
    if (!store_dir || !raw || len == 0) return;
    char rdir[PATH_MAX], rpath[PATH_MAX];
    if (snprintf(rdir, sizeof(rdir), "%s/roots", store_dir) >= (int)sizeof(rdir)) return;
    (void)mkdir(store_dir, 0700);
    (void)mkdir(rdir, 0700);
    if (snprintf(rpath, sizeof(rpath), "%s/%llu.fpr", rdir, (unsigned long long)ver) >= (int)sizeof(rpath)) return;
    (void)write_file_atomic(rpath, raw, len);
}

/* Load ONLY historical roots cryptographically chained via fp_root_verify_rotation() ending at active_root! */
static fp_err_t load_verified_hist_roots(const char *store_dir, const fp_root_doc_t *active_root,
                                         root_vec_t *out_vec) {
    memset(out_vec, 0, sizeof(*out_vec));
    if (!active_root) return FP_ERR_INVALID;
    if (!store_dir || active_root->root_version <= 1u) {
        return root_vec_push_unique(out_vec, active_root);
    }

    /* Walk backward from active_root->root_version - 1 down to 1: keep only contiguous valid rotation steps! */
    root_vec_t rev;
    memset(&rev, 0, sizeof(rev));
    fp_err_t err = root_vec_push_unique(&rev, active_root);
    if (err != FP_OK) return err;

    fp_root_doc_t cur_child = *active_root;
    for (uint64_t v = active_root->root_version - 1u; v >= 1u; v--) {
        char rpath[PATH_MAX];
        if (snprintf(rpath, sizeof(rpath), "%s/roots/%llu.fpr", store_dir, (unsigned long long)v) >= (int)sizeof(rpath)) {
            break;
        }
        uint8_t *buf = NULL;
        size_t len = 0;
        if (read_file_small(rpath, (1u << 20), &buf, &len) != FP_OK) break;
        fp_root_doc_t cand;
        int ok = (fp_root_decode(buf, len, &cand) == FP_OK &&
                  cand.root_version == v &&
                  fp_dna_equal(&cand.repo_id, &active_root->repo_id) &&
                  fp_root_verify_self(&cand, 0) == FP_OK &&
                  fp_root_verify_rotation(&cand, &cur_child, 0) == FP_OK);
        free(buf);
        if (!ok) break; /* Tampered/forged local root file breaks chain immediately! */
        err = root_vec_push_unique(&rev, &cand);
        if (err != FP_OK) { root_vec_free(&rev); return err; }
        cur_child = cand;
        if (v == 1u) break;
    }

    /* Emit in ascending version order (oldest -> active_root) */
    for (size_t i = rev.count; i > 0; i--) {
        err = root_vec_push_unique(out_vec, &rev.items[i - 1u]);
        if (err != FP_OK) { root_vec_free(&rev); root_vec_free(out_vec); return err; }
    }
    root_vec_free(&rev);
    return FP_OK;
}

/* Unified fail-closed OTA lifecycle parser + offline idempotent recovery (P0-01, P0-02, P0-03, P1-02) */
typedef enum {
    OTA_ST_NONE      = 0,
    OTA_ST_VALID     = 1,
    OTA_ST_CORRUPTED = 2,
    OTA_ST_IO        = 3
} ota_parse_status_t;

typedef struct {
    char     state[32];
    uint64_t serial;
    uint64_t start_serial;
    char     new_hex[65];
    int      has_prev;
    char     prev_hex[65];
} ota_lifecycle_t;

static int is_hex64_str(const char *s) {
    if (!s || strlen(s) != 64u) return 0;
    for (size_t i = 0; i < 64u; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static fp_err_t write_ota_lifecycle(const char *target_dir, const char *state, uint64_t serial,
                                    uint64_t start_serial, const fp_dna_t *new_dna,
                                    int has_prev, const fp_dna_t *prev_dna) {
    (void)mkdir(target_dir, 0755);
    char path[PATH_MAX], nh[65], ph[65], line[288];
    if (snprintf(path, sizeof(path), "%s/.sf_ota_state", target_dir) >= (int)sizeof(path)) return FP_ERR_BOUNDS;
    fp_hex_encode(new_dna->bytes, FP_DNA_LEN, nh);
    fp_hex_encode(prev_dna->bytes, FP_DNA_LEN, ph);
    int ln = snprintf(line, sizeof(line), "SFOTA1 %s %llu %s %d %s %llu\n",
                      state, (unsigned long long)serial, nh, has_prev ? 1 : 0, ph,
                      (unsigned long long)start_serial);
    if (ln <= 0 || (size_t)ln >= sizeof(line)) return FP_ERR_BOUNDS;
    return write_file_atomic(path, (const uint8_t *)line, (size_t)ln);
}

static fp_err_t clear_ota_lifecycle(const char *target_dir) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/.sf_ota_state", target_dir) >= (int)sizeof(path)) return FP_ERR_BOUNDS;
    if (unlink(path) == 0) return sync_parent_dir(path);
    return errno == ENOENT ? FP_OK : FP_ERR_IO;
}

static ota_parse_status_t parse_ota_lifecycle(const char *target_dir, ota_lifecycle_t *out) {
    memset(out, 0, sizeof(*out));
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/.sf_ota_state", target_dir) >= (int)sizeof(path)) {
        return OTA_ST_IO;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? OTA_ST_NONE : OTA_ST_IO;
    char buf[384];
    ssize_t n = read(fd, buf, sizeof(buf) - 1u);
    close(fd);
    if (n <= 0 || (size_t)n >= sizeof(buf) - 1u) return OTA_ST_CORRUPTED;
    buf[n] = '\0';

    char magic[16], extra[16];
    unsigned long long oseq = 0, sseq = 0;
    int got = sscanf(buf, "%15s %31s %llu %64s %d %64s %llu %15s",
                     magic, out->state, &oseq, out->new_hex, &out->has_prev, out->prev_hex, &sseq, extra);
    if (got != 6 && got != 7) return OTA_ST_CORRUPTED;
    if (strcmp(magic, "SFOTA1") != 0 || oseq == 0) return OTA_ST_CORRUPTED;
    if (strcmp(out->state, "HEALTH_PENDING") != 0 &&
        strcmp(out->state, "ROLLBACK_HEALTH_PENDING") != 0 &&
        strcmp(out->state, "LEDGER_PENDING") != 0) {
        return OTA_ST_CORRUPTED;
    }
    if ((out->has_prev != 0 && out->has_prev != 1) ||
        !is_hex64_str(out->new_hex) || !is_hex64_str(out->prev_hex)) {
        return OTA_ST_CORRUPTED;
    }
    out->serial = (uint64_t)oseq;
    out->start_serial = (got == 7) ? (uint64_t)sseq : (uint64_t)oseq;
    return OTA_ST_VALID;
}

static int read_current_gen_hex(const char *target_dir, char out_hex[65]) {
    out_hex[0] = '\0';
    char link_p[PATH_MAX], raw[PATH_MAX];
    if (snprintf(link_p, sizeof(link_p), "%s/current", target_dir) >= (int)sizeof(link_p)) return 0;
    ssize_t rl = readlink(link_p, raw, sizeof(raw) - 1u);
    if (rl <= 0) return 0;
    raw[rl] = '\0';
    const char *slash = strrchr(raw, '/');
    const char *base = slash ? slash + 1 : raw;
    if (!is_hex64_str(base)) return 0;
    memcpy(out_hex, base, 65);
    return 1;
}

static fp_err_t persist_pending_events(const char *store_dir, const fp_event_t *chain, uint64_t chain_len) {
    char pdir[PATH_MAX], ppath[PATH_MAX];
    if (snprintf(pdir, sizeof(pdir), "%s/pending_events", store_dir) >= (int)sizeof(pdir)) return FP_ERR_BOUNDS;
    (void)mkdir(store_dir, 0700);
    if (mkdir(pdir, 0700) != 0 && errno != EEXIST) return FP_ERR_IO;
    for (uint64_t i = 0; i < chain_len; i++) {
        if (snprintf(ppath, sizeof(ppath), "%s/%llu.ev", pdir, (unsigned long long)chain[i].serial) >= (int)sizeof(ppath)) {
            return FP_ERR_BOUNDS;
        }
        uint8_t *eb = NULL;
        size_t el = 0;
        fp_err_t err = fp_event_encode(&chain[i], &eb, &el);
        if (err != FP_OK) return err;
        err = write_file_atomic(ppath, eb, el);
        free(eb);
        if (err != FP_OK) return err;
    }
    return FP_OK;
}

static void cleanup_pending_events(const char *store_dir, uint64_t start_serial, uint64_t end_serial) {
    if (!store_dir || start_serial == 0 || end_serial < start_serial) return;
    char ppath[PATH_MAX];
    for (uint64_t s = start_serial; s <= end_serial; s++) {
        if (snprintf(ppath, sizeof(ppath), "%s/pending_events/%llu.ev",
                     store_dir, (unsigned long long)s) < (int)sizeof(ppath)) {
            (void)unlink(ppath);
        }
    }
}

static fp_err_t recover_ota_lifecycle_offline(const fp_agent_cfg_t *cfg) {
    /* 1. Resume any interrupted REVOKE deactivation BEFORE checking remote serials (P0-04) */
    char rpend[PATH_MAX];
    if (snprintf(rpend, sizeof(rpend), "%s/.sf_revoke_pending", cfg->target_dir) < (int)sizeof(rpend)) {
        struct stat rsb;
        if (lstat(rpend, &rsb) == 0) {
            fp_err_t derr = deactivate_live_target(cfg->target_dir, ".sf_revoked", "REVOKED_RECOVERED=1\n");
            if (derr != FP_OK) return derr;
            if (unlink(rpend) != 0 && errno != ENOENT) return FP_ERR_IO;
            fp_err_t serr = sync_parent_dir(rpend);
            if (serr != FP_OK) return serr;
        }
    }

    /* 2. Reconcile composite bundle journal locally BEFORE any network/root freshness check (P1-01) */
    fp_sql_ctx_t *rec_sql = NULL;
    if (cfg->db_path && cfg->db_path[0]) {
        fp_err_t serr = fp_sql_open(cfg->db_path, &rec_sql);
        if (serr != FP_OK) return serr;
    }
    fp_err_t rerr = fp_bundle_recover(cfg->store_dir, cfg->target_dir, rec_sql);
    if (rerr != FP_OK) {
        fp_sql_close(rec_sql);
        return rerr;
    }

    /* 3. Inspect .sf_ota_state strictly (P1-02 fail-closed, P0-01/P0-02/P0-03 idempotent R(R(S))=R(S)) */
    ota_lifecycle_t ol;
    ota_parse_status_t os = parse_ota_lifecycle(cfg->target_dir, &ol);
    if (os == OTA_ST_NONE) {
        fp_sql_close(rec_sql);
        return FP_OK;
    }
    if (os == OTA_ST_CORRUPTED) {
        fp_sql_close(rec_sql);
        return FP_ERR_INTEGRITY; /* Preserve corrupted .sf_ota_state evidence fail-closed! */
    }
    if (os == OTA_ST_IO) {
        fp_sql_close(rec_sql);
        return FP_ERR_IO;
    }

    fp_dna_t ndna, pdna;
    if (fp_hex_decode(ol.new_hex, ndna.bytes, FP_DNA_LEN) != FP_OK ||
        fp_hex_decode(ol.prev_hex, pdna.bytes, FP_DNA_LEN) != FP_OK) {
        fp_sql_close(rec_sql);
        return FP_ERR_INTEGRITY;
    }

    if (strcmp(ol.state, "HEALTH_PENDING") == 0) {
        char live_cur[65], sql_dna[65];
        int has_live = read_current_gen_hex(cfg->target_dir, live_cur);
        uint64_t sql_seq = 0;
        sql_dna[0] = '\0';
        if (rec_sql) {
            rerr = fp_sql_get_progress(rec_sql, &sql_seq, sql_dna);
            if (rerr != FP_OK) { fp_sql_close(rec_sql); return rerr; }
        }
        /* R1: Identify the ACTUAL committed head DNA (may be an intermediate step in a multi-event catch-up!) */
        const char *actual_hex = NULL;
        if (rec_sql && sql_seq > 0 && is_hex64_str(sql_dna)) actual_hex = sql_dna;
        else if (has_live) actual_hex = live_cur;
        fp_dna_t actual_dna = ndna;
        if (actual_hex && fp_hex_decode(actual_hex, actual_dna.bytes, FP_DNA_LEN) != FP_OK) {
            fp_sql_close(rec_sql);
            return FP_ERR_INTEGRITY;
        }

        if (ol.has_prev) {
            int prev_active = (has_live && strcmp(live_cur, ol.prev_hex) == 0) &&
                              (!rec_sql || strcmp(sql_dna, ol.prev_hex) == 0);
            if (!prev_active) {
                /* Crashed at ANY intermediate or final step -> roll back from actual_dna all the way to prev_dna! */
                rerr = fp_bundle_rollback(cfg->store_dir, &actual_dna, &pdna, cfg->target_dir, rec_sql);
                if (rerr != FP_OK) { fp_sql_close(rec_sql); return rerr; }
                save_failed_serial(cfg->store_dir, ol.serial, 1);
            }
            /* Else: crashed BEFORE apply OR AFTER rollback already completed -> idempotent cleanup! */
            rerr = clear_ota_lifecycle(cfg->target_dir);
        } else {
            int any_applied = has_live || (rec_sql && (sql_seq > 0 || sql_dna[0] != '\0'));
            if (any_applied) {
                /* R1 + P1-01: Initial install (single or multi-step) crashed after apply -> invert ALL SQLite steps & unlink current! */
                rerr = fp_bundle_rollback(cfg->store_dir, &actual_dna, NULL, cfg->target_dir, rec_sql);
                if (rerr != FP_OK) { fp_sql_close(rec_sql); return rerr; }
                save_failed_serial(cfg->store_dir, ol.serial, 0);
            } else {
                rerr = deactivate_live_target(cfg->target_dir, NULL, NULL);
                if (rerr != FP_OK) { fp_sql_close(rec_sql); return rerr; }
            }
            rerr = clear_ota_lifecycle(cfg->target_dir);
        }
        fp_sql_close(rec_sql);
        return rerr;
    }

    /* R3: Explicit ROLLBACK health recovery — NEVER attempt backward SQLite inversion toward newer deleted ancestor! */
    if (strcmp(ol.state, "ROLLBACK_HEALTH_PENDING") == 0) {
        char live_cur[65], sql_dna[65];
        int has_live = read_current_gen_hex(cfg->target_dir, live_cur);
        uint64_t sql_seq = 0;
        sql_dna[0] = '\0';
        if (rec_sql) {
            rerr = fp_sql_get_progress(rec_sql, &sql_seq, sql_dna);
            if (rerr != FP_OK) { fp_sql_close(rec_sql); return rerr; }
        }
        int still_at_prev = ol.has_prev &&
                            (has_live && strcmp(live_cur, ol.prev_hex) == 0) &&
                            (!rec_sql || strcmp(sql_dna, ol.prev_hex) == 0);
        if (still_at_prev) {
            /* Crashed BEFORE explicit rollback mutated target -> idempotent cleanup */
            rerr = clear_ota_lifecycle(cfg->target_dir);
            fp_sql_close(rec_sql);
            return rerr;
        }
        /* Rollback was partially or fully applied -> complete idempotently to target `ndna` if needed */
        int at_target = (has_live && strcmp(live_cur, ol.new_hex) == 0) &&
                        (!rec_sql || strcmp(sql_dna, ol.new_hex) == 0);
        if (!at_target) {
            const char *actual_hex = (rec_sql && sql_seq > 0 && is_hex64_str(sql_dna)) ? sql_dna
                                     : (has_live ? live_cur : ol.prev_hex);
            fp_dna_t actual_dna = pdna;
            if (fp_hex_decode(actual_hex, actual_dna.bytes, FP_DNA_LEN) != FP_OK) {
                fp_sql_close(rec_sql);
                return FP_ERR_INTEGRITY;
            }
            rerr = fp_bundle_rollback(cfg->store_dir, &actual_dna, &ndna, cfg->target_dir, rec_sql);
            if (rerr != FP_OK) { fp_sql_close(rec_sql); return rerr; }
        }
        fp_sql_close(rec_sql);
        /* Re-validate rollback target health offline: if unhealthy, durably deactivate BEFORE clearing journal! */
        int hrc = fp_agent_run_health_check(cfg->health_cmd, cfg->health_timeout_sec);
        if (hrc != 0) {
            rerr = deactivate_live_target(cfg->target_dir, ".sf_unhealthy", "ROLLBACK_HEALTH_FAILED=1\n");
            if (rerr != FP_OK) return rerr;
        }
        return clear_ota_lifecycle(cfg->target_dir);
    }

    /* P0-03: Offline idempotent completion of LEDGER_PENDING (health check already PASSED!) */
    if (strcmp(ol.state, "LEDGER_PENDING") == 0) {
        fp_sql_close(rec_sql);
        fp_store_state_t st;
        rerr = fp_store_load_state(cfg->store_dir, &st);
        if (rerr != FP_OK) return rerr;

        if (st.serial < ol.serial) {
            uint8_t *rbuf = NULL;
            size_t rlen = 0;
            rerr = read_file_small(cfg->root_path, (1u << 20), &rbuf, &rlen);
            if (rerr != FP_OK) return rerr;
            fp_root_doc_t pinned_root;
            rerr = fp_root_decode(rbuf, rlen, &pinned_root);
            free(rbuf);
            if (rerr == FP_OK) rerr = fp_root_verify_self(&pinned_root, 0);
            if (rerr != FP_OK) return rerr;

            root_vec_t hroots;
            rerr = load_verified_hist_roots(cfg->store_dir, &pinned_root, &hroots);
            if (rerr != FP_OK) return rerr;

            for (uint64_t s = st.serial + 1u; s <= ol.serial; s++) {
                char epath[PATH_MAX];
                if (snprintf(epath, sizeof(epath), "%s/pending_events/%llu.ev",
                             cfg->store_dir, (unsigned long long)s) >= (int)sizeof(epath)) {
                    root_vec_free(&hroots);
                    return FP_ERR_BOUNDS;
                }
                uint8_t *ebuf = NULL;
                size_t elen = 0;
                rerr = read_file_small(epath, (1u << 20), &ebuf, &elen);
                if (rerr != FP_OK) { root_vec_free(&hroots); return rerr; }
                fp_event_t ev;
                rerr = fp_event_decode(ebuf, elen, &ev);
                free(ebuf);
                if (rerr != FP_OK) { root_vec_free(&hroots); return rerr; }

                int applied = 0;
                for (size_t ri = hroots.count; ri > 0; ri--) {
                    if (fp_event_verify_with_root(&ev, &hroots.items[ri - 1u], 0) == FP_OK) {
                        rerr = fp_store_apply_event_with_root(cfg->store_dir, &ev,
                                                              &hroots.items[ri - 1u], 0, NULL, 0);
                        applied = 1;
                        break;
                    }
                }
                if (!applied) rerr = FP_ERR_SIGNATURE;
                if (rerr != FP_OK) { root_vec_free(&hroots); return rerr; }
            }
            root_vec_free(&hroots);
        } else if (st.has_current && !fp_dna_equal(&st.current_dna, &ndna)) {
            /* P1-03: Ledger serial already >= ol.serial, but active DNA diverges -> fail closed! */
            return FP_ERR_INTEGRITY;
        }
        cleanup_pending_events(cfg->store_dir, ol.start_serial, ol.serial);
        save_failed_serial(cfg->store_dir, 0, 1);
        return clear_ota_lifecycle(cfg->target_dir);
    }

    fp_sql_close(rec_sql);
    return FP_ERR_INTEGRITY;
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

    uint64_t hb_seq = next_heartbeat_seq(cfg->store_dir);
    if (hb_seq == 0) return; /* Fail-closed: never send heartbeat with non-durable stale sequence */

    char body[1536];
    int bl = snprintf(body, sizeof(body),
                      "{\"device_id\":\"%s\",\"channel\":\"%s\",\"outcome\":\"%s\","
                      "\"hb_seq\":%llu,"
                      "\"active_serial\":%llu,\"active_dna\":\"%s\","
                      "\"attempted_serial\":%llu,\"attempted_dna\":\"%s\","
                      "\"root_version\":%llu,\"health_exit\":%d,"
                      "\"bytes_downloaded\":%llu,\"bytes_from_lan\":%llu,\"bytes_resumed\":%llu,"
                      "\"elapsed_ms\":%.2f,\"detail\":\"%s\"}",
                      clean_dev, clean_ch,
                      fp_agent_outcome_name(rep->outcome),
                      (unsigned long long)hb_seq,
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

    root_vec_t hist_roots;
    memset(&hist_roots, 0, sizeof(hist_roots));

    /* P0-06: Serialize entire OTA sync cycle (recovery -> download -> apply -> health -> ledger) */
    int tx_lfd = acquire_agent_tx_lock(cfg->target_dir);
    if (tx_lfd < 0) {
        snprintf(rep.detail, sizeof(rep.detail), "cannot acquire agent transaction lock");
        rep.elapsed_ns = now_mono_ns() - t0;
        if (out_report) *out_report = rep;
        return FP_ERR_IO;
    }

    /* 0. OFFLINE-FIRST RECOVERY (P1-01, P0-01/02/03/04):
     * Reconcile any pending revoke, bundle journal, or interrupted health/ledger state locally
     * BEFORE touching the network or requiring root wall-clock freshness! */
    fp_err_t err = recover_ota_lifecycle_offline(cfg);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "local offline recovery failed (%s)", fp_strerror(err));
        goto done;
    }

    /* 1. Load pinned local Root Multi-Sig (FPR1).
     * Verify cryptographic quorum with now_unix=0 first so an offline device with an expired
     * pinned root can still walk the dual-quorum historical rotation chain vN -> vN+1 -> ...! */
    uint8_t *rbuf = NULL;
    size_t rlen = 0;
    err = read_file_small(cfg->root_path, (1u << 20), &rbuf, &rlen);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "cannot load pinned root.fpr (%s)", fp_strerror(err));
        goto done;
    }
    fp_root_doc_t root;
    err = fp_root_decode(rbuf, rlen, &root);
    if (err == FP_OK) err = fp_root_verify_self(&root, 0);
    if (err == FP_OK) persist_hist_root(cfg->store_dir, root.root_version, rbuf, rlen);
    free(rbuf);
    uint64_t now_unix = (uint64_t)time(NULL);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "pinned root.fpr invalid (%s)", fp_strerror(err));
        goto done;
    }

    /* P1-04: Load ONLY verified historical roots cryptographically chained up to pinned root */
    err = load_verified_hist_roots(cfg->store_dir, &root, &hist_roots);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "cannot load verified root history (%s)", fp_strerror(err));
        goto done;
    }
    rep.root_version = root.root_version;

    /* 2. Walk verified Multi-Sig Root rotation chain (v -> v+1 -> ...) via /repo/roots/<N>.fpr
     * with fallback to /repo/root.fpr. Supports up to 1024 contiguous rotations per sync (TRUST-01). */
    for (int step = 0; step < 1024; step++) {
        uint64_t next_ver = root.root_version + 1u;
        char rurl[1536];
        fp_http_resp_t hresp;
        snprintf(rurl, sizeof(rurl), "%s/repo/roots/%llu.fpr",
                 cfg->repo_url, (unsigned long long)next_ver);
        int got_step = (fp_http_get(rurl, (1u << 20), timeout_ms, &hresp) == FP_OK &&
                        hresp.status_code == 200 && hresp.body_len > 0);
        if (!got_step) {
            fp_http_resp_free(&hresp);
            snprintf(rurl, sizeof(rurl), "%s/repo/root.fpr", cfg->repo_url);
            if (fp_http_get(rurl, (1u << 20), timeout_ms, &hresp) != FP_OK ||
                hresp.status_code != 200 || hresp.body_len == 0) {
                fp_http_resp_free(&hresp);
                break;
            }
        }
        fp_root_doc_t remote_root;
        fp_err_t derr = fp_root_decode(hresp.body, hresp.body_len, &remote_root);
        if (derr != FP_OK) {
            fp_http_resp_free(&hresp);
            break;
        }
        if (remote_root.root_version <= root.root_version) {
            fp_http_resp_free(&hresp);
            break;
        }
        if (remote_root.root_version != next_ver) {
            fp_http_resp_free(&hresp);
            err = FP_ERR_CHAIN;
            snprintf(rep.detail, sizeof(rep.detail),
                     "non-contiguous root jump v%llu -> v%llu (missing /repo/roots/%llu.fpr)",
                     (unsigned long long)root.root_version,
                     (unsigned long long)remote_root.root_version,
                     (unsigned long long)next_ver);
            goto done;
        }
        if (fp_root_verify_rotation(&root, &remote_root, 0) != FP_OK) {
            fp_http_resp_free(&hresp);
            err = FP_ERR_SIGNATURE;
            snprintf(rep.detail, sizeof(rep.detail), "rejected untrusted remote root rotation v%llu",
                     (unsigned long long)next_ver);
            goto done;
        }
        persist_hist_root(cfg->store_dir, remote_root.root_version, hresp.body, hresp.body_len);
        err = write_file_atomic(cfg->root_path, hresp.body, hresp.body_len);
        fp_http_resp_free(&hresp);
        if (err != FP_OK) {
            snprintf(rep.detail, sizeof(rep.detail), "failed to persist rotated root v%llu (%s)",
                     (unsigned long long)next_ver, fp_strerror(err));
            goto done;
        }
        root = remote_root;
        rep.root_version = root.root_version;
        err = root_vec_push_unique(&hist_roots, &root);
        if (err != FP_OK) goto done;
    }

    /* Enforce strict wall-clock freshness on the final active Root Trust Document */
    err = fp_root_verify_self(&root, now_unix);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "active root.fpr expired/invalid (%s)", fp_strerror(err));
        goto done;
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

    /* 4. Fetch latest signed release event strictly for this device's channel (SEC-06: NO implicit global fallback!) */
    char ev_url[1536];
    snprintf(ev_url, sizeof(ev_url), "%s/repo/channels/%s/latest.ev", cfg->repo_url, channel);
    fp_http_resp_t ev_resp;
    err = fp_http_get(ev_url, (1u << 20), timeout_ms, &ev_resp);
    if (err != FP_OK || ev_resp.status_code != 200) {
        fp_http_resp_free(&ev_resp);
        err = (err != FP_OK) ? err : FP_ERR_NOT_FOUND;
        snprintf(rep.detail, sizeof(rep.detail), "failed to fetch channel '%s' latest.ev", channel);
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

    int failed_had_prev = 1;
    uint64_t failed_serial = load_failed_serial(cfg->store_dir, &failed_had_prev);
    if (latest_ev.serial == failed_serial) {
        if (failed_had_prev && st.has_current) {
            rep.outcome = FP_AGENT_ROLLED_BACK;
            snprintf(rep.detail, sizeof(rep.detail), "skipping previously failed serial %llu",
                     (unsigned long long)failed_serial);
            err = FP_OK;
        } else {
            rep.outcome = FP_AGENT_INITIAL_INSTALL_FAILED;
            rep.active_serial = 0;
            memset(&rep.active_bundle_dna, 0, sizeof(rep.active_bundle_dna));
            snprintf(rep.detail, sizeof(rep.detail), "previously failed initial install serial %llu still active",
                     (unsigned long long)failed_serial);
            err = FP_ERR_POLICY;
        }
        goto done;
    }

    /* 5. Build & verify full signed event chain from (st.serial + 1) .. latest_ev.serial.
     * Supports offline catch-up up to 4096 events across historical verified root rotations;
     * intermediate historical events are verified cryptographically (now_unix=0) against the
     * active or historical root chain, while latest_ev enforces live freshness against active root. */
    uint64_t chain_len = latest_ev.serial - st.serial;
    if (chain_len > 4096u) {
        err = FP_ERR_BOUNDS;
        snprintf(rep.detail, sizeof(rep.detail), "event chain gap too large (%llu)", (unsigned long long)chain_len);
        goto done;
    }
    fp_event_t *chain = calloc((size_t)chain_len, sizeof(fp_event_t));
    size_t *chain_ridx = calloc((size_t)chain_len, sizeof(size_t));
    if (!chain || !chain_ridx) { free(chain); free(chain_ridx); err = FP_ERR_NOMEM; goto done; }

    fp_dna_t expected_prev = st.last_event_hash;
    for (uint64_t i = 0; i < chain_len; i++) {
        uint64_t s = st.serial + 1u + i;
        if (s == latest_ev.serial) {
            chain[i] = latest_ev;
            chain_ridx[i] = hist_roots.count - 1u;
        } else {
            char curl[1536];
            snprintf(curl, sizeof(curl), "%s/repo/events/%llu.ev", cfg->repo_url, (unsigned long long)s);
            fp_http_resp_t cr;
            err = fp_http_get(curl, (1u << 20), timeout_ms, &cr);
            if (err != FP_OK || cr.status_code != 200) {
                fp_http_resp_free(&cr);
                free(chain); free(chain_ridx);
                err = FP_ERR_CHAIN;
                snprintf(rep.detail, sizeof(rep.detail), "missing intermediate event %llu", (unsigned long long)s);
                goto done;
            }
            err = fp_event_decode(cr.body, cr.body_len, &chain[i]);
            fp_http_resp_free(&cr);
            if (err == FP_OK) {
                /* Try active root first, then verified historical roots from rotation chain */
                err = FP_ERR_SIGNATURE;
                for (size_t ri = hist_roots.count; ri > 0; ri--) {
                    if (fp_event_verify_with_root(&chain[i], &hist_roots.items[ri - 1u], 0) == FP_OK) {
                        chain_ridx[i] = ri - 1u;
                        err = FP_OK;
                        break;
                    }
                }
            }
            if (err != FP_OK) {
                free(chain); free(chain_ridx);
                snprintf(rep.detail, sizeof(rep.detail), "invalid intermediate event %llu (%s)",
                         (unsigned long long)s, fp_strerror(err));
                goto done;
            }
        }
        if (chain[i].serial != s || !fp_dna_equal(&chain[i].prev_event_hash, &expected_prev)) {
            free(chain); free(chain_ridx);
            err = FP_ERR_CHAIN;
            snprintf(rep.detail, sizeof(rep.detail), "broken hash chain at serial %llu", (unsigned long long)s);
            goto done;
        }
        expected_prev = chain[i].event_hash;
    }

    /* P0-04 & P1-06: Exact store policy simulation BEFORE any file/DB/store mutation!
     * Keep `target_st` so catch-up deployment & revocation decisions follow the exact final state (P0-02, P0-05, SF-A02). */
    fp_store_state_t target_st = st;
    for (uint64_t i = 0; i < chain_len; i++) {
        err = fp_store_validate_transition(&target_st, &chain[i], &target_st);
        if (err != FP_OK) {
            uint64_t bad_s = chain[i].serial;
            free(chain); free(chain_ridx);
            snprintf(rep.detail, sizeof(rep.detail),
                     "preflight store policy rejected event serial %llu (%s)",
                     (unsigned long long)bad_s, fp_strerror(err));
            goto done;
        }
    }

    /* 6. Handle final-state deactivation (!target_st.has_current) OR pure historical revoke (active DNA unchanged)
     * crash-safely (P0-05, SF-A02): uses simulated `target_st`, NOT just `latest_ev`! */
    int active_unchanged = (st.has_current && target_st.has_current &&
                            fp_dna_equal(&st.current_dna, &target_st.current_dna));
    if (!target_st.has_current || (latest_ev.action == FP_ACTION_REVOKE && active_unchanged)) {
        int deactivate_live = !target_st.has_current;
        char rpend[PATH_MAX], rev_marker[128];
        rpend[0] = '\0';
        if (deactivate_live) {
            snprintf(rev_marker, sizeof(rev_marker), "REVOKED_SERIAL=%llu\n", (unsigned long long)latest_ev.serial);
            if (snprintf(rpend, sizeof(rpend), "%s/.sf_revoke_pending", cfg->target_dir) >= (int)sizeof(rpend)) {
                free(chain); free(chain_ridx); err = FP_ERR_BOUNDS; goto done;
            }
            (void)mkdir(cfg->target_dir, 0755);
            err = write_file_atomic(rpend, (const uint8_t *)rev_marker, strlen(rev_marker));
            if (err != FP_OK) {
                free(chain); free(chain_ridx);
                snprintf(rep.detail, sizeof(rep.detail), "cannot persist revoke intent (%s)", fp_strerror(err));
                goto done;
            }
            err = deactivate_live_target(cfg->target_dir, ".sf_revoked", rev_marker);
            if (err != FP_OK) {
                free(chain); free(chain_ridx);
                snprintf(rep.detail, sizeof(rep.detail), "revoke failed to deactivate live target (%s)", fp_strerror(err));
                goto done;
            }
        }
        for (uint64_t i = 0; i < chain_len; i++) {
            if (chain[i].action != FP_ACTION_REVOKE) {
                char h[65], u[1536];
                fp_hex_encode(chain[i].target_dna.bytes, FP_DNA_LEN, h);
                snprintf(u, sizeof(u), "%s/repo/objects/%s", cfg->repo_url, h);
                uint64_t r = 0;
                (void)fp_http_pull_object(u, cfg->store_dir, &chain[i].target_dna, chain[i].target_size, timeout_ms, &r);
            }
            uint64_t ev_now = (i + 1u == chain_len) ? now_unix : 0;
            err = fp_store_apply_event_with_root(cfg->store_dir, &chain[i],
                                                 &hist_roots.items[chain_ridx[i]], ev_now, NULL, 0);
            if (err != FP_OK) { free(chain); free(chain_ridx); snprintf(rep.detail, sizeof(rep.detail), "revoke apply failed"); goto done; }
        }
        free(chain); free(chain_ridx);
        if (deactivate_live && rpend[0]) {
            if (unlink(rpend) == 0) (void)sync_parent_dir(rpend);
        }
        save_failed_serial(cfg->store_dir, 0, 1);
        rep.outcome = FP_AGENT_REVOKED;
        rep.active_serial = latest_ev.serial;
        if (deactivate_live) {
            memset(&rep.active_bundle_dna, 0, sizeof(rep.active_bundle_dna));
            snprintf(rep.detail, sizeof(rep.detail), "revoked active DNA & deactivated live target per serial %llu",
                     (unsigned long long)latest_ev.serial);
        } else {
            snprintf(rep.detail, sizeof(rep.detail), "revoked historical DNA (active release untouched) per serial %llu",
                     (unsigned long long)latest_ev.serial);
        }
        err = FP_OK;
        goto done;
    }

    /* 7. Download target Particle Bundle AND all intermediate bundles/entries needed for sequential SQLite catch-up (P0-02) */
    fp_dna_t final_target_dna = target_st.current_dna;
    uint64_t final_target_size = latest_ev.target_size;
    uint64_t final_target_serial = 0;
    for (uint64_t i = chain_len; i > 0; i--) {
        if (chain[i - 1u].action != FP_ACTION_REVOKE &&
            fp_dna_equal(&chain[i - 1u].target_dna, &final_target_dna)) {
            final_target_size = chain[i - 1u].target_size;
            final_target_serial = chain[i - 1u].serial;
            break;
        }
    }

    /* R2: If the simulated target release is STILL the exact serial previously rejected by local health-check
     * (e.g. [INSTALL V2 (failed), REVOKE historical V0]), NEVER promote V2 as active while running V1! */
    if (failed_serial > 0u && final_target_serial == failed_serial) {
        free(chain); free(chain_ridx);
        if (failed_had_prev && st.has_current) {
            rep.outcome = FP_AGENT_ROLLED_BACK;
            rep.active_serial = st.serial;
            rep.active_bundle_dna = st.current_dna;
            snprintf(rep.detail, sizeof(rep.detail),
                     "target release serial %llu previously failed health-check (remaining on serial %llu)",
                     (unsigned long long)failed_serial, (unsigned long long)st.serial);
            err = FP_OK;
        } else {
            rep.outcome = FP_AGENT_INITIAL_INSTALL_FAILED;
            rep.active_serial = 0;
            memset(&rep.active_bundle_dna, 0, sizeof(rep.active_bundle_dna));
            snprintf(rep.detail, sizeof(rep.detail),
                     "target initial release serial %llu previously failed health-check; waiting for newer release",
                     (unsigned long long)failed_serial);
            err = FP_ERR_POLICY;
        }
        goto done;
    }

    err = download_bundle_and_entries(cfg, &final_target_dna, final_target_size,
                                      timeout_ms, &rep.bytes_downloaded, &rep.bytes_from_lan,
                                      &rep.bytes_resumed);
    if (err != FP_OK) {
        free(chain); free(chain_ridx);
        snprintf(rep.detail, sizeof(rep.detail), "artifact download/verify failed (%s)", fp_strerror(err));
        goto done;
    }

    /* Ensure every intermediate non-revoke bundle in chain is resident (and its entries if SQLite DB is used!) */
    for (uint64_t i = 0; i < chain_len; i++) {
        if (chain[i].action == FP_ACTION_REVOKE) continue;
        if (fp_dna_equal(&chain[i].target_dna, &final_target_dna)) continue;
        if (cfg->db_path && cfg->db_path[0]) {
            err = download_bundle_and_entries(cfg, &chain[i].target_dna, chain[i].target_size,
                                              timeout_ms, &rep.bytes_downloaded, &rep.bytes_from_lan,
                                              &rep.bytes_resumed);
        } else if (!fp_store_has_object(cfg->store_dir, &chain[i].target_dna, NULL)) {
            char h[65], u[1536];
            fp_hex_encode(chain[i].target_dna.bytes, FP_DNA_LEN, h);
            snprintf(u, sizeof(u), "%s/repo/objects/%s", cfg->repo_url, h);
            uint64_t r = 0;
            err = fp_http_pull_object(u, cfg->store_dir, &chain[i].target_dna,
                                      chain[i].target_size, timeout_ms, &r);
        }
        if (err != FP_OK) {
            uint64_t bad_s = chain[i].serial;
            free(chain); free(chain_ridx);
            snprintf(rep.detail, sizeof(rep.detail), "intermediate bundle fetch failed at serial %llu",
                     (unsigned long long)bad_s);
            goto done;
        }
    }

    /* 8. Open optional SQLite DB & apply Particle Bundle(s) atomically under unified HEALTH_PENDING lifecycle (P0-02/03/04) */
    fp_sql_ctx_t *sql = NULL;
    if (cfg->db_path && cfg->db_path[0]) {
        err = fp_sql_open(cfg->db_path, &sql);
        if (err != FP_OK) {
            free(chain); free(chain_ridx);
            snprintf(rep.detail, sizeof(rep.detail), "cannot open SQLite DB (%s)", fp_strerror(err));
            goto done;
        }
    }

    int is_explicit_rollback = (latest_ev.action == FP_ACTION_ROLLBACK);
    /* P0-03 + R3: Persist direction-aware lifecycle marker before any mutation! */
    err = write_ota_lifecycle(cfg->target_dir,
                              is_explicit_rollback ? "ROLLBACK_HEALTH_PENDING" : "HEALTH_PENDING",
                              latest_ev.serial, chain[0].serial, &final_target_dna,
                              st.has_current ? 1 : 0, &st.current_dna);
    if (err != FP_OK) {
        fp_sql_close(sql);
        free(chain); free(chain_ridx);
        snprintf(rep.detail, sizeof(rep.detail), "cannot persist OTA lifecycle (%s)", fp_strerror(err));
        goto done;
    }

    /* P0-02: When catching up across multiple events with SQLite (or mixed INSTALL+ROLLBACK), replay
     * non-revoke transitions in exact chronological order so no incremental SQLite changeset is skipped! */
    fp_dna_t running_dna = st.current_dna;
    int running_has = st.has_current ? 1 : 0;
    if (sql != NULL && chain_len > 1u) {
        for (uint64_t i = 0; i < chain_len && err == FP_OK; i++) {
            if (chain[i].action == FP_ACTION_REVOKE) continue;
            /* Never re-apply an intermediate release that previously failed local health-check & auto-rolled back! */
            if (failed_serial > 0u && chain[i].serial == failed_serial) continue;
            if (chain[i].action == FP_ACTION_ROLLBACK) {
                if (running_has && !fp_dna_equal(&running_dna, &chain[i].target_dna)) {
                    err = fp_bundle_rollback(cfg->store_dir, &running_dna, &chain[i].target_dna,
                                             cfg->target_dir, sql);
                } else if (!running_has) {
                    err = FP_ERR_POLICY;
                }
            } else {
                err = fp_bundle_apply(cfg->store_dir, &chain[i].target_dna, cfg->target_dir,
                                      sql, chain[i].serial, 0);
            }
            if (err == FP_OK) {
                running_dna = chain[i].target_dna;
                running_has = 1;
            }
        }
    } else if (is_explicit_rollback) {
        if (st.has_current && !fp_dna_equal(&st.current_dna, &final_target_dna)) {
            err = fp_bundle_rollback(cfg->store_dir, &st.current_dna, &final_target_dna,
                                     cfg->target_dir, sql);
        } else if (!st.has_current) {
            err = FP_ERR_POLICY;
        } else {
            err = FP_OK;
        }
    } else {
        err = fp_bundle_apply(cfg->store_dir, &final_target_dna, cfg->target_dir,
                              sql, latest_ev.serial, 0);
    }

    if (err != FP_OK) {
        /* P0-04 / SF-A05: Do NOT blindly delete HEALTH_PENDING on error!
         * If SQLite or `current` already advanced before an I/O error, keep `.sf_ota_state` so
         * offline recovery reconciles conservatively on restart. Clear ONLY if state is strictly unchanged! */
        int mutated = 0;
        char live_cur[65], sql_dna[65];
        char prev_hex[65];
        fp_hex_encode(st.current_dna.bytes, FP_DNA_LEN, prev_hex);
        int has_live = read_current_gen_hex(cfg->target_dir, live_cur);
        if (st.has_current) {
            if (!has_live || strcmp(live_cur, prev_hex) != 0) mutated = 1;
        } else if (has_live) {
            mutated = 1;
        }
        if (sql) {
            uint64_t sq = 0;
            sql_dna[0] = '\0';
            if (fp_sql_get_progress(sql, &sq, sql_dna) != FP_OK ||
                (st.has_current ? (strcmp(sql_dna, prev_hex) != 0) : (sq != 0 || sql_dna[0] != '\0'))) {
                mutated = 1;
            }
        }
        if (!mutated) (void)clear_ota_lifecycle(cfg->target_dir);
        fp_sql_close(sql);
        free(chain); free(chain_ridx);
        snprintf(rep.detail, sizeof(rep.detail), "bundle %s failed (%s)",
                 is_explicit_rollback ? "rollback" : "apply", fp_strerror(err));
        goto done;
    }

    /* R2: Strict post-apply concordance check BEFORE running health watchdog & committing ledger!
     * Ensures symlink `current`, SQLite `_fp_progress`, and reported `final_target_dna` are identical. */
    {
        char target_hex[65], live_cur[65];
        fp_hex_encode(final_target_dna.bytes, FP_DNA_LEN, target_hex);
        int cur_ok = read_current_gen_hex(cfg->target_dir, live_cur) && strcmp(live_cur, target_hex) == 0;
        int sql_ok = 1;
        if (sql) {
            uint64_t cseq = 0;
            char cdna[65];
            cdna[0] = '\0';
            sql_ok = (fp_sql_get_progress(sql, &cseq, cdna) == FP_OK && strcmp(cdna, target_hex) == 0);
        }
        if (!cur_ok || !sql_ok) {
            fp_sql_close(sql);
            free(chain); free(chain_ridx);
            err = FP_ERR_INTEGRITY;
            snprintf(rep.detail, sizeof(rep.detail),
                     "post-apply state mismatch (current/SQLite != target DNA)");
            goto done;
        }
    }

    /* 9. Run Application Health-Check with Watchdog -> AUTO-ROLLBACK ON FAILURE! */
    int hrc = fp_agent_run_health_check(cfg->health_cmd, cfg->health_timeout_sec);
    rep.health_exit_code = hrc;
    if (hrc != 0) {
        if (st.has_current && !is_explicit_rollback) {
            fp_err_t rerr = fp_bundle_rollback(cfg->store_dir, &final_target_dna,
                                               &st.current_dna, cfg->target_dir, sql);
            fp_sql_close(sql);
            free(chain); free(chain_ridx);
            if (rerr == FP_OK) {
                (void)clear_ota_lifecycle(cfg->target_dir);
                save_failed_serial(cfg->store_dir, latest_ev.serial, 1);
                rep.outcome = FP_AGENT_ROLLED_BACK;
                rep.active_serial = st.serial;
                rep.active_bundle_dna = st.current_dna;
                snprintf(rep.detail, sizeof(rep.detail),
                         "health-check failed (exit=%d) on serial %llu -> auto-rolled back to serial %llu",
                         hrc, (unsigned long long)latest_ev.serial, (unsigned long long)st.serial);
                err = FP_OK;
            } else {
                rep.outcome = FP_AGENT_ROLLBACK_FAILED;
                rep.active_serial = 0;
                memset(&rep.active_bundle_dna, 0, sizeof(rep.active_bundle_dna));
                snprintf(rep.detail, sizeof(rep.detail),
                         "CRITICAL: health-check failed (exit=%d) AND rollback failed (%s)",
                         hrc, fp_strerror(rerr));
                err = rerr;
            }
            goto done;
        }
        if (!st.has_current) {
            /* P1-01: Revert initial SQLite changesets AND deactivate current atomically! */
            fp_err_t derr = fp_bundle_rollback(cfg->store_dir, &final_target_dna, NULL,
                                               cfg->target_dir, sql);
            fp_sql_close(sql);
            free(chain); free(chain_ridx);
            if (derr == FP_OK) (void)clear_ota_lifecycle(cfg->target_dir);
            save_failed_serial(cfg->store_dir, latest_ev.serial, 0);
            rep.outcome = FP_AGENT_INITIAL_INSTALL_FAILED;
            rep.active_serial = 0;
            memset(&rep.active_bundle_dna, 0, sizeof(rep.active_bundle_dna));
            snprintf(rep.detail, sizeof(rep.detail),
                     "initial install health-check failed (exit=%d) on serial %llu; target %s",
                     hrc, (unsigned long long)latest_ev.serial,
                     derr == FP_OK ? "reverted & deactivated" : "rollback error");
            err = (derr == FP_OK) ? FP_ERR_POLICY : derr;
        } else {
            /* R3: Explicit rollback failed health check -> propagate deactivation errors & keep journal if deactivation fails! */
            fp_err_t derr = deactivate_live_target(cfg->target_dir, ".sf_unhealthy", "ROLLBACK_HEALTH_FAILED=1\n");
            if (derr == FP_OK) {
                derr = clear_ota_lifecycle(cfg->target_dir);
            }
            fp_sql_close(sql);
            free(chain); free(chain_ridx);
            rep.outcome = FP_AGENT_ROLLBACK_FAILED;
            rep.active_serial = 0;
            memset(&rep.active_bundle_dna, 0, sizeof(rep.active_bundle_dna));
            snprintf(rep.detail, sizeof(rep.detail),
                     "explicit rollback health-check failed (exit=%d) on serial %llu; %s",
                     hrc, (unsigned long long)latest_ev.serial,
                     derr == FP_OK ? "target deactivated" : "CRITICAL: deactivation failed");
            err = (derr == FP_OK) ? FP_ERR_POLICY : derr;
        }
        goto done;
    }
    fp_sql_close(sql);
    clear_revoked_marker(cfg->target_dir);

    /* 10. Health-check PASSED -> persist verified chain + LEDGER_PENDING (P0-03), commit, then clear! */
    err = persist_pending_events(cfg->store_dir, chain, chain_len);
    if (err == FP_OK) {
        err = write_ota_lifecycle(cfg->target_dir, "LEDGER_PENDING", latest_ev.serial,
                                  chain[0].serial, &final_target_dna,
                                  st.has_current ? 1 : 0, &st.current_dna);
    }
    if (err != FP_OK) {
        free(chain); free(chain_ridx);
        snprintf(rep.detail, sizeof(rep.detail), "failed to persist LEDGER_PENDING state (%s)", fp_strerror(err));
        goto done;
    }
    for (uint64_t i = 0; i < chain_len; i++) {
        uint64_t ev_now = (i + 1u == chain_len) ? now_unix : 0;
        err = fp_store_apply_event_with_root(cfg->store_dir, &chain[i],
                                             &hist_roots.items[chain_ridx[i]], ev_now, NULL, 0);
        if (err != FP_OK) {
            uint64_t bad_s = chain[i].serial;
            free(chain); free(chain_ridx);
            snprintf(rep.detail, sizeof(rep.detail), "store state commit failed at serial %llu (%s)",
                     (unsigned long long)bad_s, fp_strerror(err));
            goto done;
        }
    }
    uint64_t first_s = chain[0].serial;
    free(chain); free(chain_ridx);
    cleanup_pending_events(cfg->store_dir, first_s, latest_ev.serial);
    err = clear_ota_lifecycle(cfg->target_dir);
    if (err != FP_OK) {
        snprintf(rep.detail, sizeof(rep.detail), "failed to clear OTA lifecycle (%s)", fp_strerror(err));
        goto done;
    }
    save_failed_serial(cfg->store_dir, 0, 1);

    rep.outcome = is_explicit_rollback ? FP_AGENT_ROLLED_BACK : FP_AGENT_UPDATED;
    rep.active_serial = latest_ev.serial;
    rep.active_bundle_dna = final_target_dna;
    snprintf(rep.detail, sizeof(rep.detail),
             "%s cleanly to serial %llu (health=0, root_v=%llu)",
             is_explicit_rollback ? "rolled back" : "updated",
             (unsigned long long)latest_ev.serial, (unsigned long long)root.root_version);
    err = FP_OK;

done:
    root_vec_free(&hist_roots);
    release_agent_tx_lock(tx_lfd);
    rep.elapsed_ns = now_mono_ns() - t0;
    send_heartbeat_best_effort(cfg, &rep);
    if (out_report) *out_report = rep;
    return err;
}
