#define _POSIX_C_SOURCE 200809L
#define SQLITE_ENABLE_SESSION 1

#include "fp.h"

#include <blake3.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* SQLite changesets are bounded per-entry AND in aggregate; FP_ROLE_FILE streams in 64 KiB O(1) RAM */
#define BUNDLE_MAX_CHANGESET        (16u << 20)
#define BUNDLE_MAX_TOTAL_CHANGESETS (32u << 20)
#define BUNDLE_STREAM_BUF           65536u

static _Atomic uint64_t g_bundle_tmp_seq = 0;

struct fp_sql_ctx {
    sqlite3      *db;
    sqlite3_stmt *stmt_get_prog;
    sqlite3_stmt *stmt_set_prog;
};

static void put_be16(uint8_t dst[2], uint16_t v) {
    dst[0] = (uint8_t)(v >> 8);
    dst[1] = (uint8_t)(v);
}

static uint16_t get_be16(const uint8_t src[2]) {
    return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static void put_be32(uint8_t dst[4], uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v);
}

static uint32_t get_be32(const uint8_t src[4]) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  | ((uint32_t)src[3]);
}

static void put_be64(uint8_t dst[8], uint64_t v) {
    dst[0] = (uint8_t)(v >> 56);
    dst[1] = (uint8_t)(v >> 48);
    dst[2] = (uint8_t)(v >> 40);
    dst[3] = (uint8_t)(v >> 32);
    dst[4] = (uint8_t)(v >> 24);
    dst[5] = (uint8_t)(v >> 16);
    dst[6] = (uint8_t)(v >> 8);
    dst[7] = (uint8_t)(v);
}

static uint64_t get_be64(const uint8_t src[8]) {
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  | ((uint64_t)src[7]);
}

static int safe_rel_path(const char *p) {
    if (!p || p[0] == '\0' || p[0] == '/') return 0;
    size_t len = strnlen(p, FP_BUNDLE_MAX_PATH);
    if (len == 0 || len >= FP_BUNDLE_MAX_PATH) return 0;
    const char *seg = p;
    for (size_t i = 0; i <= len; i++) {
        unsigned char uc = (unsigned char)p[i];
        if (i < len && (uc < 0x20u || uc == 0x7fu)) return 0;
        if (p[i] == '/' || p[i] == '\0') {
            size_t slen = (size_t)(&p[i] - seg);
            if (slen == 0) return 0;
            if ((slen == 1 && seg[0] == '.') ||
                (slen == 2 && seg[0] == '.' && seg[1] == '.')) {
                return 0;
            }
            seg = &p[i + 1];
        }
    }
    return 1;
}

static int safe_ident(const char *name) {
    if (!name || name[0] == '\0') return 0;
    size_t len = strnlen(name, 128);
    if (len == 0 || len >= 128) return 0;
    if (strcmp(name, "_fp_progress") == 0) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c == '_') || (i > 0 && c >= '0' && c <= '9');
        if (!ok) return 0;
    }
    return 1;
}

/* --- Persistent SQLite Session Context --- */

fp_err_t fp_sql_open(const char *db_path, fp_sql_ctx_t **out_ctx) {
    if (!db_path || !out_ctx) return FP_ERR_INVALID;
    *out_ctx = NULL;

    fp_sql_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return FP_ERR_NOMEM;

    if (sqlite3_open(db_path, &ctx->db) != SQLITE_OK) {
        fp_sql_close(ctx);
        return FP_ERR_IO;
    }
    const char *init_sql =
        "PRAGMA journal_mode=WAL;"
        "PRAGMA synchronous=FULL;"
        "PRAGMA busy_timeout=5000;"
        "CREATE TABLE IF NOT EXISTS _fp_progress ("
        "  id INTEGER PRIMARY KEY CHECK(id=1),"
        "  seq INTEGER NOT NULL,"
        "  bundle_dna TEXT NOT NULL"
        ");"
        "INSERT OR IGNORE INTO _fp_progress(id, seq, bundle_dna) VALUES (1, 0, '');";

    if (sqlite3_exec(ctx->db, init_sql, NULL, NULL, NULL) != SQLITE_OK) {
        fp_sql_close(ctx);
        return FP_ERR_IO;
    }
    if (sqlite3_prepare_v2(ctx->db, "SELECT seq, bundle_dna FROM _fp_progress WHERE id=1",
                           -1, &ctx->stmt_get_prog, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(ctx->db, "UPDATE _fp_progress SET seq=?, bundle_dna=? WHERE id=1",
                           -1, &ctx->stmt_set_prog, NULL) != SQLITE_OK) {
        fp_sql_close(ctx);
        return FP_ERR_IO;
    }
    *out_ctx = ctx;
    return FP_OK;
}

void fp_sql_close(fp_sql_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->stmt_get_prog) sqlite3_finalize(ctx->stmt_get_prog);
    if (ctx->stmt_set_prog) sqlite3_finalize(ctx->stmt_set_prog);
    if (ctx->db) sqlite3_close(ctx->db);
    free(ctx);
}

fp_err_t fp_sql_exec(fp_sql_ctx_t *ctx, const char *sql) {
    if (!ctx || !sql) return FP_ERR_INVALID;
    return sqlite3_exec(ctx->db, sql, NULL, NULL, NULL) == SQLITE_OK ? FP_OK : FP_ERR_IO;
}

fp_err_t fp_sql_capture_changeset(fp_sql_ctx_t *ctx, const char *table_name,
                                  const char *sql,
                                  uint8_t **out_cs, size_t *out_len) {
    if (!ctx || !table_name || !sql || !out_cs || !out_len || !safe_ident(table_name)) {
        return FP_ERR_INVALID;
    }
    *out_cs = NULL;
    *out_len = 0;

    sqlite3_session *sess = NULL;
    int rc = sqlite3session_create(ctx->db, "main", &sess);
    if (rc == SQLITE_OK) rc = sqlite3session_attach(sess, table_name);
    if (rc == SQLITE_OK) rc = sqlite3_exec(ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL);
    if (rc == SQLITE_OK) rc = sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);

    void *raw = NULL;
    int raw_sz = 0;
    if (rc == SQLITE_OK) rc = sqlite3session_changeset(sess, &raw_sz, &raw);
    if (rc == SQLITE_OK) rc = sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL);

    if (rc != SQLITE_OK) {
        (void)sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_free(raw);
        sqlite3session_delete(sess);
        return FP_ERR_IO;
    }
    sqlite3session_delete(sess);

    size_t len = raw_sz > 0 ? (size_t)raw_sz : 0u;
    uint8_t *copy = malloc(len > 0 ? len : 1u);
    if (!copy) {
        sqlite3_free(raw);
        return FP_ERR_NOMEM;
    }
    if (len > 0) memcpy(copy, raw, len);
    sqlite3_free(raw);

    *out_cs = copy;
    *out_len = len;
    return FP_OK;
}

fp_err_t fp_sql_state_digest(fp_sql_ctx_t *ctx, const char *table_name, fp_dna_t *out_dna) {
    if (!ctx || !table_name || !out_dna || !safe_ident(table_name)) return FP_ERR_INVALID;

    char query[256];
    snprintf(query, sizeof(query), "SELECT * FROM \"%s\" ORDER BY rowid", table_name);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }

    static const uint8_t tag[13] = "FP1/SQLSTATE";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, table_name, strlen(table_name) + 1u);

    int cols = sqlite3_column_count(stmt);
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        for (int c = 0; c < cols; c++) {
            int t = sqlite3_column_type(stmt, c);
            uint8_t tb = (uint8_t)t;
            blake3_hasher_update(&h, &tb, 1);
            if (t == SQLITE_INTEGER) {
                uint8_t b[8];
                put_be64(b, (uint64_t)sqlite3_column_int64(stmt, c));
                blake3_hasher_update(&h, b, 8);
            } else if (t == SQLITE_FLOAT) {
                double d = sqlite3_column_double(stmt, c);
                uint64_t u = 0;
                memcpy(&u, &d, sizeof(u));
                uint8_t b[8];
                put_be64(b, u);
                blake3_hasher_update(&h, b, 8);
            } else if (t == SQLITE_TEXT || t == SQLITE_BLOB) {
                int n = sqlite3_column_bytes(stmt, c);
                const void *p = sqlite3_column_blob(stmt, c);
                uint8_t lb[4];
                put_be32(lb, (uint32_t)n);
                blake3_hasher_update(&h, lb, 4);
                if (n > 0 && p) blake3_hasher_update(&h, p, (size_t)n);
            }
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return FP_ERR_IO;

    blake3_hasher_finalize(&h, out_dna->bytes, FP_DNA_LEN);
    return FP_OK;
}

/* --- FPB1 Bundle Binary Serialization --- */

static fp_err_t validate_bundle(const fp_bundle_t *b) {
    if (!b || b->entry_count == 0 || b->entry_count > FP_BUNDLE_MAX_ENTRIES) {
        return FP_ERR_INVALID;
    }
    for (uint16_t i = 0; i < b->entry_count; i++) {
        const fp_bundle_entry_t *e = &b->entries[i];
        if (e->role == FP_ROLE_FILE) {
            if (!safe_rel_path(e->path)) return FP_ERR_POLICY;
        } else if (e->role == FP_ROLE_SQLITE_CHANGESET) {
            if (!safe_ident(e->path)) return FP_ERR_POLICY;
        } else {
            return FP_ERR_INVALID;
        }
        /* Reject duplicate paths within same role */
        for (uint16_t j = 0; j < i; j++) {
            if (b->entries[j].role == e->role && strcmp(b->entries[j].path, e->path) == 0) {
                return FP_ERR_POLICY;
            }
        }
    }
    return FP_OK;
}

fp_err_t fp_bundle_encode(const fp_bundle_t *b, uint8_t **out_buf, size_t *out_len) {
    if (!b || !out_buf || !out_len) return FP_ERR_INVALID;
    *out_buf = NULL;
    *out_len = 0;
    fp_err_t err = validate_bundle(b);
    if (err != FP_OK) return err;

    size_t total = 12u; /* "FPB1"(4) + ver(2) + count(2) + flags(4) */
    for (uint16_t i = 0; i < b->entry_count; i++) {
        size_t plen = strlen(b->entries[i].path);
        total += 1u + 4u + 8u + FP_DNA_LEN + 2u + plen;
    }

    uint8_t *buf = malloc(total);
    if (!buf) return FP_ERR_NOMEM;

    size_t p = 0;
    memcpy(buf + p, "FPB1", 4); p += 4;
    put_be16(buf + p, 1); p += 2;
    put_be16(buf + p, b->entry_count); p += 2;
    put_be32(buf + p, 0); p += 4;

    for (uint16_t i = 0; i < b->entry_count; i++) {
        const fp_bundle_entry_t *e = &b->entries[i];
        uint16_t plen = (uint16_t)strlen(e->path);
        buf[p++] = (uint8_t)e->role;
        put_be32(buf + p, e->mode); p += 4;
        put_be64(buf + p, e->size); p += 8;
        memcpy(buf + p, e->dna.bytes, FP_DNA_LEN); p += FP_DNA_LEN;
        put_be16(buf + p, plen); p += 2;
        memcpy(buf + p, e->path, plen); p += plen;
    }

    *out_buf = buf;
    *out_len = p;
    return FP_OK;
}

fp_err_t fp_bundle_decode(const uint8_t *buf, size_t len, fp_bundle_t *out_b) {
    if (!buf || !out_b || len < 12u || memcmp(buf, "FPB1", 4) != 0) {
        return FP_ERR_INVALID;
    }
    memset(out_b, 0, sizeof(*out_b));
    out_b->version = get_be16(buf + 4);
    out_b->entry_count = get_be16(buf + 6);
    uint32_t flags = get_be32(buf + 8);
    if (out_b->version != 1 || flags != 0 ||
        out_b->entry_count == 0 || out_b->entry_count > FP_BUNDLE_MAX_ENTRIES) {
        return FP_ERR_INVALID;
    }

    size_t p = 12u;
    for (uint16_t i = 0; i < out_b->entry_count; i++) {
        if (len - p < 1u + 4u + 8u + FP_DNA_LEN + 2u) return FP_ERR_BOUNDS;
        fp_bundle_entry_t *e = &out_b->entries[i];
        e->role = (fp_bundle_role_t)buf[p++];
        e->mode = get_be32(buf + p); p += 4;
        e->size = get_be64(buf + p); p += 8;
        memcpy(e->dna.bytes, buf + p, FP_DNA_LEN); p += FP_DNA_LEN;
        uint16_t plen = get_be16(buf + p); p += 2;
        if (plen == 0 || plen >= FP_BUNDLE_MAX_PATH || len - p < plen) {
            return FP_ERR_BOUNDS;
        }
        if (memchr(buf + p, '\0', plen) != NULL) {
            return FP_ERR_POLICY; /* Reject embedded NUL byte smuggling in path */
        }
        memcpy(e->path, buf + p, plen);
        e->path[plen] = '\0';
        p += plen;
    }
    if (p != len) return FP_ERR_BOUNDS;
    return validate_bundle(out_b);
}

fp_err_t fp_bundle_pack(const char *store_dir, const fp_bundle_t *b, fp_dna_t *out_bundle_dna) {
    if (!store_dir || !b || !out_bundle_dna) return FP_ERR_INVALID;
    uint8_t *buf = NULL;
    size_t len = 0;
    fp_err_t err = fp_bundle_encode(b, &buf, &len);
    if (err != FP_OK) return err;
    err = fp_store_put_object(store_dir, buf, len, out_bundle_dna);
    free(buf);
    return err;
}

/* --- Atomic Filesystem Staging & Symlink Switch Helpers --- */

static fp_err_t mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return FP_ERR_BOUNDS;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return FP_ERR_IO;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return FP_ERR_IO;
    return FP_OK;
}

static fp_err_t sync_dir_path(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return FP_ERR_IO;
    int rc = fsync(fd);
    close(fd);
    return rc == 0 ? FP_OK : FP_ERR_IO;
}

/* Hardened openat() component-by-component directory traversal (immune to intermediate symlinks / TOCTOU). */
static fp_err_t open_stage_parent_dirfd(int stage_root_fd, const char *rel_path,
                                        int *out_parent_fd, char out_base[FP_BUNDLE_MAX_PATH]) {
    if (!safe_rel_path(rel_path)) return FP_ERR_POLICY;
    int cur = dup(stage_root_fd);
    if (cur < 0) return FP_ERR_IO;

    const char *p = rel_path;
    for (;;) {
        const char *slash = strchr(p, '/');
        if (!slash) {
            size_t blen = strlen(p);
            if (blen == 0 || blen >= FP_BUNDLE_MAX_PATH) { close(cur); return FP_ERR_BOUNDS; }
            memcpy(out_base, p, blen + 1u);
            *out_parent_fd = cur;
            return FP_OK;
        }
        size_t clen = (size_t)(slash - p);
        if (clen == 0 || clen >= FP_BUNDLE_MAX_PATH) { close(cur); return FP_ERR_BOUNDS; }
        char comp[FP_BUNDLE_MAX_PATH];
        memcpy(comp, p, clen);
        comp[clen] = '\0';
        if (mkdirat(cur, comp, 0755) != 0 && errno != EEXIST) {
            close(cur);
            return FP_ERR_IO;
        }
        int next = openat(cur, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (next < 0) {
            close(cur);
            return FP_ERR_POLICY;
        }
        (void)fsync(cur);
        close(cur);
        cur = next;
        p = slash + 1;
    }
}

static fp_err_t write_staged_bytes_at(int stage_root_fd, const char *rel_path, uint32_t mode,
                                      const uint8_t *data, size_t len) {
    int pfd = -1;
    char base[FP_BUNDLE_MAX_PATH];
    fp_err_t err = open_stage_parent_dirfd(stage_root_fd, rel_path, &pfd, base);
    if (err != FP_OK) return err;

    int fd = openat(pfd, base, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                    (mode_t)(mode ? (mode & 0777u) : 0644u));
    if (fd < 0) { close(pfd); return FP_ERR_IO; }
    size_t pos = 0;
    while (pos < len) {
        ssize_t wr = write(fd, data + pos, len - pos);
        if (wr < 0) {
            if (errno == EINTR) continue;
            close(fd); (void)unlinkat(pfd, base, 0); close(pfd);
            return FP_ERR_IO;
        }
        pos += (size_t)wr;
    }
    int sync_ok = (fsync(fd) == 0);
    close(fd);
    if (!sync_ok) { (void)unlinkat(pfd, base, 0); close(pfd); return FP_ERR_IO; }
    sync_ok = (fsync(pfd) == 0);
    close(pfd);
    return sync_ok ? FP_OK : FP_ERR_IO;
}

/* O(1)-RAM multi-GB streaming staging: reads directly from CAS object fd in 64 KiB chunks,
 * computes BLAKE3 Content DNA inline, writes via openat(O_NOFOLLOW), and fails closed on bit-rot. */
static fp_err_t stream_stage_object_at(int stage_root_fd, const char *store_dir,
                                       const fp_bundle_entry_t *e) {
    char obj_path[PATH_MAX];
    uint64_t obj_sz = 0;
    int sfd = fp_store_open_object_fd(store_dir, &e->dna, obj_path, sizeof(obj_path), &obj_sz);
    if (sfd < 0) return FP_ERR_NOT_FOUND;
    if (obj_sz != e->size) {
        close(sfd);
        return FP_ERR_INTEGRITY;
    }

    int pfd = -1;
    char base[FP_BUNDLE_MAX_PATH];
    fp_err_t err = open_stage_parent_dirfd(stage_root_fd, e->path, &pfd, base);
    if (err != FP_OK) { close(sfd); return err; }

    int dfd = openat(pfd, base, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                     (mode_t)(e->mode ? (e->mode & 0777u) : 0644u));
    if (dfd < 0) { close(sfd); close(pfd); return FP_ERR_IO; }

    uint8_t *buf = malloc(BUNDLE_STREAM_BUF);
    if (!buf) {
        close(sfd); close(dfd); (void)unlinkat(pfd, base, 0); close(pfd);
        return FP_ERR_NOMEM;
    }

    fp_dna_stream_t ds;
    fp_dna_stream_init(&ds);
    uint64_t copied = 0;
    err = FP_OK;
    for (;;) {
        ssize_t r = read(sfd, buf, BUNDLE_STREAM_BUF);
        if (r < 0) {
            if (errno == EINTR) continue;
            err = FP_ERR_IO;
            break;
        }
        if (r == 0) break;
        err = fp_dna_stream_update(&ds, buf, (size_t)r);
        if (err != FP_OK) break;
        size_t pos = 0;
        while (pos < (size_t)r) {
            ssize_t w = write(dfd, buf + pos, (size_t)r - pos);
            if (w < 0) {
                if (errno == EINTR) continue;
                err = FP_ERR_IO;
                break;
            }
            pos += (size_t)w;
        }
        if (err != FP_OK) break;
        copied += (uint64_t)r;
    }
    free(buf);
    close(sfd);

    if (err == FP_OK) {
        fp_dna_t actual;
        uint64_t verified_sz = 0;
        err = fp_dna_stream_finish(&ds, &actual, &verified_sz);
        if (err == FP_OK && (copied != e->size || verified_sz != e->size || !fp_dna_equal(&actual, &e->dna))) {
            err = FP_ERR_INTEGRITY;
        }
    }
    if (err == FP_OK && fsync(dfd) != 0) err = FP_ERR_IO;
    close(dfd);
    if (err != FP_OK) {
        (void)unlinkat(pfd, base, 0);
        close(pfd);
        return err;
    }
    if (fsync(pfd) != 0) { close(pfd); return FP_ERR_IO; }
    close(pfd);
    return FP_OK;
}

static fp_err_t atomic_flip_current(const char *target_dir, const char *gen_rel) {
    char link_tmp[PATH_MAX], link_dst[PATH_MAX];
    int n1 = snprintf(link_tmp, sizeof(link_tmp), "%s/.current-new-%ld", target_dir, (long)getpid());
    int n2 = snprintf(link_dst, sizeof(link_dst), "%s/current", target_dir);
    if (n1 < 0 || (size_t)n1 >= sizeof(link_tmp) || n2 < 0 || (size_t)n2 >= sizeof(link_dst)) {
        return FP_ERR_BOUNDS;
    }
    unlink(link_tmp);
    if (symlink(gen_rel, link_tmp) != 0) return FP_ERR_IO;
    if (rename(link_tmp, link_dst) != 0) {
        unlink(link_tmp);
        return FP_ERR_IO;
    }
    return sync_dir_path(target_dir);
}

/* SQLite changeset callbacks */
static int filter_table(void *ctx, const char *zTab) {
    const char *allowed = (const char *)ctx;
    if (strcmp(zTab, "_fp_progress") == 0) return 0;
    return sqlite3_stricmp(zTab, allowed) == 0;
}

static int conflict_abort(void *ctx, int eConflict, sqlite3_changeset_iter *pIter) {
    (void)ctx; (void)eConflict; (void)pIter;
    return SQLITE_CHANGESET_ABORT;
}

static fp_err_t read_progress(fp_sql_ctx_t *sql, uint64_t *out_seq, char out_dna[65]) {
    sqlite3_reset(sql->stmt_get_prog);
    int rc = sqlite3_step(sql->stmt_get_prog);
    if (rc != SQLITE_ROW) {
        sqlite3_reset(sql->stmt_get_prog);
        return FP_ERR_IO;
    }
    *out_seq = (uint64_t)sqlite3_column_int64(sql->stmt_get_prog, 0);
    const char *txt = (const char *)sqlite3_column_text(sql->stmt_get_prog, 1);
    snprintf(out_dna, 65, "%s", txt ? txt : "");
    sqlite3_reset(sql->stmt_get_prog);
    return FP_OK;
}

static fp_err_t write_progress(fp_sql_ctx_t *sql, uint64_t seq, const char *dna_hex) {
    sqlite3_reset(sql->stmt_set_prog);
    sqlite3_bind_int64(sql->stmt_set_prog, 1, (sqlite3_int64)seq);
    sqlite3_bind_text(sql->stmt_set_prog, 2, dna_hex, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(sql->stmt_set_prog);
    sqlite3_reset(sql->stmt_set_prog);
    return rc == SQLITE_DONE ? FP_OK : FP_ERR_IO;
}

static fp_err_t load_and_verify_bundle(const char *store_dir, const fp_dna_t *bundle_dna,
                                       fp_bundle_t *out_b) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    fp_err_t err = fp_store_get_object(store_dir, bundle_dna, 1u << 20, &raw, &raw_len);
    if (err != FP_OK) return err;
    err = fp_bundle_decode(raw, raw_len, out_b);
    free(raw);
    return err;
}

/* --- Target Lifecycle Lock (.sf_lifecycle.lock) + Fail-Closed Crash-Recovery Journal --- */

static int acquire_target_lock(const char *target_dir) {
    if (mkdir_p(target_dir) != FP_OK) return -1;
    char lpath[PATH_MAX];
    int n = snprintf(lpath, sizeof(lpath), "%s/.sf_lifecycle.lock", target_dir);
    if (n < 0 || (size_t)n >= sizeof(lpath)) return -1;
    int fd = open(lpath, O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    while (flock(fd, LOCK_EX) != 0) {
        if (errno == EINTR) continue;
        close(fd);
        return -1;
    }
    return fd;
}

static void release_target_lock(int fd) {
    if (fd >= 0) {
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
}

typedef enum {
    TXJ_NOT_FOUND = 0,
    TXJ_VALID     = 1,
    TXJ_CORRUPTED = 2,
    TXJ_IO_ERROR  = 3
} tx_journal_status_t;

static int is_valid_hex64(const char *s) {
    if (!s || strlen(s) != 64u) return 0;
    for (size_t i = 0; i < 64u; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int is_valid_tx_state(const char *st) {
    return strcmp(st, "STAGING") == 0 ||
           strcmp(st, "ACTIVATION_PENDING") == 0 ||
           strcmp(st, "ROLLBACK_PENDING") == 0 ||
           strcmp(st, "COMMITTED") == 0;
}

static fp_err_t tx_journal_write(const char *target_dir, const char *state,
                                 uint64_t seq, const char *dna_hex, int has_sql) {
    if (mkdir_p(target_dir) != FP_OK) return FP_ERR_IO;
    uint64_t uq = atomic_fetch_add(&g_bundle_tmp_seq, 1) + 1u;
    char tmp[PATH_MAX], dst[PATH_MAX];
    int n1 = snprintf(tmp, sizeof(tmp), "%s/.sf_tx_journal.tmp.%ld.%llu",
                      target_dir, (long)getpid(), (unsigned long long)uq);
    int n2 = snprintf(dst, sizeof(dst), "%s/.sf_tx_journal", target_dir);
    if (n1 < 0 || (size_t)n1 >= sizeof(tmp) || n2 < 0 || (size_t)n2 >= sizeof(dst)) {
        return FP_ERR_BOUNDS;
    }
    char line[256];
    int ln = snprintf(line, sizeof(line), "SFTX1 %s %llu %s %d\n",
                      state, (unsigned long long)seq, dna_hex, has_sql ? 1 : 0);
    if (ln <= 0 || (size_t)ln >= sizeof(line)) return FP_ERR_BOUNDS;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return FP_ERR_IO;
    size_t pos = 0;
    while (pos < (size_t)ln) {
        ssize_t w = write(fd, line + pos, (size_t)ln - pos);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp); return FP_ERR_IO;
        }
        pos += (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return FP_ERR_IO; }
    close(fd);
    if (rename(tmp, dst) != 0) { unlink(tmp); return FP_ERR_IO; }
    return sync_dir_path(target_dir);
}

static tx_journal_status_t tx_journal_read(const char *target_dir, char state_out[32],
                                           uint64_t *seq_out, char dna_out[65], int *has_sql_out) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.sf_tx_journal", target_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return TXJ_IO_ERROR;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? TXJ_NOT_FOUND : TXJ_IO_ERROR;
    }
    char buf[512];
    ssize_t r = read(fd, buf, sizeof(buf) - 1u);
    close(fd);
    if (r <= 0 || (size_t)r >= sizeof(buf) - 1u) return TXJ_CORRUPTED;
    buf[r] = '\0';

    char magic[16], st[32], dna[65], extra[8];
    unsigned long long seq = 0;
    int hsql = -1;
    int got = sscanf(buf, "%15s %31s %llu %64s %d %7s", magic, st, &seq, dna, &hsql, extra);
    if (got != 5 || strcmp(magic, "SFTX1") != 0 || !is_valid_tx_state(st) ||
        !is_valid_hex64(dna) || (hsql != 0 && hsql != 1)) {
        return TXJ_CORRUPTED;
    }
    snprintf(state_out, 32, "%s", st);
    *seq_out = (uint64_t)seq;
    snprintf(dna_out, 65, "%s", dna);
    *has_sql_out = hsql;
    return TXJ_VALID;
}

/* Open a nested relative file inside an already-opened directory fd using O_NOFOLLOW at every component. */
static int open_rel_readonly_nofollow(int root_fd, const char *rel_path) {
    if (!safe_rel_path(rel_path)) return -1;
    int cur = dup(root_fd);
    if (cur < 0) return -1;
    const char *p = rel_path;
    for (;;) {
        const char *slash = strchr(p, '/');
        if (!slash) {
            int ffd = openat(cur, p, O_RDONLY | O_NOFOLLOW);
            close(cur);
            return ffd;
        }
        size_t clen = (size_t)(slash - p);
        if (clen == 0 || clen >= FP_BUNDLE_MAX_PATH) { close(cur); return -1; }
        char comp[FP_BUNDLE_MAX_PATH];
        memcpy(comp, p, clen);
        comp[clen] = '\0';
        int next = openat(cur, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        close(cur);
        if (next < 0) return -1;
        cur = next;
        p = slash + 1;
    }
}

/* Cryptographically verify an immutable sealed generation directory:
 * checks `.sf_gen_sealed` contents == dna_hex, openat(O_NOFOLLOW) traversal, file mode,
 * exact size, and streaming BLAKE3 Content DNA of EVERY FP_ROLE_FILE entry! */
static int verify_sealed_generation(const fp_bundle_t *b, const char *gen_dir,
                                    const char *expected_dna_hex) {
    int gfd = open(gen_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (gfd < 0) return 0;

    int sfd = openat(gfd, ".sf_gen_sealed", O_RDONLY | O_NOFOLLOW);
    if (sfd < 0) { close(gfd); return 0; }
    char seal_buf[72];
    ssize_t sr = read(sfd, seal_buf, sizeof(seal_buf) - 1u);
    close(sfd);
    if (sr != 64) { close(gfd); return 0; }
    seal_buf[64] = '\0';
    if (expected_dna_hex && memcmp(seal_buf, expected_dna_hex, 64u) != 0) {
        close(gfd);
        return 0;
    }

    uint8_t *buf = malloc(BUNDLE_STREAM_BUF);
    if (!buf) { close(gfd); return 0; }

    int ok = 1;
    for (uint16_t i = 0; i < b->entry_count && ok; i++) {
        if (b->entries[i].role != FP_ROLE_FILE) continue;
        int ffd = open_rel_readonly_nofollow(gfd, b->entries[i].path);
        if (ffd < 0) { ok = 0; break; }
        struct stat sb;
        mode_t exp_mode = (mode_t)(b->entries[i].mode ? (b->entries[i].mode & 0777u) : 0644u);
        if (fstat(ffd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
            (uint64_t)sb.st_size != b->entries[i].size ||
            (sb.st_mode & 0777u) != exp_mode) {
            close(ffd);
            ok = 0;
            break;
        }
        fp_dna_stream_t ds;
        fp_dna_stream_init(&ds);
        uint64_t total = 0;
        for (;;) {
            ssize_t r = read(ffd, buf, BUNDLE_STREAM_BUF);
            if (r < 0) { if (errno == EINTR) continue; ok = 0; break; }
            if (r == 0) break;
            if (fp_dna_stream_update(&ds, buf, (size_t)r) != FP_OK) { ok = 0; break; }
            total += (uint64_t)r;
        }
        close(ffd);
        if (ok) {
            fp_dna_t actual;
            uint64_t vsz = 0;
            if (fp_dna_stream_finish(&ds, &actual, &vsz) != FP_OK ||
                total != b->entries[i].size || vsz != b->entries[i].size ||
                !fp_dna_equal(&actual, &b->entries[i].dna)) {
                ok = 0;
            }
        }
    }
    free(buf);
    close(gfd);
    return ok;
}

/* Immutable generation staging: if gen/<dna> is already sealed & cryptographically verified, never mutate in place.
 * Otherwise stage into a unique temporary dir, seal it, and atomically rename into gen/<dna>. */
static fp_err_t stage_bundle_files(const char *store_dir, const fp_bundle_t *b,
                                   const char *target_dir, const char *dna_hex) {
    uint64_t uq = atomic_fetch_add(&g_bundle_tmp_seq, 1) + 1u;
    char gen_root[PATH_MAX], gen_dir[PATH_MAX], stage_dir[PATH_MAX];
    int rn = snprintf(gen_root, sizeof(gen_root), "%s/gen", target_dir);
    int gn = snprintf(gen_dir, sizeof(gen_dir), "%s/gen/%s", target_dir, dna_hex);
    int tn = snprintf(stage_dir, sizeof(stage_dir), "%s/gen/.stage-%s-%ld-%llu",
                      target_dir, dna_hex, (long)getpid(), (unsigned long long)uq);
    if (rn < 0 || (size_t)rn >= sizeof(gen_root) ||
        gn < 0 || (size_t)gn >= sizeof(gen_dir) ||
        tn < 0 || (size_t)tn >= sizeof(stage_dir)) {
        return FP_ERR_BOUNDS;
    }
    if (mkdir_p(gen_root) != FP_OK) return FP_ERR_IO;

    /* Immutable generation fast path: cryptographically verified before reuse! */
    if (verify_sealed_generation(b, gen_dir, dna_hex)) {
        return FP_OK;
    }

    if (mkdir(stage_dir, 0755) != 0) return FP_ERR_IO;
    int stage_fd = open(stage_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (stage_fd < 0) return FP_ERR_IO;

    for (uint16_t i = 0; i < b->entry_count; i++) {
        if (b->entries[i].role != FP_ROLE_FILE) continue;
        fp_err_t err = stream_stage_object_at(stage_fd, store_dir, &b->entries[i]);
        if (err != FP_OK) {
            close(stage_fd);
            return err;
        }
    }

    /* Write generation seal marker before atomic publication */
    fp_err_t serr = write_staged_bytes_at(stage_fd, ".sf_gen_sealed", 0644,
                                          (const uint8_t *)dna_hex, strlen(dna_hex));
    int sync_ok = (serr == FP_OK && fsync(stage_fd) == 0);
    close(stage_fd);
    if (!sync_ok) return serr != FP_OK ? serr : FP_ERR_IO;

    /* Publish generation directory atomically; if a corrupt/unsealed dir exists at gen_dir, move aside first */
    if (rename(stage_dir, gen_dir) != 0) {
        if (verify_sealed_generation(b, gen_dir, dna_hex)) {
            return FP_OK;
        }
        char stale[PATH_MAX];
        int stn = snprintf(stale, sizeof(stale), "%s/gen/.stale-%s-%ld-%llu",
                           target_dir, dna_hex, (long)getpid(), (unsigned long long)uq);
        if (stn < 0 || (size_t)stn >= sizeof(stale)) return FP_ERR_BOUNDS;
        (void)rename(gen_dir, stale);
        if (rename(stage_dir, gen_dir) != 0) return FP_ERR_IO;
    }
    return sync_dir_path(gen_root);
}

static fp_err_t bundle_recover_locked(const char *store_dir, const char *target_dir,
                                      fp_sql_ctx_t *sql_ctx) {
    char state[32], dna_hex[65];
    uint64_t jseq = 0;
    int has_sql = 0;
    tx_journal_status_t js = tx_journal_read(target_dir, state, &jseq, dna_hex, &has_sql);
    if (js == TXJ_NOT_FOUND) return FP_OK;
    if (js == TXJ_IO_ERROR) return FP_ERR_IO;
    if (js == TXJ_CORRUPTED) return FP_ERR_INTEGRITY; /* Fail-closed: preserve corrupt journal evidence! */

    if (strcmp(state, "COMMITTED") == 0) {
        return FP_OK;
    }
    if (strcmp(state, "ACTIVATION_PENDING") == 0 || strcmp(state, "ROLLBACK_PENDING") == 0) {
        int db_committed = 0;
        if (has_sql) {
            if (!sql_ctx) return FP_ERR_INVALID;
            uint64_t cur_seq = 0;
            char cur_dna[65];
            fp_err_t err = read_progress(sql_ctx, &cur_seq, cur_dna);
            if (err != FP_OK) return err;
            if (cur_seq == jseq && strcmp(cur_dna, dna_hex) == 0) {
                db_committed = 1;
            }
        }
        if (db_committed) {
            /* SQLite already committed (apply or rollback) before crash: reconcile symlink forward! */
            char gen_dir[PATH_MAX], rel[128];
            int gn = snprintf(gen_dir, sizeof(gen_dir), "%s/gen/%s", target_dir, dna_hex);
            if (gn < 0 || (size_t)gn >= sizeof(gen_dir)) return FP_ERR_BOUNDS;
            fp_dna_t bdna;
            if (fp_hex_decode(dna_hex, bdna.bytes, FP_DNA_LEN) != FP_OK) return FP_ERR_INTEGRITY;
            fp_bundle_t b;
            fp_err_t err = load_and_verify_bundle(store_dir, &bdna, &b);
            if (err != FP_OK) return err;
            if (!verify_sealed_generation(&b, gen_dir, dna_hex)) {
                err = stage_bundle_files(store_dir, &b, target_dir, dna_hex);
                if (err != FP_OK) return err;
            }
            snprintf(rel, sizeof(rel), "gen/%s", dna_hex);
            err = atomic_flip_current(target_dir, rel);
            if (err != FP_OK) return err;
            return tx_journal_write(target_dir, "COMMITTED", jseq, dna_hex, has_sql);
        }
        /* Interrupted BEFORE SQLite commit (or non-SQL before flip): abort pending intent cleanly */
        char jpath[PATH_MAX];
        int jn = snprintf(jpath, sizeof(jpath), "%s/.sf_tx_journal", target_dir);
        if (jn > 0 && (size_t)jn < sizeof(jpath)) {
            if (unlink(jpath) != 0 && errno != ENOENT) return FP_ERR_IO;
            (void)sync_dir_path(target_dir);
        }
        return FP_OK;
    }
    if (strcmp(state, "STAGING") == 0) {
        char jpath[PATH_MAX];
        int jn = snprintf(jpath, sizeof(jpath), "%s/.sf_tx_journal", target_dir);
        if (jn > 0 && (size_t)jn < sizeof(jpath)) {
            if (unlink(jpath) != 0 && errno != ENOENT) return FP_ERR_IO;
            (void)sync_dir_path(target_dir);
        }
        return FP_OK;
    }
    return FP_ERR_INTEGRITY;
}

fp_err_t fp_bundle_recover(const char *store_dir, const char *target_dir,
                           fp_sql_ctx_t *sql_ctx) {
    if (!store_dir || !target_dir) return FP_ERR_INVALID;
    int lfd = acquire_target_lock(target_dir);
    if (lfd < 0) return FP_ERR_IO;
    fp_err_t err = bundle_recover_locked(store_dir, target_dir, sql_ctx);
    release_target_lock(lfd);
    return err;
}

fp_err_t fp_bundle_apply(const char *store_dir, const fp_dna_t *bundle_dna,
                         const char *target_dir, fp_sql_ctx_t *sql_ctx,
                         uint64_t expected_seq, int fault_mode) {
    if (!store_dir || !bundle_dna || !target_dir) return FP_ERR_INVALID;

    int lfd = acquire_target_lock(target_dir);
    if (lfd < 0) return FP_ERR_IO;

    /* Reconcile any prior interrupted transaction deterministically before starting */
    fp_err_t rec_err = bundle_recover_locked(store_dir, target_dir, sql_ctx);
    if (rec_err != FP_OK) { release_target_lock(lfd); return rec_err; }

    fp_bundle_t b;
    fp_err_t err = load_and_verify_bundle(store_dir, bundle_dna, &b);
    if (err != FP_OK) { release_target_lock(lfd); return err; }

    /* Pre-verify aggregate changeset memory budget BEFORE allocating any buffers (RES-02) */
    int has_sql = 0;
    uint64_t total_cs_bytes = 0;
    for (uint16_t i = 0; i < b.entry_count; i++) {
        if (b.entries[i].role == FP_ROLE_SQLITE_CHANGESET) {
            has_sql = 1;
            if (b.entries[i].size > BUNDLE_MAX_CHANGESET ||
                total_cs_bytes > BUNDLE_MAX_TOTAL_CHANGESETS - b.entries[i].size) {
                release_target_lock(lfd);
                return FP_ERR_BOUNDS;
            }
            total_cs_bytes += b.entries[i].size;
        }
    }
    if (has_sql && !sql_ctx) { release_target_lock(lfd); return FP_ERR_INVALID; }

    uint8_t *cs_blobs[FP_BUNDLE_MAX_ENTRIES];
    size_t   cs_lens[FP_BUNDLE_MAX_ENTRIES];
    memset(cs_blobs, 0, sizeof(cs_blobs));
    memset(cs_lens, 0, sizeof(cs_lens));

    for (uint16_t i = 0; i < b.entry_count; i++) {
        if (b.entries[i].role == FP_ROLE_SQLITE_CHANGESET) {
            err = fp_store_get_object(store_dir, &b.entries[i].dna, BUNDLE_MAX_CHANGESET,
                                      &cs_blobs[i], &cs_lens[i]);
            if (err != FP_OK || cs_lens[i] != b.entries[i].size) {
                err = err != FP_OK ? err : FP_ERR_INTEGRITY;
                goto cleanup;
            }
        }
    }

    char dna_hex[65];
    fp_hex_encode(bundle_dna->bytes, FP_DNA_LEN, dna_hex);

    /* Check SQLite progress BEFORE staging so an already-committed generation is never re-staged */
    int sql_already_committed = 0;
    if (has_sql) {
        uint64_t cur_seq = 0;
        char cur_dna[65];
        err = read_progress(sql_ctx, &cur_seq, cur_dna);
        if (err != FP_OK) goto cleanup;
        if (cur_seq == expected_seq && strcmp(cur_dna, dna_hex) == 0) {
            sql_already_committed = 1;
        } else if (expected_seq <= cur_seq) {
            err = FP_ERR_CHAIN;
            goto cleanup;
        }
    }

    /* Record STAGING intent and publish immutable sealed generation dir (does NOT touch `current`!) */
    err = tx_journal_write(target_dir, "STAGING", expected_seq, dna_hex, has_sql);
    if (err != FP_OK) goto cleanup;

    err = stage_bundle_files(store_dir, &b, target_dir, dna_hex);
    if (err != FP_OK) goto cleanup;

    /* Persist ACTIVATION_PENDING journal BEFORE SQLite COMMIT so any crash after COMMIT recovers forward */
    err = tx_journal_write(target_dir, "ACTIVATION_PENDING", expected_seq, dna_hex, has_sql);
    if (err != FP_OK) goto cleanup;

    /* Apply SQLite changesets in ONE atomic WAL transaction */
    if (has_sql && !sql_already_committed) {
        if (sqlite3_exec(sql_ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            err = FP_ERR_IO;
            goto cleanup;
        }
        uint64_t cur_seq = 0;
        char cur_dna[65];
        err = read_progress(sql_ctx, &cur_seq, cur_dna);
        if (err == FP_OK) {
            if (cur_seq == expected_seq && strcmp(cur_dna, dna_hex) == 0) {
                (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
            } else if (expected_seq <= cur_seq) {
                (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
                err = FP_ERR_CHAIN;
            } else {
                for (uint16_t i = 0; i < b.entry_count && err == FP_OK; i++) {
                    if (b.entries[i].role != FP_ROLE_SQLITE_CHANGESET) continue;
                    int rc = sqlite3changeset_apply(sql_ctx->db, (int)cs_lens[i], cs_blobs[i],
                                                    filter_table, conflict_abort,
                                                    (void *)b.entries[i].path);
                    if (rc != SQLITE_OK) err = FP_ERR_INTEGRITY;
                }
                if (err == FP_OK) {
                    err = write_progress(sql_ctx, expected_seq, dna_hex);
                }
                if (err == FP_OK && fault_mode == 1) {
                    raise(SIGKILL); /* Fault 1: OS SIGKILL BEFORE SQLite COMMIT */
                }
                if (err == FP_OK) {
                    if (sqlite3_exec(sql_ctx->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
                        err = FP_ERR_IO;
                    }
                } else {
                    (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
                }
            }
        } else {
            (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
        }
        if (err != FP_OK) goto cleanup;
    }

    if (fault_mode == 2) {
        raise(SIGKILL); /* Fault 2: OS SIGKILL AFTER SQLite COMMIT, BEFORE `current` symlink flip */
    }

    /* Atomic POSIX symlink flip: activates the new generation in 1 atomic operation */
    char rel[128];
    snprintf(rel, sizeof(rel), "gen/%s", dna_hex);
    err = atomic_flip_current(target_dir, rel);
    if (err != FP_OK) goto cleanup;

    if (fault_mode == 3) {
        raise(SIGKILL); /* Fault 3: OS SIGKILL AFTER `current` flip, BEFORE journal COMMITTED */
    }

    err = tx_journal_write(target_dir, "COMMITTED", expected_seq, dna_hex, has_sql);

cleanup:
    for (uint16_t i = 0; i < FP_BUNDLE_MAX_ENTRIES; i++) free(cs_blobs[i]);
    release_target_lock(lfd);
    return err;
}

fp_err_t fp_bundle_rollback(const char *store_dir,
                            const fp_dna_t *current_bundle_dna,
                            const fp_dna_t *prev_bundle_dna,
                            const char *target_dir, fp_sql_ctx_t *sql_ctx) {
    if (!store_dir || !current_bundle_dna || !prev_bundle_dna || !target_dir) {
        return FP_ERR_INVALID;
    }
    int lfd = acquire_target_lock(target_dir);
    if (lfd < 0) return FP_ERR_IO;

    fp_err_t err = bundle_recover_locked(store_dir, target_dir, sql_ctx);
    if (err != FP_OK) { release_target_lock(lfd); return err; }

    fp_bundle_t cur_b, prev_b;
    err = load_and_verify_bundle(store_dir, current_bundle_dna, &cur_b);
    if (err != FP_OK) { release_target_lock(lfd); return err; }
    err = load_and_verify_bundle(store_dir, prev_bundle_dna, &prev_b);
    if (err != FP_OK) { release_target_lock(lfd); return err; }

    char cur_hex[65], prev_hex[65];
    fp_hex_encode(current_bundle_dna->bytes, FP_DNA_LEN, cur_hex);
    fp_hex_encode(prev_bundle_dna->bytes, FP_DNA_LEN, prev_hex);

    /* Ensure previous generation files are present and cryptographically verified */
    err = stage_bundle_files(store_dir, &prev_b, target_dir, prev_hex);
    if (err != FP_OK) { release_target_lock(lfd); return err; }

    int has_sql = 0;
    uint64_t total_cs = 0;
    for (uint16_t i = 0; i < cur_b.entry_count; i++) {
        if (cur_b.entries[i].role == FP_ROLE_SQLITE_CHANGESET) {
            has_sql = 1;
            if (cur_b.entries[i].size > BUNDLE_MAX_CHANGESET ||
                total_cs > BUNDLE_MAX_TOTAL_CHANGESETS - cur_b.entries[i].size) {
                release_target_lock(lfd);
                return FP_ERR_BOUNDS;
            }
            total_cs += cur_b.entries[i].size;
        }
    }

    uint64_t target_seq = 0;
    if (has_sql) {
        if (!sql_ctx) { release_target_lock(lfd); return FP_ERR_INVALID; }
        uint64_t pre_seq = 0;
        char pre_dna[65];
        err = read_progress(sql_ctx, &pre_seq, pre_dna);
        if (err != FP_OK) { release_target_lock(lfd); return err; }
        if (pre_seq == 0 || strcmp(pre_dna, cur_hex) != 0) {
            release_target_lock(lfd);
            return FP_ERR_CHAIN;
        }
        target_seq = pre_seq - 1u;
    }

    /* P0-01: Persist ROLLBACK_PENDING intent BEFORE SQLite COMMIT so any crash recovers forward! */
    err = tx_journal_write(target_dir, "ROLLBACK_PENDING", target_seq, prev_hex, has_sql);
    if (err != FP_OK) { release_target_lock(lfd); return err; }

    if (has_sql) {
        if (sqlite3_exec(sql_ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            release_target_lock(lfd);
            return FP_ERR_IO;
        }
        uint64_t seq = 0;
        char active_dna[65];
        err = read_progress(sql_ctx, &seq, active_dna);
        if (err == FP_OK && (seq == 0 || strcmp(active_dna, cur_hex) != 0)) {
            err = FP_ERR_CHAIN;
        }
        /* Invert and apply each changeset in reverse order */
        for (int i = (int)cur_b.entry_count - 1; i >= 0 && err == FP_OK; i--) {
            if (cur_b.entries[i].role != FP_ROLE_SQLITE_CHANGESET) continue;
            uint8_t *cs = NULL;
            size_t cs_len = 0;
            err = fp_store_get_object(store_dir, &cur_b.entries[i].dna, BUNDLE_MAX_CHANGESET,
                                      &cs, &cs_len);
            if (err != FP_OK) break;

            int inv_len = 0;
            void *inv = NULL;
            int rc = sqlite3changeset_invert((int)cs_len, cs, &inv_len, &inv);
            free(cs);
            if (rc != SQLITE_OK) { err = FP_ERR_INTEGRITY; break; }

            rc = sqlite3changeset_apply(sql_ctx->db, inv_len, inv,
                                        filter_table, conflict_abort,
                                        (void *)cur_b.entries[i].path);
            sqlite3_free(inv);
            if (rc != SQLITE_OK) { err = FP_ERR_INTEGRITY; break; }
        }
        if (err == FP_OK) {
            target_seq = seq - 1u;
            err = write_progress(sql_ctx, target_seq, prev_hex);
        }
        if (err == FP_OK) {
            if (sqlite3_exec(sql_ctx->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
                err = FP_ERR_IO;
            }
        } else {
            (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
        }
        if (err != FP_OK) { release_target_lock(lfd); return err; }
    }

    char rel[128];
    snprintf(rel, sizeof(rel), "gen/%s", prev_hex);
    err = atomic_flip_current(target_dir, rel);
    if (err == FP_OK) {
        err = tx_journal_write(target_dir, "COMMITTED", target_seq, prev_hex, has_sql);
    }
    release_target_lock(lfd);
    return err;
}

/* Safe recursive directory removal via openat(O_NOFOLLOW) — never follows symlinks */
static int rm_rf_at(int parent_fd, const char *name, int depth) {
    if (depth > 32) return -1;
    struct stat sb;
    if (fstatat(parent_fd, name, &sb, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISDIR(sb.st_mode)) {
        return unlinkat(parent_fd, name, 0);
    }
    int dfd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dfd < 0) return -1;
    DIR *dir = fdopendir(dfd);
    if (!dir) { close(dfd); return -1; }
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        (void)rm_rf_at(dfd, de->d_name, depth + 1);
    }
    closedir(dir); /* closes dfd */
    return unlinkat(parent_fd, name, AT_REMOVEDIR);
}

typedef struct {
    char   name[128];
    time_t mtime;
} gc_gen_entry_t;

static int cmp_gc_gen_desc(const void *a, const void *b) {
    const gc_gen_entry_t *ga = (const gc_gen_entry_t *)a;
    const gc_gen_entry_t *gb = (const gc_gen_entry_t *)b;
    if (gb->mtime > ga->mtime) return 1;
    if (gb->mtime < ga->mtime) return -1;
    return strcmp(gb->name, ga->name);
}

fp_err_t fp_bundle_gc(const char *target_dir, uint32_t keep_last, uint32_t *out_removed) {
    if (out_removed) *out_removed = 0;
    if (!target_dir || !target_dir[0]) return FP_ERR_INVALID;

    int lfd = acquire_target_lock(target_dir);
    if (lfd < 0) return FP_ERR_IO;

    /* Protect active generation (`current`) AND any generation referenced by `.sf_tx_journal` */
    char cur_link[PATH_MAX], active_target[PATH_MAX], active_gen[128];
    active_gen[0] = '\0';
    int n = snprintf(cur_link, sizeof(cur_link), "%s/current", target_dir);
    if (n < 0 || (size_t)n >= sizeof(cur_link)) { release_target_lock(lfd); return FP_ERR_BOUNDS; }
    ssize_t rl = readlink(cur_link, active_target, sizeof(active_target) - 1u);
    if (rl > 0) {
        active_target[rl] = '\0';
        const char *slash = strrchr(active_target, '/');
        snprintf(active_gen, sizeof(active_gen), "%.127s", slash ? slash + 1 : active_target);
    }

    char jstate[32], jdna[65];
    uint64_t jseq = 0;
    int jsql = 0;
    jdna[0] = '\0';
    tx_journal_status_t js = tx_journal_read(target_dir, jstate, &jseq, jdna, &jsql);
    if (js == TXJ_CORRUPTED || js == TXJ_IO_ERROR) {
        release_target_lock(lfd);
        return js == TXJ_CORRUPTED ? FP_ERR_INTEGRITY : FP_ERR_IO;
    }

    char gen_root[PATH_MAX];
    n = snprintf(gen_root, sizeof(gen_root), "%s/gen", target_dir);
    if (n < 0 || (size_t)n >= sizeof(gen_root)) { release_target_lock(lfd); return FP_ERR_BOUNDS; }
    int gfd = open(gen_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (gfd < 0) {
        int e = errno;
        release_target_lock(lfd);
        return e == ENOENT ? FP_OK : FP_ERR_IO;
    }

    DIR *dir = fdopendir(gfd);
    if (!dir) { close(gfd); release_target_lock(lfd); return FP_ERR_IO; }

    gc_gen_entry_t *gens = NULL;
    size_t gcnt = 0, gcap = 0;
    uint32_t removed = 0;
    int io_err = 0;

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        const char *nm = de->d_name;
        if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0) continue;
        if (strncmp(nm, ".stage-", 7) == 0 || strncmp(nm, ".stale-", 7) == 0) {
            if (rm_rf_at(gfd, nm, 0) == 0) removed++;
            else io_err = 1;
            continue;
        }
        if (active_gen[0] && strcmp(nm, active_gen) == 0) continue;
        if (jdna[0] && strcmp(nm, jdna) == 0) continue;
        if (strlen(nm) == 64u) {
            struct stat sb;
            if (fstatat(gfd, nm, &sb, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(sb.st_mode)) {
                if (gcnt == gcap) {
                    size_t ncap = gcap ? gcap * 2u : 16u;
                    gc_gen_entry_t *ng = realloc(gens, ncap * sizeof(*ng));
                    if (!ng) { free(gens); closedir(dir); release_target_lock(lfd); return FP_ERR_NOMEM; }
                    gens = ng; gcap = ncap;
                }
                snprintf(gens[gcnt].name, sizeof(gens[gcnt].name), "%.127s", nm);
                gens[gcnt].mtime = sb.st_mtime;
                gcnt++;
            }
        }
    }

    if (gcnt > (size_t)keep_last) {
        qsort(gens, gcnt, sizeof(*gens), cmp_gc_gen_desc);
        for (size_t i = (size_t)keep_last; i < gcnt; i++) {
            if (rm_rf_at(gfd, gens[i].name, 0) == 0) removed++;
            else io_err = 1;
        }
    }
    free(gens);
    if (fsync(gfd) != 0) io_err = 1;
    closedir(dir);
    release_target_lock(lfd);
    if (out_removed) *out_removed = removed;
    return io_err ? FP_ERR_IO : FP_OK;
}
