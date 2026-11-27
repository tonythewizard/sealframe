#define _POSIX_C_SOURCE 200809L
#define SQLITE_ENABLE_SESSION 1

#include "fp.h"

#include <blake3.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BUNDLE_MAX_OBJECT (64u << 20)

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

static fp_err_t write_staged_file(const char *full_path, uint32_t mode,
                                  const uint8_t *data, size_t len) {
    char parent[PATH_MAX];
    int n = snprintf(parent, sizeof(parent), "%s", full_path);
    if (n < 0 || (size_t)n >= sizeof(parent)) return FP_ERR_BOUNDS;
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        if (mkdir_p(parent) != FP_OK) return FP_ERR_IO;
    }

    unlink(full_path);
    int fd = open(full_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                  (mode_t)(mode ? (mode & 0777u) : 0644u));
    if (fd < 0) return FP_ERR_IO;
    size_t pos = 0;
    while (pos < len) {
        ssize_t wr = write(fd, data + pos, len - pos);
        if (wr < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return FP_ERR_IO;
        }
        pos += (size_t)wr;
    }
    if (fsync(fd) != 0) { close(fd); return FP_ERR_IO; }
    close(fd);
    return sync_dir_path(parent);
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

static fp_err_t stage_bundle_files(const char *store_dir, const fp_bundle_t *b,
                                   const char *target_dir, const char *dna_hex) {
    char gen_dir[PATH_MAX];
    int gn = snprintf(gen_dir, sizeof(gen_dir), "%s/gen/%s", target_dir, dna_hex);
    if (gn < 0 || (size_t)gn >= sizeof(gen_dir)) return FP_ERR_BOUNDS;
    if (mkdir_p(gen_dir) != FP_OK) return FP_ERR_IO;

    for (uint16_t i = 0; i < b->entry_count; i++) {
        if (b->entries[i].role != FP_ROLE_FILE) continue;
        uint8_t *data = NULL;
        size_t len = 0;
        fp_err_t err = fp_store_get_object(store_dir, &b->entries[i].dna, BUNDLE_MAX_OBJECT,
                                           &data, &len);
        if (err != FP_OK) return err;
        if (len != b->entries[i].size) { free(data); return FP_ERR_INTEGRITY; }

        char fpath[PATH_MAX];
        int fn = snprintf(fpath, sizeof(fpath), "%s/%s", gen_dir, b->entries[i].path);
        if (fn < 0 || (size_t)fn >= sizeof(fpath)) { free(data); return FP_ERR_BOUNDS; }
        err = write_staged_file(fpath, b->entries[i].mode, data, len);
        free(data);
        if (err != FP_OK) return err;
    }
    return sync_dir_path(gen_dir);
}

fp_err_t fp_bundle_apply(const char *store_dir, const fp_dna_t *bundle_dna,
                         const char *target_dir, fp_sql_ctx_t *sql_ctx,
                         uint64_t expected_seq, int fault_sigkill_before_commit) {
    if (!store_dir || !bundle_dna || !target_dir) return FP_ERR_INVALID;

    fp_bundle_t b;
    fp_err_t err = load_and_verify_bundle(store_dir, bundle_dna, &b);
    if (err != FP_OK) return err;

    /* Pre-verify ALL member atoms before mutating anything */
    int has_sql = 0;
    uint8_t *cs_blobs[FP_BUNDLE_MAX_ENTRIES];
    size_t   cs_lens[FP_BUNDLE_MAX_ENTRIES];
    memset(cs_blobs, 0, sizeof(cs_blobs));
    memset(cs_lens, 0, sizeof(cs_lens));

    for (uint16_t i = 0; i < b.entry_count; i++) {
        if (b.entries[i].role == FP_ROLE_SQLITE_CHANGESET) {
            has_sql = 1;
            err = fp_store_get_object(store_dir, &b.entries[i].dna, BUNDLE_MAX_OBJECT,
                                      &cs_blobs[i], &cs_lens[i]);
            if (err != FP_OK || cs_lens[i] != b.entries[i].size) {
                err = err != FP_OK ? err : FP_ERR_INTEGRITY;
                goto cleanup;
            }
        }
    }
    if (has_sql && !sql_ctx) {
        err = FP_ERR_INVALID;
        goto cleanup;
    }

    char dna_hex[65];
    fp_hex_encode(bundle_dna->bytes, FP_DNA_LEN, dna_hex);

    /* Stage all files into isolated generation dir (does NOT touch live `current` yet!) */
    err = stage_bundle_files(store_dir, &b, target_dir, dna_hex);
    if (err != FP_OK) goto cleanup;

    /* Apply SQLite changesets in ONE atomic WAL transaction */
    if (has_sql) {
        if (sqlite3_exec(sql_ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            err = FP_ERR_IO;
            goto cleanup;
        }
        uint64_t cur_seq = 0;
        char cur_dna[65];
        err = read_progress(sql_ctx, &cur_seq, cur_dna);
        if (err == FP_OK) {
            if (cur_seq == expected_seq && strcmp(cur_dna, dna_hex) == 0) {
                /* Already committed cleanly before a prior crash: idempotent resume! */
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
                if (err == FP_OK && fault_sigkill_before_commit) {
                    raise(SIGKILL); /* Abrupt OS process kill BEFORE COMMIT! */
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

    /* Atomic POSIX symlink flip: activates the new generation in 1 atomic operation */
    char rel[128];
    snprintf(rel, sizeof(rel), "gen/%s", dna_hex);
    err = atomic_flip_current(target_dir, rel);

cleanup:
    for (uint16_t i = 0; i < FP_BUNDLE_MAX_ENTRIES; i++) free(cs_blobs[i]);
    return err;
}

fp_err_t fp_bundle_rollback(const char *store_dir,
                            const fp_dna_t *current_bundle_dna,
                            const fp_dna_t *prev_bundle_dna,
                            const char *target_dir, fp_sql_ctx_t *sql_ctx) {
    if (!store_dir || !current_bundle_dna || !prev_bundle_dna || !target_dir) {
        return FP_ERR_INVALID;
    }
    fp_bundle_t cur_b, prev_b;
    fp_err_t err = load_and_verify_bundle(store_dir, current_bundle_dna, &cur_b);
    if (err != FP_OK) return err;
    err = load_and_verify_bundle(store_dir, prev_bundle_dna, &prev_b);
    if (err != FP_OK) return err;

    char cur_hex[65], prev_hex[65];
    fp_hex_encode(current_bundle_dna->bytes, FP_DNA_LEN, cur_hex);
    fp_hex_encode(prev_bundle_dna->bytes, FP_DNA_LEN, prev_hex);

    /* Ensure previous generation files are present and verified */
    err = stage_bundle_files(store_dir, &prev_b, target_dir, prev_hex);
    if (err != FP_OK) return err;

    int has_sql = 0;
    for (uint16_t i = 0; i < cur_b.entry_count; i++) {
        if (cur_b.entries[i].role == FP_ROLE_SQLITE_CHANGESET) { has_sql = 1; break; }
    }

    if (has_sql) {
        if (!sql_ctx) return FP_ERR_INVALID;
        if (sqlite3_exec(sql_ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
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
            err = fp_store_get_object(store_dir, &cur_b.entries[i].dna, BUNDLE_MAX_OBJECT,
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
            err = write_progress(sql_ctx, seq - 1u, prev_hex);
        }
        if (err == FP_OK) {
            if (sqlite3_exec(sql_ctx->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
                err = FP_ERR_IO;
            }
        } else {
            (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
        }
        if (err != FP_OK) return err;
    }

    char rel[128];
    snprintf(rel, sizeof(rel), "gen/%s", prev_hex);
    return atomic_flip_current(target_dir, rel);
}
