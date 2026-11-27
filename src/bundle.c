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
    /* SEC-01: Reserve entire `_fp_` internal namespace case-insensitively (matches SQLite semantics) */
    if (sqlite3_strnicmp(name, "_fp_", 4) == 0) return 0;
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
        "INSERT OR IGNORE INTO _fp_progress(id, seq, bundle_dna) VALUES (1, 0, '');"
        "CREATE TABLE IF NOT EXISTS _fp_sql_history ("
        "  seq INTEGER PRIMARY KEY,"
        "  bundle_dna TEXT NOT NULL,"
        "  prev_dna TEXT NOT NULL,"
        "  prev_seq INTEGER NOT NULL"
        ");";

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

/* A7-P0-01: Schema-bound changeset envelope (`SFCS1`) binds the exact destination table
 * schema (column order, names, types, notnull, defaults, PK positions) via BLAKE3-256 so
 * SQLite Session's positional column format can NEVER silently swap reordered columns.
 * Legacy raw SQLite changeset blobs remain readable for backward compatibility. */
#define SFCS1_MAGIC     "SFCS1"
#define SFCS1_MAGIC_LEN 5u
#define SFCS1_HDR_LEN   42u /* 5 magic + 1 flags + 32 schema_hash + 4 raw_len BE */

static void blake3_update_ascii_lower(blake3_hasher *h, const char *s, size_t len) {
    uint8_t buf[128];
    size_t pos = 0;
    while (pos < len) {
        size_t chunk = len - pos;
        if (chunk > sizeof(buf)) chunk = sizeof(buf);
        for (size_t i = 0; i < chunk; i++) {
            unsigned char c = (unsigned char)s[pos + i];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
            buf[i] = c;
        }
        blake3_hasher_update(h, buf, chunk);
        pos += chunk;
    }
}

static fp_err_t compute_table_schema_hash(sqlite3 *db, const char *table_name,
                                          uint8_t out_hash[FP_DNA_LEN],
                                          uint32_t *out_col_count,
                                          uint32_t *out_trigger_count) {
    if (out_col_count) *out_col_count = 0;
    if (out_trigger_count) *out_trigger_count = 0;
    if (!db || !table_name || !out_hash || !safe_ident(table_name)) return FP_ERR_INVALID;

    /* A8-P0-01 + A8-P1-02: Use PRAGMA table_xinfo (includes hidden/generated columns) AND bind
     * canonical table DDL + all dependent indexes & triggers from sqlite_master into the BLAKE3
     * schema hash so COLLATE, CHECK, UNIQUE, FK, STRICT, WITHOUT ROWID & triggers cannot diverge! */
    char pragma_sql[192];
    if (snprintf(pragma_sql, sizeof(pragma_sql), "PRAGMA table_xinfo(\"%s\");", table_name) >= (int)sizeof(pragma_sql)) {
        return FP_ERR_BOUNDS;
    }
    sqlite3_stmt *ps = NULL;
    if (sqlite3_prepare_v2(db, pragma_sql, -1, &ps, NULL) != SQLITE_OK) return FP_ERR_IO;

    static const uint8_t tag[15] = "SF2/SQLSCHEMA";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_update_ascii_lower(&h, table_name, strlen(table_name));
    uint8_t nul = 0;
    blake3_hasher_update(&h, &nul, 1);

    uint32_t col_count = 0;
    int prc;
    while ((prc = sqlite3_step(ps)) == SQLITE_ROW) {
        uint8_t b4[4];
        int cid = sqlite3_column_int(ps, 0);
        put_be32(b4, (uint32_t)cid);
        blake3_hasher_update(&h, b4, 4);

        const char *cname = (const char *)sqlite3_column_text(ps, 1);
        int cname_len = sqlite3_column_bytes(ps, 1);
        if (!cname || cname_len <= 0) {
            sqlite3_finalize(ps);
            return FP_ERR_INTEGRITY;
        }
        put_be32(b4, (uint32_t)cname_len);
        blake3_hasher_update(&h, b4, 4);
        blake3_update_ascii_lower(&h, cname, (size_t)cname_len);

        const char *ctype = (const char *)sqlite3_column_text(ps, 2);
        int ctype_len = ctype ? sqlite3_column_bytes(ps, 2) : 0;
        put_be32(b4, (uint32_t)ctype_len);
        blake3_hasher_update(&h, b4, 4);
        if (ctype && ctype_len > 0) {
            blake3_update_ascii_lower(&h, ctype, (size_t)ctype_len);
        }

        uint8_t nn = sqlite3_column_int(ps, 3) ? 1u : 0u;
        blake3_hasher_update(&h, &nn, 1);

        if (sqlite3_column_type(ps, 4) == SQLITE_NULL) {
            uint8_t has_dflt = 0u;
            blake3_hasher_update(&h, &has_dflt, 1);
        } else {
            uint8_t has_dflt = 1u;
            blake3_hasher_update(&h, &has_dflt, 1);
            const void *dp = sqlite3_column_blob(ps, 4);
            int dlen = sqlite3_column_bytes(ps, 4);
            put_be32(b4, (uint32_t)(dlen > 0 ? dlen : 0));
            blake3_hasher_update(&h, b4, 4);
            if (dp && dlen > 0) blake3_hasher_update(&h, dp, (size_t)dlen);
        }

        int pk = sqlite3_column_int(ps, 5);
        put_be32(b4, (uint32_t)pk);
        blake3_hasher_update(&h, b4, 4);

        uint8_t hidden = (uint8_t)(sqlite3_column_int(ps, 6) & 0xFF);
        blake3_hasher_update(&h, &hidden, 1);
        col_count++;
    }
    sqlite3_finalize(ps);
    if (prc != SQLITE_DONE) return FP_ERR_IO;
    if (col_count == 0u) return FP_ERR_INTEGRITY;

    uint8_t cb[4];
    put_be32(cb, col_count);
    blake3_hasher_update(&h, cb, 4);

    /* Bind exact table DDL from sqlite_master (captures COLLATE, CHECK, UNIQUE, FK, STRICT, WITHOUT ROWID) */
    sqlite3_stmt *ms = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(sql,'') FROM sqlite_master WHERE type='table' AND lower(name)=lower(?);",
            -1, &ms, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }
    sqlite3_bind_text(ms, 1, table_name, -1, SQLITE_TRANSIENT);
    int mrc = sqlite3_step(ms);
    if (mrc != SQLITE_ROW) {
        sqlite3_finalize(ms);
        return (mrc == SQLITE_DONE) ? FP_ERR_INTEGRITY : FP_ERR_IO;
    }
    const void *ddl = sqlite3_column_blob(ms, 0);
    int ddl_len = sqlite3_column_bytes(ms, 0);
    put_be32(cb, (uint32_t)(ddl_len > 0 ? ddl_len : 0));
    blake3_hasher_update(&h, cb, 4);
    if (ddl && ddl_len > 0) blake3_hasher_update(&h, ddl, (size_t)ddl_len);
    sqlite3_finalize(ms);

    /* Bind all dependent indexes and triggers ordered deterministically by (type, lower(name)) */
    sqlite3_stmt *ds = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT type, lower(name), COALESCE(sql,'') FROM sqlite_master "
            "WHERE lower(tbl_name)=lower(?) AND type IN ('index','trigger') "
            "ORDER BY type COLLATE BINARY, lower(name) COLLATE BINARY;",
            -1, &ds, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }
    sqlite3_bind_text(ds, 1, table_name, -1, SQLITE_TRANSIENT);
    uint32_t dep_count = 0, trig_count = 0;
    int drc;
    while ((drc = sqlite3_step(ds)) == SQLITE_ROW) {
        const char *dt = (const char *)sqlite3_column_text(ds, 0);
        int dt_len = dt ? sqlite3_column_bytes(ds, 0) : 0;
        const char *dn = (const char *)sqlite3_column_text(ds, 1);
        int dn_len = dn ? sqlite3_column_bytes(ds, 1) : 0;
        const void *dq = sqlite3_column_blob(ds, 2);
        int dq_len = sqlite3_column_bytes(ds, 2);
        if (dt && strcmp(dt, "trigger") == 0) trig_count++;

        put_be32(cb, (uint32_t)(dt_len > 0 ? dt_len : 0));
        blake3_hasher_update(&h, cb, 4);
        if (dt && dt_len > 0) blake3_hasher_update(&h, dt, (size_t)dt_len);

        put_be32(cb, (uint32_t)(dn_len > 0 ? dn_len : 0));
        blake3_hasher_update(&h, cb, 4);
        if (dn && dn_len > 0) blake3_hasher_update(&h, dn, (size_t)dn_len);

        put_be32(cb, (uint32_t)(dq_len > 0 ? dq_len : 0));
        blake3_hasher_update(&h, cb, 4);
        if (dq && dq_len > 0) blake3_hasher_update(&h, dq, (size_t)dq_len);
        dep_count++;
    }
    sqlite3_finalize(ds);
    if (drc != SQLITE_DONE) return FP_ERR_IO;

    put_be32(cb, dep_count);
    blake3_hasher_update(&h, cb, 4);
    put_be32(cb, trig_count);
    blake3_hasher_update(&h, cb, 4);

    blake3_hasher_finalize(&h, out_hash, FP_DNA_LEN);
    if (out_col_count) *out_col_count = col_count;
    if (out_trigger_count) *out_trigger_count = trig_count;
    return FP_OK;
}

static fp_err_t unwrap_changeset_blob(sqlite3 *db, const uint8_t *blob, size_t blob_len,
                                      const char *table_name, int allow_legacy_raw,
                                      const uint8_t **out_raw, size_t *out_raw_len) {
    if (!blob || blob_len == 0 || !out_raw || !out_raw_len) return FP_ERR_INVALID;
    if (blob_len >= SFCS1_MAGIC_LEN && memcmp(blob, SFCS1_MAGIC, SFCS1_MAGIC_LEN) == 0) {
        if (blob_len < SFCS1_HDR_LEN) return FP_ERR_INTEGRITY;
        if (blob[5] != 0u) return FP_ERR_INTEGRITY; /* unsupported flags */
        uint32_t raw_len = get_be32(blob + 38);
        if ((size_t)raw_len != blob_len - SFCS1_HDR_LEN) return FP_ERR_INTEGRITY;
        if (db != NULL) {
            uint8_t actual_hash[FP_DNA_LEN];
            uint32_t trig_cnt = 0;
            fp_err_t serr = compute_table_schema_hash(db, table_name, actual_hash, NULL, &trig_cnt);
            if (serr != FP_OK) return serr;
            /* A8-P0-01: Deterministic profile rejects untracked triggers on governed tables fail-closed! */
            if (trig_cnt > 0u) return FP_ERR_POLICY;
            if (memcmp(actual_hash, blob + 6, FP_DNA_LEN) != 0) {
                return FP_ERR_INTEGRITY;
            }
        }
        *out_raw = blob + SFCS1_HDR_LEN;
        *out_raw_len = (size_t)raw_len;
        return FP_OK;
    }
    /* A8-P0-02: Legacy raw SQLite changesets without SFCS1 schema attestation are rejected fail-closed
     * unless explicitly permitted (used ONLY for in-memory sqlite3changeset_invert() outputs). */
    if (!allow_legacy_raw) {
        return FP_ERR_POLICY;
    }
    if (db != NULL) {
        uint8_t dummy_hash[FP_DNA_LEN];
        uint32_t trig_cnt = 0;
        fp_err_t serr = compute_table_schema_hash(db, table_name, dummy_hash, NULL, &trig_cnt);
        if (serr != FP_OK) return serr;
        if (trig_cnt > 0u) return FP_ERR_POLICY;
    }
    *out_raw = blob;
    *out_raw_len = blob_len;
    return FP_OK;
}

/* A8-P1-01: Transactional snapshot capture — compute schema_hash, reject triggers/no-op,
 * and allocate SFCS1 wrapper INSIDE the transaction BEFORE COMMIT so any error rolls back cleanly! */
fp_err_t fp_sql_capture_changeset(fp_sql_ctx_t *ctx, const char *table_name,
                                  const char *sql,
                                  uint8_t **out_cs, size_t *out_len) {
    if (!ctx || !table_name || !sql || !out_cs || !out_len || !safe_ident(table_name)) {
        return FP_ERR_INVALID;
    }
    *out_cs = NULL;
    *out_len = 0;

    sqlite3_session *sess = NULL;
    void *raw = NULL;
    int raw_sz = 0;
    uint8_t *wrapped = NULL;
    size_t total_len = 0;
    fp_err_t err = FP_OK;

    if (sqlite3_exec(ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }

    uint8_t pre_hash[FP_DNA_LEN], post_hash[FP_DNA_LEN];
    uint32_t pre_trig = 0, post_trig = 0;
    err = compute_table_schema_hash(ctx->db, table_name, pre_hash, NULL, &pre_trig);
    if (err == FP_OK && pre_trig > 0u) err = FP_ERR_POLICY;

    if (err == FP_OK) {
        int rc = sqlite3session_create(ctx->db, "main", &sess);
        if (rc == SQLITE_OK) rc = sqlite3session_attach(sess, table_name);
        if (rc == SQLITE_OK) rc = sqlite3_exec(ctx->db, sql, NULL, NULL, NULL);
        if (rc == SQLITE_OK) rc = sqlite3session_changeset(sess, &raw_sz, &raw);
        if (rc != SQLITE_OK || raw_sz < 0) err = FP_ERR_IO;
    }
    if (sess) {
        sqlite3session_delete(sess);
        sess = NULL;
    }

    if (err == FP_OK) {
        err = compute_table_schema_hash(ctx->db, table_name, post_hash, NULL, &post_trig);
        if (err == FP_OK && post_trig > 0u) err = FP_ERR_POLICY;
        if (err == FP_OK && memcmp(pre_hash, post_hash, FP_DNA_LEN) != 0) err = FP_ERR_POLICY;
    }
    if (err == FP_OK && raw_sz == 0) {
        /* Reject no-op capture cleanly (would produce invalid raw_len=0 changeset) */
        err = FP_ERR_INVALID;
    }
    if (err == FP_OK) {
        size_t rlen = (size_t)raw_sz;
        if (rlen > (size_t)UINT32_MAX - SFCS1_HDR_LEN) {
            err = FP_ERR_BOUNDS;
        } else {
            total_len = SFCS1_HDR_LEN + rlen;
            wrapped = malloc(total_len);
            if (!wrapped) {
                err = FP_ERR_NOMEM;
            } else {
                memcpy(wrapped, SFCS1_MAGIC, SFCS1_MAGIC_LEN);
                wrapped[5] = 0u;
                memcpy(wrapped + 6, post_hash, FP_DNA_LEN);
                put_be32(wrapped + 38, (uint32_t)rlen);
                memcpy(wrapped + SFCS1_HDR_LEN, raw, rlen);
            }
        }
    }
    sqlite3_free(raw);
    raw = NULL;

    if (err == FP_OK) {
        if (sqlite3_exec(ctx->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
            err = FP_ERR_IO;
        }
    }
    if (err != FP_OK) {
        (void)sqlite3_exec(ctx->db, "ROLLBACK", NULL, NULL, NULL);
        free(wrapped);
        return err;
    }

    *out_cs = wrapped;
    *out_len = total_len;
    return FP_OK;
}

fp_err_t fp_sql_state_digest(fp_sql_ctx_t *ctx, const char *table_name, fp_dna_t *out_dna) {
    if (!ctx || !table_name || !out_dna || !safe_ident(table_name)) return FP_ERR_INVALID;

    /* A7-P1-05 + A8-P1-02: Bind full DDL/schema hash + column count + per-row delimiter,
     * support up to 64 PK columns (fail closed on >64 or invalid PK identifier), and force
     * explicit `COLLATE BINARY` on ORDER BY so ordering never depends on table collation! */
    uint8_t schema_hash[FP_DNA_LEN];
    uint32_t schema_cols = 0;
    fp_err_t serr = compute_table_schema_hash(ctx->db, table_name, schema_hash, &schema_cols, NULL);
    if (serr != FP_OK) return serr;

    char pk_cols[64][65];
    memset(pk_cols, 0, sizeof(pk_cols));
    int max_pk = 0;
    {
        char pinfo[192];
        if (snprintf(pinfo, sizeof(pinfo), "PRAGMA table_xinfo(\"%s\");", table_name) >= (int)sizeof(pinfo)) {
            return FP_ERR_BOUNDS;
        }
        sqlite3_stmt *ps = NULL;
        if (sqlite3_prepare_v2(ctx->db, pinfo, -1, &ps, NULL) != SQLITE_OK) return FP_ERR_IO;
        int prc;
        while ((prc = sqlite3_step(ps)) == SQLITE_ROW) {
            int pk = sqlite3_column_int(ps, 5);
            if (pk <= 0) continue;
            if (pk > 64) {
                sqlite3_finalize(ps);
                return FP_ERR_BOUNDS;
            }
            const char *cname = (const char *)sqlite3_column_text(ps, 1);
            if (!cname || !safe_ident(cname) || strlen(cname) >= sizeof(pk_cols[0])) {
                sqlite3_finalize(ps);
                return FP_ERR_POLICY;
            }
            snprintf(pk_cols[pk - 1], sizeof(pk_cols[0]), "%s", cname);
            if (pk > max_pk) max_pk = pk;
        }
        sqlite3_finalize(ps);
        if (prc != SQLITE_DONE) return FP_ERR_IO;
    }

    char query[6144];
    int qpos = snprintf(query, sizeof(query), "SELECT * FROM \"%s\" ORDER BY ", table_name);
    if (qpos <= 0 || (size_t)qpos >= sizeof(query)) return FP_ERR_BOUNDS;
    int added_pk = 0;
    for (int i = 0; i < max_pk; i++) {
        if (!pk_cols[i][0]) return FP_ERR_INTEGRITY; /* non-contiguous PK index */
        int w = snprintf(query + qpos, sizeof(query) - (size_t)qpos, "%s\"%s\" COLLATE BINARY",
                         added_pk ? ", " : "", pk_cols[i]);
        if (w <= 0 || (size_t)(qpos + w) >= sizeof(query)) return FP_ERR_BOUNDS;
        qpos += w;
        added_pk = 1;
    }
    if (!added_pk) {
        int w = snprintf(query + qpos, sizeof(query) - (size_t)qpos, "rowid");
        if (w <= 0 || (size_t)(qpos + w) >= sizeof(query)) return FP_ERR_BOUNDS;
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(ctx->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }

    static const uint8_t tag[13] = "FP1/SQLSTATE";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, table_name, strlen(table_name) + 1u);
    blake3_hasher_update(&h, schema_hash, FP_DNA_LEN);

    int cols = sqlite3_column_count(stmt);
    uint8_t col_be[4];
    put_be32(col_be, (uint32_t)(cols >= 0 ? cols : 0));
    blake3_hasher_update(&h, col_be, 4);
    (void)schema_cols;

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
        uint8_t row_delim = 0xFFu;
        blake3_hasher_update(&h, &row_delim, 1);
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

/* SQLite changeset callbacks & preflight strict table validator (SEC-01, SEC-02) */
static int filter_table(void *ctx, const char *zTab) {
    const char *allowed = (const char *)ctx;
    if (!zTab || sqlite3_strnicmp(zTab, "_fp_", 4) == 0) return 0;
    return sqlite3_stricmp(zTab, allowed) == 0;
}

static fp_err_t validate_changeset_table(const uint8_t *cs, size_t cs_len, const char *allowed_table) {
    if (!cs || cs_len == 0 || !allowed_table || !safe_ident(allowed_table)) return FP_ERR_INVALID;
    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    fp_err_t uerr = unwrap_changeset_blob(NULL, cs, cs_len, allowed_table, 0, &raw, &raw_len);
    if (uerr != FP_OK) return uerr;
    if (!raw || raw_len == 0) return FP_ERR_INTEGRITY;
    sqlite3_changeset_iter *iter = NULL;
    if (sqlite3changeset_start(&iter, (int)raw_len, (void *)raw) != SQLITE_OK || !iter) {
        return FP_ERR_INTEGRITY;
    }
    fp_err_t err = FP_OK;
    int rc;
    while ((rc = sqlite3changeset_next(iter)) == SQLITE_ROW) {
        const char *zTab = NULL;
        int nCol = 0, op = 0, indirect = 0;
        if (sqlite3changeset_op(iter, &zTab, &nCol, &op, &indirect) != SQLITE_OK ||
            !zTab || sqlite3_strnicmp(zTab, "_fp_", 4) == 0 ||
            sqlite3_stricmp(zTab, allowed_table) != 0) {
            err = FP_ERR_POLICY;
            break;
        }
    }
    int frc = sqlite3changeset_finalize(iter);
    if (err != FP_OK) return err;
    if (rc != SQLITE_DONE || frc != SQLITE_OK) return FP_ERR_INTEGRITY;
    return FP_OK;
}

/* P0-02 + A7-P0-01 + A8-P0-01/02: Strict destination schema/DDL/trigger/PK compatibility check
 * BEFORE sqlite3changeset_apply()! Requires SFCS1 schema attestation (unless allow_legacy_raw=1
 * for in-memory sqlite3changeset_invert() outputs) and rejects triggers fail-closed. */
static fp_err_t validate_changeset_schema(sqlite3 *db, const uint8_t *cs, size_t cs_len,
                                          const char *allowed_table, int allow_legacy_raw,
                                          int *out_op_count) {
    if (out_op_count) *out_op_count = 0;
    if (!db || !cs || cs_len == 0 || !allowed_table || !safe_ident(allowed_table)) {
        return FP_ERR_INVALID;
    }

    const uint8_t *raw = NULL;
    size_t raw_len = 0;
    fp_err_t uerr = unwrap_changeset_blob(db, cs, cs_len, allowed_table, allow_legacy_raw, &raw, &raw_len);
    if (uerr != FP_OK) return uerr;
    if (!raw || raw_len == 0) return FP_ERR_INTEGRITY;

    char pragma_sql[192];
    if (snprintf(pragma_sql, sizeof(pragma_sql), "PRAGMA table_info(\"%s\");", allowed_table) >= (int)sizeof(pragma_sql)) {
        return FP_ERR_BOUNDS;
    }
    sqlite3_stmt *ps = NULL;
    if (sqlite3_prepare_v2(db, pragma_sql, -1, &ps, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }
    int db_cols = 0;
    uint8_t db_pk[256];
    memset(db_pk, 0, sizeof(db_pk));
    int prc;
    while ((prc = sqlite3_step(ps)) == SQLITE_ROW) {
        int pk_idx = sqlite3_column_int(ps, 5);
        if (db_cols < (int)sizeof(db_pk)) {
            db_pk[db_cols] = (pk_idx > 0) ? 1u : 0u;
        }
        db_cols++;
    }
    sqlite3_finalize(ps);
    if (prc != SQLITE_DONE) return FP_ERR_IO;
    if (db_cols <= 0 || db_cols > (int)sizeof(db_pk)) {
        /* Target table does NOT exist (or exceeds supported column width) -> fail closed! */
        return FP_ERR_INTEGRITY;
    }

    sqlite3_changeset_iter *iter = NULL;
    if (sqlite3changeset_start(&iter, (int)raw_len, (void *)raw) != SQLITE_OK || !iter) {
        return FP_ERR_INTEGRITY;
    }
    fp_err_t err = FP_OK;
    int ops = 0;
    int rc;
    while ((rc = sqlite3changeset_next(iter)) == SQLITE_ROW) {
        const char *zTab = NULL;
        int nCol = 0, op = 0, indirect = 0;
        if (sqlite3changeset_op(iter, &zTab, &nCol, &op, &indirect) != SQLITE_OK ||
            !zTab || sqlite3_strnicmp(zTab, "_fp_", 4) == 0 ||
            sqlite3_stricmp(zTab, allowed_table) != 0) {
            err = FP_ERR_POLICY;
            break;
        }
        if (nCol <= 0 || nCol > db_cols) {
            err = FP_ERR_INTEGRITY;
            break;
        }
        unsigned char *abPK = NULL;
        int nPK = 0;
        if (sqlite3changeset_pk(iter, &abPK, &nPK) != SQLITE_OK || !abPK || nPK != nCol) {
            err = FP_ERR_INTEGRITY;
            break;
        }
        for (int c = 0; c < nCol; c++) {
            uint8_t want_pk = abPK[c] ? 1u : 0u;
            if (want_pk != db_pk[c]) {
                err = FP_ERR_INTEGRITY;
                break;
            }
        }
        for (int c = nCol; c < db_cols && err == FP_OK; c++) {
            if (db_pk[c] != 0u) {
                err = FP_ERR_INTEGRITY;
                break;
            }
        }
        if (err != FP_OK) break;
        ops++;
    }
    int frc = sqlite3changeset_finalize(iter);
    if (err != FP_OK) return err;
    if (rc != SQLITE_DONE || frc != SQLITE_OK) return FP_ERR_INTEGRITY;
    if (out_op_count) *out_op_count = ops;
    return FP_OK;
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

fp_err_t fp_sql_get_progress(fp_sql_ctx_t *ctx, uint64_t *out_seq, char out_dna[65]) {
    if (!ctx || !out_seq || !out_dna) return FP_ERR_INVALID;
    return read_progress(ctx, out_seq, out_dna);
}

static fp_err_t record_sql_history(fp_sql_ctx_t *sql, uint64_t seq, const char *dna_hex,
                                   const char *prev_dna, uint64_t prev_seq) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(
            sql->db,
            "INSERT OR REPLACE INTO _fp_sql_history(seq, bundle_dna, prev_dna, prev_seq) VALUES(?,?,?,?);",
            -1, &s, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }
    sqlite3_bind_int64(s, 1, (sqlite3_int64)seq);
    sqlite3_bind_text(s, 2, dna_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, prev_dna ? prev_dna : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)prev_seq);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? FP_OK : FP_ERR_IO;
}

static fp_err_t delete_sql_history_seq(fp_sql_ctx_t *sql, uint64_t seq) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(sql->db, "DELETE FROM _fp_sql_history WHERE seq=?;",
                           -1, &s, NULL) != SQLITE_OK) {
        return FP_ERR_IO;
    }
    sqlite3_bind_int64(s, 1, (sqlite3_int64)seq);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    return rc == SQLITE_DONE ? FP_OK : FP_ERR_IO;
}

static int lookup_sql_history_by_seq_dna(fp_sql_ctx_t *sql, uint64_t seq, const char *dna_hex,
                                         char out_prev_dna[65], uint64_t *out_prev_seq) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(
            sql->db,
            "SELECT prev_dna, prev_seq FROM _fp_sql_history WHERE seq=? AND bundle_dna=?;",
            -1, &s, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(s, 1, (sqlite3_int64)seq);
    sqlite3_bind_text(s, 2, dna_hex, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    int found = 0;
    if (rc == SQLITE_ROW) {
        found = 1;
        const char *p = (const char *)sqlite3_column_text(s, 0);
        snprintf(out_prev_dna, 65, "%s", p ? p : "");
        *out_prev_seq = (uint64_t)sqlite3_column_int64(s, 1);
    } else if (rc != SQLITE_DONE) {
        found = -1;
    }
    sqlite3_finalize(s);
    return found;
}

static int is_zero_hex64(const char *s) {
    if (!s || strlen(s) != 64u) return 0;
    for (size_t i = 0; i < 64u; i++) {
        if (s[i] != '0') return 0;
    }
    return 1;
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
    int fd = open(lpath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
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
        int is_empty_target = (strcmp(state, "ROLLBACK_PENDING") == 0 && jseq == 0 && is_zero_hex64(dna_hex));
        int db_committed = 0;
        if (has_sql) {
            if (!sql_ctx) return FP_ERR_INVALID;
            uint64_t cur_seq = 0;
            char cur_dna[65];
            fp_err_t err = read_progress(sql_ctx, &cur_seq, cur_dna);
            if (err != FP_OK) return err;
            if (is_empty_target) {
                if (cur_seq == 0 && cur_dna[0] == '\0') db_committed = 1;
            } else if (cur_seq == jseq && strcmp(cur_dna, dna_hex) == 0) {
                db_committed = 1;
            }
        }
        if (db_committed) {
            /* SQLite already committed (apply or rollback) before crash: reconcile symlink forward! */
            if (is_empty_target) {
                char cur_link[PATH_MAX];
                if (snprintf(cur_link, sizeof(cur_link), "%s/current", target_dir) >= (int)sizeof(cur_link)) {
                    return FP_ERR_BOUNDS;
                }
                if (unlink(cur_link) != 0 && errno != ENOENT) return FP_ERR_IO;
                fp_err_t serr = sync_dir_path(target_dir);
                if (serr != FP_OK) return serr;
                char jpath[PATH_MAX];
                if (snprintf(jpath, sizeof(jpath), "%s/.sf_tx_journal", target_dir) < (int)sizeof(jpath)) {
                    if (unlink(jpath) != 0 && errno != ENOENT) return FP_ERR_IO;
                    (void)sync_dir_path(target_dir);
                }
                return FP_OK;
            }
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

static fp_err_t bundle_apply_impl(const char *store_dir, const fp_dna_t *bundle_dna,
                                  const char *target_dir, fp_sql_ctx_t *sql_ctx,
                                  uint64_t expected_seq, int fault_mode, int sql_only) {
    if (!store_dir || !bundle_dna || !target_dir) return FP_ERR_INVALID;
    if (sql_only && !sql_ctx) return FP_ERR_INVALID;

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
            /* SEC-02: Reject any changeset touching unauthorized or internal `_fp_*` tables before mutation */
            err = validate_changeset_table(cs_blobs[i], cs_lens[i], b.entries[i].path);
            if (err != FP_OK) goto cleanup;
        }
    }

    char dna_hex[65];
    fp_hex_encode(bundle_dna->bytes, FP_DNA_LEN, dna_hex);

    /* P0-01 / SF-A03: Track EVERY applied generation in SQLite `_fp_progress` + `_fp_sql_history`
     * whenever `sql_ctx != NULL` (including file-only no-op generations!) so mixed rollbacks V3->V1
     * always walk the exact SQLite history chain! */
    int track_sql = (sql_ctx != NULL);
    int sql_already_committed = 0;
    if (track_sql) {
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

    if (!sql_only) {
        /* Record STAGING intent and publish immutable sealed generation dir (does NOT touch `current`!) */
        err = tx_journal_write(target_dir, "STAGING", expected_seq, dna_hex, track_sql);
        if (err != FP_OK) goto cleanup;

        err = stage_bundle_files(store_dir, &b, target_dir, dna_hex);
        if (err != FP_OK) goto cleanup;

        /* Persist ACTIVATION_PENDING journal BEFORE SQLite COMMIT so any crash after COMMIT recovers forward */
        err = tx_journal_write(target_dir, "ACTIVATION_PENDING", expected_seq, dna_hex, track_sql);
        if (err != FP_OK) goto cleanup;
    }

    /* Apply SQLite changesets & record generation checkpoint in ONE atomic WAL transaction */
    if (track_sql && !sql_already_committed) {
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
                    int op_cnt = 0;
                    err = validate_changeset_schema(sql_ctx->db, cs_blobs[i], cs_lens[i],
                                                    b.entries[i].path, 0, &op_cnt);
                    if (err != FP_OK) break;
                    const uint8_t *raw_cs = NULL;
                    size_t raw_len = 0;
                    err = unwrap_changeset_blob(NULL, cs_blobs[i], cs_lens[i],
                                                b.entries[i].path, 0, &raw_cs, &raw_len);
                    if (err != FP_OK) break;
                    sqlite3_int64 ch_before = sqlite3_total_changes64(sql_ctx->db);
                    int rc = sqlite3changeset_apply(sql_ctx->db, (int)raw_len, (void *)raw_cs,
                                                    filter_table, conflict_abort,
                                                    (void *)b.entries[i].path);
                    sqlite3_int64 ch_after = sqlite3_total_changes64(sql_ctx->db);
                    if (rc != SQLITE_OK || (op_cnt > 0 && (ch_after - ch_before) != (sqlite3_int64)op_cnt)) {
                        err = FP_ERR_INTEGRITY;
                    }
                }
                if (err == FP_OK) {
                    err = record_sql_history(sql_ctx, expected_seq, dna_hex, cur_dna, cur_seq);
                }
                if (err == FP_OK) {
                    err = write_progress(sql_ctx, expected_seq, dna_hex);
                }
                if (err == FP_OK && !sql_only && fault_mode == 1) {
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

    if (sql_only) {
        goto cleanup;
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

    err = tx_journal_write(target_dir, "COMMITTED", expected_seq, dna_hex, track_sql);

cleanup:
    for (uint16_t i = 0; i < FP_BUNDLE_MAX_ENTRIES; i++) free(cs_blobs[i]);
    release_target_lock(lfd);
    return err;
}

fp_err_t fp_bundle_apply(const char *store_dir, const fp_dna_t *bundle_dna,
                         const char *target_dir, fp_sql_ctx_t *sql_ctx,
                         uint64_t expected_seq, int fault_mode) {
    return bundle_apply_impl(store_dir, bundle_dna, target_dir, sql_ctx, expected_seq, fault_mode, 0);
}

fp_err_t fp_bundle_apply_sql_only(const char *store_dir, const fp_dna_t *bundle_dna,
                                  const char *target_dir, fp_sql_ctx_t *sql_ctx,
                                  uint64_t expected_seq) {
    return bundle_apply_impl(store_dir, bundle_dna, target_dir, sql_ctx, expected_seq, 0, 1);
}

/* A8-P0-03: Single-transaction multi-step bundle chain apply (1..64 steps).
 * Executes ALL intermediate + final SQLite changesets inside ONE atomic SQLite WAL transaction,
 * stages ONLY the final generation's files, and flips `current` once to the final generation! */
typedef struct {
    fp_bundle_t b;
    char        dna_hex[65];
    uint8_t    *cs_blobs[FP_BUNDLE_MAX_ENTRIES];
    size_t      cs_lens[FP_BUNDLE_MAX_ENTRIES];
} chain_step_mem_t;

fp_err_t fp_bundle_apply_chain(const char *store_dir,
                               const fp_bundle_step_t *steps, size_t step_count,
                               const char *target_dir, fp_sql_ctx_t *sql_ctx) {
    if (!store_dir || !steps || step_count == 0u || step_count > 64u || !target_dir || !sql_ctx) {
        return FP_ERR_INVALID;
    }
    if (step_count == 1u) {
        return bundle_apply_impl(store_dir, &steps[0].bundle_dna, target_dir,
                                 sql_ctx, steps[0].expected_seq, 0, 0);
    }

    int lfd = acquire_target_lock(target_dir);
    if (lfd < 0) return FP_ERR_IO;

    fp_err_t err = bundle_recover_locked(store_dir, target_dir, sql_ctx);
    if (err != FP_OK) { release_target_lock(lfd); return err; }

    chain_step_mem_t *mem = calloc(step_count, sizeof(*mem));
    if (!mem) { release_target_lock(lfd); return FP_ERR_NOMEM; }

    uint64_t total_cs_bytes = 0;
    for (size_t k = 0; k < step_count && err == FP_OK; k++) {
        if (k > 0u && steps[k].expected_seq <= steps[k - 1u].expected_seq) {
            err = FP_ERR_CHAIN;
            break;
        }
        fp_hex_encode(steps[k].bundle_dna.bytes, FP_DNA_LEN, mem[k].dna_hex);
        err = load_and_verify_bundle(store_dir, &steps[k].bundle_dna, &mem[k].b);
        if (err != FP_OK) break;
        for (uint16_t i = 0; i < mem[k].b.entry_count && err == FP_OK; i++) {
            if (mem[k].b.entries[i].role != FP_ROLE_SQLITE_CHANGESET) continue;
            if (mem[k].b.entries[i].size > BUNDLE_MAX_CHANGESET ||
                total_cs_bytes > BUNDLE_MAX_TOTAL_CHANGESETS - mem[k].b.entries[i].size) {
                err = FP_ERR_BOUNDS;
                break;
            }
            total_cs_bytes += mem[k].b.entries[i].size;
            err = fp_store_get_object(store_dir, &mem[k].b.entries[i].dna, BUNDLE_MAX_CHANGESET,
                                      &mem[k].cs_blobs[i], &mem[k].cs_lens[i]);
            if (err != FP_OK || mem[k].cs_lens[i] != mem[k].b.entries[i].size) {
                err = err != FP_OK ? err : FP_ERR_INTEGRITY;
                break;
            }
            err = validate_changeset_table(mem[k].cs_blobs[i], mem[k].cs_lens[i],
                                           mem[k].b.entries[i].path);
        }
    }
    if (err != FP_OK) goto cleanup;

    const chain_step_mem_t *final_step = &mem[step_count - 1u];
    uint64_t final_seq = steps[step_count - 1u].expected_seq;
    int sql_already_committed = 0;
    {
        uint64_t cur_seq = 0;
        char cur_dna[65];
        err = read_progress(sql_ctx, &cur_seq, cur_dna);
        if (err != FP_OK) goto cleanup;
        if (cur_seq == final_seq && strcmp(cur_dna, final_step->dna_hex) == 0) {
            sql_already_committed = 1;
        } else if (steps[0].expected_seq <= cur_seq) {
            err = FP_ERR_CHAIN;
            goto cleanup;
        }
    }

    /* Stage ONLY the final generation's files (intermediate generations are never materialized on disk!) */
    err = tx_journal_write(target_dir, "STAGING", final_seq, final_step->dna_hex, 1);
    if (err != FP_OK) goto cleanup;
    err = stage_bundle_files(store_dir, &final_step->b, target_dir, final_step->dna_hex);
    if (err != FP_OK) goto cleanup;
    err = tx_journal_write(target_dir, "ACTIVATION_PENDING", final_seq, final_step->dna_hex, 1);
    if (err != FP_OK) goto cleanup;

    /* Execute ALL step_count SQLite migrations in ONE SINGLE atomic WAL transaction! */
    if (!sql_already_committed) {
        if (sqlite3_exec(sql_ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            err = FP_ERR_IO;
            goto cleanup;
        }
        uint64_t prev_seq = 0;
        char prev_dna[65];
        err = read_progress(sql_ctx, &prev_seq, prev_dna);
        if (err == FP_OK) {
            if (prev_seq == final_seq && strcmp(prev_dna, final_step->dna_hex) == 0) {
                (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
            } else if (steps[0].expected_seq <= prev_seq) {
                (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
                err = FP_ERR_CHAIN;
            } else {
                for (size_t k = 0; k < step_count && err == FP_OK; k++) {
                    const fp_bundle_t *kb = &mem[k].b;
                    for (uint16_t i = 0; i < kb->entry_count && err == FP_OK; i++) {
                        if (kb->entries[i].role != FP_ROLE_SQLITE_CHANGESET) continue;
                        int op_cnt = 0;
                        err = validate_changeset_schema(sql_ctx->db, mem[k].cs_blobs[i], mem[k].cs_lens[i],
                                                        kb->entries[i].path, 0, &op_cnt);
                        if (err != FP_OK) break;
                        const uint8_t *raw_cs = NULL;
                        size_t raw_len = 0;
                        err = unwrap_changeset_blob(NULL, mem[k].cs_blobs[i], mem[k].cs_lens[i],
                                                    kb->entries[i].path, 0, &raw_cs, &raw_len);
                        if (err != FP_OK) break;
                        sqlite3_int64 ch_before = sqlite3_total_changes64(sql_ctx->db);
                        int rc = sqlite3changeset_apply(sql_ctx->db, (int)raw_len, (void *)raw_cs,
                                                        filter_table, conflict_abort,
                                                        (void *)kb->entries[i].path);
                        sqlite3_int64 ch_after = sqlite3_total_changes64(sql_ctx->db);
                        if (rc != SQLITE_OK ||
                            (op_cnt > 0 && (ch_after - ch_before) != (sqlite3_int64)op_cnt)) {
                            err = FP_ERR_INTEGRITY;
                        }
                    }
                    if (err == FP_OK) {
                        err = record_sql_history(sql_ctx, steps[k].expected_seq, mem[k].dna_hex,
                                                 prev_dna, prev_seq);
                    }
                    if (err == FP_OK) {
                        prev_seq = steps[k].expected_seq;
                        memcpy(prev_dna, mem[k].dna_hex, sizeof(prev_dna));
                    }
                }
                if (err == FP_OK) {
                    err = write_progress(sql_ctx, final_seq, final_step->dna_hex);
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

    char rel[128];
    snprintf(rel, sizeof(rel), "gen/%s", final_step->dna_hex);
    err = atomic_flip_current(target_dir, rel);
    if (err != FP_OK) goto cleanup;

    err = tx_journal_write(target_dir, "COMMITTED", final_seq, final_step->dna_hex, 1);

cleanup:
    for (size_t k = 0; k < step_count; k++) {
        for (uint16_t i = 0; i < FP_BUNDLE_MAX_ENTRIES; i++) free(mem[k].cs_blobs[i]);
    }
    free(mem);
    release_target_lock(lfd);
    return err;
}

/* Multi-step atomic & idempotent rollback (P0-01, P0-02, P0-05, P1-01):
 *   - Supports rolling back single-step OR multi-step SQLite chains (V4 -> V1) in ONE atomic transaction
 *     by walking `_fp_sql_history` backward and inverting every intermediate bundle in reverse order.
 *   - Supports `prev_bundle_dna == NULL` to cleanly revert an initial install (restoring SQLite to seq=0
 *     and removing `current`).
 *   - Idempotent: if SQLite is already at `prev_bundle_dna`, reconciles symlink cleanly and returns FP_OK.
 *   - Fails closed BEFORE any mutation if any intermediate bundle/changeset in the chain is missing! */
typedef struct {
    uint64_t    seq;
    char        dna_hex[65];
    fp_bundle_t b;
} rb_step_t;

static fp_err_t bundle_rollback_impl(const char *store_dir,
                                     const fp_dna_t *current_bundle_dna,
                                     const fp_dna_t *prev_bundle_dna,
                                     const char *target_dir, fp_sql_ctx_t *sql_ctx,
                                     int sql_only) {
    if (!store_dir || !current_bundle_dna || !target_dir) {
        return FP_ERR_INVALID;
    }
    if (sql_only && !sql_ctx) {
        return FP_ERR_INVALID;
    }
    int lfd = acquire_target_lock(target_dir);
    if (lfd < 0) return FP_ERR_IO;

    fp_err_t err = bundle_recover_locked(store_dir, target_dir, sql_ctx);
    if (err != FP_OK) { release_target_lock(lfd); return err; }

    char cur_hex[65], prev_hex[65], journal_dna_hex[65];
    fp_hex_encode(current_bundle_dna->bytes, FP_DNA_LEN, cur_hex);
    if (prev_bundle_dna) {
        fp_hex_encode(prev_bundle_dna->bytes, FP_DNA_LEN, prev_hex);
        memcpy(journal_dna_hex, prev_hex, sizeof(journal_dna_hex));
    } else {
        prev_hex[0] = '\0';
        memset(journal_dna_hex, '0', 64);
        journal_dna_hex[64] = '\0';
    }

    fp_bundle_t cur_b, prev_b;
    err = load_and_verify_bundle(store_dir, current_bundle_dna, &cur_b);
    if (err != FP_OK) { release_target_lock(lfd); return err; }
    if (prev_bundle_dna && !sql_only) {
        err = load_and_verify_bundle(store_dir, prev_bundle_dna, &prev_b);
        if (err != FP_OK) { release_target_lock(lfd); return err; }
        /* Ensure previous generation files are present and cryptographically verified */
        err = stage_bundle_files(store_dir, &prev_b, target_dir, prev_hex);
        if (err != FP_OK) { release_target_lock(lfd); return err; }
    }

    int cur_has_sql = 0;
    for (uint16_t i = 0; i < cur_b.entry_count; i++) {
        if (cur_b.entries[i].role == FP_ROLE_SQLITE_CHANGESET) { cur_has_sql = 1; break; }
    }
    if (cur_has_sql && !sql_ctx) { release_target_lock(lfd); return FP_ERR_INVALID; }

    /* Plan SQLite rollback chain BEFORE mutating anything (P0-05 & P0-02 idempotency!) */
    rb_step_t *steps = NULL;
    size_t step_cnt = 0, step_cap = 0;
    int need_sql_rb = 0;
    uint64_t target_seq = 0;

    if (sql_ctx) {
        uint64_t pre_seq = 0;
        char pre_dna[65];
        err = read_progress(sql_ctx, &pre_seq, pre_dna);
        if (err != FP_OK) { release_target_lock(lfd); return err; }

        if ((prev_bundle_dna && strcmp(pre_dna, prev_hex) == 0) ||
            (!prev_bundle_dna && pre_seq == 0 && pre_dna[0] == '\0')) {
            /* Already at target SQLite state (e.g. crash recovery / idempotent retry) */
            need_sql_rb = 0;
            target_seq = pre_seq;
        } else if (pre_seq > 0) {
            /* P0-01 / SF-A03: Always walk `_fp_sql_history` backward from actual DB head (`pre_seq`, `pre_dna`)
             * whenever DB is not yet at `prev_hex` (handles both SQL and mixed file-only generations!). */
            if (cur_has_sql && strcmp(pre_dna, cur_hex) != 0) {
                release_target_lock(lfd);
                return FP_ERR_CHAIN;
            }
            need_sql_rb = 1;
            uint64_t walk_seq = pre_seq;
            char walk_dna[65];
            memcpy(walk_dna, pre_dna, sizeof(walk_dna));
            uint64_t total_cs = 0;

            while (strcmp(walk_dna, prev_hex) != 0) {
                if (step_cnt >= 64u) { err = FP_ERR_BOUNDS; break; }
                char next_prev_dna[65];
                uint64_t next_prev_seq = 0;
                int found = lookup_sql_history_by_seq_dna(sql_ctx, walk_seq, walk_dna,
                                                          next_prev_dna, &next_prev_seq);
                if (found < 0) { err = FP_ERR_IO; break; }
                if (found == 0) {
                    /* Fail closed if history is missing (prevents silent multi-step SQLite divergence!) */
                    err = FP_ERR_CHAIN;
                    break;
                }
                fp_dna_t wdna;
                if (fp_hex_decode(walk_dna, wdna.bytes, FP_DNA_LEN) != FP_OK) {
                    err = FP_ERR_INTEGRITY;
                    break;
                }
                fp_bundle_t wb;
                err = load_and_verify_bundle(store_dir, &wdna, &wb);
                if (err != FP_OK) break;

                for (uint16_t i = 0; i < wb.entry_count; i++) {
                    if (wb.entries[i].role == FP_ROLE_SQLITE_CHANGESET) {
                        if (wb.entries[i].size > BUNDLE_MAX_CHANGESET ||
                            total_cs > BUNDLE_MAX_TOTAL_CHANGESETS - wb.entries[i].size) {
                            err = FP_ERR_BOUNDS;
                            break;
                        }
                        total_cs += wb.entries[i].size;
                    }
                }
                if (err != FP_OK) break;

                if (step_cnt == step_cap) {
                    size_t nc = step_cap ? step_cap * 2u : 4u;
                    rb_step_t *ns = realloc(steps, nc * sizeof(*ns));
                    if (!ns) { err = FP_ERR_NOMEM; break; }
                    steps = ns;
                    step_cap = nc;
                }
                steps[step_cnt].seq = walk_seq;
                memcpy(steps[step_cnt].dna_hex, walk_dna, 65);
                steps[step_cnt].b = wb;
                step_cnt++;

                walk_seq = next_prev_seq;
                memcpy(walk_dna, next_prev_dna, 65);
                if (walk_seq == 0 && walk_dna[0] == '\0') break;
            }
            if (err == FP_OK && strcmp(walk_dna, prev_hex) != 0) {
                err = FP_ERR_CHAIN; /* Requested rollback target is not an ancestor in SQLite history! */
            }
            if (err != FP_OK) {
                free(steps);
                release_target_lock(lfd);
                return err;
            }
            target_seq = walk_seq;
        }
    }

    if (!sql_only) {
        /* P0-01: Persist ROLLBACK_PENDING intent BEFORE SQLite COMMIT so any crash recovers forward! */
        err = tx_journal_write(target_dir, "ROLLBACK_PENDING", target_seq, journal_dna_hex, need_sql_rb);
        if (err != FP_OK) { free(steps); release_target_lock(lfd); return err; }
    }

    if (need_sql_rb && step_cnt > 0) {
        if (sqlite3_exec(sql_ctx->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            free(steps);
            release_target_lock(lfd);
            return FP_ERR_IO;
        }
        uint64_t seq = 0;
        char active_dna[65];
        err = read_progress(sql_ctx, &seq, active_dna);
        if (err == FP_OK && (seq != steps[0].seq || strcmp(active_dna, steps[0].dna_hex) != 0)) {
            err = FP_ERR_CHAIN;
        }
        /* Invert and apply each bundle in reverse chain order (V4 -> V3 -> V2) inside ONE transaction */
        for (size_t s = 0; s < step_cnt && err == FP_OK; s++) {
            const fp_bundle_t *sb = &steps[s].b;
            for (int i = (int)sb->entry_count - 1; i >= 0 && err == FP_OK; i--) {
                if (sb->entries[i].role != FP_ROLE_SQLITE_CHANGESET) continue;
                uint8_t *cs = NULL;
                size_t cs_len = 0;
                err = fp_store_get_object(store_dir, &sb->entries[i].dna, BUNDLE_MAX_CHANGESET,
                                          &cs, &cs_len);
                if (err != FP_OK) break;

                /* A7-P0-01 + A8-P0-01/02: Verify SFCS1 schema hash & unwrap raw bytes BEFORE sqlite3changeset_invert() */
                const uint8_t *raw_cs = NULL;
                size_t raw_len = 0;
                err = unwrap_changeset_blob(sql_ctx->db, cs, cs_len, sb->entries[i].path,
                                            0, &raw_cs, &raw_len);
                if (err != FP_OK || !raw_cs || raw_len == 0) {
                    free(cs);
                    if (err == FP_OK) err = FP_ERR_INTEGRITY;
                    break;
                }

                int inv_len = 0;
                void *inv = NULL;
                int rc = sqlite3changeset_invert((int)raw_len, raw_cs, &inv_len, &inv);
                free(cs);
                if (rc != SQLITE_OK) { err = FP_ERR_INTEGRITY; break; }

                int inv_ops = 0;
                err = validate_changeset_schema(sql_ctx->db, (const uint8_t *)inv, (size_t)inv_len,
                                                sb->entries[i].path, 1, &inv_ops);
                if (err != FP_OK) { sqlite3_free(inv); break; }

                sqlite3_int64 ch_before = sqlite3_total_changes64(sql_ctx->db);
                rc = sqlite3changeset_apply(sql_ctx->db, inv_len, inv,
                                            filter_table, conflict_abort,
                                            (void *)sb->entries[i].path);
                sqlite3_int64 ch_after = sqlite3_total_changes64(sql_ctx->db);
                sqlite3_free(inv);
                if (rc != SQLITE_OK || (inv_ops > 0 && (ch_after - ch_before) != (sqlite3_int64)inv_ops)) {
                    err = FP_ERR_INTEGRITY;
                    break;
                }
            }
            if (err == FP_OK) {
                err = delete_sql_history_seq(sql_ctx, steps[s].seq);
            }
        }
        if (err == FP_OK) {
            err = write_progress(sql_ctx, target_seq, prev_hex);
        }
        if (err == FP_OK) {
            if (sqlite3_exec(sql_ctx->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
                err = FP_ERR_IO;
            }
        } else {
            (void)sqlite3_exec(sql_ctx->db, "ROLLBACK", NULL, NULL, NULL);
        }
        if (err != FP_OK) { free(steps); release_target_lock(lfd); return err; }
    }
    free(steps);

    if (sql_only) {
        release_target_lock(lfd);
        return FP_OK;
    }

    if (prev_bundle_dna) {
        char rel[128];
        snprintf(rel, sizeof(rel), "gen/%s", prev_hex);
        err = atomic_flip_current(target_dir, rel);
        if (err == FP_OK) {
            err = tx_journal_write(target_dir, "COMMITTED", target_seq, prev_hex, need_sql_rb);
        }
    } else {
        char cur_link[PATH_MAX];
        if (snprintf(cur_link, sizeof(cur_link), "%s/current", target_dir) >= (int)sizeof(cur_link)) {
            err = FP_ERR_BOUNDS;
        } else if (unlink(cur_link) != 0 && errno != ENOENT) {
            err = FP_ERR_IO;
        } else {
            err = sync_dir_path(target_dir);
        }
        if (err == FP_OK) {
            char jpath[PATH_MAX];
            if (snprintf(jpath, sizeof(jpath), "%s/.sf_tx_journal", target_dir) < (int)sizeof(jpath)) {
                if (unlink(jpath) != 0 && errno != ENOENT) err = FP_ERR_IO;
                else (void)sync_dir_path(target_dir);
            }
        }
    }
    release_target_lock(lfd);
    return err;
}

fp_err_t fp_bundle_rollback(const char *store_dir,
                            const fp_dna_t *current_bundle_dna,
                            const fp_dna_t *prev_bundle_dna,
                            const char *target_dir, fp_sql_ctx_t *sql_ctx) {
    return bundle_rollback_impl(store_dir, current_bundle_dna, prev_bundle_dna, target_dir, sql_ctx, 0);
}

fp_err_t fp_bundle_rollback_sql_only(const char *store_dir,
                                     const fp_dna_t *current_bundle_dna,
                                     const fp_dna_t *prev_bundle_dna,
                                     const char *target_dir, fp_sql_ctx_t *sql_ctx) {
    return bundle_rollback_impl(store_dir, current_bundle_dna, prev_bundle_dna, target_dir, sql_ctx, 1);
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
