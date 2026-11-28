#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void assert_file_eq(const char *path, const uint8_t *expected, size_t len) {
    FILE *f = fopen(path, "rb");
    assert(f != NULL);
    uint8_t *buf = malloc(len + 1u);
    assert(buf != NULL);
    size_t got = fread(buf, 1, len + 1u, f);
    fclose(f);
    assert(got == len && memcmp(buf, expected, len) == 0);
    free(buf);
}

static void test_bundle_security_validation(void) {
    fp_bundle_t b;
    memset(&b, 0, sizeof(b));
    b.version = 1;
    b.entry_count = 1;
    b.entries[0].role = FP_ROLE_FILE;
    snprintf(b.entries[0].path, sizeof(b.entries[0].path), "../etc/passwd");
    uint8_t *out = NULL; size_t len = 0;
    assert(fp_bundle_encode(&b, &out, &len) == FP_ERR_POLICY);

    snprintf(b.entries[0].path, sizeof(b.entries[0].path), "/abs/path");
    assert(fp_bundle_encode(&b, &out, &len) == FP_ERR_POLICY);

    b.entries[0].role = FP_ROLE_SQLITE_CHANGESET;
    snprintf(b.entries[0].path, sizeof(b.entries[0].path), "_fp_progress");
    assert(fp_bundle_encode(&b, &out, &len) == FP_ERR_POLICY);
    printf("[PASS] Bundle path traversal & _fp_progress injection rejected\n");
}

static void test_composite_atomic_sigkill_and_rollback(void) {
    char dt[] = "/tmp/fp-bundle-XXXXXX";
    char *dir = mkdtemp(dt);
    assert(dir != NULL);

    char store[256], target[256], src_db_path[256], dst_db_path[256];
    snprintf(store, sizeof(store), "%s/store", dir);
    snprintf(target, sizeof(target), "%s/live", dir);
    snprintf(src_db_path, sizeof(src_db_path), "%s/source.db", dir);
    snprintf(dst_db_path, sizeof(dst_db_path), "%s/replica.db", dir);

    const char *schema = "CREATE TABLE nodes(id INTEGER PRIMARY KEY, name TEXT NOT NULL, score INTEGER NOT NULL);";

    fp_sql_ctx_t *src_db = NULL, *dst_db = NULL;
    assert(fp_sql_open(src_db_path, &src_db) == FP_OK);
    assert(fp_sql_open(dst_db_path, &dst_db) == FP_OK);
    assert(fp_sql_exec(src_db, schema) == FP_OK);
    assert(fp_sql_exec(dst_db, schema) == FP_OK);

    /* --- Build Bundle v1: app binary + AI model weights + SQLite changeset v1 --- */
    const uint8_t app_v1[] = "EDGE-APP-BINARY-V1";
    const uint8_t ai_v1[]  = "AI-WEIGHTS-FP8-V1-000111222333";
    uint8_t *cs1 = NULL; size_t cs1_len = 0;
    assert(fp_sql_capture_changeset(src_db, "nodes",
        "INSERT INTO nodes VALUES (1,'alpha',10),(2,'beta',20),(3,'gamma',30);",
        &cs1, &cs1_len) == FP_OK);
    fp_dna_t sql_state_v1;
    assert(fp_sql_state_digest(src_db, "nodes", &sql_state_v1) == FP_OK);

    fp_bundle_t b1;
    memset(&b1, 0, sizeof(b1));
    b1.version = 1;
    b1.entry_count = 3;
    b1.entries[0].role = FP_ROLE_FILE; b1.entries[0].mode = 0755; b1.entries[0].size = sizeof(app_v1);
    snprintf(b1.entries[0].path, sizeof(b1.entries[0].path), "bin/app");
    assert(fp_store_put_object(store, app_v1, sizeof(app_v1), &b1.entries[0].dna) == FP_OK);

    b1.entries[1].role = FP_ROLE_FILE; b1.entries[1].mode = 0644; b1.entries[1].size = sizeof(ai_v1);
    snprintf(b1.entries[1].path, sizeof(b1.entries[1].path), "models/weights.bin");
    assert(fp_store_put_object(store, ai_v1, sizeof(ai_v1), &b1.entries[1].dna) == FP_OK);

    b1.entries[2].role = FP_ROLE_SQLITE_CHANGESET; b1.entries[2].size = cs1_len;
    snprintf(b1.entries[2].path, sizeof(b1.entries[2].path), "nodes");
    assert(fp_store_put_object(store, cs1, cs1_len, &b1.entries[2].dna) == FP_OK);
    free(cs1);

    fp_dna_t bdna1;
    assert(fp_bundle_pack(store, &b1, &bdna1) == FP_OK);

    /* Apply Bundle v1 atomically */
    assert(fp_bundle_apply(store, &bdna1, target, dst_db, 1, 0) == FP_OK);

    char p_app[384], p_ai[384];
    snprintf(p_app, sizeof(p_app), "%s/current/bin/app", target);
    snprintf(p_ai, sizeof(p_ai), "%s/current/models/weights.bin", target);
    assert_file_eq(p_app, app_v1, sizeof(app_v1));
    assert_file_eq(p_ai, ai_v1, sizeof(ai_v1));

    fp_dna_t dst_state;
    assert(fp_sql_state_digest(dst_db, "nodes", &dst_state) == FP_OK);
    assert(fp_dna_equal(&dst_state, &sql_state_v1));
    printf("[PASS] Composite Bundle v1 applied atomically (files + AI weights + SQLite changeset)\n");

    /* --- Build Bundle v2: app v2 + AI weights v2 + SQLite changeset v2 --- */
    const uint8_t app_v2[] = "EDGE-APP-BINARY-V2-SUPER";
    const uint8_t ai_v2[]  = "AI-WEIGHTS-FP8-V2-999888777666";
    uint8_t *cs2 = NULL; size_t cs2_len = 0;
    assert(fp_sql_capture_changeset(src_db, "nodes",
        "UPDATE nodes SET score=99 WHERE id=2; DELETE FROM nodes WHERE id=3; INSERT INTO nodes VALUES (4,'delta',40);",
        &cs2, &cs2_len) == FP_OK);
    fp_dna_t sql_state_v2;
    assert(fp_sql_state_digest(src_db, "nodes", &sql_state_v2) == FP_OK);
    assert(!fp_dna_equal(&sql_state_v1, &sql_state_v2));

    fp_bundle_t b2 = b1;
    b2.entries[0].size = sizeof(app_v2);
    assert(fp_store_put_object(store, app_v2, sizeof(app_v2), &b2.entries[0].dna) == FP_OK);
    b2.entries[1].size = sizeof(ai_v2);
    assert(fp_store_put_object(store, ai_v2, sizeof(ai_v2), &b2.entries[1].dna) == FP_OK);
    b2.entries[2].size = cs2_len;
    assert(fp_store_put_object(store, cs2, cs2_len, &b2.entries[2].dna) == FP_OK);
    free(cs2);

    fp_dna_t bdna2;
    assert(fp_bundle_pack(store, &b2, &bdna2) == FP_OK);

    /* --- REAL OS SIGKILL INJECTION RIGHT BEFORE SQLITE COMMIT! --- */
    fp_sql_close(dst_db);
    dst_db = NULL;

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        fp_sql_ctx_t *child_db = NULL;
        if (fp_sql_open(dst_db_path, &child_db) != FP_OK) _exit(2);
        /* Child will raise(SIGKILL) right before SQLite COMMIT! */
        (void)fp_bundle_apply(store, &bdna2, target, child_db, 2, 1);
        _exit(3); /* Must never reach here */
    }
    int wstatus = 0;
    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGKILL);

    /* Reopen replica DB & verify ZERO partial mutation: BOTH files AND DB are still v1! */
    assert(fp_sql_open(dst_db_path, &dst_db) == FP_OK);
    assert_file_eq(p_app, app_v1, sizeof(app_v1));
    assert_file_eq(p_ai, ai_v1, sizeof(ai_v1));
    assert(fp_sql_state_digest(dst_db, "nodes", &dst_state) == FP_OK);
    assert(fp_dna_equal(&dst_state, &sql_state_v1));
    printf("[PASS] Real SIGKILL before COMMIT: zero partial files, zero partial SQLite rows (100%% v1 intact)\n");

    /* --- Now apply v2 cleanly + test idempotent replay --- */
    assert(fp_bundle_apply(store, &bdna2, target, dst_db, 2, 0) == FP_OK);
    assert_file_eq(p_app, app_v2, sizeof(app_v2));
    assert_file_eq(p_ai, ai_v2, sizeof(ai_v2));
    assert(fp_sql_state_digest(dst_db, "nodes", &dst_state) == FP_OK);
    assert(fp_dna_equal(&dst_state, &sql_state_v2));

    /* Idempotent replay of seq=2 must succeed without double-applying changeset! */
    assert(fp_bundle_apply(store, &bdna2, target, dst_db, 2, 0) == FP_OK);
    assert(fp_sql_state_digest(dst_db, "nodes", &dst_state) == FP_OK);
    assert(fp_dna_equal(&dst_state, &sql_state_v2));
    printf("[PASS] Bundle v2 recovered cleanly + idempotent replay verified\n");

    /* --- FULL-STACK ATOMIC ROLLBACK (v2 -> v1): files + AI weights + SQLite INVERT! --- */
    assert(fp_bundle_rollback(store, &bdna2, &bdna1, target, dst_db) == FP_OK);
    assert_file_eq(p_app, app_v1, sizeof(app_v1));
    assert_file_eq(p_ai, ai_v1, sizeof(ai_v1));
    assert(fp_sql_state_digest(dst_db, "nodes", &dst_state) == FP_OK);
    assert(fp_dna_equal(&dst_state, &sql_state_v1));
    printf("[PASS] Full-stack atomic rollback v2 -> v1 (files + AI weights + inverted SQLite changeset = bit-exact v1!)\n");

    fp_sql_close(src_db);
    fp_sql_close(dst_db);
}

static void test_p1_streaming_gc_and_merkle_index(void) {
    char tmpl[] = "/tmp/fp-p1-bundle-XXXXXX";
    char *dir = mkdtemp(tmpl);
    assert(dir != NULL);

    char store[256], target[256];
    snprintf(store, sizeof(store), "%s/store", dir);
    snprintf(target, sizeof(target), "%s/live", dir);

    /* 1. Streaming staging + GC across 4 immutable generations + orphaned .stage dir */
    fp_dna_t dnas[4];
    for (int g = 0; g < 4; g++) {
        uint8_t payload[131072]; /* 128 KiB -> exercises multi-chunk 64 KiB streaming loop */
        for (size_t i = 0; i < sizeof(payload); i++) {
            payload[i] = (uint8_t)((i * 13u + (size_t)g * 31u) & 0xFFu);
        }
        fp_bundle_t b;
        memset(&b, 0, sizeof(b));
        b.version = 1;
        b.entry_count = 1;
        b.entries[0].role = FP_ROLE_FILE;
        b.entries[0].mode = 0644;
        b.entries[0].size = sizeof(payload);
        snprintf(b.entries[0].path, sizeof(b.entries[0].path), "models/nested/v%d.bin", g);
        assert(fp_store_put_object(store, payload, sizeof(payload), &b.entries[0].dna) == FP_OK);
        assert(fp_bundle_pack(store, &b, &dnas[g]) == FP_OK);
        assert(fp_bundle_apply(store, &dnas[g], target, NULL, (uint64_t)(g + 1), 0) == FP_OK);
    }

    char orphan[512];
    snprintf(orphan, sizeof(orphan), "%s/gen/.stage-orphan-99999", target);
    assert(mkdir(orphan, 0755) == 0);

    uint32_t removed = 0;
    assert(fp_bundle_gc(target, 1, &removed) == FP_OK);
    assert(removed == 3u); /* 2 old generations + 1 orphaned .stage dir */
    struct stat sb;
    assert(lstat(orphan, &sb) != 0);
    /* Active generation (v3) MUST remain intact */
    char active_f[512];
    snprintf(active_f, sizeof(active_f), "%s/current/models/nested/v3.bin", target);
    assert(stat(active_f, &sb) == 0 && sb.st_size == 131072);
    printf("[PASS] P1-01/02/03: O(1)-RAM streaming bundle staging (openat/O_NOFOLLOW) + safe GC (removed=%u)\n",
           removed);

    /* 2. Persistent FPM1 Merkle Index + O(log N) disk proof in O(1) RAM */
    const size_t N = 512u << 10; /* 32 chunks */
    uint8_t *big = malloc(N);
    assert(big != NULL);
    for (size_t i = 0; i < N; i++) big[i] = (uint8_t)((i * 29u + 7u) & 0xFFu);
    fp_dna_t big_dna;
    assert(fp_store_put_object(store, big, N, &big_dna) == FP_OK);

    char hex[65], obj_p[512], idx_p[528];
    fp_hex_encode(big_dna.bytes, FP_DNA_LEN, hex);
    snprintf(obj_p, sizeof(obj_p), "%s/objects/%s", store, hex);
    snprintf(idx_p, sizeof(idx_p), "%s.fpm", obj_p);

    /* First build creates persistent .fpm index */
    fp_merkle_tree_t *t1 = fp_merkle_tree_build_file_cached(obj_p, &big_dna, NULL);
    assert(t1 != NULL);
    assert(stat(idx_p, &sb) == 0 && sb.st_size > 56);
    fp_merkle_tree_free(t1);

    /* Second load reads directly from .fpm without re-hashing object */
    fp_merkle_tree_t *t2 = fp_merkle_tree_build_file_cached(obj_p, &big_dna, NULL);
    assert(t2 != NULL);
    fp_dna_t tdna = fp_merkle_tree_dna(t2);
    assert(fp_dna_equal(&tdna, &big_dna));
    fp_merkle_tree_free(t2);

    /* O(1)-RAM disk proof reader matches fp_merkle_verify() on first/mid/last chunks */
    uint64_t idxs[3] = { 0, 15, 31 };
    for (int k = 0; k < 3; k++) {
        fp_merkle_proof_t pr;
        assert(fp_merkle_prove_from_index_file(idx_p, idxs[k], &pr) == FP_OK);
        assert(fp_merkle_verify(&big_dna, &pr, big + idxs[k] * FP_CHUNK_SIZE, pr.chunk_len) == FP_OK);
    }

    /* Corrupt 1 bit in .fpm root hash -> load_index MUST fail closed (NULL)! */
    FILE *f = fopen(idx_p, "r+b");
    assert(f != NULL);
    assert(fseek(f, 56, SEEK_SET) == 0);
    int c = fgetc(f);
    assert(fseek(f, 56, SEEK_SET) == 0);
    fputc(c ^ 0x01, f);
    fclose(f);
    assert(fp_merkle_tree_load_index(idx_p, N, &big_dna) == NULL);

    free(big);
    printf("[PASS] P1-05: Persistent FPM1 Merkle index (cached hit + O(1)-RAM disk proofs + tamper rejection)\n");
}

static void test_m0_m1_hardening(void) {
    char tmpl[] = "/tmp/fp-m0m1-bundle-XXXXXX";
    char *dir = mkdtemp(tmpl);
    assert(dir != NULL);

    char store[256], target[256];
    snprintf(store, sizeof(store), "%s/store", dir);
    snprintf(target, sizeof(target), "%s/live", dir);

    const uint8_t v1_data[] = "SEALED-GENERATION-V1-PAYLOAD";
    const uint8_t v2_data[] = "SEALED-GENERATION-V2-PAYLOAD";
    fp_bundle_t b1, b2;
    memset(&b1, 0, sizeof(b1));
    memset(&b2, 0, sizeof(b2));
    b1.version = 1; b1.entry_count = 1;
    b1.entries[0].role = FP_ROLE_FILE; b1.entries[0].mode = 0644; b1.entries[0].size = sizeof(v1_data);
    snprintf(b1.entries[0].path, sizeof(b1.entries[0].path), "bin/app");
    assert(fp_store_put_object(store, v1_data, sizeof(v1_data), &b1.entries[0].dna) == FP_OK);
    fp_dna_t d1, d2;
    assert(fp_bundle_pack(store, &b1, &d1) == FP_OK);

    b2 = b1;
    b2.entries[0].size = sizeof(v2_data);
    assert(fp_store_put_object(store, v2_data, sizeof(v2_data), &b2.entries[0].dna) == FP_OK);
    assert(fp_bundle_pack(store, &b2, &d2) == FP_OK);

    assert(fp_bundle_apply(store, &d1, target, NULL, 1, 0) == FP_OK);

    /* P0-03: Flip 1 bit inside sealed generation (same size!) -> re-apply must detect & restage from CAS */
    char d1_hex[65], d2_hex[65], gen1_file[512], cur_file[512];
    fp_hex_encode(d1.bytes, FP_DNA_LEN, d1_hex);
    fp_hex_encode(d2.bytes, FP_DNA_LEN, d2_hex);
    snprintf(gen1_file, sizeof(gen1_file), "%s/gen/%s/bin/app", target, d1_hex);
    snprintf(cur_file, sizeof(cur_file), "%s/current/bin/app", target);
    FILE *f = fopen(gen1_file, "r+b");
    assert(f != NULL);
    int b0 = fgetc(f);
    assert(b0 != EOF);
    assert(fseek(f, 0, SEEK_SET) == 0);
    fputc(b0 ^ 0x01, f);
    fclose(f);
    assert(fp_bundle_apply(store, &d1, target, NULL, 1, 0) == FP_OK);
    assert_file_eq(cur_file, v1_data, sizeof(v1_data));
    printf("[PASS] P0-03: Sealed generation 1-bit tamper detected via BLAKE3 DNA and restaged from CAS\n");

    /* P1-02: Corrupted .sf_tx_journal must fail closed WITHOUT deleting evidence */
    char jpath[512];
    snprintf(jpath, sizeof(jpath), "%s/.sf_tx_journal", target);
    f = fopen(jpath, "wb");
    assert(f != NULL);
    fputs("SFTXJ1 CORRUPTED_ENTRY\n", f);
    fclose(f);
    assert(fp_bundle_recover(store, target, NULL) == FP_ERR_INTEGRITY);
    struct stat sb;
    assert(lstat(jpath, &sb) == 0); /* Evidence preserved! */
    assert(unlink(jpath) == 0);
    printf("[PASS] P1-02: Corrupted .sf_tx_journal fails closed (FP_ERR_INTEGRITY) and preserves journal\n");

    /* Apply v2 so both gen/d1 and gen/d2 exist, then test P0-07 GC journal protection & P0-01 ROLLBACK_PENDING */
    assert(fp_bundle_apply(store, &d2, target, NULL, 2, 0) == FP_OK);
    assert_file_eq(cur_file, v2_data, sizeof(v2_data));

    /* Set up a SQLite DB whose _fp_progress already committed rollback to (seq=1, d1_hex) before crash! */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/recover.db", dir);
    fp_sql_ctx_t *rdb = NULL;
    assert(fp_sql_open(db_path, &rdb) == FP_OK);
    assert(fp_sql_exec(rdb, "CREATE TABLE t(id INTEGER PRIMARY KEY);") == FP_OK);
    /* Write _fp_progress directly as if fp_bundle_rollback committed SQLite right before SIGKILL */
    char up_sql[256];
    snprintf(up_sql, sizeof(up_sql),
             "UPDATE _fp_progress SET seq=1, bundle_dna='%s' WHERE id=1;", d1_hex);
    assert(fp_sql_exec(rdb, up_sql) == FP_OK);

    /* P0-07: Pending journal target gen/d1 must NOT be deleted by fp_bundle_gc(keep_extra=0) */
    f = fopen(jpath, "wb");
    assert(f != NULL);
    fprintf(f, "SFTX1 ROLLBACK_PENDING 1 %s 1\n", d1_hex);
    fclose(f);
    uint32_t removed = 99;
    assert(fp_bundle_gc(target, 0, &removed) == FP_OK);
    char gen1_dir[512];
    snprintf(gen1_dir, sizeof(gen1_dir), "%s/gen/%s", target, d1_hex);
    assert(stat(gen1_dir, &sb) == 0);

    /* P0-01: fp_bundle_recover() sees DB committed (1, d1_hex) and reconciles symlink forward to d1! */
    assert(fp_bundle_recover(store, target, rdb) == FP_OK);
    assert_file_eq(cur_file, v1_data, sizeof(v1_data));
    fp_sql_close(rdb);
    printf("[PASS] P0-01/P0-07: GC protects journaled generation & ROLLBACK_PENDING reconciles forward\n");
}

static void test_tx06_tx07_multistep_and_initial_sql_rollback(void) {
    char tmpl[] = "/tmp/fp-tx0607-XXXXXX";
    char *dir = mkdtemp(tmpl);
    assert(dir != NULL);

    char store[256], target[256], src_p[256], dst_p[256];
    snprintf(store, sizeof(store), "%s/store", dir);
    snprintf(target, sizeof(target), "%s/live", dir);
    snprintf(src_p, sizeof(src_p), "%s/src.db", dir);
    snprintf(dst_p, sizeof(dst_p), "%s/dst.db", dir);

    const char *schema = "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER NOT NULL);";
    fp_sql_ctx_t *src_db = NULL, *dst_db = NULL;
    assert(fp_sql_open(src_p, &src_db) == FP_OK && fp_sql_open(dst_p, &dst_db) == FP_OK);
    assert(fp_sql_exec(src_db, schema) == FP_OK && fp_sql_exec(dst_db, schema) == FP_OK);

    fp_dna_t empty_dig;
    assert(fp_sql_state_digest(src_db, "kv", &empty_dig) == FP_OK);

    /* Build 4 incremental bundles V1(100) -> V2(200) -> V3(300) -> V4(400) */
    const char *sqls[4] = {
        "INSERT INTO kv VALUES (1, 100);",
        "UPDATE kv SET v=200 WHERE k=1;",
        "UPDATE kv SET v=300 WHERE k=1;",
        "UPDATE kv SET v=400 WHERE k=1;"
    };
    const char *cfgs[4] = { "V1=100\n", "V2=200\n", "V3=300\n", "V4=400\n" };
    fp_dna_t bdnas[4], sql_digs[4];
    for (int i = 0; i < 4; i++) {
        uint8_t *cs = NULL; size_t csl = 0;
        assert(fp_sql_capture_changeset(src_db, "kv", sqls[i], &cs, &csl) == FP_OK);
        assert(fp_sql_state_digest(src_db, "kv", &sql_digs[i]) == FP_OK);
        fp_bundle_t b;
        memset(&b, 0, sizeof(b));
        b.version = 1; b.entry_count = 2;
        b.entries[0].role = FP_ROLE_FILE; b.entries[0].mode = 0644; b.entries[0].size = strlen(cfgs[i]);
        snprintf(b.entries[0].path, sizeof(b.entries[0].path), "ver.cfg");
        assert(fp_store_put_object(store, (const uint8_t *)cfgs[i], strlen(cfgs[i]), &b.entries[0].dna) == FP_OK);
        b.entries[1].role = FP_ROLE_SQLITE_CHANGESET; b.entries[1].size = csl;
        snprintf(b.entries[1].path, sizeof(b.entries[1].path), "kv");
        assert(fp_store_put_object(store, cs, csl, &b.entries[1].dna) == FP_OK);
        free(cs);
        assert(fp_bundle_pack(store, &b, &bdnas[i]) == FP_OK);
    }

    /* TX-07: Initial install V1 -> rollback with prev=NULL -> exact empty SQLite baseline + no `current`! */
    assert(fp_bundle_apply(store, &bdnas[0], target, dst_db, 1, 0) == FP_OK);
    fp_dna_t cur_dig;
    assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &sql_digs[0]));
    assert(fp_bundle_rollback(store, &bdnas[0], NULL, target, dst_db) == FP_OK);
    assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &empty_dig));
    uint64_t pseq = 99; char pdna[65];
    assert(fp_sql_get_progress(dst_db, &pseq, pdna) == FP_OK && pseq == 0 && pdna[0] == '\0');
    char cur_link[384], cur_cfg[384];
    snprintf(cur_link, sizeof(cur_link), "%s/current", target);
    snprintf(cur_cfg, sizeof(cur_cfg), "%s/current/ver.cfg", target);
    struct stat sb;
    assert(lstat(cur_link, &sb) != 0);
    printf("[PASS] TX-07 (P1-01): Initial install rollback reverted SQLite to exact empty baseline & unlinked current\n");

    /* TX-06: Apply V1 -> V2 -> V3 -> V4, then multi-step rollback V4 -> V1 in ONE atomic transaction! */
    for (int i = 0; i < 4; i++) {
        assert(fp_bundle_apply(store, &bdnas[i], target, dst_db, (uint64_t)(i + 1), 0) == FP_OK);
    }
    assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &sql_digs[3]));
    assert_file_eq(cur_cfg, (const uint8_t *)cfgs[3], strlen(cfgs[3]));

    assert(fp_bundle_rollback(store, &bdnas[3], &bdnas[0], target, dst_db) == FP_OK);
    assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &sql_digs[0]));
    assert_file_eq(cur_cfg, (const uint8_t *)cfgs[0], strlen(cfgs[0]));
    assert(fp_sql_get_progress(dst_db, &pseq, pdna) == FP_OK && pseq == 1);

    /* TX-05: Idempotent repeat of rollback V4 -> V1 when already at V1 MUST succeed with unchanged state! */
    for (int r = 0; r < 10; r++) {
        assert(fp_bundle_rollback(store, &bdnas[3], &bdnas[0], target, dst_db) == FP_OK);
    }
    assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &sql_digs[0]));
    printf("[PASS] TX-06/TX-05 (P0-05/P0-02): Multi-step V4->V1 SQLite+file rollback exact & 10x idempotent\n");

    fp_sql_close(src_db);
    fp_sql_close(dst_db);
}

static void test_m4_mixed_rollback_and_sql_namespace_guards(void) {
    char tmp[] = "/tmp/sf_m4_bundle_XXXXXX";
    assert(mkdtemp(tmp) != NULL);
    char store[256], target[256], src_p[256], dst_p[256];
    snprintf(store, sizeof(store), "%s/store", tmp);
    snprintf(target, sizeof(target), "%s/target", tmp);
    snprintf(src_p, sizeof(src_p), "%s/src.db", tmp);
    snprintf(dst_p, sizeof(dst_p), "%s/dst.db", tmp);

    fp_sql_ctx_t *src_db = NULL, *dst_db = NULL;
    assert(fp_sql_open(src_p, &src_db) == FP_OK);
    assert(fp_sql_open(dst_p, &dst_db) == FP_OK);
    assert(fp_sql_exec(src_db, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
    assert(fp_sql_exec(dst_db, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
    assert(fp_sql_exec(src_db, "CREATE TABLE secret(id INTEGER PRIMARY KEY, val TEXT);") == FP_OK);
    assert(fp_sql_exec(dst_db, "CREATE TABLE secret(id INTEGER PRIMARY KEY, val TEXT);") == FP_OK);

    fp_dna_t empty_dig;
    assert(fp_sql_state_digest(src_db, "kv", &empty_dig) == FP_OK);

    /* SEC-01: Case-insensitive reservation of entire _fp_* SQLite internal namespace */
    {
        const char *bad_tbls[4] = { "_fp_progress", "_FP_PROGRESS", "_Fp_Sql_History", "_FP_custom" };
        for (int i = 0; i < 4; i++) {
            fp_bundle_t bad;
            memset(&bad, 0, sizeof(bad));
            bad.version = 1; bad.entry_count = 1;
            bad.entries[0].role = FP_ROLE_SQLITE_CHANGESET;
            bad.entries[0].size = 4;
            snprintf(bad.entries[0].path, sizeof(bad.entries[0].path), "%s", bad_tbls[i]);
            uint8_t *enc = NULL; size_t elen = 0;
            assert(fp_bundle_encode(&bad, &enc, &elen) == FP_ERR_POLICY);
        }
        printf("[PASS] SEC-01: Case-insensitive _fp_* SQLite internal namespace rejected in bundle encode\n");
    }

    /* SEC-02: Changeset touching unauthorized table (`secret` while entry declares `kv`) rejected fail-closed */
    {
        uint8_t *cs = NULL; size_t csl = 0;
        assert(fp_sql_capture_changeset(src_db, "secret",
                                        "INSERT INTO secret VALUES (1, 'pwned');", &cs, &csl) == FP_OK);
        fp_bundle_t b_evil;
        memset(&b_evil, 0, sizeof(b_evil));
        b_evil.version = 1; b_evil.entry_count = 1;
        b_evil.entries[0].role = FP_ROLE_SQLITE_CHANGESET;
        b_evil.entries[0].size = csl;
        snprintf(b_evil.entries[0].path, sizeof(b_evil.entries[0].path), "kv"); /* claims kv, mutates secret! */
        assert(fp_store_put_object(store, cs, csl, &b_evil.entries[0].dna) == FP_OK);
        free(cs);
        fp_dna_t evil_dna;
        assert(fp_bundle_pack(store, &b_evil, &evil_dna) == FP_OK);

        fp_dna_t sec_before, sec_after;
        assert(fp_sql_state_digest(dst_db, "secret", &sec_before) == FP_OK);
        assert(fp_bundle_apply(store, &evil_dna, target, dst_db, 1, 0) == FP_ERR_POLICY);
        assert(fp_sql_state_digest(dst_db, "secret", &sec_after) == FP_OK);
        assert(fp_dna_equal(&sec_before, &sec_after));
        uint64_t pseq = 99; char pdna[65];
        assert(fp_sql_get_progress(dst_db, &pseq, pdna) == FP_OK && pseq == 0 && pdna[0] == '\0');
        printf("[PASS] SEC-02: Changeset mutating undeclared table rejected preflight (FP_ERR_POLICY)\n");
    }

    /* P0-01 / SF-A03: Mixed sequence V1(SQL=100) -> V2(SQL=200) -> V3(file-only!), then rollback V3 -> V1! */
    fp_dna_t b1_dna, b2_dna, b3_dna, dig1, dig2, cur_dig;
    {
        uint8_t *cs1 = NULL, *cs2 = NULL; size_t l1 = 0, l2 = 0;
        assert(fp_sql_capture_changeset(src_db, "kv", "INSERT INTO kv VALUES (1, 100);", &cs1, &l1) == FP_OK);
        assert(fp_sql_state_digest(src_db, "kv", &dig1) == FP_OK);
        assert(fp_sql_capture_changeset(src_db, "kv", "UPDATE kv SET v=200 WHERE k=1;", &cs2, &l2) == FP_OK);
        assert(fp_sql_state_digest(src_db, "kv", &dig2) == FP_OK);

        fp_bundle_t b1, b2, b3;
        memset(&b1, 0, sizeof(b1)); memset(&b2, 0, sizeof(b2)); memset(&b3, 0, sizeof(b3));
        b1.version = 1; b1.entry_count = 2;
        b1.entries[0].role = FP_ROLE_FILE; b1.entries[0].mode = 0644; b1.entries[0].size = 3;
        snprintf(b1.entries[0].path, sizeof(b1.entries[0].path), "f.txt");
        assert(fp_store_put_object(store, (const uint8_t *)"V1\n", 3, &b1.entries[0].dna) == FP_OK);
        b1.entries[1].role = FP_ROLE_SQLITE_CHANGESET; b1.entries[1].size = l1;
        snprintf(b1.entries[1].path, sizeof(b1.entries[1].path), "kv");
        assert(fp_store_put_object(store, cs1, l1, &b1.entries[1].dna) == FP_OK);
        assert(fp_bundle_pack(store, &b1, &b1_dna) == FP_OK);

        b2.version = 1; b2.entry_count = 2;
        b2.entries[0].role = FP_ROLE_FILE; b2.entries[0].mode = 0644; b2.entries[0].size = 3;
        snprintf(b2.entries[0].path, sizeof(b2.entries[0].path), "f.txt");
        assert(fp_store_put_object(store, (const uint8_t *)"V2\n", 3, &b2.entries[0].dna) == FP_OK);
        b2.entries[1].role = FP_ROLE_SQLITE_CHANGESET; b2.entries[1].size = l2;
        snprintf(b2.entries[1].path, sizeof(b2.entries[1].path), "kv");
        assert(fp_store_put_object(store, cs2, l2, &b2.entries[1].dna) == FP_OK);
        assert(fp_bundle_pack(store, &b2, &b2_dna) == FP_OK);

        /* V3 is FILE-ONLY (no SQLite changeset entry at all!) */
        b3.version = 1; b3.entry_count = 1;
        b3.entries[0].role = FP_ROLE_FILE; b3.entries[0].mode = 0644; b3.entries[0].size = 3;
        snprintf(b3.entries[0].path, sizeof(b3.entries[0].path), "f.txt");
        assert(fp_store_put_object(store, (const uint8_t *)"V3\n", 3, &b3.entries[0].dna) == FP_OK);
        assert(fp_bundle_pack(store, &b3, &b3_dna) == FP_OK);
        free(cs1); free(cs2);

        assert(fp_bundle_apply(store, &b1_dna, target, dst_db, 1, 0) == FP_OK);
        assert(fp_bundle_apply(store, &b2_dna, target, dst_db, 2, 0) == FP_OK);
        assert(fp_bundle_apply(store, &b3_dna, target, dst_db, 3, 0) == FP_OK);

        char fpath[384];
        snprintf(fpath, sizeof(fpath), "%s/current/f.txt", target);
        assert_file_eq(fpath, (const uint8_t *)"V3\n", 3);
        assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &dig2));

        /* Rollback from file-only V3 back to V1 MUST invert V2's SQLite changeset AND flip file to V1! */
        assert(fp_bundle_rollback(store, &b3_dna, &b1_dna, target, dst_db) == FP_OK);
        assert_file_eq(fpath, (const uint8_t *)"V1\n", 3);
        assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &dig1));

        /* Re-apply V2 -> V3 and rollback all the way to prev=NULL -> empty SQLite baseline! */
        assert(fp_bundle_apply(store, &b2_dna, target, dst_db, 4, 0) == FP_OK);
        assert(fp_bundle_apply(store, &b3_dna, target, dst_db, 5, 0) == FP_OK);
        assert(fp_bundle_rollback(store, &b3_dna, NULL, target, dst_db) == FP_OK);
        assert(fp_sql_state_digest(dst_db, "kv", &cur_dig) == FP_OK && fp_dna_equal(&cur_dig, &empty_dig));
        printf("[PASS] P0-01/SF-A03: Mixed V1(SQL)->V2(SQL)->V3(file-only) rollback to V1 & NULL restored exact SQLite+files\n");
    }

    /* SQL-01 & SQL-02 (P0-02): Missing table, fewer columns, and mismatched PK MUST fail closed (FP_ERR_INTEGRITY)
     * instead of letting sqlite3changeset_apply() silently return SQLITE_OK and advance _fp_progress! */
    {
        char s1p[256], s2p[256], s3p[256], t_bad[256];
        snprintf(s1p, sizeof(s1p), "%s/missing_tbl.db", tmp);
        snprintf(s2p, sizeof(s2p), "%s/fewer_cols.db", tmp);
        snprintf(s3p, sizeof(s3p), "%s/wrong_pk.db", tmp);
        snprintf(t_bad, sizeof(t_bad), "%s/t_bad", tmp);

        fp_sql_ctx_t *db_miss = NULL, *db_cols = NULL, *db_pk = NULL;
        assert(fp_sql_open(s1p, &db_miss) == FP_OK);
        assert(fp_sql_open(s2p, &db_cols) == FP_OK);
        assert(fp_sql_open(s3p, &db_pk) == FP_OK);

        /* db_miss has NO table `kv` at all */
        /* db_cols has `kv(k INTEGER PRIMARY KEY)` (1 col instead of 2) */
        assert(fp_sql_exec(db_cols, "CREATE TABLE kv(k INTEGER PRIMARY KEY);") == FP_OK);
        /* db_pk has `kv(k INTEGER, v INTEGER PRIMARY KEY)` (PK on col 1 instead of col 0) */
        assert(fp_sql_exec(db_pk, "CREATE TABLE kv(k INTEGER, v INTEGER PRIMARY KEY);") == FP_OK);

        fp_sql_ctx_t *bad_dbs[3] = { db_miss, db_cols, db_pk };
        for (int i = 0; i < 3; i++) {
            assert(fp_bundle_apply(store, &b1_dna, t_bad, bad_dbs[i], 1, 0) == FP_ERR_INTEGRITY);
            uint64_t pseq = 99; char pdna[65];
            assert(fp_sql_get_progress(bad_dbs[i], &pseq, pdna) == FP_OK && pseq == 0 && pdna[0] == '\0');
        }
        fp_sql_close(db_miss);
        fp_sql_close(db_cols);
        fp_sql_close(db_pk);
        printf("[PASS] SQL-01/SQL-02 (P0-02): Missing table, fewer columns & mismatched PK rejected fail-closed (no silent SQLITE_OK)\n");
    }

    /* A7-P0-01 (SQL-01 swapped non-PK columns): Identical column count & PK bitmap, swapped column order!
     * `kv_swap(id INTEGER PRIMARY KEY, a TEXT, b TEXT)` vs `kv_swap(id INTEGER PRIMARY KEY, b TEXT, a TEXT)`.
     * SFCS1 schema hash MUST reject fail-closed (FP_ERR_INTEGRITY) with ZERO rows inserted & _fp_progress unchanged! */
    {
        char sw_src[256], sw_dst[256], sw_tgt[256];
        snprintf(sw_src, sizeof(sw_src), "%s/swap_src.db", tmp);
        snprintf(sw_dst, sizeof(sw_dst), "%s/swap_dst.db", tmp);
        snprintf(sw_tgt, sizeof(sw_tgt), "%s/swap_tgt", tmp);

        fp_sql_ctx_t *db_sw_s = NULL, *db_sw_d = NULL;
        assert(fp_sql_open(sw_src, &db_sw_s) == FP_OK);
        assert(fp_sql_open(sw_dst, &db_sw_d) == FP_OK);
        assert(fp_sql_exec(db_sw_s, "CREATE TABLE kv_swap(id INTEGER PRIMARY KEY, a TEXT, b TEXT);") == FP_OK);
        assert(fp_sql_exec(db_sw_d, "CREATE TABLE kv_swap(id INTEGER PRIMARY KEY, b TEXT, a TEXT);") == FP_OK);

        fp_dna_t dst_before;
        assert(fp_sql_state_digest(db_sw_d, "kv_swap", &dst_before) == FP_OK);

        uint8_t *sw_cs = NULL; size_t sw_csl = 0;
        assert(fp_sql_capture_changeset(db_sw_s, "kv_swap",
                                        "INSERT INTO kv_swap(id,a,b) VALUES(1,'ALPHA','BETA');",
                                        &sw_cs, &sw_csl) == FP_OK);
        fp_bundle_t b_sw;
        memset(&b_sw, 0, sizeof(b_sw));
        b_sw.version = 1; b_sw.entry_count = 1;
        b_sw.entries[0].role = FP_ROLE_SQLITE_CHANGESET;
        b_sw.entries[0].size = sw_csl;
        snprintf(b_sw.entries[0].path, sizeof(b_sw.entries[0].path), "kv_swap");
        assert(fp_store_put_object(store, sw_cs, sw_csl, &b_sw.entries[0].dna) == FP_OK);
        free(sw_cs);
        fp_dna_t sw_bdna;
        assert(fp_bundle_pack(store, &b_sw, &sw_bdna) == FP_OK);

        assert(fp_bundle_apply(store, &sw_bdna, sw_tgt, db_sw_d, 1, 0) == FP_ERR_INTEGRITY);
        fp_dna_t dst_after;
        assert(fp_sql_state_digest(db_sw_d, "kv_swap", &dst_after) == FP_OK);
        assert(fp_dna_equal(&dst_before, &dst_after));
        uint64_t pseq = 99; char pdna[65];
        assert(fp_sql_get_progress(db_sw_d, &pseq, pdna) == FP_OK && pseq == 0 && pdna[0] == '\0');

        /* A7-P1-05 (SQL-04): Digest MUST distinguish (1 col x 2 rows) vs (2 cols x 1 row) AND empty schemas! */
        char d1p[256], d2p[256];
        snprintf(d1p, sizeof(d1p), "%s/dig1.db", tmp);
        snprintf(d2p, sizeof(d2p), "%s/dig2.db", tmp);
        fp_sql_ctx_t *dd1 = NULL, *dd2 = NULL;
        assert(fp_sql_open(d1p, &dd1) == FP_OK && fp_sql_open(d2p, &dd2) == FP_OK);
        assert(fp_sql_exec(dd1, "CREATE TABLE shape(x INTEGER PRIMARY KEY);") == FP_OK);
        assert(fp_sql_exec(dd2, "CREATE TABLE shape(x INTEGER PRIMARY KEY, y INTEGER);") == FP_OK);
        fp_dna_t e1, e2;
        assert(fp_sql_state_digest(dd1, "shape", &e1) == FP_OK);
        assert(fp_sql_state_digest(dd2, "shape", &e2) == FP_OK);
        assert(!fp_dna_equal(&e1, &e2)); /* Different empty schemas! */
        assert(fp_sql_exec(dd1, "INSERT INTO shape VALUES (1),(2);") == FP_OK);
        assert(fp_sql_exec(dd2, "INSERT INTO shape VALUES (1,2);") == FP_OK);
        fp_dna_t r1, r2;
        assert(fp_sql_state_digest(dd1, "shape", &r1) == FP_OK);
        assert(fp_sql_state_digest(dd2, "shape", &r2) == FP_OK);
        assert(!fp_dna_equal(&r1, &r2)); /* (1 col x 2 rows) != (2 cols x 1 row)! */
        fp_sql_close(dd1);
        fp_sql_close(dd2);
        fp_sql_close(db_sw_s);
        fp_sql_close(db_sw_d);
        printf("[PASS] A7-P0-01/A7-P1-05 (SQL-01/SQL-04): Swapped non-PK columns rejected (SFCS1) & digest distinguishes schema/row shape\n");
    }

    /* A8-P0-01/02/03 & A8-P1-01/02: 8th Audit SQLite Semantics, Legacy Raw Block, Trigger Reject & Atomic Chain Batch */
    {
        /* SQL-01 (A8-P0-01): Appendix A trigger side-effect reproducer -> MUST fail closed (FP_ERR_POLICY)! */
        char ta_p[256], tb_p[256], ttgt[256];
        snprintf(ta_p, sizeof(ta_p), "%s/trig_a.db", tmp);
        snprintf(tb_p, sizeof(tb_p), "%s/trig_b.db", tmp);
        snprintf(ttgt, sizeof(ttgt), "%s/trig_tgt", tmp);
        fp_sql_ctx_t *dba = NULL, *dbb = NULL;
        assert(fp_sql_open(ta_p, &dba) == FP_OK && fp_sql_open(tb_p, &dbb) == FP_OK);
        const char *tschema = "CREATE TABLE kv_t(id INTEGER PRIMARY KEY, val TEXT); CREATE TABLE aux(v TEXT);";
        assert(fp_sql_exec(dba, tschema) == FP_OK && fp_sql_exec(dbb, tschema) == FP_OK);
        assert(fp_sql_exec(dbb, "CREATE TRIGGER side_effect AFTER INSERT ON kv_t BEGIN INSERT INTO aux VALUES(new.val); END;") == FP_OK);

        fp_dna_t b_kv_before, b_aux_before, b_kv_after, b_aux_after;
        assert(fp_sql_state_digest(dbb, "kv_t", &b_kv_before) == FP_OK);
        assert(fp_sql_state_digest(dbb, "aux", &b_aux_before) == FP_OK);

        uint8_t *tcs = NULL; size_t tcsl = 0;
        assert(fp_sql_capture_changeset(dba, "kv_t", "INSERT INTO kv_t VALUES(1,'alpha');", &tcs, &tcsl) == FP_OK);
        /* A8-P1-01 (SQL-05): No-op capture returns FP_ERR_INVALID; capture on table with trigger returns FP_ERR_POLICY & rolls back! */
        uint8_t *noop_cs = NULL; size_t noop_l = 0;
        assert(fp_sql_capture_changeset(dba, "kv_t", "DELETE FROM kv_t WHERE id=9999;", &noop_cs, &noop_l) == FP_ERR_INVALID);
        assert(fp_sql_capture_changeset(dbb, "kv_t", "INSERT INTO kv_t VALUES(2,'boom');", &noop_cs, &noop_l) == FP_ERR_POLICY);
        assert(fp_sql_state_digest(dbb, "kv_t", &b_kv_after) == FP_OK && fp_dna_equal(&b_kv_before, &b_kv_after));
        assert(fp_sql_state_digest(dbb, "aux", &b_aux_after) == FP_OK && fp_dna_equal(&b_aux_before, &b_aux_after));

        fp_bundle_t bt;
        memset(&bt, 0, sizeof(bt));
        bt.version = 1; bt.entry_count = 1;
        bt.entries[0].role = FP_ROLE_SQLITE_CHANGESET; bt.entries[0].size = tcsl;
        snprintf(bt.entries[0].path, sizeof(bt.entries[0].path), "kv_t");
        assert(fp_store_put_object(store, tcs, tcsl, &bt.entries[0].dna) == FP_OK);
        fp_dna_t bt_dna;
        assert(fp_bundle_pack(store, &bt, &bt_dna) == FP_OK);

        /* Apply to DB B with hidden trigger MUST fail closed with zero mutation to kv_t, aux, _fp_progress! */
        assert(fp_bundle_apply(store, &bt_dna, ttgt, dbb, 1, 0) == FP_ERR_POLICY);
        assert(fp_sql_state_digest(dbb, "kv_t", &b_kv_after) == FP_OK && fp_dna_equal(&b_kv_before, &b_kv_after));
        assert(fp_sql_state_digest(dbb, "aux", &b_aux_after) == FP_OK && fp_dna_equal(&b_aux_before, &b_aux_after));
        uint64_t pseq = 99; char pdna[65];
        assert(fp_sql_get_progress(dbb, &pseq, pdna) == FP_OK && pseq == 0 && pdna[0] == '\0');

        /* SQL-02 (A8-P0-02): Legacy raw SQLite changeset (stripped of 42B SFCS1 header) MUST be rejected fail-closed! */
        assert(tcsl > 42u);
        fp_bundle_t bl;
        memset(&bl, 0, sizeof(bl));
        bl.version = 1; bl.entry_count = 1;
        bl.entries[0].role = FP_ROLE_SQLITE_CHANGESET; bl.entries[0].size = tcsl - 42u;
        snprintf(bl.entries[0].path, sizeof(bl.entries[0].path), "kv_t");
        assert(fp_store_put_object(store, tcs + 42u, tcsl - 42u, &bl.entries[0].dna) == FP_OK);
        free(tcs);
        fp_dna_t bl_dna;
        assert(fp_bundle_pack(store, &bl, &bl_dna) == FP_OK);
        assert(fp_bundle_apply(store, &bl_dna, ttgt, dba, 1, 0) == FP_ERR_POLICY);

        /* SQL-04b (A8-P1-02): COLLATE BINARY vs COLLATE NOCASE MUST produce distinct digests AND fail cross-apply! */
        char cb1_p[256], cb2_p[256];
        snprintf(cb1_p, sizeof(cb1_p), "%s/col_bin.db", tmp);
        snprintf(cb2_p, sizeof(cb2_p), "%s/col_nocase.db", tmp);
        fp_sql_ctx_t *dcb1 = NULL, *dcb2 = NULL;
        assert(fp_sql_open(cb1_p, &dcb1) == FP_OK && fp_sql_open(cb2_p, &dcb2) == FP_OK);
        assert(fp_sql_exec(dcb1, "CREATE TABLE ck(id TEXT PRIMARY KEY, v TEXT);") == FP_OK);
        assert(fp_sql_exec(dcb2, "CREATE TABLE ck(id TEXT PRIMARY KEY COLLATE NOCASE, v TEXT);") == FP_OK);
        uint8_t *ccs = NULL; size_t ccsl = 0;
        assert(fp_sql_capture_changeset(dcb1, "ck", "INSERT INTO ck VALUES('Z','z'),('a','a');", &ccs, &ccsl) == FP_OK);
        fp_bundle_t bc;
        memset(&bc, 0, sizeof(bc));
        bc.version = 1; bc.entry_count = 1;
        bc.entries[0].role = FP_ROLE_SQLITE_CHANGESET; bc.entries[0].size = ccsl;
        snprintf(bc.entries[0].path, sizeof(bc.entries[0].path), "ck");
        assert(fp_store_put_object(store, ccs, ccsl, &bc.entries[0].dna) == FP_OK);
        free(ccs);
        fp_dna_t bc_dna;
        assert(fp_bundle_pack(store, &bc, &bc_dna) == FP_OK);
        assert(fp_bundle_apply(store, &bc_dna, ttgt, dcb2, 1, 0) == FP_ERR_INTEGRITY);
        assert(fp_sql_exec(dcb2, "INSERT INTO ck VALUES('Z','z'),('a','a');") == FP_OK);
        fp_dna_t cd1, cd2;
        assert(fp_sql_state_digest(dcb1, "ck", &cd1) == FP_OK && fp_sql_state_digest(dcb2, "ck", &cd2) == FP_OK);
        assert(!fp_dna_equal(&cd1, &cd2));

        /* TX-01 (A8-P0-03): Single-transaction fp_bundle_apply_chain() stages ONLY final gen & commits atomically! */
        char ch_tgt[256], ch_db_p[256];
        snprintf(ch_tgt, sizeof(ch_tgt), "%s/chain_tgt", tmp);
        snprintf(ch_db_p, sizeof(ch_db_p), "%s/chain.db", tmp);
        fp_sql_ctx_t *ch_db = NULL;
        assert(fp_sql_open(ch_db_p, &ch_db) == FP_OK);
        assert(fp_sql_exec(ch_db, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
        fp_bundle_step_t csteps[3] = {
            { b1_dna, 1 },
            { b2_dna, 2 },
            { b3_dna, 3 }
        };
        assert(fp_bundle_apply_chain(store, csteps, 3, ch_tgt, ch_db) == FP_OK);
        char g1h[65], g2h[65], g3h[65], gp1[360], gp2[360], gp3[360];
        fp_hex_encode(b1_dna.bytes, FP_DNA_LEN, g1h);
        fp_hex_encode(b2_dna.bytes, FP_DNA_LEN, g2h);
        fp_hex_encode(b3_dna.bytes, FP_DNA_LEN, g3h);
        snprintf(gp1, sizeof(gp1), "%s/gen/%s", ch_tgt, g1h);
        snprintf(gp2, sizeof(gp2), "%s/gen/%s", ch_tgt, g2h);
        snprintf(gp3, sizeof(gp3), "%s/gen/%s", ch_tgt, g3h);
        struct stat csb;
        assert(lstat(gp1, &csb) != 0 && lstat(gp2, &csb) != 0 && stat(gp3, &csb) == 0);
        fp_dna_t ch_dig;
        assert(fp_sql_state_digest(ch_db, "kv", &ch_dig) == FP_OK && fp_dna_equal(&ch_dig, &dig2));
        assert(fp_bundle_rollback(store, &b3_dna, NULL, ch_tgt, ch_db) == FP_OK);
        assert(fp_sql_state_digest(ch_db, "kv", &ch_dig) == FP_OK && fp_dna_equal(&ch_dig, &empty_dig));

        fp_sql_close(ch_db);
        fp_sql_close(dcb1);
        fp_sql_close(dcb2);
        fp_sql_close(dba);
        fp_sql_close(dbb);
        printf("[PASS] A8-P0-01/02/03 & A8-P1-01/02: Trigger side-effects, legacy raw, COLLATE mismatch & single-TX batch verified!\n");
    }

    /* A9-P0-01/02/03/04: Confined capture authorizer, FK/CASCADE fail-closed, SFCS1 rejection & global activation gate! */
    {
        /* SQL-01 (A9-P0-01): Exact Audit #9 Appendix A reproducer — multi-table DML & transaction-escape attempts
         * inside fp_sql_capture_changeset() MUST return FP_ERR_POLICY and leave BOTH tables 100% unchanged! */
        char a9_dbp[256];
        snprintf(a9_dbp, sizeof(a9_dbp), "%s/a9_auth.db", tmp);
        fp_sql_ctx_t *a9db = NULL;
        assert(fp_sql_open(a9_dbp, &a9db) == FP_OK);
        assert(fp_sql_exec(a9db, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
        assert(fp_sql_exec(a9db, "CREATE TABLE extra(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
        assert(fp_sql_exec(a9db, "INSERT INTO kv VALUES(1,10); INSERT INTO extra VALUES(1,20);") == FP_OK);
        fp_dna_t kv0, ex0, kv1, ex1;
        assert(fp_sql_state_digest(a9db, "kv", &kv0) == FP_OK);
        assert(fp_sql_state_digest(a9db, "extra", &ex0) == FP_OK);

        uint8_t *bad_cs = NULL; size_t bad_l = 0;
        assert(fp_sql_capture_changeset(a9db, "kv",
                                        "UPDATE kv SET v=11 WHERE k=1; UPDATE extra SET v=21 WHERE k=1;",
                                        &bad_cs, &bad_l) == FP_ERR_POLICY);
        assert(bad_cs == NULL && bad_l == 0);
        assert(fp_sql_state_digest(a9db, "kv", &kv1) == FP_OK && fp_dna_equal(&kv0, &kv1));
        assert(fp_sql_state_digest(a9db, "extra", &ex1) == FP_OK && fp_dna_equal(&ex0, &ex1));

        /* Also reject COMMIT escape / PRAGMA / DDL inside capture */
        assert(fp_sql_capture_changeset(a9db, "kv",
                                        "UPDATE kv SET v=12 WHERE k=1; COMMIT;",
                                        &bad_cs, &bad_l) == FP_ERR_POLICY);
        assert(fp_sql_capture_changeset(a9db, "kv",
                                        "PRAGMA foreign_keys=OFF; UPDATE kv SET v=12 WHERE k=1;",
                                        &bad_cs, &bad_l) == FP_ERR_POLICY);
        assert(fp_sql_state_digest(a9db, "kv", &kv1) == FP_OK && fp_dna_equal(&kv0, &kv1));

        /* Valid single-table capture produces SFCS2 header and succeeds cleanly */
        uint8_t *ok_cs = NULL; size_t ok_l = 0;
        assert(fp_sql_capture_changeset(a9db, "kv", "UPDATE kv SET v=99 WHERE k=1;", &ok_cs, &ok_l) == FP_OK);
        assert(ok_l > 42u && memcmp(ok_cs, "SFCS2", 5) == 0);

        /* COMPAT-01 (A9-P0-03): Explicit SFCS1 magic MUST be rejected fail-closed (FP_ERR_POLICY) */
        uint8_t *sfcs1_cs = malloc(ok_l);
        assert(sfcs1_cs != NULL);
        memcpy(sfcs1_cs, ok_cs, ok_l);
        memcpy(sfcs1_cs, "SFCS1", 5);
        fp_bundle_t b_sfcs1;
        memset(&b_sfcs1, 0, sizeof(b_sfcs1));
        b_sfcs1.version = 1; b_sfcs1.entry_count = 1;
        b_sfcs1.entries[0].role = FP_ROLE_SQLITE_CHANGESET; b_sfcs1.entries[0].size = ok_l;
        snprintf(b_sfcs1.entries[0].path, sizeof(b_sfcs1.entries[0].path), "kv");
        assert(fp_store_put_object(store, sfcs1_cs, ok_l, &b_sfcs1.entries[0].dna) == FP_OK);
        free(sfcs1_cs);
        free(ok_cs);
        fp_dna_t b_sfcs1_dna;
        assert(fp_bundle_pack(store, &b_sfcs1, &b_sfcs1_dna) == FP_OK);
        char a9_tgt[256];
        snprintf(a9_tgt, sizeof(a9_tgt), "%s/a9_tgt", tmp);
        assert(fp_bundle_apply(store, &b_sfcs1_dna, a9_tgt, a9db, 1, 0) == FP_ERR_POLICY);
        fp_sql_close(a9db);

        /* SQL-02 (A9-P0-02): Exact Audit #9 Appendix A Experiment B — inbound ON DELETE CASCADE MUST be
         * rejected fail-closed at capture (FP_ERR_POLICY), and PRAGMA foreign_keys mismatch rejected! */
        char fk_p[256], fk2_p[256];
        snprintf(fk_p, sizeof(fk_p), "%s/a9_fk.db", tmp);
        snprintf(fk2_p, sizeof(fk2_p), "%s/a9_fk2.db", tmp);
        fp_sql_ctx_t *fkdb = NULL, *fkdb2 = NULL;
        assert(fp_sql_open(fk_p, &fkdb) == FP_OK && fp_sql_open(fk2_p, &fkdb2) == FP_OK);
        assert(fp_sql_exec(fkdb, "CREATE TABLE parent(id INTEGER PRIMARY KEY);") == FP_OK);
        assert(fp_sql_exec(fkdb, "CREATE TABLE child(id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent(id) ON DELETE CASCADE);") == FP_OK);
        assert(fp_sql_exec(fkdb, "INSERT INTO parent VALUES(1); INSERT INTO child VALUES(10,1);") == FP_OK);
        assert(fp_sql_capture_changeset(fkdb, "parent", "DELETE FROM parent WHERE id=1;", &bad_cs, &bad_l) == FP_ERR_POLICY);
        /* Also test PRAGMA foreign_keys=ON vs OFF mismatch on non-cascading table */
        assert(fp_sql_exec(fkdb2, "CREATE TABLE p2(id INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
        assert(fp_sql_exec(fkdb, "CREATE TABLE p2(id INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
        assert(fp_sql_capture_changeset(fkdb, "p2", "INSERT INTO p2 VALUES(1,10);", &ok_cs, &ok_l) == FP_OK);
        assert(fp_sql_exec(fkdb2, "PRAGMA foreign_keys=OFF;") == FP_OK);
        fp_bundle_t b_fk;
        memset(&b_fk, 0, sizeof(b_fk));
        b_fk.version = 1; b_fk.entry_count = 1;
        b_fk.entries[0].role = FP_ROLE_SQLITE_CHANGESET; b_fk.entries[0].size = ok_l;
        snprintf(b_fk.entries[0].path, sizeof(b_fk.entries[0].path), "p2");
        assert(fp_store_put_object(store, ok_cs, ok_l, &b_fk.entries[0].dna) == FP_OK);
        free(ok_cs);
        fp_dna_t b_fk_dna;
        assert(fp_bundle_pack(store, &b_fk, &b_fk_dna) == FP_OK);
        assert(fp_bundle_apply(store, &b_fk_dna, a9_tgt, fkdb2, 1, 0) == FP_ERR_INTEGRITY);
        fp_sql_close(fkdb);
        fp_sql_close(fkdb2);

        /* REV-01 (A9-P0-04): Single Activation Authority — ACTIVATION_PENDING journal for a DNA in
         * `<store_dir>/.revoked_dnas` MUST NEVER create/flip `current` during fp_bundle_recover(),
         * AND direct fp_bundle_apply() on a revoked DNA MUST return FP_ERR_REVOKED! */
        char rev_store[256], rev_tgt[256], rev_dbp[256], rev_j[320], rev_cur[320];
        snprintf(rev_store, sizeof(rev_store), "%s/a9_rev_store", tmp);
        snprintf(rev_tgt, sizeof(rev_tgt), "%s/a9_rev_tgt", tmp);
        snprintf(rev_dbp, sizeof(rev_dbp), "%s/a9_rev.db", tmp);
        snprintf(rev_j, sizeof(rev_j), "%s/.sf_tx_journal", rev_tgt);
        snprintf(rev_cur, sizeof(rev_cur), "%s/current", rev_tgt);
        assert(mkdir(rev_store, 0755) == 0 && mkdir(rev_tgt, 0755) == 0);
        fp_sql_ctx_t *rdb = NULL;
        assert(fp_sql_open(rev_dbp, &rdb) == FP_OK);
        assert(fp_sql_exec(rdb, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
        uint8_t *rcs = NULL; size_t rcsl = 0;
        assert(fp_sql_capture_changeset(rdb, "kv", "INSERT INTO kv VALUES(7,70);", &rcs, &rcsl) == FP_OK);
        fp_bundle_t rb;
        memset(&rb, 0, sizeof(rb));
        rb.version = 1; rb.entry_count = 2;
        rb.entries[0].role = FP_ROLE_FILE; rb.entries[0].mode = 0644; rb.entries[0].size = 5;
        snprintf(rb.entries[0].path, sizeof(rb.entries[0].path), "r.txt");
        assert(fp_store_put_object(rev_store, (const uint8_t *)"REV!\n", 5, &rb.entries[0].dna) == FP_OK);
        rb.entries[1].role = FP_ROLE_SQLITE_CHANGESET; rb.entries[1].size = rcsl;
        snprintf(rb.entries[1].path, sizeof(rb.entries[1].path), "kv");
        assert(fp_store_put_object(rev_store, rcs, rcsl, &rb.entries[1].dna) == FP_OK);
        free(rcs);
        fp_dna_t rb_dna;
        assert(fp_bundle_pack(rev_store, &rb, &rb_dna) == FP_OK);
        fp_sql_close(rdb);

        /* Prepare fresh DB committed at seq=1 / rb_dna, write ACTIVATION_PENDING journal, add rb_dna to deny-set */
        char rev_dbp2[256];
        snprintf(rev_dbp2, sizeof(rev_dbp2), "%s/a9_rev2.db", tmp);
        assert(fp_sql_open(rev_dbp2, &rdb) == FP_OK);
        assert(fp_sql_exec(rdb, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v INTEGER);") == FP_OK);
        assert(fp_bundle_apply_sql_only(rev_store, &rb_dna, rev_tgt, rdb, 1) == FP_OK);
        char rb_hex[65], jline[160];
        fp_hex_encode(rb_dna.bytes, FP_DNA_LEN, rb_hex);
        int jln = snprintf(jline, sizeof(jline), "SFTX1 ACTIVATION_PENDING 1 %s 1\n", rb_hex);
        FILE *jf = fopen(rev_j, "wb");
        assert(jf != NULL && fwrite(jline, 1, (size_t)jln, jf) == (size_t)jln && fclose(jf) == 0);
        assert(fp_denyset_add(rev_store, &rb_dna) == FP_OK);
        assert(fp_denyset_check(rev_store, &rb_dna) == FP_DENY_REVOKED);

        /* Recover MUST NOT flip `current` to revoked DNA and MUST be idempotent R(R(S))==R(S) */
        assert(fp_bundle_recover(rev_store, rev_tgt, rdb) == FP_OK);
        struct stat rsb;
        assert(lstat(rev_cur, &rsb) != 0);
        assert(fp_bundle_recover(rev_store, rev_tgt, rdb) == FP_OK);
        assert(lstat(rev_cur, &rsb) != 0);
        /* Direct fp_bundle_apply() on revoked DNA MUST return FP_ERR_REVOKED */
        assert(fp_bundle_apply(rev_store, &rb_dna, rev_tgt, rdb, 2, 0) == FP_ERR_REVOKED);
        assert(lstat(rev_cur, &rsb) != 0);
        fp_sql_close(rdb);
        printf("[PASS] A9-P0-01/02/03/04 (SQL-01/SQL-02/COMPAT-01/REV-01): Authorizer, FK cascade, SFCS2 & global activation gate verified!\n");
    }

    fp_sql_close(src_db);
    fp_sql_close(dst_db);
}

int main(void) {
    assert(fp_init() == FP_OK);
    test_bundle_security_validation();
    test_composite_atomic_sigkill_and_rollback();
    test_p1_streaming_gc_and_merkle_index();
    test_m0_m1_hardening();
    test_tx06_tx07_multistep_and_initial_sql_rollback();
    test_m4_mixed_rollback_and_sql_namespace_guards();
    printf("ALL M3 PARTICLE BUNDLE & SQLITE SESSION TESTS PASSED.\n");
    return 0;
}
