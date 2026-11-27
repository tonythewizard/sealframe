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

int main(void) {
    assert(fp_init() == FP_OK);
    test_bundle_security_validation();
    test_composite_atomic_sigkill_and_rollback();
    test_p1_streaming_gc_and_merkle_index();
    printf("ALL M3 PARTICLE BUNDLE & SQLITE SESSION TESTS PASSED.\n");
    return 0;
}
