#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(void) {
    assert(fp_init() == FP_OK);
    test_bundle_security_validation();
    test_composite_atomic_sigkill_and_rollback();
    printf("ALL M3 PARTICLE BUNDLE & SQLITE SESSION TESTS PASSED.\n");
    return 0;
}
