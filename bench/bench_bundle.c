#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(void) {
    if (fp_init() != FP_OK) return 1;
    char dt[] = "/tmp/fp-bbundle-XXXXXX";
    char *dir = mkdtemp(dt);
    char store[256], target[256], sdb_p[256], ddb_p[256];
    snprintf(store, sizeof(store), "%s/store", dir);
    snprintf(target, sizeof(target), "%s/live", dir);
    snprintf(sdb_p, sizeof(sdb_p), "%s/src.db", dir);
    snprintf(ddb_p, sizeof(ddb_p), "%s/dst.db", dir);

    fp_sql_ctx_t *sdb = NULL, *ddb = NULL;
    fp_sql_open(sdb_p, &sdb);
    fp_sql_open(ddb_p, &ddb);
    const char *schema = "CREATE TABLE kv(k INTEGER PRIMARY KEY, v TEXT NOT NULL);";
    fp_sql_exec(sdb, schema);
    fp_sql_exec(ddb, schema);

    const int N = 20;
    fp_dna_t bundles[20];
    uint64_t cap_ns = 0, app_ns = 0;

    for (int i = 1; i <= N; i++) {
        char sql[256], cfg[128];
        snprintf(sql, sizeof(sql), "INSERT INTO kv VALUES (%d, 'state-val-%d');", i, i);
        snprintf(cfg, sizeof(cfg), "config_generation=%d\n", i);

        uint64_t t0 = now_ns();
        uint8_t *cs = NULL; size_t cs_len = 0;
        fp_sql_capture_changeset(sdb, "kv", sql, &cs, &cs_len);
        cap_ns += now_ns() - t0;

        fp_bundle_t b;
        memset(&b, 0, sizeof(b));
        b.version = 1; b.entry_count = 2;
        b.entries[0].role = FP_ROLE_FILE; b.entries[0].mode = 0644; b.entries[0].size = strlen(cfg);
        snprintf(b.entries[0].path, sizeof(b.entries[0].path), "config.ini");
        fp_store_put_object(store, (const uint8_t *)cfg, strlen(cfg), &b.entries[0].dna);
        b.entries[1].role = FP_ROLE_SQLITE_CHANGESET; b.entries[1].size = cs_len;
        snprintf(b.entries[1].path, sizeof(b.entries[1].path), "kv");
        fp_store_put_object(store, cs, cs_len, &b.entries[1].dna);
        free(cs);
        fp_bundle_pack(store, &b, &bundles[i - 1]);

        t0 = now_ns();
        fp_bundle_apply(store, &bundles[i - 1], target, ddb, (uint64_t)i, 0);
        app_ns += now_ns() - t0;
    }

    uint64_t t0 = now_ns();
    fp_bundle_rollback(store, &bundles[N - 1], &bundles[N - 2], target, ddb);
    uint64_t rb_ns = now_ns() - t0;

    printf("\n=== M3 Composite Particle Bundle (File + Persistent SQLite WAL FULL) ===\n");
    printf("SQLite Changeset Capture   : %6.3f ms / txn (avg over %d)\n", (double)cap_ns / (N * 1e6), N);
    printf("Atomic Bundle Apply (fsync): %6.3f ms / bundle (files + DB commit + symlink)\n",
           (double)app_ns / (N * 1e6));
    printf("Full-Stack Atomic Rollback : %6.3f ms (files + sqlite3changeset_invert)\n", (double)rb_ns / 1e6);

    fp_sql_close(sdb);
    fp_sql_close(ddb);
    return 0;
}
