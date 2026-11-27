#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct { int fd; fp_net_server_cfg_t cfg; } tsrv_t;
typedef struct { int fd; fp_udp_server_cfg_t cfg; } usrv_t;

static void *run_t(void *a) { tsrv_t *s = a; (void)fp_net_serve_fd(s->fd, &s->cfg); close(s->fd); return NULL; }
static void *run_u(void *a) { usrv_t *s = a; (void)fp_udp_serve_fd(s->fd, &s->cfg); close(s->fd); return NULL; }

static void fill_prng(uint8_t *buf, size_t len, uint64_t seed) {
    uint64_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        buf[i] = (uint8_t)((x * UINT64_C(0x2545F4914F6CDD1D)) >> 56);
    }
}

/* Chaos 1: 10 consecutive OS SIGKILL crashes during composite bundle apply */
static void chaos_repeated_sigkill_bundles(void) {
    char dt[] = "/tmp/fp-ch-kill-XXXXXX";
    char *dir = mkdtemp(dt);
    assert(dir != NULL);

    char store[256], target[256], sdb_p[256], ddb_p[256];
    snprintf(store, sizeof(store), "%s/store", dir);
    snprintf(target, sizeof(target), "%s/live", dir);
    snprintf(sdb_p, sizeof(sdb_p), "%s/src.db", dir);
    snprintf(ddb_p, sizeof(ddb_p), "%s/dst.db", dir);

    const char *schema = "CREATE TABLE ledger(id INTEGER PRIMARY KEY, val TEXT NOT NULL);";
    fp_sql_ctx_t *sdb = NULL, *ddb = NULL;
    assert(fp_sql_open(sdb_p, &sdb) == FP_OK);
    assert(fp_sql_open(ddb_p, &ddb) == FP_OK);
    assert(fp_sql_exec(sdb, schema) == FP_OK);
    assert(fp_sql_exec(ddb, schema) == FP_OK);

    fp_dna_t expected_sql_state;
    assert(fp_sql_state_digest(sdb, "ledger", &expected_sql_state) == FP_OK);

    for (int round = 1; round <= 10; round++) {
        char sql[128], payload[128];
        snprintf(sql, sizeof(sql), "INSERT INTO ledger VALUES (%d, 'round-%d');", round, round);
        snprintf(payload, sizeof(payload), "binary-generation-%d", round);

        uint8_t *cs = NULL; size_t cs_len = 0;
        assert(fp_sql_capture_changeset(sdb, "ledger", sql, &cs, &cs_len) == FP_OK);
        fp_dna_t new_sql_state;
        assert(fp_sql_state_digest(sdb, "ledger", &new_sql_state) == FP_OK);

        fp_bundle_t b;
        memset(&b, 0, sizeof(b));
        b.version = 1; b.entry_count = 2;
        b.entries[0].role = FP_ROLE_FILE; b.entries[0].mode = 0644; b.entries[0].size = strlen(payload);
        snprintf(b.entries[0].path, sizeof(b.entries[0].path), "state.txt");
        assert(fp_store_put_object(store, (const uint8_t *)payload, strlen(payload), &b.entries[0].dna) == FP_OK);
        b.entries[1].role = FP_ROLE_SQLITE_CHANGESET; b.entries[1].size = cs_len;
        snprintf(b.entries[1].path, sizeof(b.entries[1].path), "ledger");
        assert(fp_store_put_object(store, cs, cs_len, &b.entries[1].dna) == FP_OK);
        free(cs);

        fp_dna_t bdna;
        assert(fp_bundle_pack(store, &b, &bdna) == FP_OK);

        /* Close DB, fork child, inject SIGKILL right before COMMIT! */
        fp_sql_close(ddb); ddb = NULL;
        pid_t pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
            fp_sql_ctx_t *cdb = NULL;
            if (fp_sql_open(ddb_p, &cdb) != FP_OK) _exit(2);
            (void)fp_bundle_apply(store, &bdna, target, cdb, (uint64_t)round, 1);
            _exit(3);
        }
        int ws = 0;
        assert(waitpid(pid, &ws, 0) == pid);
        assert(WIFSIGNALED(ws) && WTERMSIG(ws) == SIGKILL);

        /* Reopen & confirm ZERO partial DB corruption */
        assert(fp_sql_open(ddb_p, &ddb) == FP_OK);
        fp_dna_t after_kill;
        assert(fp_sql_state_digest(ddb, "ledger", &after_kill) == FP_OK);
        assert(fp_dna_equal(&after_kill, &expected_sql_state));

        /* Now apply cleanly and verify state advances identically */
        assert(fp_bundle_apply(store, &bdna, target, ddb, (uint64_t)round, 0) == FP_OK);
        assert(fp_sql_state_digest(ddb, "ledger", &after_kill) == FP_OK);
        assert(fp_dna_equal(&after_kill, &new_sql_state));
        expected_sql_state = new_sql_state;
    }

    fp_sql_close(sdb);
    fp_sql_close(ddb);
    printf("[PASS] Chaos 1: 10 consecutive OS SIGKILL crashes during composite apply -> 0 corrupt states\n");
}

/* Chaos 2: 4-stage multi-drop TCP blackout resume (drops at chunks 5, 17, 41, then finishes 64) */
static void chaos_multidrop_tcp_resume(void) {
    char st[] = "/tmp/fp-ch-s-XXXXXX", ct[] = "/tmp/fp-ch-c-XXXXXX";
    char *sdir = mkdtemp(st), *cdir = mkdtemp(ct);
    assert(sdir && cdir);

    const size_t N = 1u << 20; /* 64 chunks */
    uint8_t *data = malloc(N);
    assert(data != NULL);
    fill_prng(data, N, 0xBAD0C0DEu);
    fp_dna_t dna;
    assert(fp_store_put_object(sdir, data, N, &dna) == FP_OK);

    fp_keypair_t skp, ckp;
    assert(fp_keygen(&skp) == FP_OK);
    assert(fp_keygen(&ckp) == FP_OK);

    const uint64_t drops[4] = { 5, 12, 24, 0 }; /* 5 -> +12 (17) -> +24 (41) -> +23 (64) */
    uint64_t expected_resumed[4] = { 0, 5, 17, 41 };

    for (int step = 0; step < 4; step++) {
        uint16_t port = 0;
        tsrv_t s;
        memset(&s, 0, sizeof(s));
        s.fd = fp_net_listen("127.0.0.1", 0, &port);
        assert(s.fd >= 0);
        s.cfg.bind_addr = "127.0.0.1"; s.cfg.port = port; s.cfg.store_dir = sdir;
        s.cfg.server_kp = &skp; s.cfg.max_requests = 1;
        s.cfg.fault_drop_after_chunks = drops[step];
        pthread_t th;
        assert(pthread_create(&th, NULL, run_t, &s) == 0);

        fp_net_pull_cfg_t pc;
        fp_net_stats_t res;
        memset(&pc, 0, sizeof(pc));
        pc.host = "127.0.0.1"; pc.port = port; pc.store_dir = cdir;
        pc.client_kp = &ckp; pc.expected_srv_pk = skp.pk;
        pc.target_dna = dna; pc.force_merkle_stream = 1;

        fp_err_t err = fp_net_pull(&pc, &res);
        pthread_join(th, NULL);
        assert(res.resumed_chunks == expected_resumed[step]);
        if (step < 3) {
            assert(err == FP_ERR_IO && res.received_chunks == drops[step]);
        } else {
            assert(err == FP_OK && res.received_chunks == 23);
        }
    }

    uint8_t *got = NULL; size_t got_len = 0;
    assert(fp_store_get_object(cdir, &dna, N, &got, &got_len) == FP_OK);
    assert(got_len == N && memcmp(got, data, N) == 0);
    free(got); free(data);
    printf("[PASS] Chaos 2: 4-stage repeated TCP blackouts (0->5->17->41->64 chunks) resumed bit-exact\n");
}

/* Chaos 3: Extreme 25% UDP packet loss + live socket/port migration */
static void chaos_extreme_udp_25pct_loss(void) {
    char st[] = "/tmp/fp-ch-us-XXXXXX", ct[] = "/tmp/fp-ch-uc-XXXXXX";
    char *sdir = mkdtemp(st), *cdir = mkdtemp(ct);
    assert(sdir && cdir);

    const size_t N = 256u << 10; /* 16 chunks */
    uint8_t *data = malloc(N);
    assert(data != NULL);
    fill_prng(data, N, 0x25252525u);
    fp_dna_t dna;
    assert(fp_store_put_object(sdir, data, N, &dna) == FP_OK);

    fp_keypair_t skp, ckp;
    assert(fp_keygen(&skp) == FP_OK);
    assert(fp_keygen(&ckp) == FP_OK);

    uint16_t port = 0;
    usrv_t u;
    memset(&u, 0, sizeof(u));
    u.fd = fp_udp_bind("127.0.0.1", 0, &port);
    assert(u.fd >= 0);
    u.cfg.bind_addr = "127.0.0.1"; u.cfg.port = port; u.cfg.store_dir = sdir;
    u.cfg.server_kp = &skp; u.cfg.max_sessions = 1;
    u.cfg.fault_drop_pct = 25; /* 1 out of 4 packets dropped! */
    pthread_t th;
    assert(pthread_create(&th, NULL, run_u, &u) == 0);

    fp_udp_pull_cfg_t pc;
    fp_udp_stats_t res;
    memset(&pc, 0, sizeof(pc));
    pc.host = "127.0.0.1"; pc.port = port; pc.store_dir = cdir;
    pc.client_kp = &ckp; pc.expected_srv_pk = skp.pk;
    pc.target_dna = dna; pc.test_migrate_at_chunk = 8;

    assert(fp_udp_pull(&pc, &res) == FP_OK);
    pthread_join(th, NULL);
    assert(res.retransmits > 10 && res.migrations == 1);

    uint8_t *got = NULL; size_t got_len = 0;
    assert(fp_store_get_object(cdir, &dna, N, &got, &got_len) == FP_OK);
    assert(got_len == N && memcmp(got, data, N) == 0);
    free(got); free(data);
    printf("[PASS] Chaos 3: Extreme 25%% UDP packet loss + live migration recovered cleanly (retrans=%llu, %.2f ms)\n",
           (unsigned long long)res.retransmits, (double)res.elapsed_ns / 1e6);
}

/* Chaos 4: Silent disk bit-rot in objects/ and state.bin fails closed */
static void chaos_silent_bitrot_detection(void) {
    char dt[] = "/tmp/fp-ch-rot-XXXXXX";
    char *sdir = mkdtemp(dt);
    assert(sdir != NULL);

    const uint8_t msg[] = "critical flight firmware image";
    fp_dna_t dna;
    assert(fp_store_put_object(sdir, msg, sizeof(msg), &dna) == FP_OK);

    char hex[65], opath[512];
    fp_hex_encode(dna.bytes, FP_DNA_LEN, hex);
    snprintf(opath, sizeof(opath), "%s/objects/%s", sdir, hex);

    /* Flip 1 bit silently on disk */
    FILE *f = fopen(opath, "r+b");
    assert(f != NULL);
    int b = fgetc(f);
    rewind(f);
    fputc(b ^ 0x01, f);
    fclose(f);

    uint8_t *out = NULL; size_t olen = 0;
    assert(fp_store_get_object(sdir, &dna, 1024, &out, &olen) == FP_ERR_INTEGRITY);
    assert(out == NULL);

    /* Corrupt state.bin magic */
    char spath[512];
    snprintf(spath, sizeof(spath), "%s/state.bin", sdir);
    f = fopen(spath, "wb");
    assert(f != NULL);
    fwrite("CORRUPT_STATE_BYTES", 1, 19, f);
    fclose(f);
    fp_store_state_t st;
    assert(fp_store_load_state(sdir, &st) == FP_ERR_INTEGRITY);

    printf("[PASS] Chaos 4: Silent bit-rot on objects/ and state.bin detected fail-closed\n");
}

int main(void) {
    assert(fp_init() == FP_OK);
    chaos_repeated_sigkill_bundles();
    chaos_multidrop_tcp_resume();
    chaos_extreme_udp_25pct_loss();
    chaos_silent_bitrot_detection();
    printf("ALL M6 CHAOS & FAULT-INJECTION TESTS PASSED.\n");
    return 0;
}
