#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int                 lfd;
    fp_net_server_cfg_t cfg;
} srv_ctx_t;

static void *srv_main(void *arg) {
    srv_ctx_t *s = (srv_ctx_t *)arg;
    (void)fp_net_serve_fd(s->lfd, &s->cfg);
    close(s->lfd);
    return NULL;
}

static void fill_structured(uint8_t *buf, size_t len) {
    uint32_t x = 0xCAFEBABEu;
    for (size_t i = 0; i < len; i++) {
        if ((i & 63u) < 40u) buf[i] = (uint8_t)('A' + (i % 26u));
        else { x = x * 1664525u + 1013904223u; buf[i] = (uint8_t)(x >> 24); }
    }
}

int main(void) {
    if (fp_init() != FP_OK) return 1;
    fp_keypair_t skp, ckp;
    fp_keygen(&skp);
    fp_keygen(&ckp);

    char st[] = "/tmp/fp-bnet-s-XXXXXX";
    char ct[] = "/tmp/fp-bnet-c-XXXXXX";
    char *sdir = mkdtemp(st);
    char *cdir = mkdtemp(ct);

    const size_t N = 4u << 20; /* 4 MiB */
    uint8_t *v1 = malloc(N);
    uint8_t *v2 = malloc(N);
    fill_structured(v1, N);
    memcpy(v2, v1, N);
    for (size_t i = 0; i < 4096; i++) v2[N / 3 + i] ^= (uint8_t)(i * 19u + 3u);

    fp_dna_t d1, d2;
    fp_store_put_object(sdir, v1, N, &d1);
    fp_store_put_object(sdir, v2, N, &d2);

    uint16_t port = 0;
    srv_ctx_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.lfd = fp_net_listen("127.0.0.1", 0, &port);
    sc.cfg.bind_addr = "127.0.0.1";
    sc.cfg.port = port;
    sc.cfg.store_dir = sdir;
    sc.cfg.server_kp = &skp;
    sc.cfg.allowed_peer_pk = ckp.pk;
    sc.cfg.max_requests = 4;

    pthread_t th;
    pthread_create(&th, NULL, srv_main, &sc);

    printf("\n=== FP-NET v1 Encrypted TCP Benchmark (4.00 MiB, X25519+XChaCha20-Poly1305) ===\n");

    fp_net_pull_cfg_t pc;
    fp_net_stats_t res;

    /* 1. Merkle Verified Streaming (forced) */
    memset(&pc, 0, sizeof(pc));
    pc.host = "127.0.0.1"; pc.port = port; pc.store_dir = cdir;
    pc.client_kp = &ckp; pc.expected_srv_pk = skp.pk;
    pc.target_dna = d1; pc.force_merkle_stream = 1;
    fp_net_pull(&pc, &res);
    printf("Merkle Stream (16KiB) : wire=%9llu B | elapsed=%7.3f ms | eff=%7.1f MiB/s\n",
           (unsigned long long)res.wire_bytes, (double)res.elapsed_ns / 1e6,
           ((double)N / (1024.0 * 1024.0)) / ((double)res.elapsed_ns / 1e9));

    /* 2. Autonomous ZSTD (fresh client store) */
    char ct2[] = "/tmp/fp-bnet-c2-XXXXXX";
    char *cdir2 = mkdtemp(ct2);
    pc.store_dir = cdir2; pc.force_merkle_stream = 0;
    fp_net_pull(&pc, &res);
    printf("Autonomous ZSTD       : wire=%9llu B | elapsed=%7.3f ms | eff=%7.1f MiB/s\n",
           (unsigned long long)res.wire_bytes, (double)res.elapsed_ns / 1e6,
           ((double)N / (1024.0 * 1024.0)) / ((double)res.elapsed_ns / 1e9));

    /* 3. Autonomous DELTA (v1 resident -> pull v2) */
    pc.target_dna = d2;
    pc.extra_refs[0] = d1;
    pc.extra_ref_count = 1;
    fp_net_pull(&pc, &res);
    printf("Autonomous DELTA      : wire=%9llu B | elapsed=%7.3f ms | eff=%7.1f MiB/s\n",
           (unsigned long long)res.wire_bytes, (double)res.elapsed_ns / 1e6,
           ((double)N / (1024.0 * 1024.0)) / ((double)res.elapsed_ns / 1e9));

    /* 4. Autonomous REF (v2 already resident) */
    pc.extra_ref_count = 0;
    fp_net_pull(&pc, &res);
    printf("Autonomous REF (0 B)  : wire=%9llu B | elapsed=%7.3f ms\n",
           (unsigned long long)res.wire_bytes, (double)res.elapsed_ns / 1e6);

    pthread_join(th, NULL);
    free(v1); free(v2);
    return 0;
}
