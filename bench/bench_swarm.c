#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct { int fd; fp_net_server_cfg_t cfg; } tsrv_t;
typedef struct { int fd; fp_udp_server_cfg_t cfg; } usrv_t;

static void *run_t(void *a) { tsrv_t *s = a; (void)fp_net_serve_fd(s->fd, &s->cfg); close(s->fd); return NULL; }
static void *run_u(void *a) { usrv_t *s = a; (void)fp_udp_serve_fd(s->fd, &s->cfg); close(s->fd); return NULL; }

int main(void) {
    if (fp_init() != FP_OK) return 1;
    char st[] = "/tmp/fp-bsw-s-XXXXXX", ct[] = "/tmp/fp-bsw-c-XXXXXX";
    char *sdir = mkdtemp(st), *cdir = mkdtemp(ct);

    const size_t N = 4u << 20; /* 4 MiB */
    uint8_t *buf = malloc(N);
    for (size_t i = 0; i < N; i++) buf[i] = (uint8_t)((i * 131u) ^ (i >> 7));
    fp_dna_t dna;
    fp_store_put_object(sdir, buf, N, &dna);
    free(buf);

    fp_keypair_t ckp, skp[3];
    fp_keygen(&ckp);
    for (int i = 0; i < 3; i++) fp_keygen(&skp[i]);

    /* 1. 3-Peer Parallel Swarm (4 MiB) */
    pthread_t th[3]; tsrv_t srvs[3]; fp_swarm_peer_t peers[3];
    for (int i = 0; i < 3; i++) {
        uint16_t p = 0;
        memset(&srvs[i], 0, sizeof(srvs[i]));
        srvs[i].fd = fp_net_listen("127.0.0.1", 0, &p);
        srvs[i].cfg.bind_addr = "127.0.0.1"; srvs[i].cfg.port = p;
        srvs[i].cfg.store_dir = sdir; srvs[i].cfg.server_kp = &skp[i];
        srvs[i].cfg.max_requests = 1;
        pthread_create(&th[i], NULL, run_t, &srvs[i]);
        peers[i] = (fp_swarm_peer_t){ "127.0.0.1", p, NULL };
    }
    fp_swarm_cfg_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.store_dir = cdir; scfg.client_kp = &ckp; scfg.target_dna = dna;
    scfg.peers = peers; scfg.peer_count = 3;
    fp_swarm_stats_t sw;
    fp_swarm_pull(&scfg, &sw);
    for (int i = 0; i < 3; i++) pthread_join(th[i], NULL);

    printf("\n=== M5 Multi-Peer Swarm & Encrypted UDP Benchmark (4.00 MiB) ===\n");
    printf("3-Peer Parallel Swarm     : %7.1f MiB/s | elapsed=%6.2f ms | chunks=[%llu,%llu,%llu]\n",
           4.0 / ((double)sw.elapsed_ns / 1e9), (double)sw.elapsed_ns / 1e6,
           (unsigned long long)sw.per_peer_chunks[0],
           (unsigned long long)sw.per_peer_chunks[1],
           (unsigned long long)sw.per_peer_chunks[2]);

    /* 2. Encrypted UDP (0% loss vs 5% loss) */
    uint32_t losses[2] = { 0, 5 };
    for (int li = 0; li < 2; li++) {
        char uct[] = "/tmp/fp-budp-c-XXXXXX";
        char *ucdir = mkdtemp(uct);
        uint16_t p = 0;
        usrv_t us;
        memset(&us, 0, sizeof(us));
        us.fd = fp_udp_bind("127.0.0.1", 0, &p);
        us.cfg.bind_addr = "127.0.0.1"; us.cfg.port = p; us.cfg.store_dir = sdir;
        us.cfg.server_kp = &skp[0]; us.cfg.max_sessions = 1;
        us.cfg.fault_drop_pct = losses[li];
        pthread_t uth;
        pthread_create(&uth, NULL, run_u, &us);

        fp_udp_pull_cfg_t upc;
        memset(&upc, 0, sizeof(upc));
        upc.host = "127.0.0.1"; upc.port = p; upc.store_dir = ucdir;
        upc.client_kp = &ckp; upc.expected_srv_pk = skp[0].pk; upc.target_dna = dna;
        fp_udp_stats_t ust;
        fp_udp_pull(&upc, &ust);
        pthread_join(uth, NULL);

        printf("Encrypted UDP (%2u%% loss)  : %7.1f MiB/s | elapsed=%6.2f ms | retrans=%llu | cwnd=%u | srtt=%.2f ms\n",
               losses[li], 4.0 / ((double)ust.elapsed_ns / 1e9),
               (double)ust.elapsed_ns / 1e6, (unsigned long long)ust.retransmits,
               ust.final_cwnd, (double)ust.srtt_us / 1000.0);
    }
    return 0;
}
