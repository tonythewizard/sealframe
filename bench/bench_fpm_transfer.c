/* Linux loopback benchmark. Build with make build/bench_fpm_transfer. */
#ifdef NDEBUG
#error "The benchmark requires its integrity checks"
#endif
#define _GNU_SOURCE
#include "fp.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t sent, previous, count, capacity, *gaps;
static uint64_t now(clockid_t clock) {
    struct timespec ts;
    assert(clock_gettime(clock, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

ssize_t __real_send(int, const void *, size_t, int);
ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    ssize_t n = __real_send(fd, buf, len, flags);
    if (n > 0) sent += (uint64_t)n;
    return n;
}
ssize_t __real_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *addr, socklen_t alen) {
    ssize_t n = __real_sendto(fd, buf, len, flags, addr, alen);
    if (n > 0) sent += (uint64_t)n;
    return n;
}
fp_err_t __real_fp_merkle_verify(const fp_dna_t *, const fp_merkle_proof_t *,
                                 const uint8_t *, size_t);
fp_err_t __wrap_fp_merkle_verify(const fp_dna_t *dna, const fp_merkle_proof_t *proof,
                                 const uint8_t *data, size_t size) {
    fp_err_t err = __real_fp_merkle_verify(dna, proof, data, size);
    if (err == FP_OK && gaps) {
        uint64_t t = now(CLOCK_MONOTONIC);
        assert(count < capacity);
        if (count) gaps[count - 1] = t - previous;
        previous = t;
        count++;
    }
    return err;
}
static int compare(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    if (argc != 5 || (strcmp(argv[1],"tcp") && strcmp(argv[1],"udp"))) {
        fprintf(stderr, "usage: bench tcp|udp server-store empty-client-store dna\n");
        return 2;
    }
    int udp = !strcmp(argv[1],"udp");
    fp_keypair_t server, client;
    fp_dna_t expected, actual;
    assert(fp_init() == FP_OK && fp_keygen(&server) == FP_OK && fp_keygen(&client) == FP_OK);
    assert(fp_hex_decode(argv[4], expected.bytes, FP_DNA_LEN) == FP_OK);
    uint64_t bytes = 0;
    assert(fp_store_has_object(argv[2], &expected, &bytes) && bytes > (1ull << 30));
    capacity = (bytes - 1) / FP_CHUNK_SIZE + 1;
    uint16_t port = 0;
    int fd = udp ? fp_udp_bind("127.0.0.1", 0, &port) : fp_net_listen("127.0.0.1", 0, &port);
    assert(fd >= 0);
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(pipefd[0]);
        fp_err_t err;
        if (udp) {
            fp_udp_server_cfg_t cfg = {.store_dir=argv[2], .server_kp=&server,
                .allowed_peer_pk=client.pk, .max_sessions=1, .io_timeout_ms=15000};
            err = fp_udp_serve_fd(fd, &cfg);
        } else {
            fp_net_server_cfg_t cfg = {.store_dir=argv[2], .server_kp=&server,
                .allowed_peer_pk=client.pk, .max_requests=1, .io_timeout_ms=60000};
            err = fp_net_serve_fd(fd, &cfg);
        }
        assert(write(pipefd[1], &sent, sizeof(sent)) == sizeof(sent));
        _exit(err == FP_OK ? 0 : 1);
    }
    close(fd);
    close(pipefd[1]);
    gaps = calloc(capacity, sizeof(*gaps));
    assert(gaps);
    uint64_t cpu = now(CLOCK_PROCESS_CPUTIME_ID), start = now(CLOCK_MONOTONIC);
    fp_err_t err;
    if (udp) {
        fp_udp_pull_cfg_t cfg = {.host="127.0.0.1", .port=port, .store_dir=argv[3],
            .client_kp=&client, .expected_srv_pk=server.pk, .target_dna=expected,
            .max_output=bytes, .io_timeout_ms=60000};
        err = fp_udp_pull(&cfg, NULL);
    } else {
        fp_net_pull_cfg_t cfg = {.host="127.0.0.1", .port=port, .store_dir=argv[3],
            .client_kp=&client, .expected_srv_pk=server.pk, .target_dna=expected,
            .max_output=bytes, .force_merkle_stream=1, .io_timeout_ms=60000};
        err = fp_net_pull(&cfg, NULL);
    }
    uint64_t elapsed = now(CLOCK_MONOTONIC) - start;
    cpu = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    if (err != FP_OK) {
        fprintf(stderr, "pull: %s\n", fp_strerror(err));
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 1;
    }
    int status;
    struct rusage sr, cr;
    assert(getrusage(RUSAGE_SELF, &cr) == 0);
    assert(wait4(pid, &status, 0, &sr) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    uint64_t server_sent;
    assert(read(pipefd[0], &server_sent, sizeof(server_sent)) == sizeof(server_sent));
    close(pipefd[0]);
    char path[4096];
    assert(snprintf(path,sizeof(path),"%s/objects/%s",argv[3],argv[4]) < (int)sizeof(path));
    uint64_t verified;
    assert(fp_dna_compute_file(path,&actual,&verified) == FP_OK && verified == bytes &&
           fp_dna_equal(&actual,&expected) && count == capacity);
    qsort(gaps, count-1, sizeof(*gaps), compare);
    uint64_t server_cpu = 1000000ull * (sr.ru_utime.tv_sec + sr.ru_stime.tv_sec)
                        + sr.ru_utime.tv_usec + sr.ru_stime.tv_usec;
    printf("{\"wall_ns\":%"PRIu64",\"verified_gap_p99_ns\":%"PRIu64
           ",\"client_cpu_ns\":%"PRIu64",\"server_cpu_us\":%"PRIu64
           ",\"client_rss_kib\":%ld,\"server_rss_kib\":%ld,\"socket_bytes\":%"PRIu64
           ",\"chunks\":%"PRIu64",\"dna\":\"%s\"}\n", elapsed,
           gaps[((count-1)*99+99)/100-1],cpu,server_cpu,cr.ru_maxrss,sr.ru_maxrss,
           sent+server_sent,count,argv[4]);
    free(gaps);
    return 0;
}
