#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void fill_prng(uint8_t *buf, size_t len, uint64_t seed) {
    uint64_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        buf[i] = (uint8_t)((x * UINT64_C(0x2545F4914F6CDD1D)) >> 56);
    }
}

int main(void) {
    if (fp_init() != FP_OK) return 1;

    /* 1. Pure FastCDC scan speed on 32 MiB */
    const size_t N = 32u << 20;
    uint8_t *buf = malloc(N);
    if (!buf) return 1;
    fill_prng(buf, N, 0x55AAu);

    uint64_t t0 = now_ns();
    size_t pos = 0, chunks = 0;
    while (pos < N) {
        size_t cut = fp_fastcdc_cut(buf + pos, N - pos);
        pos += cut;
        chunks++;
    }
    double cdc_s = (double)(now_ns() - t0) / 1e9;
    printf("\n=== M2 FastCDC & Cross-File Composition Benchmark ===\n");
    printf("Pure FastCDC Cut (32 MiB)  : %8.1f MiB/s | chunks=%zu | avg=%.1f KiB\n",
           32.0 / cdc_s, chunks, ((double)N / (double)chunks) / 1024.0);

    /* 2. Streaming O(1) RAM Ingest + Shift Dedup + Reconstruct on 16 MiB incompressible data */
    char dt[] = "/tmp/fp-bcdc-XXXXXX";
    char *dir = mkdtemp(dt);
    char store[256], f1[256], f2[256], fout[256];
    snprintf(store, sizeof(store), "%s/store", dir);
    snprintf(f1, sizeof(f1), "%s/v1.bin", dir);
    snprintf(f2, sizeof(f2), "%s/v2.bin", dir);
    snprintf(fout, sizeof(fout), "%s/v2.out", dir);

    const size_t FSZ = 16u << 20;
    FILE *fp1 = fopen(f1, "wb");
    fwrite(buf, 1, FSZ, fp1);
    fclose(fp1);

    /* v2 = 251 bytes prepended + v1 (incompressible random, shifted!) */
    uint8_t prefix[251];
    fill_prng(prefix, sizeof(prefix), 0x1234u);
    FILE *fp2 = fopen(f2, "wb");
    fwrite(prefix, 1, sizeof(prefix), fp2);
    fwrite(buf, 1, FSZ, fp2);
    fclose(fp2);
    free(buf); /* Release test generator buffer before measuring streaming */

    fp_cdc_stats_t s1, s2;
    fp_cdc_ingest_file(store, f1, &s1);
    fp_cdc_ingest_file(store, f2, &s2);

    t0 = now_ns();
    uint64_t rbytes = 0;
    fp_cdc_reconstruct_file(store, &s2.dna, fout, &rbytes);
    double rec_s = (double)(now_ns() - t0) / 1e9;

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);

    printf("Ingest v1 (16 MiB cold)    : %7.1f MiB/s | new=%llu chunks | stored=%llu B\n",
           16.0 / ((double)s1.elapsed_ns / 1e9),
           (unsigned long long)s1.new_chunks, (unsigned long long)s1.stored_bytes);
    printf("Ingest v2 (+251B shifted)  : %7.1f MiB/s | new=%llu | dedup=%llu | reused=%.2f%% (only %llu B new!)\n",
           16.0 / ((double)s2.elapsed_ns / 1e9),
           (unsigned long long)s2.new_chunks, (unsigned long long)s2.dedup_chunks,
           100.0 * (double)s2.reused_bytes / (double)s2.canonical_size,
           (unsigned long long)s2.stored_bytes);
    printf("Reconstruct v2 (verified)  : %7.1f MiB/s | bytes=%llu | proc_peak_rss=%.1f MiB\n",
           16.0 / rec_s, (unsigned long long)rbytes, (double)ru.ru_maxrss / 1024.0);

    return 0;
}
