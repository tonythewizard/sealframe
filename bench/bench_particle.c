#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void fill_structured(uint8_t *buf, size_t len) {
    uint32_t x = 0x12345678u;
    for (size_t i = 0; i < len; i++) {
        if ((i & 63u) < 40u) {
            buf[i] = (uint8_t)('A' + (i % 26u));
        } else {
            x = x * 1664525u + 1013904223u;
            buf[i] = (uint8_t)(x >> 24);
        }
    }
}

int main(void) {
    if (fp_init() != FP_OK) return 1;
    fp_morph_ctx_t *ctx = fp_morph_ctx_new();
    if (!ctx) return 1;

    const size_t N = 4u << 20; /* 4 MiB */
    uint8_t *v1 = malloc(N);
    uint8_t *v2 = malloc(N);
    fill_structured(v1, N);
    memcpy(v2, v1, N);
    for (size_t i = 0; i < 4096; i++) {
        v2[(N / 3) + i] ^= (uint8_t)(i * 31u + 7u);
    }

    printf("=== SealFrame (FP01) C11 Benchmark (payload = %.2f MiB) ===\n",
           (double)N / (1024.0 * 1024.0));

    /* 1. DNA BLAKE3 Merkle Streaming */
    fp_dna_t dna;
    const int dna_iters = 50;
    uint64_t t0 = now_ns();
    for (int i = 0; i < dna_iters; i++) {
        fp_dna_compute(v2, N, &dna);
    }
    double dna_s = (double)(now_ns() - t0) / 1e9;
    double dna_mbps = ((double)N * dna_iters / (1024.0 * 1024.0)) / dna_s;
    printf("DNA (BLAKE3 16KiB Merkle) : %8.1f MiB/s  (%.3f ms / 4 MiB)\n",
           dna_mbps, (dna_s / dna_iters) * 1000.0);

    /* 2. Morph Encode & Materialize: RAW, ZSTD, DELTA, REF */
    const fp_morph_kind_t kinds[] = { FP_MORPH_RAW, FP_MORPH_ZSTD, FP_MORPH_DELTA, FP_MORPH_REF };
    const char *names[] = { "RAW  ", "ZSTD ", "DELTA", "REF  " };

    for (size_t k = 0; k < 4; k++) {
        const uint8_t *ref = (kinds[k] == FP_MORPH_DELTA) ? v1
                           : (kinds[k] == FP_MORPH_REF) ? v2 : NULL;
        size_t ref_len = ref ? N : 0;

        uint8_t *wire = NULL;
        size_t wire_len = 0;
        const int iters = 20;

        t0 = now_ns();
        for (int i = 0; i < iters; i++) {
            free(wire);
            wire = NULL;
            if (fp_morph_encode(ctx, kinds[k], v2, N, ref, ref_len, 3, &wire, &wire_len) != FP_OK) {
                fprintf(stderr, "encode failed for %s\n", names[k]);
                return 1;
            }
        }
        double enc_ms = ((double)(now_ns() - t0) / 1e6) / iters;

        t0 = now_ns();
        for (int i = 0; i < iters; i++) {
            uint8_t *out = NULL;
            size_t out_len = 0;
            if (fp_morph_materialize(ctx, wire, wire_len, ref, ref_len, N, &out, &out_len, NULL) != FP_OK) {
                fprintf(stderr, "materialize failed for %s\n", names[k]);
                return 1;
            }
            free(out);
        }
        double dec_ms = ((double)(now_ns() - t0) / 1e6) / iters;

        printf("Morph %s               : wire=%9zu B (%6.2f%%) | enc=%7.3f ms | mat+verify=%7.3f ms\n",
               names[k], wire_len, 100.0 * (double)wire_len / (double)N, enc_ms, dec_ms);
        free(wire);
    }

    /* 3. Ed25519 Event Sign & Verify */
    fp_keypair_t kp;
    fp_dna_t repo;
    fp_keygen(&kp);
    fp_random_id(&repo);
    fp_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.action = FP_ACTION_INSTALL;
    ev.repo_id = repo;
    ev.serial = 1;
    ev.timestamp_unix = 1000;
    ev.expires_unix = 2000;
    ev.target_dna = dna;
    ev.target_size = N;

    const int sig_iters = 2000;
    t0 = now_ns();
    for (int i = 0; i < sig_iters; i++) fp_event_sign(&ev, &kp);
    double sign_us = ((double)(now_ns() - t0) / 1e3) / sig_iters;

    t0 = now_ns();
    for (int i = 0; i < sig_iters; i++) fp_event_verify(&ev, kp.pk, &repo, 1500);
    double ver_us = ((double)(now_ns() - t0) / 1e3) / sig_iters;

    printf("Lineage Ed25519 Event     : sign=%6.1f us | verify=%6.1f us\n", sign_us, ver_us);

    free(v1);
    free(v2);
    fp_morph_ctx_free(ctx);
    return 0;
}
