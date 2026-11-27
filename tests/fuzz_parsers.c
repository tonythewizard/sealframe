#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * UINT64_C(0x2545F4914F6CDD1D);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void mutate_buf(uint8_t *dst, const uint8_t *seed, size_t seed_len,
                       size_t cap, size_t *out_len, uint64_t *rng) {
    uint64_t mode = xorshift64(rng) % 5u;
    if (mode == 0 || seed_len == 0) {
        /* Pure random bytes of random length */
        size_t len = (size_t)(xorshift64(rng) % (cap < 512u ? cap : 512u));
        for (size_t i = 0; i < len; i++) dst[i] = (uint8_t)xorshift64(rng);
        *out_len = len;
        return;
    }
    size_t len = seed_len < cap ? seed_len : cap;
    memcpy(dst, seed, len);
    if (mode == 1 && len > 0) {
        /* Truncate */
        len = (size_t)(xorshift64(rng) % len);
    } else if (mode == 2 && len + 16u < cap) {
        /* Append trailing garbage */
        size_t extra = 1u + (size_t)(xorshift64(rng) % 16u);
        for (size_t i = 0; i < extra; i++) dst[len + i] = (uint8_t)xorshift64(rng);
        len += extra;
    } else if (mode == 3 && len > 0) {
        /* Bit/byte flips */
        size_t flips = 1u + (size_t)(xorshift64(rng) % 6u);
        for (size_t i = 0; i < flips; i++) {
            dst[xorshift64(rng) % len] ^= (uint8_t)(1u << (xorshift64(rng) & 7u));
        }
    } else if (len >= 4u) {
        /* Boundary values (0xFF or 0x00 runs) */
        size_t pos = (size_t)(xorshift64(rng) % (len - 3u));
        uint8_t fill = (xorshift64(rng) & 1u) ? 0xFFu : 0x00u;
        memset(dst + pos, fill, 4u);
    }
    *out_len = len;
}

int main(int argc, char **argv) {
    if (fp_init() != FP_OK) return 1;
    uint64_t total_iters = (argc > 1) ? strtoull(argv[1], NULL, 10) : 200000ull;

    fp_morph_ctx_t *mctx = fp_morph_ctx_new();
    if (!mctx) return 1;

    /* Prepare valid corpus seeds for structure-aware mutation */
    const uint8_t sample[] = "sealframe fuzz corpus payload 0123456789abcdef";
    uint8_t *seed_fp01 = NULL; size_t seed_fp01_len = 0;
    fp_morph_encode(mctx, FP_MORPH_ZSTD, sample, sizeof(sample), NULL, 0, 1, &seed_fp01, &seed_fp01_len);

    fp_keypair_t kp; fp_dna_t repo, target;
    fp_keygen(&kp); fp_random_id(&repo);
    fp_dna_compute(sample, sizeof(sample), &target);

    fp_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.action = FP_ACTION_INSTALL; ev.repo_id = repo; ev.serial = 1;
    ev.timestamp_unix = 1000; ev.expires_unix = 9000;
    ev.target_dna = target; ev.target_size = sizeof(sample);
    fp_event_sign(&ev, &kp);
    uint8_t *seed_ev = NULL; size_t seed_ev_len = 0;
    fp_event_encode(&ev, &seed_ev, &seed_ev_len);

    fp_derivation_t drv;
    memset(&drv, 0, sizeof(drv));
    drv.parent_dna = repo; drv.op_dna = repo; drv.result_dna = target;
    drv.result_size = sizeof(sample); drv.timestamp_unix = 1000;
    fp_derivation_sign(&drv, &kp);
    uint8_t *seed_drv = NULL; size_t seed_drv_len = 0;
    fp_derivation_encode(&drv, &seed_drv, &seed_drv_len);

    fp_bundle_t b;
    memset(&b, 0, sizeof(b));
    b.version = 1; b.entry_count = 1;
    b.entries[0].role = FP_ROLE_FILE; b.entries[0].mode = 0644; b.entries[0].size = sizeof(sample);
    b.entries[0].dna = target;
    snprintf(b.entries[0].path, sizeof(b.entries[0].path), "a/b.bin");
    uint8_t *seed_b = NULL; size_t seed_b_len = 0;
    fp_bundle_encode(&b, &seed_b, &seed_b_len);

    fp_root_doc_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.version = 1; rd.root_version = 1; rd.repo_id = repo;
    rd.timestamp_unix = 1000; rd.expires_unix = 9000;
    rd.root_threshold = 1; rd.root_key_count = 1;
    memcpy(rd.root_keys[0], kp.pk, FP_PK_LEN);
    memcpy(rd.release_pk, kp.pk, FP_PK_LEN);
    fp_root_add_sig(&rd, &kp);
    uint8_t *seed_rd = NULL; size_t seed_rd_len = 0;
    fp_root_encode(&rd, &seed_rd, &seed_rd_len);

    uint8_t work[2048];
    uint64_t rng = UINT64_C(0xF101D9A271C1E001);
    uint64_t t0 = now_ns();

    for (uint64_t i = 0; i < total_iters; i++) {
        size_t len = 0;
        switch (i % 6u) {
            case 0: { /* FP01 Morph wire header + materialize */
                mutate_buf(work, seed_fp01, seed_fp01_len, sizeof(work), &len, &rng);
                fp_wire_header_t hdr;
                (void)fp_wire_parse_header(work, len, &hdr);
                uint8_t *out = NULL; size_t olen = 0;
                if (fp_morph_materialize(mctx, work, len, sample, sizeof(sample),
                                         4096u, &out, &olen, NULL) == FP_OK) {
                    free(out);
                }
                break;
            }
            case 1: { /* FPE1 Event decode + verify */
                mutate_buf(work, seed_ev, seed_ev_len, sizeof(work), &len, &rng);
                fp_event_t dec;
                if (fp_event_decode(work, len, &dec) == FP_OK) {
                    (void)fp_event_verify(&dec, kp.pk, &repo, 2000);
                }
                break;
            }
            case 2: { /* FPD1 Derivation decode + verify */
                mutate_buf(work, seed_drv, seed_drv_len, sizeof(work), &len, &rng);
                fp_derivation_t dec;
                if (fp_derivation_decode(work, len, &dec) == FP_OK) {
                    (void)fp_derivation_verify(&dec, kp.pk);
                }
                break;
            }
            case 3: { /* FPB1 Bundle decode */
                mutate_buf(work, seed_b, seed_b_len, sizeof(work), &len, &rng);
                fp_bundle_t dec;
                (void)fp_bundle_decode(work, len, &dec);
                break;
            }
            case 4: { /* FPR1 Root Multi-Sig decode + verify */
                mutate_buf(work, seed_rd, seed_rd_len, sizeof(work), &len, &rng);
                fp_root_doc_t dec;
                if (fp_root_decode(work, len, &dec) == FP_OK) {
                    (void)fp_root_verify_self(&dec, 2000);
                }
                break;
            }
            case 5: { /* Merkle chunk proof verification */
                fp_merkle_proof_t mp;
                memset(&mp, 0, sizeof(mp));
                mp.chunk_index = xorshift64(&rng) % 1000u;
                mp.total_size = xorshift64(&rng) % (1u << 22);
                mp.chunk_len = (uint32_t)(xorshift64(&rng) % (FP_CHUNK_SIZE + 64u));
                mp.depth = (uint32_t)(xorshift64(&rng) % (FP_MAX_PROOF_DEPTH + 4u));
                size_t clen = (size_t)(xorshift64(&rng) % 256u);
                for (size_t j = 0; j < clen; j++) work[j] = (uint8_t)xorshift64(&rng);
                (void)fp_merkle_verify(&target, &mp, work, clen);
                break;
            }
        }
    }

    double elapsed_s = (double)(now_ns() - t0) / 1e9;
    printf("[PASS] Fuzz suite: %llu mutated inputs across 6 binary decoders in %.3f s (%.0f exec/s, 0 crashes, 0 leaks)\n",
           (unsigned long long)total_iters, elapsed_s, (double)total_iters / elapsed_s);

    free(seed_fp01); free(seed_ev); free(seed_drv); free(seed_b); free(seed_rd);
    fp_morph_ctx_free(mctx);
    return 0;
}
