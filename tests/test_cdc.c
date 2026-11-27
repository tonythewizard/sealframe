#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void fill_prng(uint8_t *buf, size_t len, uint64_t seed) {
    uint64_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        buf[i] = (uint8_t)((x * UINT64_C(0x2545F4914F6CDD1D)) >> 56);
    }
}

static void write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    assert(len == 0 || fwrite(data, 1, len, f) == len);
    fclose(f);
}

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    assert(f != NULL);
    struct stat st;
    assert(fstat(fileno(f), &st) == 0);
    size_t sz = (size_t)st.st_size;
    uint8_t *b = malloc(sz > 0 ? sz : 1u);
    assert(b != NULL);
    assert(sz == 0 || fread(b, 1, sz, f) == sz);
    fclose(f);
    *out_len = sz;
    return b;
}

static void test_streaming_dna_equivalence(void) {
    const size_t N = 123456u;
    uint8_t *buf = malloc(N);
    assert(buf != NULL);
    fill_prng(buf, N, 42u);

    fp_dna_t direct, streamed;
    assert(fp_dna_compute(buf, N, &direct) == FP_OK);

    fp_dna_stream_t st;
    fp_dna_stream_init(&st);
    const size_t steps[] = { 1, 7, 13, 16383, 16385, 33333, 50000 };
    size_t pos = 0, si = 0;
    while (pos < N) {
        size_t take = steps[si % (sizeof(steps) / sizeof(steps[0]))];
        if (take > N - pos) take = N - pos;
        assert(fp_dna_stream_update(&st, buf + pos, take) == FP_OK);
        pos += take;
        si++;
    }
    uint64_t total = 0;
    assert(fp_dna_stream_finish(&st, &streamed, &total) == FP_OK);
    assert(total == N && fp_dna_equal(&direct, &streamed));
    free(buf);
    printf("[PASS] Streaming DNA (arbitrary write boundaries) matches canonical DNA bit-for-bit\n");
}

static void test_shift_resilience_and_cross_file_dedup(void) {
    char dt[] = "/tmp/fp-cdc-XXXXXX";
    char *dir = mkdtemp(dt);
    assert(dir != NULL);

    char store1[256], store2[256];
    snprintf(store1, sizeof(store1), "%s/store1", dir);
    snprintf(store2, sizeof(store2), "%s/store2", dir);

    /* 1. Shift resilience: prepend 137 random bytes at byte 0 of a 3 MiB high-entropy file!
     * Fixed-block dedup gets 0% reuse here. Normalized FastCDC must get > 95%! */
    const size_t N = 3u << 20;
    const size_t SHIFT = 137u;
    uint8_t *a = malloc(N);
    uint8_t *b = malloc(N + SHIFT);
    assert(a && b);
    fill_prng(a, N, 0x1111u);
    fill_prng(b, SHIFT, 0x9999u);
    memcpy(b + SHIFT, a, N);

    char pa[256], pb[256], pout[256];
    snprintf(pa, sizeof(pa), "%s/a.bin", dir);
    snprintf(pb, sizeof(pb), "%s/b.bin", dir);
    snprintf(pout, sizeof(pout), "%s/out.bin", dir);
    write_file(pa, a, N);
    write_file(pb, b, N + SHIFT);

    fp_cdc_stats_t sa, sb;
    assert(fp_cdc_ingest_file(store1, pa, &sa) == FP_OK);
    assert(fp_cdc_ingest_file(store1, pb, &sb) == FP_OK);

    fp_dna_t expected_a, expected_b;
    assert(fp_dna_compute(a, N, &expected_a) == FP_OK);
    assert(fp_dna_compute(b, N + SHIFT, &expected_b) == FP_OK);
    assert(fp_dna_equal(&sa.dna, &expected_a));
    assert(fp_dna_equal(&sb.dna, &expected_b));

    double reuse_pct = 100.0 * (double)sb.reused_bytes / (double)sb.canonical_size;
    assert(reuse_pct > 95.0);

    /* Reconstruct B in O(1) RAM and verify byte-for-byte */
    uint64_t rbytes = 0;
    assert(fp_cdc_reconstruct_file(store1, &sb.dna, pout, &rbytes) == FP_OK);
    assert(rbytes == N + SHIFT);
    size_t out_len = 0;
    uint8_t *out_buf = read_file(pout, &out_len);
    assert(out_len == N + SHIFT && memcmp(out_buf, b, N + SHIFT) == 0);
    free(out_buf);
    printf("[PASS] FastCDC shift resilience (+137 B prepended to 3 MiB random): %.2f%% reused!\n",
           reuse_pct);

    /* 2. Cross-File Composition: Z combines slices from two unrelated files X and Y */
    const size_t M = 1u << 20;
    uint8_t *x = malloc(M);
    uint8_t *y = malloc(M);
    uint8_t *z = malloc(M + 200u);
    assert(x && y && z);
    fill_prng(x, M, 0xAAAAu);
    fill_prng(y, M, 0xBBBBu);
    fill_prng(z, 100u, 0xCCCCu);
    memcpy(z + 100u, x + 200000u, 500000u);
    fill_prng(z + 100u + 500000u, 50u, 0xDDDDu);
    memcpy(z + 150u + 500000u, y + 300000u, 500000u);
    fill_prng(z + 150u + 1000000u, 50u, 0xEEEEu);
    size_t zlen = 1000200u;

    char px[256], py[256], pz[256];
    snprintf(px, sizeof(px), "%s/x.bin", dir);
    snprintf(py, sizeof(py), "%s/y.bin", dir);
    snprintf(pz, sizeof(pz), "%s/z.bin", dir);
    write_file(px, x, M);
    write_file(py, y, M);
    write_file(pz, z, zlen);

    fp_cdc_stats_t sx, sy, sz;
    assert(fp_cdc_ingest_file(store2, px, &sx) == FP_OK);
    assert(fp_cdc_ingest_file(store2, py, &sy) == FP_OK);
    /* Ingest Z in store1 (cold) and check missing chunks vs store2 (which has X and Y!) */
    assert(fp_cdc_ingest_file(store1, pz, &sz) == FP_OK);

    uint64_t tot_c = 0, miss_c = 0, miss_b = 0;
    assert(fp_cdc_recipe_missing(store1, &sz.dna, store2, &tot_c, &miss_c, &miss_b) == FP_OK);
    double cross_saved = 100.0 * (1.0 - (double)miss_b / (double)zlen);
    assert(cross_saved > 85.0);

    /* Now ingest Z directly into store2 -> cross-file pool reuse */
    fp_cdc_stats_t sz2;
    assert(fp_cdc_ingest_file(store2, pz, &sz2) == FP_OK);
    assert(fp_dna_equal(&sz.dna, &sz2.dna));
    assert(fp_cdc_reconstruct_file(store2, &sz2.dna, pout, &rbytes) == FP_OK);
    assert(rbytes == zlen);
    out_buf = read_file(pout, &out_len);
    assert(out_len == zlen && memcmp(out_buf, z, zlen) == 0);
    free(out_buf);
    printf("[PASS] Cross-File Composition (Z built from unrelated X+Y): %.2f%% chunks already present!\n",
           cross_saved);

    /* 3. Corrupt 1 chunk on disk -> reconstruct MUST fail closed with FP_ERR_INTEGRITY */
    size_t first_cut = fp_fastcdc_cut(a, N);
    fp_dna_t first_cid;
    assert(fp_cdc_chunk_id(a, first_cut, &first_cid) == FP_OK);
    char cid_hex[65], cpath[512];
    fp_hex_encode(first_cid.bytes, FP_DNA_LEN, cid_hex);
    snprintf(cpath, sizeof(cpath), "%s/chunks/%.2s/%s", store1, cid_hex, cid_hex);
    FILE *cf = fopen(cpath, "r+b");
    assert(cf != NULL);
    int ch = fgetc(cf);
    assert(ch != EOF);
    rewind(cf);
    fputc(ch ^ 0xFF, cf);
    fclose(cf);

    char bad_out[256];
    snprintf(bad_out, sizeof(bad_out), "%s/should-not-exist.bin", dir);
    assert(fp_cdc_reconstruct_file(store1, &sa.dna, bad_out, &rbytes) == FP_ERR_INTEGRITY);
    struct stat dummy;
    assert(stat(bad_out, &dummy) != 0); /* Atomic: no partial corrupted output left behind! */
    printf("[PASS] Corrupted chunk detected immediately; atomic reconstruct leaves zero corrupt output\n");

    free(a); free(b); free(x); free(y); free(z);
}

int main(void) {
    assert(fp_init() == FP_OK);
    test_streaming_dna_equivalence();
    test_shift_resilience_and_cross_file_dedup();
    printf("ALL M2 FASTCDC & CROSS-FILE COMPOSITION TESTS PASSED.\n");
    return 0;
}
