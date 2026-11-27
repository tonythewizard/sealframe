#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Deterministic COMPUTE skill: XOR every byte of ref_data with params[0] */
static fp_err_t skill_xor_byte(const uint8_t *ref_data, size_t ref_len,
                               const uint8_t *params, size_t params_len,
                               uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!ref_data || params_len != 1 || out_cap < ref_len) {
        return FP_ERR_INVALID;
    }
    uint8_t mask = params[0];
    for (size_t i = 0; i < ref_len; i++) {
        out[i] = (uint8_t)(ref_data[i] ^ mask);
    }
    *out_len = ref_len;
    return FP_OK;
}

static void fill_pattern(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t x = seed;
    for (size_t i = 0; i < len; i++) {
        x = x * 1664525u + 1013904223u;
        buf[i] = (uint8_t)((x >> 24) & 0x3Fu); /* compressible structured bytes */
    }
}

static void test_dna_and_merkle_streaming(void) {
    /* Empty payload */
    fp_dna_t d0a, d0b;
    assert(fp_dna_compute(NULL, 0, &d0a) == FP_OK);
    assert(fp_dna_compute((const uint8_t *)"", 0, &d0b) == FP_OK);
    assert(fp_dna_equal(&d0a, &d0b));

    /* Test awkward non-power-of-two chunk counts: 1, 2, 3, 5, 6, 7, 13 chunks */
    const size_t sizes[] = {
        1u, 17u, FP_CHUNK_SIZE, FP_CHUNK_SIZE + 1u,
        FP_CHUNK_SIZE * 2u + 777u, FP_CHUNK_SIZE * 5u + 123u,
        FP_CHUNK_SIZE * 6u, FP_CHUNK_SIZE * 7u + 9999u,
        FP_CHUNK_SIZE * 13u + 3u
    };

    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t len = sizes[s];
        uint8_t *buf = malloc(len);
        assert(buf != NULL);
        fill_pattern(buf, len, (uint32_t)(1000u + s));

        fp_dna_t dna;
        assert(fp_dna_compute(buf, len, &dna) == FP_OK);

        /* Streaming file DNA must match memory DNA bit-for-bit */
        char tmp[] = "/tmp/fp-dna-XXXXXX";
        int fd = mkstemp(tmp);
        assert(fd >= 0);
        assert(write(fd, buf, len) == (ssize_t)len);
        close(fd);
        fp_dna_t file_dna;
        uint64_t fsz = 0;
        assert(fp_dna_compute_file(tmp, &file_dna, &fsz) == FP_OK);
        assert(fsz == len);
        assert(fp_dna_equal(&dna, &file_dna));

        /* Streaming file Merkle tree (zero file-size malloc) must match memory DNA & proofs */
        uint64_t tree_sz = 0;
        fp_merkle_tree_t *ftree = fp_merkle_tree_build_file(tmp, &tree_sz);
        assert(ftree != NULL);
        assert(tree_sz == len);
        fp_dna_t ftree_dna = fp_merkle_tree_dna(ftree);
        assert(fp_dna_equal(&dna, &ftree_dna));
        unlink(tmp);

        /* Every single chunk must prove and verify against root DNA (both memory & file tree) */
        uint64_t nchunks = (len + FP_CHUNK_SIZE - 1u) / FP_CHUNK_SIZE;
        for (uint64_t ci = 0; ci < nchunks; ci++) {
            fp_merkle_proof_t proof, fproof;
            fp_dna_t proved_dna;
            assert(fp_merkle_prove(buf, len, ci, &proof, &proved_dna) == FP_OK);
            assert(fp_dna_equal(&dna, &proved_dna));
            assert(fp_merkle_tree_prove(ftree, ci, &fproof) == FP_OK);
            assert(fproof.chunk_index == proof.chunk_index &&
                   fproof.total_size == proof.total_size &&
                   fproof.chunk_len == proof.chunk_len &&
                   fproof.depth == proof.depth &&
                   memcmp(fproof.siblings, proof.siblings, proof.depth * FP_DNA_LEN) == 0);

            size_t off = (size_t)(ci * FP_CHUNK_SIZE);
            size_t clen = (len - off > FP_CHUNK_SIZE) ? FP_CHUNK_SIZE : (len - off);
            assert(fp_merkle_verify(&dna, &proof, buf + off, clen) == FP_OK);
            assert(fp_merkle_verify(&dna, &fproof, buf + off, clen) == FP_OK);

            /* Flip 1 bit in chunk -> MUST fail verification */
            buf[off] ^= 0x01u;
            assert(fp_merkle_verify(&dna, &proof, buf + off, clen) == FP_ERR_INTEGRITY);
            buf[off] ^= 0x01u;
        }
        fp_merkle_tree_free(ftree);
        free(buf);
    }
    printf("[PASS] DNA & Merkle streaming proofs (all edge chunk counts + tamper)\n");
}

static void test_morph_all_modes_and_large_delta(void) {
    fp_morph_ctx_t *ctx = fp_morph_ctx_new();
    assert(ctx != NULL);
    assert(fp_morph_register_skill(ctx, 42u, skill_xor_byte) == FP_OK);

    /* 2.5 MiB payload (> old 1 MiB limit!) with small diff from v1 -> v2 */
    const size_t N = (2u << 20) + 524288u;
    uint8_t *v1 = malloc(N);
    uint8_t *v2 = malloc(N);
    assert(v1 && v2);
    fill_pattern(v1, N, 77u);
    memcpy(v2, v1, N);
    /* Modify 256 bytes in the middle */
    for (size_t i = 0; i < 256; i++) {
        v2[N / 2 + i] ^= 0xA5u;
    }

    fp_dna_t dna_v2;
    assert(fp_dna_compute(v2, N, &dna_v2) == FP_OK);

    /* 1. RAW */
    uint8_t *w_raw = NULL; size_t l_raw = 0;
    assert(fp_morph_encode(ctx, FP_MORPH_RAW, v2, N, NULL, 0, 0, &w_raw, &l_raw) == FP_OK);
    uint8_t *out = NULL; size_t out_len = 0; fp_dna_t out_dna;
    assert(fp_morph_materialize(ctx, w_raw, l_raw, NULL, 0, N, &out, &out_len, &out_dna) == FP_OK);
    assert(out_len == N && fp_dna_equal(&out_dna, &dna_v2) && memcmp(out, v2, N) == 0);
    free(out);

    /* 2. ZSTD */
    uint8_t *w_zstd = NULL; size_t l_zstd = 0;
    assert(fp_morph_encode(ctx, FP_MORPH_ZSTD, v2, N, NULL, 0, 3, &w_zstd, &l_zstd) == FP_OK);
    assert(l_zstd < l_raw);
    assert(fp_morph_materialize(ctx, w_zstd, l_zstd, NULL, 0, N, &out, &out_len, &out_dna) == FP_OK);
    assert(out_len == N && fp_dna_equal(&out_dna, &dna_v2));
    free(out);

    /* 3. DELTA (2.5 MiB -> tiny wire delta!) */
    uint8_t *w_delta = NULL; size_t l_delta = 0;
    assert(fp_morph_encode(ctx, FP_MORPH_DELTA, v2, N, v1, N, 3, &w_delta, &l_delta) == FP_OK);
    assert(l_delta < 4096u); /* 2.5 MiB delta with 256B changed should be < 4 KiB! */
    assert(fp_morph_materialize(ctx, w_delta, l_delta, v1, N, N, &out, &out_len, &out_dna) == FP_OK);
    assert(out_len == N && fp_dna_equal(&out_dna, &dna_v2) && memcmp(out, v2, N) == 0);
    free(out);

    /* Missing/wrong ref must FAIL CLOSED, and fallback to RAW must SUCCEED */
    assert(fp_morph_materialize(ctx, w_delta, l_delta, NULL, 0, N, &out, &out_len, &out_dna) == FP_ERR_MISSING_REF);
    int used_fb = 0;
    assert(fp_morph_materialize_fallback(ctx, w_delta, l_delta, w_raw, l_raw, NULL, 0, N,
                                         &out, &out_len, &out_dna, &used_fb) == FP_OK);
    assert(used_fb == 1 && out_len == N && fp_dna_equal(&out_dna, &dna_v2));
    free(out);

    /* 4. REF (0-byte payload!) */
    uint8_t *w_ref = NULL; size_t l_ref = 0;
    assert(fp_morph_encode(ctx, FP_MORPH_REF, v2, N, v2, N, 0, &w_ref, &l_ref) == FP_OK);
    assert(l_ref == FP_WIRE_HEADER_BASE + FP_DNA_LEN);
    assert(fp_morph_materialize(ctx, w_ref, l_ref, v2, N, N, &out, &out_len, &out_dna) == FP_OK);
    assert(out_len == N && fp_dna_equal(&out_dna, &dna_v2));
    free(out);

    /* 5. COMPUTE (computation as transport: 5-byte payload reconstructs 2.5 MiB!) */
    uint8_t *v_xor = malloc(N);
    assert(v_xor != NULL);
    for (size_t i = 0; i < N; i++) v_xor[i] = (uint8_t)(v1[i] ^ 0x5Au);
    uint8_t param = 0x5Au;
    uint8_t *w_comp = NULL; size_t l_comp = 0;
    assert(fp_morph_encode_compute(ctx, v_xor, N, v1, N, 42u, &param, 1, &w_comp, &l_comp) == FP_OK);
    assert(l_comp == FP_WIRE_HEADER_BASE + FP_DNA_LEN + 5u);
    assert(fp_morph_materialize(ctx, w_comp, l_comp, v1, N, N, &out, &out_len, &out_dna) == FP_OK);
    assert(out_len == N && memcmp(out, v_xor, N) == 0);
    free(out);

    /* Corrupt 1 byte in wire payload -> MUST reject */
    w_raw[l_raw - 1] ^= 0xFFu;
    assert(fp_morph_materialize(ctx, w_raw, l_raw, NULL, 0, N, &out, &out_len, &out_dna) == FP_ERR_INTEGRITY);

    free(w_raw); free(w_zstd); free(w_delta); free(w_ref); free(w_comp);
    free(v1); free(v2); free(v_xor);
    fp_morph_ctx_free(ctx);
    printf("[PASS] Morph RAW, ZSTD, DELTA (2.5 MiB -> %zu B), REF (88 B), COMPUTE (93 B), fallback\n",
           l_delta);
}

static void test_lineage_store_and_transparency_anchor(void) {
    fp_keypair_t kp, wrong_kp;
    fp_dna_t repo;
    assert(fp_keygen(&kp) == FP_OK);
    assert(fp_keygen(&wrong_kp) == FP_OK);
    assert(fp_random_id(&repo) == FP_OK);

    char dir_tmpl[] = "/tmp/fp-store-XXXXXX";
    char *store_dir = mkdtemp(dir_tmpl);
    assert(store_dir != NULL);

    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s/transparency.anchor.log", store_dir);

    const uint8_t d1[] = "sealframe genesis artifact v1";
    const uint8_t d2[] = "sealframe evolved artifact v2";
    fp_dna_t dna1, dna2, op_dna;
    assert(fp_dna_compute(d1, sizeof(d1), &dna1) == FP_OK);
    assert(fp_dna_compute(d2, sizeof(d2), &dna2) == FP_OK);
    assert(fp_dna_compute((const uint8_t *)"upgrade-v1-to-v2", 16, &op_dna) == FP_OK);

    /* Signed Derivation A + Op -> B */
    fp_derivation_t drv;
    memset(&drv, 0, sizeof(drv));
    drv.parent_dna = dna1;
    drv.op_dna = op_dna;
    drv.result_dna = dna2;
    drv.result_size = sizeof(d2);
    drv.timestamp_unix = 1700000000u;
    assert(fp_derivation_sign(&drv, &kp) == FP_OK);
    assert(fp_derivation_verify(&drv, kp.pk) == FP_OK);
    assert(fp_derivation_verify(&drv, wrong_kp.pk) == FP_ERR_SIGNATURE);

    uint8_t *dbuf = NULL; size_t dlen = 0;
    fp_derivation_t drv2;
    assert(fp_derivation_encode(&drv, &dbuf, &dlen) == FP_OK);
    assert(fp_derivation_decode(dbuf, dlen, &drv2) == FP_OK);
    assert(fp_derivation_verify(&drv2, kp.pk) == FP_OK);
    free(dbuf);

    /* Event 1: INSTALL v1 */
    fp_event_t e1;
    memset(&e1, 0, sizeof(e1));
    e1.action = FP_ACTION_INSTALL;
    e1.repo_id = repo;
    e1.serial = 1;
    e1.timestamp_unix = 1000;
    e1.expires_unix = 2000;
    e1.target_dna = dna1;
    e1.target_size = sizeof(d1);
    assert(fp_event_sign(&e1, &kp) == FP_OK);

    /* Anti-freeze: expired at t=2001 must fail */
    assert(fp_store_apply_event(store_dir, &e1, kp.pk, &repo, 2001, d1, sizeof(d1)) == FP_ERR_EXPIRED);
    /* Wrong key must fail */
    assert(fp_store_apply_event(store_dir, &e1, wrong_kp.pk, &repo, 1500, d1, sizeof(d1)) == FP_ERR_SIGNATURE);
    /* Valid apply */
    assert(fp_store_apply_event(store_dir, &e1, kp.pk, &repo, 1500, d1, sizeof(d1)) == FP_OK);
    /* Replay must fail */
    assert(fp_store_apply_event(store_dir, &e1, kp.pk, &repo, 1500, d1, sizeof(d1)) == FP_ERR_CHAIN);

    /* Anchor Event 1 to local transparency log */
    fp_anchor_commitment_t c1;
    assert(fp_anchor_compute(&e1, &c1) == FP_OK);
    assert(fp_anchor_local_publish(log_path, &c1) == FP_OK);
    assert(fp_anchor_local_verify(log_path, &c1) == FP_OK);

    /* Split-view equivocation test: attacker signs a DIFFERENT serial=1 event! */
    fp_event_t e1_evil = e1;
    e1_evil.target_dna = dna2;
    e1_evil.target_size = sizeof(d2);
    assert(fp_event_sign(&e1_evil, &kp) == FP_OK);
    fp_anchor_commitment_t c1_evil;
    assert(fp_anchor_compute(&e1_evil, &c1_evil) == FP_OK);
    assert(fp_anchor_local_verify(log_path, &c1_evil) == FP_ERR_CHAIN);
    assert(fp_anchor_local_publish(log_path, &c1_evil) == FP_ERR_CHAIN);

    /* Event 2: INSTALL v2 */
    fp_event_t e2;
    memset(&e2, 0, sizeof(e2));
    e2.action = FP_ACTION_INSTALL;
    e2.repo_id = repo;
    e2.serial = 2;
    e2.prev_event_hash = e1.event_hash;
    e2.timestamp_unix = 1500;
    e2.expires_unix = 3000;
    e2.target_dna = dna2;
    e2.target_size = sizeof(d2);
    assert(fp_event_sign(&e2, &kp) == FP_OK);
    assert(fp_store_apply_event(store_dir, &e2, kp.pk, &repo, 1600, d2, sizeof(d2)) == FP_OK);

    /* Event 3: ROLLBACK to v1 (must require reason, uses resident object without payload!) */
    fp_event_t e3;
    memset(&e3, 0, sizeof(e3));
    e3.action = FP_ACTION_ROLLBACK;
    e3.repo_id = repo;
    e3.serial = 3;
    e3.prev_event_hash = e2.event_hash;
    e3.timestamp_unix = 1700;
    e3.expires_unix = 3000;
    e3.target_dna = dna1;
    e3.target_size = sizeof(d1);
    assert(fp_event_sign(&e3, &kp) == FP_ERR_POLICY); /* missing reason! */
    snprintf(e3.reason, sizeof(e3.reason), "regression in v2");
    assert(fp_event_sign(&e3, &kp) == FP_OK);
    assert(fp_store_apply_event(store_dir, &e3, kp.pk, &repo, 1750, NULL, 0) == FP_OK);

    fp_store_state_t st;
    assert(fp_store_load_state(store_dir, &st) == FP_OK);
    assert(st.serial == 3 && st.has_current == 1 && fp_dna_equal(&st.current_dna, &dna1));

    /* Event 4: REVOKE v1 -> clears active current and permanently blocks reuse */
    fp_event_t e4;
    memset(&e4, 0, sizeof(e4));
    e4.action = FP_ACTION_REVOKE;
    e4.repo_id = repo;
    e4.serial = 4;
    e4.prev_event_hash = e3.event_hash;
    e4.timestamp_unix = 1800;
    e4.expires_unix = 3000;
    e4.target_dna = dna1;
    e4.target_size = 0;
    assert(fp_event_sign(&e4, &kp) == FP_OK);
    assert(fp_store_apply_event(store_dir, &e4, kp.pk, &repo, 1850, NULL, 0) == FP_OK);

    assert(fp_store_load_state(store_dir, &st) == FP_OK);
    assert(st.serial == 4 && st.has_current == 0 && st.revoked_count == 1);

    /* Attempt to rollback to revoked v1 MUST fail with FP_ERR_REVOKED */
    fp_event_t e5;
    memset(&e5, 0, sizeof(e5));
    e5.action = FP_ACTION_ROLLBACK;
    e5.repo_id = repo;
    e5.serial = 5;
    e5.prev_event_hash = e4.event_hash;
    e5.timestamp_unix = 1900;
    e5.expires_unix = 3000;
    e5.target_dna = dna1;
    e5.target_size = sizeof(d1);
    snprintf(e5.reason, sizeof(e5.reason), "trying revoked");
    assert(fp_event_sign(&e5, &kp) == FP_OK);
    assert(fp_store_apply_event(store_dir, &e5, kp.pk, &repo, 1950, NULL, 0) == FP_ERR_REVOKED);

    printf("[PASS] Lineage (Ed25519, anti-freeze, derivation, atomic rollback/revoke, anti-equivocation anchor)\n");
}

int main(void) {
    assert(fp_init() == FP_OK);
    test_dna_and_merkle_streaming();
    test_morph_all_modes_and_large_delta();
    test_lineage_store_and_transparency_anchor();
    printf("ALL SEALFRAME C11 TESTS PASSED.\n");
    return 0;
}
