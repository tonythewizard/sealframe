#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    assert(fp_init() == FP_OK);

    fp_keypair_t r1, r2, r3, r4, evil, rel1, rel2;
    assert(fp_keygen(&r1) == FP_OK);
    assert(fp_keygen(&r2) == FP_OK);
    assert(fp_keygen(&r3) == FP_OK);
    assert(fp_keygen(&r4) == FP_OK);
    assert(fp_keygen(&evil) == FP_OK);
    assert(fp_keygen(&rel1) == FP_OK);
    assert(fp_keygen(&rel2) == FP_OK);

    fp_dna_t repo;
    assert(fp_random_id(&repo) == FP_OK);

    /* --- 1. Root v1: 2-of-3 quorum {r1, r2, r3}, active release key = rel1 --- */
    fp_root_doc_t v1;
    memset(&v1, 0, sizeof(v1));
    v1.version = 1;
    v1.root_version = 1;
    v1.repo_id = repo;
    v1.timestamp_unix = 1000;
    v1.expires_unix = 5000;
    v1.root_threshold = 2;
    v1.root_key_count = 3;
    memcpy(v1.root_keys[0], r1.pk, FP_PK_LEN);
    memcpy(v1.root_keys[1], r2.pk, FP_PK_LEN);
    memcpy(v1.root_keys[2], r3.pk, FP_PK_LEN);
    memcpy(v1.release_pk, rel1.pk, FP_PK_LEN);

    /* 0 sigs or 1 sig MUST fail */
    assert(fp_root_verify_self(&v1, 1500) == FP_ERR_SIGNATURE);
    assert(fp_root_add_sig(&v1, &r1) == FP_OK);
    assert(fp_root_verify_self(&v1, 1500) == FP_ERR_SIGNATURE);

    /* Duplicate sig by r1 rejected, and manual duplicate slot MUST NOT count twice! */
    assert(fp_root_add_sig(&v1, &r1) == FP_ERR_POLICY);
    fp_root_doc_t dup_attack = v1;
    dup_attack.sigs[1] = dup_attack.sigs[0];
    dup_attack.sig_count = 2;
    assert(fp_root_verify_self(&dup_attack, 1500) == FP_ERR_SIGNATURE);

    /* Unauthorized key sig MUST NOT satisfy quorum */
    fp_root_doc_t evil_sig = v1;
    assert(fp_root_add_sig(&evil_sig, &evil) == FP_OK);
    assert(fp_root_verify_self(&evil_sig, 1500) == FP_ERR_SIGNATURE);

    /* 2nd valid root key (r2) completes 2-of-3 quorum! */
    assert(fp_root_add_sig(&v1, &r2) == FP_OK);
    assert(fp_root_verify_self(&v1, 1500) == FP_OK);
    assert(fp_root_verify_self(&v1, 5001) == FP_ERR_EXPIRED);

    /* Binary encode/decode round-trip */
    uint8_t *enc = NULL; size_t enc_len = 0;
    fp_root_doc_t v1_dec;
    assert(fp_root_encode(&v1, &enc, &enc_len) == FP_OK);
    assert(fp_root_decode(enc, enc_len, &v1_dec) == FP_OK);
    assert(fp_dna_equal(&v1.doc_hash, &v1_dec.doc_hash));
    assert(fp_root_verify_self(&v1_dec, 1500) == FP_OK);
    free(enc);
    printf("[PASS] Root v1 2-of-3 Ed25519 multi-sig quorum (dup/unauth/expiry rejected)\n");

    /* --- 2. Emergency Release Key Compromise & Seamless Store Rotation --- */
    char dt[] = "/tmp/fp-trust-XXXXXX";
    char *store_dir = mkdtemp(dt);
    assert(store_dir != NULL);

    const uint8_t p1[] = "release-1-payload";
    const uint8_t p2[] = "release-2-payload-after-key-rotation";
    fp_dna_t d1, d2;
    assert(fp_dna_compute(p1, sizeof(p1), &d1) == FP_OK);
    assert(fp_dna_compute(p2, sizeof(p2), &d2) == FP_OK);

    fp_event_t e1;
    memset(&e1, 0, sizeof(e1));
    e1.action = FP_ACTION_INSTALL; e1.repo_id = repo; e1.serial = 1;
    e1.timestamp_unix = 1200; e1.expires_unix = 4000;
    e1.target_dna = d1; e1.target_size = sizeof(p1);
    assert(fp_event_sign(&e1, &rel1) == FP_OK);
    assert(fp_store_apply_event_with_root(store_dir, &e1, &v1, 1500, p1, sizeof(p1)) == FP_OK);

    /* rel1 leaked! Quorum signs Root v2 revoking rel1 and activating rel2 */
    fp_root_doc_t v2 = v1;
    v2.root_version = 2;
    v2.timestamp_unix = 2000;
    v2.expires_unix = 8000;
    v2.sig_count = 0;
    memcpy(v2.release_pk, rel2.pk, FP_PK_LEN);
    memcpy(v2.revoked_keys[0], rel1.pk, FP_PK_LEN);
    v2.revoked_key_count = 1;
    assert(fp_root_add_sig(&v2, &r2) == FP_OK);
    assert(fp_root_add_sig(&v2, &r3) == FP_OK);
    assert(fp_root_verify_rotation(&v1, &v2, 2500) == FP_OK);

    /* Compromised rel1 tries to sign Event #2 -> REJECTED with FP_ERR_REVOKED! */
    fp_event_t e2_bad;
    memset(&e2_bad, 0, sizeof(e2_bad));
    e2_bad.action = FP_ACTION_INSTALL; e2_bad.repo_id = repo; e2_bad.serial = 2;
    e2_bad.prev_event_hash = e1.event_hash;
    e2_bad.timestamp_unix = 2200; e2_bad.expires_unix = 6000;
    e2_bad.target_dna = d2; e2_bad.target_size = sizeof(p2);
    assert(fp_event_sign(&e2_bad, &rel1) == FP_OK);
    assert(fp_store_apply_event_with_root(store_dir, &e2_bad, &v2, 2500, p2, sizeof(p2)) == FP_ERR_REVOKED);

    /* Legitimate new rel2 signs Event #2 -> ACCEPTED seamlessly on the same Store chain! */
    fp_event_t e2_ok = e2_bad;
    assert(fp_event_sign(&e2_ok, &rel2) == FP_OK);
    assert(fp_store_apply_event_with_root(store_dir, &e2_ok, &v2, 2500, p2, sizeof(p2)) == FP_OK);

    fp_store_state_t st;
    assert(fp_store_load_state(store_dir, &st) == FP_OK);
    assert(st.serial == 2 && fp_dna_equal(&st.current_dna, &d2));
    printf("[PASS] Release key compromise revoked & rotated seamlessly without breaking Store chain\n");

    /* --- 3. Root Key Rotation (Dual-Quorum TUF Rule + Monotonic Revocation) --- */
    /* Rotate root set from {r1, r2, r3} to {r2, r4, evil} (2-of-3) */
    fp_root_doc_t v3 = v2;
    v3.root_version = 3;
    v3.timestamp_unix = 3000;
    v3.expires_unix = 12000;
    v3.sig_count = 0;
    memcpy(v3.root_keys[0], r2.pk, FP_PK_LEN);
    memcpy(v3.root_keys[1], r4.pk, FP_PK_LEN);
    memcpy(v3.root_keys[2], evil.pk, FP_PK_LEN);

    /* Only new keys {r4, evil} without old quorum -> REJECTED! */
    fp_root_doc_t v3_hijack = v3;
    assert(fp_root_add_sig(&v3_hijack, &r4) == FP_OK);
    assert(fp_root_add_sig(&v3_hijack, &evil) == FP_OK);
    assert(fp_root_verify_rotation(&v2, &v3_hijack, 3500) == FP_ERR_SIGNATURE);

    /* Only old keys {r1, r3} without new quorum -> REJECTED! */
    fp_root_doc_t v3_brick = v3;
    assert(fp_root_add_sig(&v3_brick, &r1) == FP_OK);
    assert(fp_root_add_sig(&v3_brick, &r3) == FP_OK);
    assert(fp_root_verify_rotation(&v2, &v3_brick, 3500) == FP_ERR_SIGNATURE);

    /* Un-revoking rel1 -> REJECTED with FP_ERR_POLICY! */
    fp_root_doc_t v3_unrevoke = v3;
    v3_unrevoke.revoked_key_count = 0;
    assert(fp_root_add_sig(&v3_unrevoke, &r1) == FP_OK);
    assert(fp_root_add_sig(&v3_unrevoke, &r2) == FP_OK);
    assert(fp_root_add_sig(&v3_unrevoke, &r4) == FP_OK);
    assert(fp_root_verify_rotation(&v2, &v3_unrevoke, 3500) == FP_ERR_POLICY);

    /* Dual-quorum valid: {r1, r2} satisfies old 2-of-3 AND {r2, r4} satisfies new 2-of-3! */
    assert(fp_root_add_sig(&v3, &r1) == FP_OK);
    assert(fp_root_add_sig(&v3, &r2) == FP_OK);
    assert(fp_root_add_sig(&v3, &r4) == FP_OK);
    assert(fp_root_verify_rotation(&v2, &v3, 3500) == FP_OK);

    /* Downgrade v3 -> v2 rejected with FP_ERR_CHAIN */
    assert(fp_root_verify_rotation(&v3, &v2, 3500) == FP_ERR_CHAIN);
    printf("[PASS] Root dual-quorum rotation, anti-hijack, anti-brick & monotonic revocation verified\n");
    printf("ALL M4 INDUSTRIAL SECURITY TESTS PASSED.\n");
    return 0;
}
