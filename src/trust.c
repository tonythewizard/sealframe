#include "fp.h"

#include <blake3.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static void put_be16(uint8_t dst[2], uint16_t v) {
    dst[0] = (uint8_t)(v >> 8);
    dst[1] = (uint8_t)(v);
}

static uint16_t get_be16(const uint8_t src[2]) {
    return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

static void put_be64(uint8_t dst[8], uint64_t v) {
    dst[0] = (uint8_t)(v >> 56);
    dst[1] = (uint8_t)(v >> 48);
    dst[2] = (uint8_t)(v >> 40);
    dst[3] = (uint8_t)(v >> 32);
    dst[4] = (uint8_t)(v >> 24);
    dst[5] = (uint8_t)(v >> 16);
    dst[6] = (uint8_t)(v >> 8);
    dst[7] = (uint8_t)(v);
}

static uint64_t get_be64(const uint8_t src[8]) {
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  | ((uint64_t)src[7]);
}

static int pk_in_array(const uint8_t pk[FP_PK_LEN],
                       const uint8_t *flat_keys, uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        if (sodium_memcmp(pk, flat_keys + (size_t)i * FP_PK_LEN, FP_PK_LEN) == 0) return 1;
    }
    return 0;
}

static fp_err_t validate_root_structure(const fp_root_doc_t *doc) {
    if (!doc) return FP_ERR_INVALID;
    if (doc->version != 1 || doc->root_version == 0) return FP_ERR_INVALID;
    if (doc->root_key_count == 0 || doc->root_key_count > FP_MAX_ROOT_KEYS) return FP_ERR_BOUNDS;
    if (doc->root_threshold == 0 || doc->root_threshold > doc->root_key_count) return FP_ERR_POLICY;
    if (doc->revoked_key_count > FP_MAX_REVOKED_KEYS) return FP_ERR_BOUNDS;
    if (doc->sig_count > FP_MAX_ROOT_SIGS) return FP_ERR_BOUNDS;
    if (doc->expires_unix != 0 && doc->expires_unix < doc->timestamp_unix) return FP_ERR_EXPIRED;

    /* Root keys must be unique */
    for (uint8_t i = 0; i < doc->root_key_count; i++) {
        for (uint8_t j = 0; j < i; j++) {
            if (sodium_memcmp(doc->root_keys[i], doc->root_keys[j], FP_PK_LEN) == 0) {
                return FP_ERR_POLICY;
            }
        }
    }
    /* Active release key cannot be revoked */
    if (pk_in_array(doc->release_pk, &doc->revoked_keys[0][0], doc->revoked_key_count)) {
        return FP_ERR_REVOKED;
    }
    return FP_OK;
}

/*
 * Canonical Root body (signed by k-of-n root keys):
 *   "FP1/ROOT\0" (9)
 *   version (2) | root_version (8) | repo_id (32)
 *   timestamp_unix (8) | expires_unix (8)
 *   root_threshold (1) | root_key_count (1) | revoked_key_count (1) | reserved (1)
 *   release_pk (32)
 *   root_keys[root_key_count * 32]
 *   revoked_keys[revoked_key_count * 32]
 */
#define ROOT_BODY_FIXED (9u + 2u + 8u + 32u + 8u + 8u + 4u + 32u)
#define ROOT_BODY_MAX   (ROOT_BODY_FIXED + (FP_MAX_ROOT_KEYS + FP_MAX_REVOKED_KEYS) * FP_PK_LEN)

static size_t build_root_signing_bytes(const fp_root_doc_t *doc, uint8_t buf[ROOT_BODY_MAX]) {
    static const uint8_t domain[9] = "FP1/ROOT";
    size_t p = 0;
    memcpy(buf + p, domain, 9); p += 9;
    put_be16(buf + p, doc->version); p += 2;
    put_be64(buf + p, doc->root_version); p += 8;
    memcpy(buf + p, doc->repo_id.bytes, 32); p += 32;
    put_be64(buf + p, doc->timestamp_unix); p += 8;
    put_be64(buf + p, doc->expires_unix); p += 8;
    buf[p++] = doc->root_threshold;
    buf[p++] = doc->root_key_count;
    buf[p++] = doc->revoked_key_count;
    buf[p++] = 0;
    memcpy(buf + p, doc->release_pk, 32); p += 32;
    for (uint8_t i = 0; i < doc->root_key_count; i++) {
        memcpy(buf + p, doc->root_keys[i], 32);
        p += 32;
    }
    for (uint8_t i = 0; i < doc->revoked_key_count; i++) {
        memcpy(buf + p, doc->revoked_keys[i], 32);
        p += 32;
    }
    return p;
}

static void compute_root_hash(const uint8_t *body, size_t len, fp_dna_t *out) {
    static const uint8_t tag[13] = "FP1/ROOTHASH";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, body, len);
    blake3_hasher_finalize(&h, out->bytes, FP_DNA_LEN);
}

static uint8_t count_valid_quorum_sigs(const fp_root_doc_t *doc,
                                       const uint8_t *body, size_t body_len,
                                       const uint8_t *allowed_flat,
                                       uint8_t allowed_count) {
    uint8_t seen[FP_MAX_ROOT_KEYS * FP_PK_LEN];
    uint8_t seen_count = 0;

    for (uint8_t i = 0; i < doc->sig_count; i++) {
        const uint8_t *pk = doc->sigs[i].signer_pk;
        if (!pk_in_array(pk, allowed_flat, allowed_count)) {
            continue;
        }
        if (pk_in_array(pk, seen, seen_count)) {
            continue; /* Duplicate signature by same key does not count twice! */
        }
        if (crypto_sign_ed25519_verify_detached(doc->sigs[i].sig, body, body_len, pk) == 0) {
            if (seen_count < FP_MAX_ROOT_KEYS) {
                memcpy(seen + (size_t)seen_count * FP_PK_LEN, pk, FP_PK_LEN);
                seen_count++;
            }
        }
    }
    return seen_count;
}

fp_err_t fp_root_add_sig(fp_root_doc_t *doc, const fp_keypair_t *root_kp) {
    if (!doc || !root_kp) return FP_ERR_INVALID;
    doc->version = 1;
    fp_err_t err = validate_root_structure(doc);
    if (err != FP_OK) return err;
    if (doc->sig_count >= FP_MAX_ROOT_SIGS) return FP_ERR_BOUNDS;

    /* Prevent duplicate signer entry */
    for (uint8_t i = 0; i < doc->sig_count; i++) {
        if (sodium_memcmp(doc->sigs[i].signer_pk, root_kp->pk, FP_PK_LEN) == 0) {
            return FP_ERR_POLICY;
        }
    }

    uint8_t body[ROOT_BODY_MAX];
    size_t blen = build_root_signing_bytes(doc, body);

    fp_root_sig_t *slot = &doc->sigs[doc->sig_count];
    memcpy(slot->signer_pk, root_kp->pk, FP_PK_LEN);
    unsigned long long siglen = 0;
    if (crypto_sign_ed25519_detached(slot->sig, &siglen, body, blen, root_kp->sk) != 0 ||
        siglen != FP_SIG_LEN) {
        return FP_ERR_SIGNATURE;
    }
    doc->sig_count++;
    compute_root_hash(body, blen, &doc->doc_hash);
    return FP_OK;
}

fp_err_t fp_root_verify_self(const fp_root_doc_t *doc, uint64_t now_unix) {
    fp_err_t err = validate_root_structure(doc);
    if (err != FP_OK) return err;
    if (now_unix > 0 && doc->expires_unix > 0 && now_unix > doc->expires_unix) {
        return FP_ERR_EXPIRED;
    }

    uint8_t body[ROOT_BODY_MAX];
    size_t blen = build_root_signing_bytes(doc, body);

    uint8_t valid = count_valid_quorum_sigs(doc, body, blen, &doc->root_keys[0][0], doc->root_key_count);
    if (valid < doc->root_threshold) {
        return FP_ERR_SIGNATURE;
    }
    return FP_OK;
}

fp_err_t fp_root_verify_rotation(const fp_root_doc_t *prev, const fp_root_doc_t *next,
                                 uint64_t now_unix) {
    if (!prev || !next) return FP_ERR_INVALID;
    fp_err_t err = validate_root_structure(prev);
    if (err != FP_OK) return err;
    err = validate_root_structure(next);
    if (err != FP_OK) return err;

    if (!fp_dna_equal(&prev->repo_id, &next->repo_id)) return FP_ERR_POLICY;
    if (next->root_version != prev->root_version + 1u) return FP_ERR_CHAIN;
    if (next->timestamp_unix < prev->timestamp_unix) return FP_ERR_POLICY;
    if (now_unix > 0 && next->expires_unix > 0 && now_unix > next->expires_unix) {
        return FP_ERR_EXPIRED;
    }

    /* Monotonic revocation: every key revoked in prev MUST remain revoked in next */
    for (uint8_t i = 0; i < prev->revoked_key_count; i++) {
        if (!pk_in_array(prev->revoked_keys[i], &next->revoked_keys[0][0], next->revoked_key_count)) {
            return FP_ERR_POLICY;
        }
    }

    uint8_t body[ROOT_BODY_MAX];
    size_t blen = build_root_signing_bytes(next, body);

    /* TUF Dual-Quorum Rule:
     * 1) Authorized by old quorum (prev.root_threshold distinct keys in prev.root_keys)
     * 2) Acknowledged by new quorum (next.root_threshold distinct keys in next.root_keys) */
    uint8_t old_valid = count_valid_quorum_sigs(next, body, blen, &prev->root_keys[0][0], prev->root_key_count);
    if (old_valid < prev->root_threshold) {
        return FP_ERR_SIGNATURE;
    }
    uint8_t new_valid = count_valid_quorum_sigs(next, body, blen, &next->root_keys[0][0], next->root_key_count);
    if (new_valid < next->root_threshold) {
        return FP_ERR_SIGNATURE;
    }
    return FP_OK;
}

fp_err_t fp_root_encode(const fp_root_doc_t *doc, uint8_t **out_buf, size_t *out_len) {
    if (!doc || !out_buf || !out_len) return FP_ERR_INVALID;
    *out_buf = NULL;
    *out_len = 0;
    fp_err_t err = validate_root_structure(doc);
    if (err != FP_OK) return err;

    uint8_t body[ROOT_BODY_MAX];
    size_t blen = build_root_signing_bytes(doc, body);
    size_t total = 4u + blen + 1u + (size_t)doc->sig_count * (FP_PK_LEN + FP_SIG_LEN);
    uint8_t *buf = malloc(total);
    if (!buf) return FP_ERR_NOMEM;

    size_t p = 0;
    memcpy(buf + p, "FPR1", 4); p += 4;
    memcpy(buf + p, body, blen); p += blen;
    buf[p++] = doc->sig_count;
    for (uint8_t i = 0; i < doc->sig_count; i++) {
        memcpy(buf + p, doc->sigs[i].signer_pk, FP_PK_LEN); p += FP_PK_LEN;
        memcpy(buf + p, doc->sigs[i].sig, FP_SIG_LEN); p += FP_SIG_LEN;
    }
    *out_buf = buf;
    *out_len = p;
    return FP_OK;
}

fp_err_t fp_root_decode(const uint8_t *buf, size_t len, fp_root_doc_t *out_doc) {
    if (!buf || !out_doc || len < 4u + ROOT_BODY_FIXED + 1u) return FP_ERR_INVALID;
    if (memcmp(buf, "FPR1", 4) != 0) return FP_ERR_INVALID;
    const uint8_t *body = buf + 4;
    static const uint8_t domain[9] = "FP1/ROOT";
    if (memcmp(body, domain, 9) != 0) return FP_ERR_INVALID;

    memset(out_doc, 0, sizeof(*out_doc));
    size_t p = 9;
    out_doc->version = get_be16(body + p); p += 2;
    out_doc->root_version = get_be64(body + p); p += 8;
    memcpy(out_doc->repo_id.bytes, body + p, 32); p += 32;
    out_doc->timestamp_unix = get_be64(body + p); p += 8;
    out_doc->expires_unix = get_be64(body + p); p += 8;
    out_doc->root_threshold = body[p++];
    out_doc->root_key_count = body[p++];
    out_doc->revoked_key_count = body[p++];
    if (body[p++] != 0) return FP_ERR_INVALID;
    memcpy(out_doc->release_pk, body + p, 32); p += 32;

    if (out_doc->root_key_count == 0 || out_doc->root_key_count > FP_MAX_ROOT_KEYS ||
        out_doc->revoked_key_count > FP_MAX_REVOKED_KEYS) {
        return FP_ERR_BOUNDS;
    }
    size_t keys_bytes = (size_t)(out_doc->root_key_count + out_doc->revoked_key_count) * FP_PK_LEN;
    if (len < 4u + p + keys_bytes + 1u) return FP_ERR_BOUNDS;

    for (uint8_t i = 0; i < out_doc->root_key_count; i++) {
        memcpy(out_doc->root_keys[i], body + p, 32); p += 32;
    }
    for (uint8_t i = 0; i < out_doc->revoked_key_count; i++) {
        memcpy(out_doc->revoked_keys[i], body + p, 32); p += 32;
    }
    size_t blen = p;
    out_doc->sig_count = body[p++];
    if (out_doc->sig_count > FP_MAX_ROOT_SIGS) return FP_ERR_BOUNDS;
    size_t expected_total = 4u + p + (size_t)out_doc->sig_count * (FP_PK_LEN + FP_SIG_LEN);
    if (len != expected_total) return FP_ERR_BOUNDS;

    for (uint8_t i = 0; i < out_doc->sig_count; i++) {
        memcpy(out_doc->sigs[i].signer_pk, body + p, FP_PK_LEN); p += FP_PK_LEN;
        memcpy(out_doc->sigs[i].sig, body + p, FP_SIG_LEN); p += FP_SIG_LEN;
    }

    fp_err_t err = validate_root_structure(out_doc);
    if (err != FP_OK) return err;
    compute_root_hash(body, blen, &out_doc->doc_hash);
    return FP_OK;
}

fp_err_t fp_event_verify_with_root(const fp_event_t *ev, const fp_root_doc_t *root,
                                   uint64_t now_unix) {
    if (!ev || !root) return FP_ERR_INVALID;
    fp_err_t err = fp_root_verify_self(root, now_unix);
    if (err != FP_OK) return err;
    if (pk_in_array(ev->signer_pk, &root->revoked_keys[0][0], root->revoked_key_count)) {
        return FP_ERR_REVOKED;
    }
    return fp_event_verify(ev, root->release_pk, &root->repo_id, now_unix);
}
