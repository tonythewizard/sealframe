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

fp_err_t fp_keygen(fp_keypair_t *out_kp) {
    if (!out_kp) return FP_ERR_INVALID;
    if (crypto_sign_ed25519_keypair(out_kp->pk, out_kp->sk) != 0) {
        return FP_ERR_INVALID;
    }
    return FP_OK;
}

fp_err_t fp_random_id(fp_dna_t *out_id) {
    if (!out_id) return FP_ERR_INVALID;
    randombytes_buf(out_id->bytes, FP_DNA_LEN);
    return FP_OK;
}

/*
 * Canonical signed payload for Event (fixed + bounded reason):
 *   "FP1/EVENT\0" (10)
 *   version (2) | action (1) | reserved (1)
 *   repo_id (32) | serial (8) | prev_event_hash (32)
 *   timestamp_unix (8) | expires_unix (8)
 *   target_dna (32) | target_size (8)
 *   signer_pk (32) | reason_len (2) | reason[reason_len]
 */
#define EVENT_SIGN_FIXED (10u + 2u + 1u + 1u + 32u + 8u + 32u + 8u + 8u + 32u + 8u + 32u + 2u)

static fp_err_t build_event_signing_bytes(const fp_event_t *ev,
                                          uint8_t *buf, size_t cap, size_t *out_len) {
    const void *nul = memchr(ev->reason, '\0', FP_MAX_REASON);
    if (!nul) {
        return FP_ERR_BOUNDS;
    }
    size_t rlen = (size_t)((const char *)nul - ev->reason);
    size_t needed = EVENT_SIGN_FIXED + rlen;
    if (needed > cap) {
        return FP_ERR_BOUNDS;
    }
    size_t p = 0;
    static const uint8_t domain[10] = "FP1/EVENT";
    memcpy(buf + p, domain, 10); p += 10;
    put_be16(buf + p, ev->version); p += 2;
    buf[p++] = (uint8_t)ev->action;
    buf[p++] = 0;
    memcpy(buf + p, ev->repo_id.bytes, 32); p += 32;
    put_be64(buf + p, ev->serial); p += 8;
    memcpy(buf + p, ev->prev_event_hash.bytes, 32); p += 32;
    put_be64(buf + p, ev->timestamp_unix); p += 8;
    put_be64(buf + p, ev->expires_unix); p += 8;
    memcpy(buf + p, ev->target_dna.bytes, 32); p += 32;
    put_be64(buf + p, ev->target_size); p += 8;
    memcpy(buf + p, ev->signer_pk, 32); p += 32;
    put_be16(buf + p, (uint16_t)rlen); p += 2;
    if (rlen > 0) {
        memcpy(buf + p, ev->reason, rlen);
        p += rlen;
    }
    *out_len = p;
    return FP_OK;
}

static void compute_event_hash(const uint8_t *signed_bytes, size_t len,
                               const uint8_t sig[FP_SIG_LEN], fp_dna_t *out) {
    static const uint8_t tag[11] = "FP1/EVHASH";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, signed_bytes, len);
    blake3_hasher_update(&h, sig, FP_SIG_LEN);
    blake3_hasher_finalize(&h, out->bytes, FP_DNA_LEN);
}

static fp_err_t validate_event_semantics(const fp_event_t *ev) {
    if (!ev) return FP_ERR_INVALID;
    if (ev->version != 1) return FP_ERR_INVALID;
    if (ev->serial == 0) return FP_ERR_CHAIN;
    if (ev->action != FP_ACTION_INSTALL &&
        ev->action != FP_ACTION_ROLLBACK &&
        ev->action != FP_ACTION_REVOKE) {
        return FP_ERR_INVALID;
    }
    if (ev->expires_unix != 0 && ev->expires_unix < ev->timestamp_unix) {
        return FP_ERR_EXPIRED;
    }
    if (ev->action == FP_ACTION_ROLLBACK && ev->reason[0] == '\0') {
        return FP_ERR_POLICY;
    }
    if (ev->action == FP_ACTION_REVOKE && ev->target_size != 0) {
        return FP_ERR_POLICY;
    }
    return FP_OK;
}

fp_err_t fp_event_sign(fp_event_t *ev, const fp_keypair_t *kp) {
    if (!ev || !kp) return FP_ERR_INVALID;
    ev->version = 1;
    memcpy(ev->signer_pk, kp->pk, FP_PK_LEN);
    fp_err_t err = validate_event_semantics(ev);
    if (err != FP_OK) return err;

    uint8_t msg[EVENT_SIGN_FIXED + FP_MAX_REASON];
    size_t mlen = 0;
    err = build_event_signing_bytes(ev, msg, sizeof(msg), &mlen);
    if (err != FP_OK) return err;

    unsigned long long siglen = 0;
    if (crypto_sign_ed25519_detached(ev->sig, &siglen, msg, mlen, kp->sk) != 0 ||
        siglen != FP_SIG_LEN) {
        return FP_ERR_SIGNATURE;
    }
    compute_event_hash(msg, mlen, ev->sig, &ev->event_hash);
    return FP_OK;
}

fp_err_t fp_event_verify(const fp_event_t *ev,
                         const uint8_t expected_pk[FP_PK_LEN],
                         const fp_dna_t *expected_repo,
                         uint64_t now_unix) {
    fp_err_t err = validate_event_semantics(ev);
    if (err != FP_OK) return err;

    if (expected_pk && sodium_memcmp(ev->signer_pk, expected_pk, FP_PK_LEN) != 0) {
        return FP_ERR_SIGNATURE;
    }
    if (expected_repo && !fp_dna_equal(&ev->repo_id, expected_repo)) {
        return FP_ERR_POLICY;
    }
    if (now_unix > 0 && ev->expires_unix > 0 && now_unix > ev->expires_unix) {
        return FP_ERR_EXPIRED;
    }

    uint8_t msg[EVENT_SIGN_FIXED + FP_MAX_REASON];
    size_t mlen = 0;
    err = build_event_signing_bytes(ev, msg, sizeof(msg), &mlen);
    if (err != FP_OK) return err;

    if (crypto_sign_ed25519_verify_detached(ev->sig, msg, mlen, ev->signer_pk) != 0) {
        return FP_ERR_SIGNATURE;
    }

    fp_dna_t expected_hash;
    compute_event_hash(msg, mlen, ev->sig, &expected_hash);
    if (!fp_dna_equal(&expected_hash, &ev->event_hash)) {
        return FP_ERR_INTEGRITY;
    }
    return FP_OK;
}

fp_err_t fp_event_encode(const fp_event_t *ev, uint8_t **out_buf, size_t *out_len) {
    if (!ev || !out_buf || !out_len) return FP_ERR_INVALID;
    *out_buf = NULL;
    *out_len = 0;

    uint8_t msg[EVENT_SIGN_FIXED + FP_MAX_REASON];
    size_t mlen = 0;
    fp_err_t err = build_event_signing_bytes(ev, msg, sizeof(msg), &mlen);
    if (err != FP_OK) return err;

    /* Wire: "FPE1" (4) + signed_bytes (mlen) + sig (64) */
    size_t total = 4u + mlen + FP_SIG_LEN;
    uint8_t *buf = malloc(total);
    if (!buf) return FP_ERR_NOMEM;
    memcpy(buf, "FPE1", 4);
    memcpy(buf + 4, msg, mlen);
    memcpy(buf + 4 + mlen, ev->sig, FP_SIG_LEN);

    *out_buf = buf;
    *out_len = total;
    return FP_OK;
}

fp_err_t fp_event_decode(const uint8_t *buf, size_t len, fp_event_t *out_ev) {
    if (!buf || !out_ev || len < 4u + EVENT_SIGN_FIXED + FP_SIG_LEN) {
        return FP_ERR_INVALID;
    }
    if (memcmp(buf, "FPE1", 4) != 0) {
        return FP_ERR_INVALID;
    }
    const uint8_t *msg = buf + 4;
    size_t mlen = len - 4u - FP_SIG_LEN;

    static const uint8_t domain[10] = "FP1/EVENT";
    if (memcmp(msg, domain, 10) != 0) {
        return FP_ERR_INVALID;
    }

    memset(out_ev, 0, sizeof(*out_ev));
    size_t p = 10;
    out_ev->version = get_be16(msg + p); p += 2;
    out_ev->action = (fp_action_t)msg[p++];
    if (msg[p++] != 0) return FP_ERR_INVALID;
    memcpy(out_ev->repo_id.bytes, msg + p, 32); p += 32;
    out_ev->serial = get_be64(msg + p); p += 8;
    memcpy(out_ev->prev_event_hash.bytes, msg + p, 32); p += 32;
    out_ev->timestamp_unix = get_be64(msg + p); p += 8;
    out_ev->expires_unix = get_be64(msg + p); p += 8;
    memcpy(out_ev->target_dna.bytes, msg + p, 32); p += 32;
    out_ev->target_size = get_be64(msg + p); p += 8;
    memcpy(out_ev->signer_pk, msg + p, 32); p += 32;
    uint16_t rlen = get_be16(msg + p); p += 2;

    if (rlen >= FP_MAX_REASON || p + rlen != mlen) {
        return FP_ERR_BOUNDS;
    }
    if (rlen > 0) {
        if (memchr(msg + p, '\0', rlen) != NULL) {
            return FP_ERR_INVALID; /* Reject embedded NUL bytes in signed reason */
        }
        memcpy(out_ev->reason, msg + p, rlen);
    }
    out_ev->reason[rlen] = '\0';
    memcpy(out_ev->sig, buf + 4 + mlen, FP_SIG_LEN);
    compute_event_hash(msg, mlen, out_ev->sig, &out_ev->event_hash);
    return FP_OK;
}

/* --- Derivations (FP1/DERIVE) --- */

#define DERIV_SIGN_LEN (11u + 2u + 32u + 32u + 32u + 8u + 8u + 32u)

static void build_deriv_signing_bytes(const fp_derivation_t *d, uint8_t buf[DERIV_SIGN_LEN]) {
    static const uint8_t domain[11] = "FP1/DERIVE";
    size_t p = 0;
    memcpy(buf + p, domain, 11); p += 11;
    put_be16(buf + p, d->version); p += 2;
    memcpy(buf + p, d->parent_dna.bytes, 32); p += 32;
    memcpy(buf + p, d->op_dna.bytes, 32); p += 32;
    memcpy(buf + p, d->result_dna.bytes, 32); p += 32;
    put_be64(buf + p, d->result_size); p += 8;
    put_be64(buf + p, d->timestamp_unix); p += 8;
    memcpy(buf + p, d->signer_pk, 32);
}

fp_err_t fp_derivation_sign(fp_derivation_t *drv, const fp_keypair_t *kp) {
    if (!drv || !kp) return FP_ERR_INVALID;
    if (fp_dna_equal(&drv->parent_dna, &drv->result_dna)) {
        return FP_ERR_POLICY;
    }
    drv->version = 1;
    memcpy(drv->signer_pk, kp->pk, FP_PK_LEN);

    uint8_t msg[DERIV_SIGN_LEN];
    build_deriv_signing_bytes(drv, msg);
    unsigned long long siglen = 0;
    if (crypto_sign_ed25519_detached(drv->sig, &siglen, msg, sizeof(msg), kp->sk) != 0 ||
        siglen != FP_SIG_LEN) {
        return FP_ERR_SIGNATURE;
    }
    return FP_OK;
}

fp_err_t fp_derivation_verify(const fp_derivation_t *drv,
                              const uint8_t expected_pk[FP_PK_LEN]) {
    if (!drv || drv->version != 1) return FP_ERR_INVALID;
    if (fp_dna_equal(&drv->parent_dna, &drv->result_dna)) {
        return FP_ERR_POLICY;
    }
    if (expected_pk && sodium_memcmp(drv->signer_pk, expected_pk, FP_PK_LEN) != 0) {
        return FP_ERR_SIGNATURE;
    }
    uint8_t msg[DERIV_SIGN_LEN];
    build_deriv_signing_bytes(drv, msg);
    if (crypto_sign_ed25519_verify_detached(drv->sig, msg, sizeof(msg), drv->signer_pk) != 0) {
        return FP_ERR_SIGNATURE;
    }
    return FP_OK;
}

fp_err_t fp_derivation_encode(const fp_derivation_t *drv, uint8_t **out_buf, size_t *out_len) {
    if (!drv || !out_buf || !out_len) return FP_ERR_INVALID;
    size_t total = 4u + DERIV_SIGN_LEN + FP_SIG_LEN;
    uint8_t *buf = malloc(total);
    if (!buf) return FP_ERR_NOMEM;
    memcpy(buf, "FPD1", 4);
    build_deriv_signing_bytes(drv, buf + 4);
    memcpy(buf + 4 + DERIV_SIGN_LEN, drv->sig, FP_SIG_LEN);
    *out_buf = buf;
    *out_len = total;
    return FP_OK;
}

fp_err_t fp_derivation_decode(const uint8_t *buf, size_t len, fp_derivation_t *out_drv) {
    if (!buf || !out_drv || len != 4u + DERIV_SIGN_LEN + FP_SIG_LEN) {
        return FP_ERR_INVALID;
    }
    if (memcmp(buf, "FPD1", 4) != 0) return FP_ERR_INVALID;
    const uint8_t *msg = buf + 4;
    static const uint8_t domain[11] = "FP1/DERIVE";
    if (memcmp(msg, domain, 11) != 0) return FP_ERR_INVALID;

    memset(out_drv, 0, sizeof(*out_drv));
    size_t p = 11;
    out_drv->version = get_be16(msg + p); p += 2;
    memcpy(out_drv->parent_dna.bytes, msg + p, 32); p += 32;
    memcpy(out_drv->op_dna.bytes, msg + p, 32); p += 32;
    memcpy(out_drv->result_dna.bytes, msg + p, 32); p += 32;
    out_drv->result_size = get_be64(msg + p); p += 8;
    out_drv->timestamp_unix = get_be64(msg + p); p += 8;
    memcpy(out_drv->signer_pk, msg + p, 32);
    memcpy(out_drv->sig, buf + 4 + DERIV_SIGN_LEN, FP_SIG_LEN);
    return FP_OK;
}
