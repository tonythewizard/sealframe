#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <blake3.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

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

/*
 * Off-path 32-byte commitment designed for external or local transparency logs:
 *   commitment = BLAKE3("FP1/ANCHOR\0" || repo_id || u64_be(serial) || event_hash || target_dna)
 */
fp_err_t fp_anchor_compute(const fp_event_t *ev, fp_anchor_commitment_t *out) {
    if (!ev || !out) return FP_ERR_INVALID;
    static const uint8_t tag[11] = "FP1/ANCHOR";
    uint8_t sbuf[8];
    put_be64(sbuf, ev->serial);

    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, ev->repo_id.bytes, FP_DNA_LEN);
    blake3_hasher_update(&h, sbuf, sizeof(sbuf));
    blake3_hasher_update(&h, ev->event_hash.bytes, FP_DNA_LEN);
    blake3_hasher_update(&h, ev->target_dna.bytes, FP_DNA_LEN);

    out->repo_id = ev->repo_id;
    out->serial = ev->serial;
    out->event_hash = ev->event_hash;
    out->target_dna = ev->target_dna;
    blake3_hasher_finalize(&h, out->commitment.bytes, FP_DNA_LEN);
    return FP_OK;
}

/* Local transparency-log record: 136 bytes fixed */
#define ANCHOR_REC_LEN (32u + 8u + 32u + 32u + 32u)

static void encode_rec(const fp_anchor_commitment_t *c, uint8_t rec[ANCHOR_REC_LEN]) {
    memcpy(rec, c->repo_id.bytes, 32);
    put_be64(rec + 32, c->serial);
    memcpy(rec + 40, c->event_hash.bytes, 32);
    memcpy(rec + 72, c->target_dna.bytes, 32);
    memcpy(rec + 104, c->commitment.bytes, 32);
}

static void decode_rec(const uint8_t rec[ANCHOR_REC_LEN], fp_anchor_commitment_t *c) {
    memcpy(c->repo_id.bytes, rec, 32);
    c->serial = get_be64(rec + 32);
    memcpy(c->event_hash.bytes, rec + 40, 32);
    memcpy(c->target_dna.bytes, rec + 72, 32);
    memcpy(c->commitment.bytes, rec + 104, 32);
}

static fp_err_t verify_log_fd(int fd, const fp_anchor_commitment_t *c) {
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        return FP_ERR_IO;
    }
    if ((uint64_t)st.st_size % ANCHOR_REC_LEN != 0) {
        return FP_ERR_INTEGRITY; /* Reject truncated or misaligned transparency log */
    }
    if (lseek(fd, 0, SEEK_SET) != 0) return FP_ERR_IO;

    uint8_t rec[ANCHOR_REC_LEN];
    int found = 0;
    for (uint64_t off = 0; off < (uint64_t)st.st_size; off += ANCHOR_REC_LEN) {
        size_t got = 0;
        while (got < sizeof(rec)) {
            ssize_t n = read(fd, rec + got, sizeof(rec) - got);
            if (n < 0) { if (errno == EINTR) continue; return FP_ERR_IO; }
            if (n == 0) return FP_ERR_INTEGRITY;
            got += (size_t)n;
        }
        fp_anchor_commitment_t cur;
        decode_rec(rec, &cur);
        if (fp_dna_equal(&cur.repo_id, &c->repo_id) && cur.serial == c->serial) {
            if (!fp_dna_equal(&cur.commitment, &c->commitment) ||
                !fp_dna_equal(&cur.event_hash, &c->event_hash) ||
                !fp_dna_equal(&cur.target_dna, &c->target_dna)) {
                return FP_ERR_CHAIN; /* Split-view equivocation detected! */
            }
            found = 1;
        }
    }
    return found ? FP_OK : FP_ERR_NOT_FOUND;
}

fp_err_t fp_anchor_local_verify(const char *log_path, const fp_anchor_commitment_t *c) {
    if (!log_path || !c) return FP_ERR_INVALID;
    int fd = open(log_path, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? FP_ERR_NOT_FOUND : FP_ERR_IO;
    fp_err_t err = verify_log_fd(fd, c);
    close(fd);
    return err;
}

fp_err_t fp_anchor_local_publish(const char *log_path, const fp_anchor_commitment_t *c) {
    if (!log_path || !c) return FP_ERR_INVALID;
    int fd = open(log_path, O_CREAT | O_RDWR | O_APPEND, 0600);
    if (fd < 0) return FP_ERR_IO;
    if (flock(fd, LOCK_EX) != 0) { close(fd); return FP_ERR_IO; }

    fp_err_t existing = verify_log_fd(fd, c);
    if (existing == FP_OK) {
        close(fd);
        return FP_OK; /* Idempotent */
    }
    if (existing != FP_ERR_NOT_FOUND) {
        close(fd);
        return existing; /* Refuse split-view equivocation or corrupt/truncated log */
    }

    uint8_t rec[ANCHOR_REC_LEN];
    encode_rec(c, rec);
    size_t pos = 0;
    while (pos < sizeof(rec)) {
        ssize_t n = write(fd, rec + pos, sizeof(rec) - pos);
        if (n < 0) { if (errno == EINTR) continue; close(fd); return FP_ERR_IO; }
        pos += (size_t)n;
    }
    int sync_rc = fsync(fd);
    close(fd);
    return sync_rc == 0 ? FP_OK : FP_ERR_IO;
}
