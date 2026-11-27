#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void put_be32(uint8_t dst[4], uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v);
}

static uint32_t get_be32(const uint8_t src[4]) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  | ((uint32_t)src[3]);
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

static fp_err_t ensure_dir(const char *path) {
    if (mkdir(path, 0700) == 0 || errno == EEXIST) {
        return FP_OK;
    }
    return FP_ERR_IO;
}

static fp_err_t sync_dir(const char *dir_path) {
    int fd = open(dir_path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return FP_ERR_IO;
    int rc = fsync(fd);
    close(fd);
    return rc == 0 ? FP_OK : FP_ERR_IO;
}

static fp_err_t write_all_fd(int fd, const uint8_t *data, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return FP_ERR_IO;
        }
        written += (size_t)n;
    }
    return FP_OK;
}

static fp_err_t atomic_write_file(const char *dir, const char *dest_path,
                                  const uint8_t *data, size_t len) {
    char tmp_path[PATH_MAX];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s/.fp-stage-XXXXXX", dir);
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) return FP_ERR_BOUNDS;

    int fd = mkstemp(tmp_path);
    if (fd < 0) return FP_ERR_IO;

    fp_err_t err = write_all_fd(fd, data, len);
    if (err == FP_OK && fsync(fd) != 0) {
        err = FP_ERR_IO;
    }
    close(fd);

    if (err != FP_OK) {
        unlink(tmp_path);
        return err;
    }
    if (rename(tmp_path, dest_path) != 0) {
        unlink(tmp_path);
        return FP_ERR_IO;
    }
    return sync_dir(dir);
}

static fp_err_t read_file_bounded(const char *path, size_t max_size,
                                  uint8_t **out_data, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return errno == ENOENT ? FP_ERR_NOT_FOUND : FP_ERR_IO;
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size < 0) {
        fclose(f);
        return FP_ERR_IO;
    }
    if ((uint64_t)st.st_size > (uint64_t)max_size) {
        fclose(f);
        return FP_ERR_BOUNDS;
    }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = malloc(sz > 0 ? sz : 1u);
    if (!buf) {
        fclose(f);
        return FP_ERR_NOMEM;
    }
    if (sz > 0 && fread(buf, 1, sz, f) != sz) {
        free(buf);
        fclose(f);
        return FP_ERR_IO;
    }
    fclose(f);
    *out_data = buf;
    *out_len = sz;
    return FP_OK;
}

static int acquire_store_lock(const char *root) {
    if (ensure_dir(root) != FP_OK) return -1;
    char lock_path[PATH_MAX];
    int n = snprintf(lock_path, sizeof(lock_path), "%s/.lock", root);
    if (n < 0 || (size_t)n >= sizeof(lock_path)) return -1;
    int fd = open(lock_path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int dna_in_list(const fp_dna_t *list, uint32_t count, const fp_dna_t *target) {
    for (uint32_t i = 0; i < count; i++) {
        if (fp_dna_equal(&list[i], target)) return 1;
    }
    return 0;
}

/* State binary encoding:
 *   "FPS1" (4) | repo_id (32) | signer_pk (32) | serial (8) | last_event_hash (32)
 *   has_current (1) | reserved (3) | current_dna (32)
 *   installed_count (4) | revoked_count (4)
 *   installed[installed_count * 32] | revoked[revoked_count * 32]
 */
#define STATE_HDR_LEN (4u + 32u + 32u + 8u + 32u + 1u + 3u + 32u + 4u + 4u)

static fp_err_t encode_state(const fp_store_state_t *st, uint8_t **out, size_t *out_len) {
    if (st->installed_count > FP_MAX_HISTORY || st->revoked_count > FP_MAX_HISTORY) {
        return FP_ERR_BOUNDS;
    }
    size_t total = STATE_HDR_LEN +
                   (size_t)st->installed_count * FP_DNA_LEN +
                   (size_t)st->revoked_count * FP_DNA_LEN;
    uint8_t *buf = malloc(total);
    if (!buf) return FP_ERR_NOMEM;

    size_t p = 0;
    memcpy(buf + p, "FPS1", 4); p += 4;
    memcpy(buf + p, st->repo_id.bytes, 32); p += 32;
    memcpy(buf + p, st->signer_pk, 32); p += 32;
    put_be64(buf + p, st->serial); p += 8;
    memcpy(buf + p, st->last_event_hash.bytes, 32); p += 32;
    buf[p++] = st->has_current ? 1u : 0u;
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0;
    memcpy(buf + p, st->current_dna.bytes, 32); p += 32;
    put_be32(buf + p, st->installed_count); p += 4;
    put_be32(buf + p, st->revoked_count); p += 4;
    for (uint32_t i = 0; i < st->installed_count; i++) {
        memcpy(buf + p, st->installed[i].bytes, 32);
        p += 32;
    }
    for (uint32_t i = 0; i < st->revoked_count; i++) {
        memcpy(buf + p, st->revoked[i].bytes, 32);
        p += 32;
    }
    *out = buf;
    *out_len = total;
    return FP_OK;
}

static fp_err_t decode_state(const uint8_t *buf, size_t len, fp_store_state_t *st) {
    if (len < STATE_HDR_LEN || memcmp(buf, "FPS1", 4) != 0) {
        return FP_ERR_INTEGRITY;
    }
    memset(st, 0, sizeof(*st));
    size_t p = 4;
    memcpy(st->repo_id.bytes, buf + p, 32); p += 32;
    memcpy(st->signer_pk, buf + p, 32); p += 32;
    st->serial = get_be64(buf + p); p += 8;
    memcpy(st->last_event_hash.bytes, buf + p, 32); p += 32;
    st->has_current = buf[p++] != 0 ? 1u : 0u;
    if (buf[p] != 0 || buf[p + 1] != 0 || buf[p + 2] != 0) {
        return FP_ERR_INTEGRITY;
    }
    p += 3;
    memcpy(st->current_dna.bytes, buf + p, 32); p += 32;
    st->installed_count = get_be32(buf + p); p += 4;
    st->revoked_count = get_be32(buf + p); p += 4;

    if (st->installed_count > FP_MAX_HISTORY || st->revoked_count > FP_MAX_HISTORY) {
        return FP_ERR_BOUNDS;
    }
    size_t expected = STATE_HDR_LEN +
                      (size_t)st->installed_count * FP_DNA_LEN +
                      (size_t)st->revoked_count * FP_DNA_LEN;
    if (len != expected) {
        return FP_ERR_INTEGRITY;
    }
    for (uint32_t i = 0; i < st->installed_count; i++) {
        memcpy(st->installed[i].bytes, buf + p, 32);
        p += 32;
    }
    for (uint32_t i = 0; i < st->revoked_count; i++) {
        memcpy(st->revoked[i].bytes, buf + p, 32);
        p += 32;
    }
    return FP_OK;
}

static fp_err_t load_state_unlocked(const char *root, fp_store_state_t *out_state) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/state.bin", root);
    if (n < 0 || (size_t)n >= sizeof(path)) return FP_ERR_BOUNDS;

    uint8_t *buf = NULL;
    size_t len = 0;
    fp_err_t err = read_file_bounded(path, 1u << 20, &buf, &len);
    if (err == FP_ERR_NOT_FOUND) {
        memset(out_state, 0, sizeof(*out_state));
        return FP_OK;
    }
    if (err != FP_OK) return err;

    err = decode_state(buf, len, out_state);
    free(buf);
    return err;
}

fp_err_t fp_store_put_object(const char *root, const uint8_t *data, size_t len,
                             fp_dna_t *out_dna) {
    if (!root || (len > 0 && !data)) return FP_ERR_INVALID;
    fp_dna_t dna;
    fp_err_t err = fp_dna_compute(data, len, &dna);
    if (err != FP_OK) return err;

    char obj_dir[PATH_MAX];
    char obj_path[PATH_MAX];
    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(dna.bytes, FP_DNA_LEN, hex);

    if (ensure_dir(root) != FP_OK) return FP_ERR_IO;
    int n = snprintf(obj_dir, sizeof(obj_dir), "%s/objects", root);
    if (n < 0 || (size_t)n >= sizeof(obj_dir)) return FP_ERR_BOUNDS;
    if (ensure_dir(obj_dir) != FP_OK) return FP_ERR_IO;

    n = snprintf(obj_path, sizeof(obj_path), "%s/%s", obj_dir, hex);
    if (n < 0 || (size_t)n >= sizeof(obj_path)) return FP_ERR_BOUNDS;

    err = atomic_write_file(obj_dir, obj_path, data, len);
    if (err == FP_OK && out_dna) {
        *out_dna = dna;
    }
    return err;
}

fp_err_t fp_store_put_file(const char *root, const char *src_path,
                           fp_dna_t *out_dna, uint64_t *out_size) {
    if (!root || !src_path) return FP_ERR_INVALID;
    int sfd = open(src_path, O_RDONLY);
    if (sfd < 0) return errno == ENOENT ? FP_ERR_NOT_FOUND : FP_ERR_IO;

    char obj_dir[PATH_MAX];
    char tmp_path[PATH_MAX];
    char obj_path[PATH_MAX];
    if (ensure_dir(root) != FP_OK) { close(sfd); return FP_ERR_IO; }
    int n = snprintf(obj_dir, sizeof(obj_dir), "%s/objects", root);
    if (n < 0 || (size_t)n >= sizeof(obj_dir)) { close(sfd); return FP_ERR_BOUNDS; }
    if (ensure_dir(obj_dir) != FP_OK) { close(sfd); return FP_ERR_IO; }

    n = snprintf(tmp_path, sizeof(tmp_path), "%s/.fp-put-XXXXXX", obj_dir);
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) { close(sfd); return FP_ERR_BOUNDS; }
    int dfd = mkstemp(tmp_path);
    if (dfd < 0) { close(sfd); return FP_ERR_IO; }

    fp_dna_stream_t st;
    fp_dna_stream_init(&st);
    uint8_t buf[65536];
    fp_err_t err = FP_OK;
    for (;;) {
        ssize_t r = read(sfd, buf, sizeof(buf));
        if (r < 0) { if (errno == EINTR) continue; err = FP_ERR_IO; break; }
        if (r == 0) break;
        err = fp_dna_stream_update(&st, buf, (size_t)r);
        if (err != FP_OK) break;
        err = write_all_fd(dfd, buf, (size_t)r);
        if (err != FP_OK) break;
    }
    close(sfd);

    fp_dna_t dna;
    uint64_t total_sz = 0;
    if (err == FP_OK) err = fp_dna_stream_finish(&st, &dna, &total_sz);
    if (err == FP_OK && fsync(dfd) != 0) err = FP_ERR_IO;
    close(dfd);

    if (err != FP_OK) {
        unlink(tmp_path);
        return err;
    }

    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(dna.bytes, FP_DNA_LEN, hex);
    n = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", root, hex);
    if (n < 0 || (size_t)n >= sizeof(obj_path)) { unlink(tmp_path); return FP_ERR_BOUNDS; }
    if (rename(tmp_path, obj_path) != 0) {
        unlink(tmp_path);
        return FP_ERR_IO;
    }
    err = sync_dir(obj_dir);
    if (err == FP_OK) {
        if (out_dna) *out_dna = dna;
        if (out_size) *out_size = total_sz;
    }
    return err;
}

fp_err_t fp_store_get_object(const char *root, const fp_dna_t *dna, size_t max_size,
                             uint8_t **out_data, size_t *out_len) {
    if (!root || !dna || !out_data || !out_len) return FP_ERR_INVALID;
    *out_data = NULL;
    *out_len = 0;

    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(dna->bytes, FP_DNA_LEN, hex);

    char obj_path[PATH_MAX];
    int n = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", root, hex);
    if (n < 0 || (size_t)n >= sizeof(obj_path)) return FP_ERR_BOUNDS;

    uint8_t *buf = NULL;
    size_t len = 0;
    fp_err_t err = read_file_bounded(obj_path, max_size, &buf, &len);
    if (err != FP_OK) return err;

    fp_dna_t actual;
    err = fp_dna_compute(buf, len, &actual);
    if (err != FP_OK || !fp_dna_equal(&actual, dna)) {
        free(buf);
        return FP_ERR_INTEGRITY;
    }
    *out_data = buf;
    *out_len = len;
    return FP_OK;
}

int fp_store_has_object(const char *root, const fp_dna_t *dna, uint64_t *out_size) {
    if (!root || !dna) return 0;
    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(dna->bytes, FP_DNA_LEN, hex);
    char obj_path[PATH_MAX];
    int n = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", root, hex);
    if (n < 0 || (size_t)n >= sizeof(obj_path)) return 0;
    struct stat st;
    if (stat(obj_path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        return 0;
    }
    if (out_size) *out_size = (uint64_t)st.st_size;
    return 1;
}

int fp_store_open_object_fd(const char *root, const fp_dna_t *dna,
                            char *out_path, size_t out_path_cap, uint64_t *out_size) {
    if (!root || !dna) return -1;
    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(dna->bytes, FP_DNA_LEN, hex);
    char obj_path[PATH_MAX];
    int n = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", root, hex);
    if (n < 0 || (size_t)n >= sizeof(obj_path)) return -1;
    int fd = open(obj_path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd);
        return -1;
    }
    if (out_path && out_path_cap > 0) {
        if ((size_t)n >= out_path_cap) { close(fd); return -1; }
        memcpy(out_path, obj_path, (size_t)n + 1u);
    }
    if (out_size) *out_size = (uint64_t)st.st_size;
    return fd;
}

fp_err_t fp_store_load_state(const char *root, fp_store_state_t *out_state) {
    if (!root || !out_state) return FP_ERR_INVALID;
    int lfd = acquire_store_lock(root);
    if (lfd < 0) return FP_ERR_IO;
    fp_err_t err = load_state_unlocked(root, out_state);
    close(lfd);
    return err;
}

fp_err_t fp_store_validate_transition(const fp_store_state_t *current,
                                      const fp_event_t *ev,
                                      fp_store_state_t *out_next) {
    if (!current || !ev) return FP_ERR_INVALID;

    fp_store_state_t next = *current;
    if (next.serial > 0) {
        if (!fp_dna_equal(&next.repo_id, &ev->repo_id)) {
            return FP_ERR_POLICY;
        }
    } else {
        next.repo_id = ev->repo_id;
        memcpy(next.signer_pk, ev->signer_pk, FP_PK_LEN);
    }

    if (ev->serial != next.serial + 1u ||
        !fp_dna_equal(&ev->prev_event_hash, &next.last_event_hash)) {
        return FP_ERR_CHAIN;
    }

    if (ev->action == FP_ACTION_REVOKE) {
        if (!dna_in_list(next.revoked, next.revoked_count, &ev->target_dna)) {
            if (next.revoked_count >= FP_MAX_HISTORY) {
                return FP_ERR_BOUNDS;
            }
            next.revoked[next.revoked_count++] = ev->target_dna;
        }
        if (next.has_current && fp_dna_equal(&next.current_dna, &ev->target_dna)) {
            next.has_current = 0;
            memset(&next.current_dna, 0, sizeof(next.current_dna));
        }
    } else if (ev->action == FP_ACTION_INSTALL || ev->action == FP_ACTION_ROLLBACK) {
        if (dna_in_list(next.revoked, next.revoked_count, &ev->target_dna)) {
            return FP_ERR_REVOKED;
        }
        int known = dna_in_list(next.installed, next.installed_count, &ev->target_dna);
        if (ev->action == FP_ACTION_INSTALL && known) {
            return FP_ERR_POLICY;
        }
        if (ev->action == FP_ACTION_ROLLBACK && !known) {
            return FP_ERR_POLICY;
        }
        if (!known) {
            if (next.installed_count >= FP_MAX_HISTORY) {
                return FP_ERR_BOUNDS;
            }
            next.installed[next.installed_count++] = ev->target_dna;
        }
        next.has_current = 1;
        next.current_dna = ev->target_dna;
    } else {
        return FP_ERR_INVALID;
    }

    next.serial = ev->serial;
    next.last_event_hash = ev->event_hash;
    if (out_next) *out_next = next;
    return FP_OK;
}

fp_err_t fp_store_apply_event(const char *root, const fp_event_t *ev,
                              const uint8_t expected_pk[FP_PK_LEN],
                              const fp_dna_t *expected_repo,
                              uint64_t now_unix,
                              const uint8_t *payload_data, size_t payload_len) {
    if (!root || !ev || !expected_pk || !expected_repo) return FP_ERR_INVALID;

    fp_err_t err = fp_event_verify(ev, expected_pk, expected_repo, now_unix);
    if (err != FP_OK) return err;

    int lfd = acquire_store_lock(root);
    if (lfd < 0) return FP_ERR_IO;

    fp_store_state_t st;
    err = load_state_unlocked(root, &st);
    if (err != FP_OK) {
        close(lfd);
        return err;
    }

    if (st.serial > 0 && sodium_memcmp(st.signer_pk, ev->signer_pk, FP_PK_LEN) != 0) {
        close(lfd);
        return FP_ERR_POLICY;
    }

    fp_store_state_t next_st;
    err = fp_store_validate_transition(&st, ev, &next_st);
    if (err != FP_OK) {
        close(lfd);
        return err;
    }

    if (ev->action != FP_ACTION_REVOKE) {
        if (!payload_data && payload_len > 0) {
            close(lfd);
            return FP_ERR_INVALID;
        }
        if (payload_data) {
            if (payload_len != ev->target_size) {
                close(lfd);
                return FP_ERR_INTEGRITY;
            }
            fp_dna_t actual;
            err = fp_dna_compute(payload_data, payload_len, &actual);
            if (err != FP_OK || !fp_dna_equal(&actual, &ev->target_dna)) {
                close(lfd);
                return FP_ERR_INTEGRITY;
            }
            err = fp_store_put_object(root, payload_data, payload_len, NULL);
            if (err != FP_OK) {
                close(lfd);
                return err;
            }
        } else {
            /* Must already exist intact in store — stream-verify in O(1) RAM (Multi-GB safe!) */
            char existing_path[PATH_MAX];
            uint64_t existing_sz = 0;
            int efd = fp_store_open_object_fd(root, &ev->target_dna,
                                              existing_path, sizeof(existing_path), &existing_sz);
            if (efd < 0) {
                close(lfd);
                return FP_ERR_NOT_FOUND;
            }
            close(efd);
            fp_dna_t actual;
            uint64_t verified_sz = 0;
            err = fp_dna_compute_file(existing_path, &actual, &verified_sz);
            if (err != FP_OK || verified_sz != ev->target_size ||
                !fp_dna_equal(&actual, &ev->target_dna)) {
                close(lfd);
                return err != FP_OK ? err : FP_ERR_INTEGRITY;
            }
        }
    }

    /* Persist signed event audit copy */
    char ev_dir[PATH_MAX], ev_path[PATH_MAX];
    int n = snprintf(ev_dir, sizeof(ev_dir), "%s/events", root);
    if (n < 0 || (size_t)n >= sizeof(ev_dir)) { close(lfd); return FP_ERR_BOUNDS; }
    if (ensure_dir(ev_dir) != FP_OK) { close(lfd); return FP_ERR_IO; }
    n = snprintf(ev_path, sizeof(ev_path), "%s/%llu.ev", ev_dir,
                 (unsigned long long)ev->serial);
    if (n < 0 || (size_t)n >= sizeof(ev_path)) { close(lfd); return FP_ERR_BOUNDS; }

    uint8_t *ev_bytes = NULL;
    size_t ev_len = 0;
    err = fp_event_encode(ev, &ev_bytes, &ev_len);
    if (err != FP_OK) { close(lfd); return err; }
    err = atomic_write_file(ev_dir, ev_path, ev_bytes, ev_len);
    free(ev_bytes);
    if (err != FP_OK) { close(lfd); return err; }

    /* Advance state atomically */
    uint8_t *st_bytes = NULL;
    size_t st_len = 0;
    err = encode_state(&next_st, &st_bytes, &st_len);
    if (err != FP_OK) { close(lfd); return err; }

    char st_path[PATH_MAX];
    n = snprintf(st_path, sizeof(st_path), "%s/state.bin", root);
    if (n < 0 || (size_t)n >= sizeof(st_path)) {
        free(st_bytes);
        close(lfd);
        return FP_ERR_BOUNDS;
    }
    err = atomic_write_file(root, st_path, st_bytes, st_len);
    free(st_bytes);
    close(lfd);
    return err;
}

fp_err_t fp_store_apply_event_with_root(const char *root_dir, const fp_event_t *ev,
                                        const fp_root_doc_t *trusted_root,
                                        uint64_t now_unix,
                                        const uint8_t *payload_data, size_t payload_len) {
    if (!root_dir || !ev || !trusted_root) return FP_ERR_INVALID;
    fp_err_t err = fp_event_verify_with_root(ev, trusted_root, now_unix);
    if (err != FP_OK) return err;

    /* If store already exists with an older rotated release key, authorize the key rotation
     * inside the store lock by updating signer_pk to trusted_root->release_pk (same repo_id). */
    int lfd = acquire_store_lock(root_dir);
    if (lfd < 0) return FP_ERR_IO;
    fp_store_state_t st;
    err = load_state_unlocked(root_dir, &st);
    if (err == FP_OK && st.serial > 0) {
        if (!fp_dna_equal(&st.repo_id, &trusted_root->repo_id)) {
            close(lfd);
            return FP_ERR_POLICY;
        }
        if (sodium_memcmp(st.signer_pk, trusted_root->release_pk, FP_PK_LEN) != 0) {
            memcpy(st.signer_pk, trusted_root->release_pk, FP_PK_LEN);
            uint8_t *st_bytes = NULL;
            size_t st_len = 0;
            err = encode_state(&st, &st_bytes, &st_len);
            if (err == FP_OK) {
                char st_path[PATH_MAX];
                int n = snprintf(st_path, sizeof(st_path), "%s/state.bin", root_dir);
                if (n < 0 || (size_t)n >= sizeof(st_path)) err = FP_ERR_BOUNDS;
                else err = atomic_write_file(root_dir, st_path, st_bytes, st_len);
                free(st_bytes);
            }
        }
    }
    close(lfd);
    if (err != FP_OK) return err;

    return fp_store_apply_event(root_dir, ev, trusted_root->release_pk,
                                &trusted_root->repo_id, now_unix,
                                payload_data, payload_len);
}
