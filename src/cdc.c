#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <blake3.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Normalized FastCDC (USENIX ATC '16) masks for 16 KiB average chunk size:
 * MASK_S: 15 bits set (strict, used for [FP_CDC_MIN, FP_CDC_AVG))
 * MASK_L: 13 bits set (lenient, used for [FP_CDC_AVG, FP_CDC_MAX))
 */
#define FP_CDC_MASK_S UINT64_C(0x0000D93503530000)
#define FP_CDC_MASK_L UINT64_C(0x0000D90303530000)

#define FPC1_HDR_LEN   (4u + 2u + 2u + 8u + 32u + 8u) /* 56 B */
#define FPC1_ENTRY_LEN (32u + 4u)                      /* 36 B */

static uint64_t       g_gear[256];
static pthread_once_t g_gear_once = PTHREAD_ONCE_INIT;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void put_be16(uint8_t dst[2], uint16_t v) {
    dst[0] = (uint8_t)(v >> 8);
    dst[1] = (uint8_t)(v);
}

static uint16_t get_be16(const uint8_t src[2]) {
    return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
}

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

static void init_gear_table_once(void) {
    static const uint8_t tag[9] = "FP1/GEAR";
    for (unsigned i = 0; i < 256; i++) {
        uint8_t b = (uint8_t)i;
        uint8_t out[8];
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, tag, sizeof(tag));
        blake3_hasher_update(&h, &b, 1);
        blake3_hasher_finalize(&h, out, sizeof(out));
        g_gear[i] = get_be64(out);
    }
}

static void init_gear_table(void) {
    (void)pthread_once(&g_gear_once, init_gear_table_once);
}

size_t fp_fastcdc_cut(const uint8_t *data, size_t len) {
    if (!data || len == 0) return 0;
    if (len <= FP_CDC_MIN) return len;
    init_gear_table();

    size_t max_len = len < FP_CDC_MAX ? len : FP_CDC_MAX;
    size_t normal = FP_CDC_AVG < max_len ? FP_CDC_AVG : max_len;

    uint64_t fp = 0;
    size_t i = FP_CDC_MIN;

    /* Strict phase: [FP_CDC_MIN, normal) */
    for (; i < normal; i++) {
        fp = (fp << 1) + g_gear[data[i]];
        if ((fp & FP_CDC_MASK_S) == 0) {
            return i + 1u;
        }
    }
    /* Lenient phase: [normal, max_len) */
    for (; i < max_len; i++) {
        fp = (fp << 1) + g_gear[data[i]];
        if ((fp & FP_CDC_MASK_L) == 0) {
            return i + 1u;
        }
    }
    return max_len;
}

fp_err_t fp_cdc_chunk_id(const uint8_t *chunk, size_t len, fp_dna_t *out_id) {
    if (!out_id || (len > 0 && !chunk) || len > FP_CDC_MAX) {
        return FP_ERR_INVALID;
    }
    static const uint8_t tag[10] = "FP1/CHUNK";
    uint8_t lbuf[4];
    put_be32(lbuf, (uint32_t)len);

    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, lbuf, sizeof(lbuf));
    if (len > 0) blake3_hasher_update(&h, chunk, len);
    blake3_hasher_finalize(&h, out_id->bytes, FP_DNA_LEN);
    return FP_OK;
}

static fp_err_t ensure_dir(const char *path) {
    if (mkdir(path, 0700) == 0 || errno == EEXIST) return FP_OK;
    return FP_ERR_IO;
}

static fp_err_t write_all_fd(int fd, const uint8_t *buf, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = write(fd, buf + pos, len - pos);
        if (n < 0) {
            if (errno == EINTR) continue;
            return FP_ERR_IO;
        }
        pos += (size_t)n;
    }
    return FP_OK;
}

static fp_err_t chunk_path_for(const char *store_dir, const fp_dna_t *cid,
                               char shard_dir[PATH_MAX], char full_path[PATH_MAX]) {
    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(cid->bytes, FP_DNA_LEN, hex);
    int n1 = snprintf(shard_dir, PATH_MAX, "%s/chunks/%.2s", store_dir, hex);
    int n2 = snprintf(full_path, PATH_MAX, "%s/chunks/%.2s/%s", store_dir, hex, hex);
    if (n1 < 0 || n1 >= PATH_MAX || n2 < 0 || n2 >= PATH_MAX) {
        return FP_ERR_BOUNDS;
    }
    return FP_OK;
}

static fp_err_t store_chunk_if_missing(const char *store_dir, const fp_dna_t *cid,
                                       const uint8_t *data, size_t len, int *was_new) {
    char shard_dir[PATH_MAX], cpath[PATH_MAX];
    fp_err_t err = chunk_path_for(store_dir, cid, shard_dir, cpath);
    if (err != FP_OK) return err;

    struct stat st;
    if (stat(cpath, &st) == 0 && S_ISREG(st.st_mode) && (size_t)st.st_size == len) {
        *was_new = 0;
        return FP_OK;
    }

    if (ensure_dir(shard_dir) != FP_OK) return FP_ERR_IO;

    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s/.fp-chk-XXXXXX", shard_dir);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return FP_ERR_BOUNDS;

    int fd = mkstemp(tmp);
    if (fd < 0) return FP_ERR_IO;
    err = write_all_fd(fd, data, len);
    close(fd);
    if (err != FP_OK) {
        unlink(tmp);
        return err;
    }
    if (rename(tmp, cpath) != 0) {
        unlink(tmp);
        return FP_ERR_IO;
    }
    *was_new = 1;
    return FP_OK;
}

/*
 * Single-pass O(1) RAM streaming ingest:
 *   Reads input file into a fixed 128 KiB sliding buffer, simultaneously:
 *   1) Computing canonical 16 KiB Merkle DNA via fp_dna_stream_t
 *   2) Cutting content-defined chunks via Normalized FastCDC
 *   3) Writing only non-duplicate chunks to <store>/chunks/<aa>/<chunk_id>
 *   4) Streaming the FPC1 recipe to <store>/recipes/<dna>.fpc
 */
fp_err_t fp_cdc_ingest_file(const char *store_dir, const char *file_path,
                            fp_cdc_stats_t *out_stats) {
    if (!store_dir || !file_path) return FP_ERR_INVALID;
    uint64_t t0 = now_ns();

    char chunks_root[PATH_MAX], recipes_root[PATH_MAX];
    int n1 = snprintf(chunks_root, sizeof(chunks_root), "%s/chunks", store_dir);
    int n2 = snprintf(recipes_root, sizeof(recipes_root), "%s/recipes", store_dir);
    if (n1 < 0 || (size_t)n1 >= sizeof(chunks_root) ||
        n2 < 0 || (size_t)n2 >= sizeof(recipes_root)) {
        return FP_ERR_BOUNDS;
    }
    if (ensure_dir(store_dir) != FP_OK ||
        ensure_dir(chunks_root) != FP_OK ||
        ensure_dir(recipes_root) != FP_OK) {
        return FP_ERR_IO;
    }

    FILE *in = fopen(file_path, "rb");
    if (!in) return FP_ERR_IO;

    char rtmp[PATH_MAX];
    int rn = snprintf(rtmp, sizeof(rtmp), "%s/.fp-rec-XXXXXX", recipes_root);
    if (rn < 0 || (size_t)rn >= sizeof(rtmp)) {
        fclose(in);
        return FP_ERR_BOUNDS;
    }
    int rfd = mkstemp(rtmp);
    if (rfd < 0) {
        fclose(in);
        return FP_ERR_IO;
    }

    /* Reserve 56-byte FPC1 header at offset 0 */
    uint8_t hdr[FPC1_HDR_LEN];
    memset(hdr, 0, sizeof(hdr));
    if (write_all_fd(rfd, hdr, sizeof(hdr)) != FP_OK) {
        close(rfd); unlink(rtmp); fclose(in);
        return FP_ERR_IO;
    }

    /* Fixed O(1) sliding window buffer = 2 * FP_CDC_MAX = 128 KiB */
    uint8_t window[FP_CDC_MAX * 2u];
    size_t buffered = 0;
    int eof = 0;

    fp_dna_stream_t dna_stream;
    fp_dna_stream_init(&dna_stream);

    fp_cdc_stats_t st;
    memset(&st, 0, sizeof(st));
    fp_err_t err = FP_OK;

    while (err == FP_OK) {
        if (!eof && buffered < FP_CDC_MAX) {
            size_t space = sizeof(window) - buffered;
            size_t got = fread(window + buffered, 1, space, in);
            if (got > 0) {
                err = fp_dna_stream_update(&dna_stream, window + buffered, got);
                buffered += got;
            }
            if (got < space) {
                if (ferror(in)) { err = FP_ERR_IO; break; }
                eof = 1;
            }
        }
        if (buffered == 0) break;

        size_t cut = (buffered < FP_CDC_MAX && !eof) ? 0 : fp_fastcdc_cut(window, buffered);
        if (cut == 0) break;

        fp_dna_t cid;
        err = fp_cdc_chunk_id(window, cut, &cid);
        if (err != FP_OK) break;

        int was_new = 0;
        err = store_chunk_if_missing(store_dir, &cid, window, cut, &was_new);
        if (err != FP_OK) break;

        uint8_t entry[FPC1_ENTRY_LEN];
        memcpy(entry, cid.bytes, FP_DNA_LEN);
        put_be32(entry + FP_DNA_LEN, (uint32_t)cut);
        err = write_all_fd(rfd, entry, sizeof(entry));
        if (err != FP_OK) break;

        st.total_chunks++;
        if (was_new) {
            st.new_chunks++;
            st.stored_bytes += cut;
        } else {
            st.dedup_chunks++;
            st.reused_bytes += cut;
        }

        buffered -= cut;
        if (buffered > 0) {
            memmove(window, window + cut, buffered);
        }
    }

    fclose(in);

    if (err == FP_OK) {
        err = fp_dna_stream_finish(&dna_stream, &st.dna, &st.canonical_size);
    }
    if (err == FP_OK) {
        /* Patch FPC1 header at offset 0 */
        memcpy(hdr, "FPC1", 4);
        put_be16(hdr + 4, 1);
        put_be16(hdr + 6, 0);
        put_be64(hdr + 8, st.canonical_size);
        memcpy(hdr + 16, st.dna.bytes, FP_DNA_LEN);
        put_be64(hdr + 48, st.total_chunks);

        if (lseek(rfd, 0, SEEK_SET) != 0 ||
            write_all_fd(rfd, hdr, sizeof(hdr)) != FP_OK ||
            fsync(rfd) != 0) {
            err = FP_ERR_IO;
        }
    }
    close(rfd);

    if (err != FP_OK) {
        unlink(rtmp);
        return err;
    }

    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(st.dna.bytes, FP_DNA_LEN, hex);
    char rdest[PATH_MAX];
    int dn = snprintf(rdest, sizeof(rdest), "%s/%s.fpc", recipes_root, hex);
    if (dn < 0 || (size_t)dn >= sizeof(rdest)) {
        unlink(rtmp);
        return FP_ERR_BOUNDS;
    }
    if (rename(rtmp, rdest) != 0) {
        unlink(rtmp);
        return FP_ERR_IO;
    }
    int dfd = open(recipes_root, O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) { (void)fsync(dfd); close(dfd); }

    st.elapsed_ns = now_ns() - t0;
    if (out_stats) *out_stats = st;
    return FP_OK;
}

static fp_err_t parse_fpc1_header(FILE *f, uint64_t *out_size, fp_dna_t *out_dna,
                                  uint64_t *out_chunks) {
    uint8_t hdr[FPC1_HDR_LEN];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) return FP_ERR_INTEGRITY;
    if (memcmp(hdr, "FPC1", 4) != 0 || get_be16(hdr + 4) != 1 || get_be16(hdr + 6) != 0) {
        return FP_ERR_INTEGRITY;
    }
    *out_size = get_be64(hdr + 8);
    memcpy(out_dna->bytes, hdr + 16, FP_DNA_LEN);
    *out_chunks = get_be64(hdr + 48);
    if ((*out_size == 0 && *out_chunks != 0) || (*out_size > 0 && *out_chunks == 0)) {
        return FP_ERR_INTEGRITY;
    }
    return FP_OK;
}

fp_err_t fp_cdc_reconstruct_file(const char *store_dir, const fp_dna_t *dna,
                                 const char *out_path, uint64_t *out_bytes) {
    if (!store_dir || !dna || !out_path) return FP_ERR_INVALID;

    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(dna->bytes, FP_DNA_LEN, hex);
    char rpath[PATH_MAX];
    int n = snprintf(rpath, sizeof(rpath), "%s/recipes/%s.fpc", store_dir, hex);
    if (n < 0 || (size_t)n >= sizeof(rpath)) return FP_ERR_BOUNDS;

    FILE *rf = fopen(rpath, "rb");
    if (!rf) return errno == ENOENT ? FP_ERR_NOT_FOUND : FP_ERR_IO;

    uint64_t expected_size = 0, total_chunks = 0;
    fp_dna_t recipe_dna;
    fp_err_t err = parse_fpc1_header(rf, &expected_size, &recipe_dna, &total_chunks);
    if (err != FP_OK || !fp_dna_equal(&recipe_dna, dna)) {
        fclose(rf);
        return FP_ERR_INTEGRITY;
    }

    char tmp_out[PATH_MAX];
    int tn = snprintf(tmp_out, sizeof(tmp_out), "%s.fp-tmp-XXXXXX", out_path);
    if (tn < 0 || (size_t)tn >= sizeof(tmp_out)) {
        fclose(rf);
        return FP_ERR_BOUNDS;
    }
    int ofd = mkstemp(tmp_out);
    if (ofd < 0) {
        fclose(rf);
        return FP_ERR_IO;
    }

    /* Streaming O(1) RAM reconstruction + per-chunk ID check + full canonical DNA check */
    uint8_t chunk_buf[FP_CDC_MAX];
    fp_dna_stream_t dna_stream;
    fp_dna_stream_init(&dna_stream);
    uint64_t written_total = 0;

    for (uint64_t i = 0; i < total_chunks && err == FP_OK; i++) {
        uint8_t entry[FPC1_ENTRY_LEN];
        if (fread(entry, 1, sizeof(entry), rf) != sizeof(entry)) {
            err = FP_ERR_INTEGRITY;
            break;
        }
        fp_dna_t cid;
        memcpy(cid.bytes, entry, FP_DNA_LEN);
        uint32_t clen = get_be32(entry + FP_DNA_LEN);
        if (clen == 0 || clen > FP_CDC_MAX) {
            err = FP_ERR_BOUNDS;
            break;
        }
        if (clen > expected_size || written_total > expected_size - clen) {
            err = FP_ERR_INTEGRITY;
            break;
        }

        char shard_dir[PATH_MAX], cpath[PATH_MAX];
        err = chunk_path_for(store_dir, &cid, shard_dir, cpath);
        if (err != FP_OK) break;

        FILE *cf = fopen(cpath, "rb");
        if (!cf) { err = FP_ERR_MISSING_REF; break; }
        size_t got = fread(chunk_buf, 1, clen, cf);
        int extra = fgetc(cf);
        fclose(cf);
        if (got != clen || extra != EOF) {
            err = FP_ERR_INTEGRITY;
            break;
        }

        fp_dna_t actual_cid;
        err = fp_cdc_chunk_id(chunk_buf, clen, &actual_cid);
        if (err != FP_OK || !fp_dna_equal(&actual_cid, &cid)) {
            err = FP_ERR_INTEGRITY;
            break;
        }

        err = fp_dna_stream_update(&dna_stream, chunk_buf, clen);
        if (err == FP_OK) err = write_all_fd(ofd, chunk_buf, clen);
        written_total += clen;
    }
    if (err == FP_OK && fgetc(rf) != EOF) {
        err = FP_ERR_INTEGRITY; /* Reject trailing garbage in FPC1 recipe */
    }
    fclose(rf);

    if (err == FP_OK) {
        fp_dna_t verified_dna;
        uint64_t verified_sz = 0;
        err = fp_dna_stream_finish(&dna_stream, &verified_dna, &verified_sz);
        if (err == FP_OK && (verified_sz != expected_size || written_total != expected_size ||
                             !fp_dna_equal(&verified_dna, dna))) {
            err = FP_ERR_INTEGRITY;
        }
    }
    if (err == FP_OK && fsync(ofd) != 0) err = FP_ERR_IO;
    close(ofd);

    if (err != FP_OK) {
        unlink(tmp_out);
        return err;
    }
    if (rename(tmp_out, out_path) != 0) {
        unlink(tmp_out);
        return FP_ERR_IO;
    }
    if (out_bytes) *out_bytes = written_total;
    return FP_OK;
}

fp_err_t fp_cdc_recipe_missing(const char *store_dir, const fp_dna_t *recipe_dna,
                               const char *target_store_dir,
                               uint64_t *out_total_chunks, uint64_t *out_missing_chunks,
                               uint64_t *out_missing_bytes) {
    if (!store_dir || !recipe_dna || !target_store_dir) return FP_ERR_INVALID;

    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(recipe_dna->bytes, FP_DNA_LEN, hex);
    char rpath[PATH_MAX];
    int n = snprintf(rpath, sizeof(rpath), "%s/recipes/%s.fpc", store_dir, hex);
    if (n < 0 || (size_t)n >= sizeof(rpath)) return FP_ERR_BOUNDS;

    FILE *rf = fopen(rpath, "rb");
    if (!rf) return errno == ENOENT ? FP_ERR_NOT_FOUND : FP_ERR_IO;

    uint64_t expected_size = 0, total_chunks = 0;
    fp_dna_t hdr_dna;
    fp_err_t err = parse_fpc1_header(rf, &expected_size, &hdr_dna, &total_chunks);
    if (err != FP_OK || !fp_dna_equal(&hdr_dna, recipe_dna)) {
        fclose(rf);
        return FP_ERR_INTEGRITY;
    }

    uint64_t missing_c = 0, missing_b = 0;
    uint64_t sum_bytes = 0;
    for (uint64_t i = 0; i < total_chunks; i++) {
        uint8_t entry[FPC1_ENTRY_LEN];
        if (fread(entry, 1, sizeof(entry), rf) != sizeof(entry)) {
            fclose(rf);
            return FP_ERR_INTEGRITY;
        }
        fp_dna_t cid;
        memcpy(cid.bytes, entry, FP_DNA_LEN);
        uint32_t clen = get_be32(entry + FP_DNA_LEN);
        if (clen == 0 || clen > FP_CDC_MAX) {
            fclose(rf);
            return FP_ERR_BOUNDS;
        }
        if (clen > expected_size || sum_bytes > expected_size - clen) {
            fclose(rf);
            return FP_ERR_INTEGRITY;
        }
        sum_bytes += clen;

        char shard_dir[PATH_MAX], cpath[PATH_MAX];
        if (chunk_path_for(target_store_dir, &cid, shard_dir, cpath) != FP_OK) {
            fclose(rf);
            return FP_ERR_BOUNDS;
        }
        struct stat st;
        if (stat(cpath, &st) != 0 || !S_ISREG(st.st_mode) || (uint64_t)st.st_size != clen) {
            missing_c++;
            missing_b += clen;
        }
    }
    int extra = fgetc(rf);
    fclose(rf);
    if (extra != EOF || sum_bytes != expected_size) {
        return FP_ERR_INTEGRITY;
    }
    if (out_total_chunks)   *out_total_chunks = total_chunks;
    if (out_missing_chunks) *out_missing_chunks = missing_c;
    if (out_missing_bytes)  *out_missing_bytes = missing_b;
    return FP_OK;
}
