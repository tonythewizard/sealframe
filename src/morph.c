#include "fp.h"

#include <stdlib.h>
#include <string.h>
#include <zstd.h>

#define FP_MAX_SKILLS     32u
#define FP_MAX_WINDOW_LOG 27  /* 128 MiB */

typedef struct {
    uint32_t            skill_id;
    fp_compute_skill_fn fn;
} skill_slot_t;

struct fp_morph_ctx {
    ZSTD_CCtx   *cctx;
    ZSTD_DCtx   *dctx;
    skill_slot_t skills[FP_MAX_SKILLS];
    size_t       skill_count;
};

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

static int compute_window_log(size_t total_bytes) {
    int wlog = 10;
    while (wlog < FP_MAX_WINDOW_LOG && ((size_t)1u << wlog) < total_bytes) {
        wlog++;
    }
    return wlog;
}

static void write_header(uint8_t *dst, fp_morph_kind_t kind, uint8_t flags,
                         uint64_t canonical_size, uint64_t payload_size,
                         const fp_dna_t *dna, const fp_dna_t *ref_dna) {
    memcpy(dst, "FP01", 4);
    dst[4] = (uint8_t)kind;
    dst[5] = flags;
    dst[6] = 0;
    dst[7] = 0;
    put_be64(dst + 8, canonical_size);
    put_be64(dst + 16, payload_size);
    memcpy(dst + 24, dna->bytes, FP_DNA_LEN);
    if (flags & FP_WIRE_FLAG_REF) {
        memcpy(dst + FP_WIRE_HEADER_BASE, ref_dna->bytes, FP_DNA_LEN);
    }
}

fp_morph_ctx_t *fp_morph_ctx_new(void) {
    fp_morph_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    ctx->cctx = ZSTD_createCCtx();
    ctx->dctx = ZSTD_createDCtx();
    if (!ctx->cctx || !ctx->dctx) {
        fp_morph_ctx_free(ctx);
        return NULL;
    }
    return ctx;
}

void fp_morph_ctx_free(fp_morph_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->cctx) ZSTD_freeCCtx(ctx->cctx);
    if (ctx->dctx) ZSTD_freeDCtx(ctx->dctx);
    free(ctx);
}

fp_err_t fp_morph_register_skill(fp_morph_ctx_t *ctx, uint32_t skill_id,
                                 fp_compute_skill_fn fn) {
    if (!ctx || !fn) {
        return FP_ERR_INVALID;
    }
    for (size_t i = 0; i < ctx->skill_count; i++) {
        if (ctx->skills[i].skill_id == skill_id) {
            ctx->skills[i].fn = fn;
            return FP_OK;
        }
    }
    if (ctx->skill_count >= FP_MAX_SKILLS) {
        return FP_ERR_BOUNDS;
    }
    ctx->skills[ctx->skill_count].skill_id = skill_id;
    ctx->skills[ctx->skill_count].fn = fn;
    ctx->skill_count++;
    return FP_OK;
}

static fp_compute_skill_fn find_skill(const fp_morph_ctx_t *ctx, uint32_t skill_id) {
    for (size_t i = 0; i < ctx->skill_count; i++) {
        if (ctx->skills[i].skill_id == skill_id) {
            return ctx->skills[i].fn;
        }
    }
    return NULL;
}

fp_err_t fp_wire_parse_header(const uint8_t *wire, size_t wire_len,
                              fp_wire_header_t *out) {
    if (!wire || !out || wire_len < FP_WIRE_HEADER_BASE) {
        return FP_ERR_INVALID;
    }
    if (memcmp(wire, "FP01", 4) != 0) {
        return FP_ERR_INVALID;
    }
    uint8_t kind = wire[4];
    uint8_t flags = wire[5];
    if (kind > FP_MORPH_COMPUTE || (flags & ~FP_WIRE_FLAG_REF) != 0 ||
        wire[6] != 0 || wire[7] != 0) {
        return FP_ERR_INVALID;
    }
    size_t hdr_size = FP_WIRE_HEADER_BASE + ((flags & FP_WIRE_FLAG_REF) ? FP_DNA_LEN : 0u);
    if (wire_len < hdr_size) {
        return FP_ERR_BOUNDS;
    }

    uint64_t canonical_size = get_be64(wire + 8);
    uint64_t payload_size = get_be64(wire + 16);
    if (payload_size != wire_len - hdr_size) {
        return FP_ERR_BOUNDS;
    }

    memset(out, 0, sizeof(*out));
    out->kind = (fp_morph_kind_t)kind;
    out->flags = flags;
    out->canonical_size = canonical_size;
    out->payload_size = payload_size;
    memcpy(out->dna.bytes, wire + 24, FP_DNA_LEN);
    if (flags & FP_WIRE_FLAG_REF) {
        memcpy(out->ref_dna.bytes, wire + FP_WIRE_HEADER_BASE, FP_DNA_LEN);
    }
    out->header_size = hdr_size;
    return FP_OK;
}

fp_err_t fp_morph_encode(fp_morph_ctx_t *ctx, fp_morph_kind_t kind,
                         const uint8_t *canonical, size_t canonical_len,
                         const uint8_t *ref_data, size_t ref_len,
                         int zstd_level,
                         uint8_t **out_wire, size_t *out_wire_len) {
    if (!ctx || !out_wire || !out_wire_len || (canonical_len > 0 && !canonical)) {
        return FP_ERR_INVALID;
    }
    *out_wire = NULL;
    *out_wire_len = 0;

    fp_dna_t dna;
    fp_err_t err = fp_dna_compute(canonical, canonical_len, &dna);
    if (err != FP_OK) {
        return err;
    }

    if (kind == FP_MORPH_RAW) {
        size_t total = FP_WIRE_HEADER_BASE + canonical_len;
        uint8_t *buf = malloc(total);
        if (!buf) return FP_ERR_NOMEM;
        write_header(buf, FP_MORPH_RAW, 0, canonical_len, canonical_len, &dna, NULL);
        if (canonical_len > 0) {
            memcpy(buf + FP_WIRE_HEADER_BASE, canonical, canonical_len);
        }
        *out_wire = buf;
        *out_wire_len = total;
        return FP_OK;
    }

    if (kind == FP_MORPH_REF) {
        if ((ref_len > 0 && !ref_data) || ref_len != canonical_len) {
            return FP_ERR_MISSING_REF;
        }
        fp_dna_t ref_dna;
        err = fp_dna_compute(ref_data, ref_len, &ref_dna);
        if (err != FP_OK) return err;
        if (!fp_dna_equal(&dna, &ref_dna)) {
            return FP_ERR_MISSING_REF;
        }
        size_t hdr = FP_WIRE_HEADER_BASE + FP_DNA_LEN;
        uint8_t *buf = malloc(hdr);
        if (!buf) return FP_ERR_NOMEM;
        write_header(buf, FP_MORPH_REF, FP_WIRE_FLAG_REF, canonical_len, 0, &dna, &ref_dna);
        *out_wire = buf;
        *out_wire_len = hdr;
        return FP_OK;
    }

    if (kind == FP_MORPH_ZSTD || kind == FP_MORPH_DELTA) {
        if (zstd_level == 0) {
            zstd_level = 3;
        }
        uint8_t flags = 0;
        fp_dna_t ref_dna;
        memset(&ref_dna, 0, sizeof(ref_dna));

        size_t zrc = ZSTD_CCtx_reset(ctx->cctx, ZSTD_reset_session_and_parameters);
        if (ZSTD_isError(zrc)) return FP_ERR_CODEC;
        zrc = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_compressionLevel, zstd_level);
        if (ZSTD_isError(zrc)) return FP_ERR_CODEC;

        if (kind == FP_MORPH_DELTA) {
            if (!ref_data || ref_len == 0) {
                return FP_ERR_MISSING_REF;
            }
            err = fp_dna_compute(ref_data, ref_len, &ref_dna);
            if (err != FP_OK) return err;
            flags = FP_WIRE_FLAG_REF;

            int wlog = compute_window_log(ref_len + canonical_len);
            zrc = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_enableLongDistanceMatching, 1);
            if (ZSTD_isError(zrc)) return FP_ERR_CODEC;
            zrc = ZSTD_CCtx_setParameter(ctx->cctx, ZSTD_c_windowLog, wlog);
            if (ZSTD_isError(zrc)) return FP_ERR_CODEC;
            zrc = ZSTD_CCtx_refPrefix(ctx->cctx, ref_data, ref_len);
            if (ZSTD_isError(zrc)) return FP_ERR_CODEC;
        }

        size_t hdr = FP_WIRE_HEADER_BASE + ((flags & FP_WIRE_FLAG_REF) ? FP_DNA_LEN : 0u);
        size_t bound = ZSTD_compressBound(canonical_len);
        uint8_t *buf = malloc(hdr + bound);
        if (!buf) return FP_ERR_NOMEM;

        size_t csize = ZSTD_compress2(ctx->cctx, buf + hdr, bound, canonical, canonical_len);
        if (ZSTD_isError(csize)) {
            free(buf);
            return FP_ERR_CODEC;
        }

        write_header(buf, kind, flags, canonical_len, csize, &dna, &ref_dna);
        *out_wire = buf;
        *out_wire_len = hdr + csize;
        return FP_OK;
    }

    return FP_ERR_INVALID;
}

fp_err_t fp_morph_encode_compute(fp_morph_ctx_t *ctx,
                                 const uint8_t *canonical, size_t canonical_len,
                                 const uint8_t *ref_data, size_t ref_len,
                                 uint32_t skill_id,
                                 const uint8_t *params, size_t params_len,
                                 uint8_t **out_wire, size_t *out_wire_len) {
    if (!ctx || !out_wire || !out_wire_len || (canonical_len > 0 && !canonical) ||
        (params_len > 0 && !params)) {
        return FP_ERR_INVALID;
    }
    *out_wire = NULL;
    *out_wire_len = 0;

    fp_dna_t dna;
    fp_err_t err = fp_dna_compute(canonical, canonical_len, &dna);
    if (err != FP_OK) return err;

    uint8_t flags = 0;
    fp_dna_t ref_dna;
    memset(&ref_dna, 0, sizeof(ref_dna));
    if (ref_data && ref_len > 0) {
        err = fp_dna_compute(ref_data, ref_len, &ref_dna);
        if (err != FP_OK) return err;
        flags = FP_WIRE_FLAG_REF;
    }

    size_t hdr = FP_WIRE_HEADER_BASE + ((flags & FP_WIRE_FLAG_REF) ? FP_DNA_LEN : 0u);
    size_t payload_len = 4u + params_len;
    uint8_t *buf = malloc(hdr + payload_len);
    if (!buf) return FP_ERR_NOMEM;

    write_header(buf, FP_MORPH_COMPUTE, flags, canonical_len, payload_len, &dna, &ref_dna);
    put_be32(buf + hdr, skill_id);
    if (params_len > 0) {
        memcpy(buf + hdr + 4u, params, params_len);
    }

    /* Fail-closed verification on encode if skill is registered */
    uint8_t *check = NULL;
    size_t check_len = 0;
    fp_dna_t check_dna;
    err = fp_morph_materialize(ctx, buf, hdr + payload_len, ref_data, ref_len,
                               canonical_len, &check, &check_len, &check_dna);
    free(check);
    if (err != FP_OK) {
        free(buf);
        return err;
    }

    *out_wire = buf;
    *out_wire_len = hdr + payload_len;
    return FP_OK;
}

fp_err_t fp_morph_materialize(fp_morph_ctx_t *ctx,
                              const uint8_t *wire, size_t wire_len,
                              const uint8_t *ref_data, size_t ref_len,
                              size_t max_output,
                              uint8_t **out_canonical, size_t *out_len,
                              fp_dna_t *out_dna) {
    if (!ctx || !wire || !out_canonical || !out_len) {
        return FP_ERR_INVALID;
    }
    *out_canonical = NULL;
    *out_len = 0;

    fp_wire_header_t hdr;
    fp_err_t err = fp_wire_parse_header(wire, wire_len, &hdr);
    if (err != FP_OK) return err;

    if (hdr.canonical_size > max_output) {
        return FP_ERR_BOUNDS;
    }

    const uint8_t *payload = wire + hdr.header_size;
    size_t payload_len = (size_t)hdr.payload_size;
    size_t out_sz = (size_t)hdr.canonical_size;

    if (hdr.flags & FP_WIRE_FLAG_REF) {
        if (!ref_data && ref_len > 0) {
            return FP_ERR_MISSING_REF;
        }
        fp_dna_t actual_ref;
        err = fp_dna_compute(ref_data, ref_len, &actual_ref);
        if (err != FP_OK) return err;
        if (!fp_dna_equal(&actual_ref, &hdr.ref_dna)) {
            return FP_ERR_MISSING_REF;
        }
    }

    uint8_t *result = malloc(out_sz > 0 ? out_sz : 1u);
    if (!result) return FP_ERR_NOMEM;

    switch (hdr.kind) {
        case FP_MORPH_RAW:
            if (payload_len != out_sz) {
                free(result);
                return FP_ERR_BOUNDS;
            }
            if (out_sz > 0) {
                memcpy(result, payload, out_sz);
            }
            break;

        case FP_MORPH_REF:
            if (!(hdr.flags & FP_WIRE_FLAG_REF) || payload_len != 0 || ref_len != out_sz) {
                free(result);
                return FP_ERR_MISSING_REF;
            }
            if (out_sz > 0) {
                memcpy(result, ref_data, out_sz);
            }
            break;

        case FP_MORPH_ZSTD:
        case FP_MORPH_DELTA: {
            if (hdr.kind == FP_MORPH_DELTA && !(hdr.flags & FP_WIRE_FLAG_REF)) {
                free(result);
                return FP_ERR_MISSING_REF;
            }
            size_t frame_sz = ZSTD_findFrameCompressedSize(payload, payload_len);
            if (ZSTD_isError(frame_sz) || frame_sz != payload_len) {
                free(result);
                return FP_ERR_CODEC;
            }
            size_t zrc = ZSTD_DCtx_reset(ctx->dctx, ZSTD_reset_session_and_parameters);
            if (ZSTD_isError(zrc)) {
                free(result);
                return FP_ERR_CODEC;
            }
            zrc = ZSTD_DCtx_setParameter(ctx->dctx, ZSTD_d_windowLogMax, FP_MAX_WINDOW_LOG);
            if (ZSTD_isError(zrc)) {
                free(result);
                return FP_ERR_CODEC;
            }
            if (hdr.kind == FP_MORPH_DELTA) {
                zrc = ZSTD_DCtx_refPrefix(ctx->dctx, ref_data, ref_len);
                if (ZSTD_isError(zrc)) {
                    free(result);
                    return FP_ERR_CODEC;
                }
            }
            size_t dsize = ZSTD_decompressDCtx(ctx->dctx, result, out_sz, payload, payload_len);
            if (ZSTD_isError(dsize) || dsize != out_sz) {
                free(result);
                return FP_ERR_CODEC;
            }
            break;
        }

        case FP_MORPH_COMPUTE: {
            if (payload_len < 4u) {
                free(result);
                return FP_ERR_INVALID;
            }
            uint32_t skill_id = get_be32(payload);
            fp_compute_skill_fn fn = find_skill(ctx, skill_id);
            if (!fn) {
                free(result);
                return FP_ERR_POLICY;
            }
            size_t produced = 0;
            err = fn(ref_data, ref_len, payload + 4u, payload_len - 4u,
                     result, out_sz, &produced);
            if (err != FP_OK || produced != out_sz) {
                free(result);
                return err != FP_OK ? err : FP_ERR_INTEGRITY;
            }
            break;
        }

        default:
            free(result);
            return FP_ERR_INVALID;
    }

    /* Universal fail-closed canonical DNA verification */
    fp_dna_t verified;
    err = fp_dna_compute(result, out_sz, &verified);
    if (err != FP_OK || !fp_dna_equal(&verified, &hdr.dna)) {
        free(result);
        return FP_ERR_INTEGRITY;
    }

    *out_canonical = result;
    *out_len = out_sz;
    if (out_dna) {
        *out_dna = verified;
    }
    return FP_OK;
}

fp_err_t fp_morph_materialize_fallback(fp_morph_ctx_t *ctx,
                                       const uint8_t *preferred_wire, size_t preferred_len,
                                       const uint8_t *raw_wire, size_t raw_len,
                                       const uint8_t *ref_data, size_t ref_len,
                                       size_t max_output,
                                       uint8_t **out_canonical, size_t *out_len,
                                       fp_dna_t *out_dna, int *used_fallback) {
    if (used_fallback) *used_fallback = 0;
    fp_wire_header_t pref_hdr, raw_hdr;
    fp_err_t err = fp_wire_parse_header(raw_wire, raw_len, &raw_hdr);
    if (err != FP_OK || raw_hdr.kind != FP_MORPH_RAW || (raw_hdr.flags & FP_WIRE_FLAG_REF)) {
        return FP_ERR_POLICY;
    }
    if (preferred_wire && preferred_len > 0) {
        if (fp_wire_parse_header(preferred_wire, preferred_len, &pref_hdr) == FP_OK &&
            fp_dna_equal(&pref_hdr.dna, &raw_hdr.dna) &&
            pref_hdr.canonical_size == raw_hdr.canonical_size) {
            err = fp_morph_materialize(ctx, preferred_wire, preferred_len,
                                       ref_data, ref_len, max_output,
                                       out_canonical, out_len, out_dna);
            if (err == FP_OK) {
                return FP_OK;
            }
        }
    }
    if (used_fallback) *used_fallback = 1;
    return fp_morph_materialize(ctx, raw_wire, raw_len, NULL, 0, max_output,
                                out_canonical, out_len, out_dna);
}
