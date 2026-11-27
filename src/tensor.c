/*
 * SealFrame (SFT1) — Verified Tensor & KV-Cache Slice Codec + Encrypted Streaming
 *
 * Binary wire format SFT1 (32-byte fixed header + raw contiguous row-major payload):
 *   "SFT1" (4) | dtype (1) | ndim (1: 1..4) | flags (1) | reserved (1)
 *   dims[4] (4 * uint32 BE) | seq_id (uint64 BE) | payload
 *
 * Wire Quantization modes (pure ISO C11, zero F16C/AVX hardware dependency):
 *   - FP_WIRE_CAST_NONE : raw payload [elem_count * elem_size]
 *   - FP_WIRE_CAST_FP16 : IEEE-754 binary16 (-50% wire bytes)
 *   - FP_WIRE_CAST_BF16 : IEEE-754 bfloat16 (-50% wire bytes, full FP32 dynamic range!)
 *   - FP_WIRE_CAST_INT8 : per-tensor symmetric INT8 ([f32 scale (4B LE) | int8[elems]], -75% wire!)
 */
#include "fp.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define SFT1_HDR_LEN   32u
#define SFT1_VALID_FLAGS (FP_TENSOR_FLAG_WIRE_FP16 | FP_TENSOR_FLAG_WIRE_BF16 | \
                          FP_TENSOR_FLAG_WIRE_INT8 | FP_TENSOR_FLAG_WIRE_INT4_G32 | \
                          FP_TENSOR_FLAG_WIRE_INT4_OUTLIER)
#define SFT1_INT4_GROUP_SIZE   32u
#define SFT1_INT4_GROUP_BYTES  18u /* 2B FP16 scale (LE) + 16B packed signed nibbles */
#define SFT1_OUTLIER_ENTRY_LEN 6u  /* uint32 idx (LE) + uint16 FP16 val (LE) */

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

size_t fp_dtype_size(fp_dtype_t dtype) {
    switch (dtype) {
        case FP_DTYPE_FP32:     return 4u;
        case FP_DTYPE_FP16:     return 2u;
        case FP_DTYPE_BF16:     return 2u;
        case FP_DTYPE_INT8:     return 1u;
        case FP_DTYPE_UINT8:    return 1u;
        case FP_DTYPE_INT32:        return 4u;
        case FP_DTYPE_INT4_G32:     return 1u; /* Block-packed: 18 B per 32 elems (see payload calc) */
        case FP_DTYPE_INT4_OUTLIER: return 1u; /* Block-packed + sparse FP16 outliers */
        default:                    return 0u;
    }
}

uint16_t fp_f32_to_f16(float f) {
    uint32_t x = 0;
    memcpy(&x, &f, sizeof(x));
    uint32_t sign = (x >> 16) & 0x8000u;
    uint32_t abs_x = x & 0x7FFFFFFFu;
    if (abs_x >= 0x7F800000u) {
        uint32_t mant = x & 0x007FFFFFu;
        return (uint16_t)(sign | 0x7C00u | (mant ? (0x0200u | (mant >> 13)) : 0u));
    }
    int32_t exp = (int32_t)((x >> 23) & 0xFFu) - 127 + 15;
    uint32_t mant = x & 0x007FFFFFu;
    if (exp <= 0) {
        if (exp < -10) return (uint16_t)sign;
        mant = (mant | 0x00800000u) >> (uint32_t)(1 - exp);
        return (uint16_t)(sign | ((mant + 0x00001000u) >> 13));
    }
    if (exp >= 31) return (uint16_t)(sign | 0x7C00u);
    mant += 0x00001000u;
    if (mant & 0x00800000u) {
        mant = 0;
        exp++;
        if (exp >= 31) return (uint16_t)(sign | 0x7C00u);
    }
    return (uint16_t)(sign | ((uint32_t)exp << 10) | (mant >> 13));
}

float fp_f16_to_f32(uint16_t h) {
    uint32_t sign = ((uint32_t)(h & 0x8000u)) << 16;
    uint32_t exp = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x03FFu;
    uint32_t out = 0;

    if (exp == 0) {
        if (mant == 0) {
            out = sign;
        } else {
            exp = 127u - 14u;
            while ((mant & 0x0400u) == 0) {
                mant <<= 1;
                exp--;
            }
            mant &= 0x03FFu;
            out = sign | (exp << 23) | (mant << 13);
        }
    } else if (exp == 31u) {
        out = sign | 0x7F800000u | (mant << 13);
    } else {
        out = sign | ((exp + (127u - 15u)) << 23) | (mant << 13);
    }

    float f = 0.0f;
    memcpy(&f, &out, sizeof(f));
    return f;
}

uint16_t fp_f32_to_bf16(float f) {
    uint32_t x = 0;
    memcpy(&x, &f, sizeof(x));
    if ((x & 0x7FFFFFFFu) > 0x7F800000u) {
        /* Preserve quiet NaN */
        return (uint16_t)((x >> 16) | 0x0040u);
    }
    if ((x & 0x7FFFFFFFu) == 0x7F800000u) {
        /* Preserve +/-Inf */
        return (uint16_t)(x >> 16);
    }
    uint32_t lsb = (x >> 16) & 1u;
    uint32_t round_bias = 0x7FFFu + lsb;
    return (uint16_t)((x + round_bias) >> 16);
}

float fp_bf16_to_f32(uint16_t b) {
    uint32_t x = ((uint32_t)b) << 16;
    float f = 0.0f;
    memcpy(&f, &x, sizeof(f));
    return f;
}

static fp_err_t compute_elem_count(uint8_t ndim, const uint32_t dims[4], uint64_t *out_elems) {
    if (ndim == 0 || ndim > 4u) return FP_ERR_INVALID;
    uint64_t total = 1u;
    for (uint8_t i = 0; i < ndim; i++) {
        if (dims[i] == 0) return FP_ERR_INVALID;
        if (total > UINT64_MAX / dims[i]) return FP_ERR_BOUNDS;
        total *= dims[i];
    }
    for (uint8_t i = ndim; i < 4u; i++) {
        if (dims[i] != 0) return FP_ERR_INVALID;
    }
    *out_elems = total;
    return FP_OK;
}

fp_err_t fp_tensor_pack_ex(const fp_tensor_meta_t *meta, const void *data, size_t data_len,
                           fp_wire_cast_t wire_cast, uint8_t **out_buf, size_t *out_len) {
    if (!meta || !data || !out_buf || !out_len) return FP_ERR_INVALID;
    *out_buf = NULL;
    *out_len = 0;

    size_t src_esz = fp_dtype_size(meta->dtype);
    if (src_esz == 0) return FP_ERR_INVALID;
    if (wire_cast != FP_WIRE_CAST_NONE && meta->dtype != FP_DTYPE_FP32) return FP_ERR_INVALID;

    uint64_t elems = 0;
    fp_err_t err = compute_elem_count(meta->ndim, meta->dims, &elems);
    if (err != FP_OK) return err;
    if (elems > (uint64_t)SIZE_MAX / src_esz || (size_t)(elems * src_esz) != data_len) {
        return FP_ERR_BOUNDS;
    }

    /* Automatic massive-outlier guard (e.g. Qwen3 / Llama-3 activation spikes > 24x RMS):
     * per-tensor INT8 would quantize normal activations to 0; transparently promote to BF16! */
    if (wire_cast == FP_WIRE_CAST_INT8 && elems >= 32u) {
        const uint8_t *ps = (const uint8_t *)data;
        float amax = 0.0f;
        double sum2 = 0.0;
        for (uint64_t i = 0; i < elems; i++) {
            float f = 0.0f;
            memcpy(&f, ps + (size_t)i * 4u, 4u);
            if (!isfinite(f)) return FP_ERR_INVALID;
            float a = fabsf(f);
            if (a > amax) amax = a;
            sum2 += (double)f * (double)f;
        }
        float rms = (float)sqrt(sum2 / (double)elems);
        if (rms > 1e-8f && amax > rms * 24.0f) {
            wire_cast = FP_WIRE_CAST_BF16;
        }
    }

    fp_dtype_t wire_dtype = meta->dtype;
    uint8_t flags = 0u;
    size_t prefix_bytes = 0u;
    if (wire_cast == FP_WIRE_CAST_FP16) {
        wire_dtype = FP_DTYPE_FP16;
        flags = FP_TENSOR_FLAG_WIRE_FP16;
    } else if (wire_cast == FP_WIRE_CAST_BF16) {
        wire_dtype = FP_DTYPE_BF16;
        flags = FP_TENSOR_FLAG_WIRE_BF16;
    } else if (wire_cast == FP_WIRE_CAST_INT8) {
        wire_dtype = FP_DTYPE_INT8;
        flags = FP_TENSOR_FLAG_WIRE_INT8;
        prefix_bytes = 4u; /* float32 scale (LE) */
    } else if (wire_cast == FP_WIRE_CAST_INT4_G32) {
        wire_dtype = FP_DTYPE_INT4_G32;
        flags = FP_TENSOR_FLAG_WIRE_INT4_G32;
    } else if (wire_cast == FP_WIRE_CAST_INT4_OUTLIER) {
        wire_dtype = FP_DTYPE_INT4_OUTLIER;
        flags = FP_TENSOR_FLAG_WIRE_INT4_OUTLIER;
    } else if (wire_cast != FP_WIRE_CAST_NONE) {
        return FP_ERR_INVALID;
    }

    const uint8_t *src = (const uint8_t *)data;
    uint32_t *out_idxs = NULL;
    uint8_t  *out_mask = NULL;
    uint32_t  out_cnt  = 0u;

    size_t payload_bytes = 0u;
    if (wire_cast == FP_WIRE_CAST_INT4_G32) {
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        if (groups > ((uint64_t)SIZE_MAX - SFT1_HDR_LEN) / SFT1_INT4_GROUP_BYTES) return FP_ERR_BOUNDS;
        payload_bytes = (size_t)(groups * SFT1_INT4_GROUP_BYTES);
    } else if (wire_cast == FP_WIRE_CAST_INT4_OUTLIER) {
        if (elems > (uint64_t)UINT32_MAX) return FP_ERR_BOUNDS;
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        /* Pass 1: validate finiteness & compute RMS for outlier threshold (|x| > 2.8 * RMS) */
        double sum2 = 0.0;
        for (uint64_t i = 0; i < elems; i++) {
            float f = 0.0f;
            memcpy(&f, src + (size_t)i * 4u, 4u);
            if (!isfinite(f)) return FP_ERR_INVALID;
            sum2 += (double)f * (double)f;
        }
        float rms = (elems > 0) ? (float)sqrt(sum2 / (double)elems) : 0.0f;
        float thresh = rms * 2.8f;
        uint32_t max_out = (uint32_t)(elems / 64u); /* Cap at ~1.56% of elements */
        if (max_out < 1u && elems >= 32u) max_out = 1u;
        if (max_out > 0u && thresh > 1e-8f) {
            out_idxs = malloc((size_t)max_out * sizeof(uint32_t));
            out_mask = calloc((size_t)elems, 1u);
            if (!out_idxs || !out_mask) {
                free(out_idxs); free(out_mask);
                return FP_ERR_NOMEM;
            }
            for (uint64_t i = 0; i < elems && out_cnt < max_out; i++) {
                float f = 0.0f;
                memcpy(&f, src + (size_t)i * 4u, 4u);
                if (fabsf(f) > thresh) {
                    out_idxs[out_cnt++] = (uint32_t)i;
                    out_mask[i] = 1u;
                }
            }
        }
        size_t hdr_and_out = 4u + (size_t)out_cnt * SFT1_OUTLIER_ENTRY_LEN;
        if (groups > ((uint64_t)SIZE_MAX - SFT1_HDR_LEN - hdr_and_out) / SFT1_INT4_GROUP_BYTES) {
            free(out_idxs); free(out_mask);
            return FP_ERR_BOUNDS;
        }
        payload_bytes = hdr_and_out + (size_t)(groups * SFT1_INT4_GROUP_BYTES);
    } else {
        size_t wire_esz = fp_dtype_size(wire_dtype);
        if (elems > ((uint64_t)SIZE_MAX - SFT1_HDR_LEN - prefix_bytes) / wire_esz) return FP_ERR_BOUNDS;
        payload_bytes = prefix_bytes + (size_t)(elems * wire_esz);
    }
    size_t total = SFT1_HDR_LEN + payload_bytes;

    uint8_t *buf = malloc(total);
    if (!buf) { free(out_idxs); free(out_mask); return FP_ERR_NOMEM; }

    memcpy(buf, "SFT1", 4);
    buf[4] = (uint8_t)wire_dtype;
    buf[5] = meta->ndim;
    buf[6] = flags;
    buf[7] = 0u;
    for (int i = 0; i < 4; i++) put_be32(buf + 8 + i * 4, meta->dims[i]);
    put_be64(buf + 24, meta->seq_id);

    uint8_t *dst = buf + SFT1_HDR_LEN;
    if (wire_cast == FP_WIRE_CAST_FP16) {
        for (uint64_t i = 0; i < elems; i++) {
            float f = 0.0f;
            memcpy(&f, src + (size_t)i * 4u, 4u);
            uint16_t h = fp_f32_to_f16(f);
            dst[(size_t)i * 2u]     = (uint8_t)(h & 0xFFu);
            dst[(size_t)i * 2u + 1] = (uint8_t)(h >> 8);
        }
    } else if (wire_cast == FP_WIRE_CAST_BF16) {
        for (uint64_t i = 0; i < elems; i++) {
            float f = 0.0f;
            memcpy(&f, src + (size_t)i * 4u, 4u);
            uint16_t b = fp_f32_to_bf16(f);
            dst[(size_t)i * 2u]     = (uint8_t)(b & 0xFFu);
            dst[(size_t)i * 2u + 1] = (uint8_t)(b >> 8);
        }
    } else if (wire_cast == FP_WIRE_CAST_INT8) {
        float amax = 1e-8f;
        for (uint64_t i = 0; i < elems; i++) {
            float f = 0.0f;
            memcpy(&f, src + (size_t)i * 4u, 4u);
            if (!isfinite(f)) { free(buf); return FP_ERR_INVALID; }
            float a = fabsf(f);
            if (a > amax) amax = a;
        }
        float scale = amax / 127.0f;
        float inv = 127.0f / amax;
        uint32_t sbits = 0;
        memcpy(&sbits, &scale, 4u);
        dst[0] = (uint8_t)(sbits & 0xFFu);
        dst[1] = (uint8_t)((sbits >> 8) & 0xFFu);
        dst[2] = (uint8_t)((sbits >> 16) & 0xFFu);
        dst[3] = (uint8_t)((sbits >> 24) & 0xFFu);
        int8_t *qdst = (int8_t *)(dst + 4);
        for (uint64_t i = 0; i < elems; i++) {
            float f = 0.0f;
            memcpy(&f, src + (size_t)i * 4u, 4u);
            long q = lroundf(f * inv);
            if (q < -127) q = -127;
            if (q > 127) q = 127;
            qdst[i] = (int8_t)q;
        }
    } else if (wire_cast == FP_WIRE_CAST_INT4_G32) {
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        for (uint64_t g = 0; g < groups; g++) {
            uint64_t base = g * SFT1_INT4_GROUP_SIZE;
            uint64_t cnt = (base + SFT1_INT4_GROUP_SIZE <= elems)
                               ? SFT1_INT4_GROUP_SIZE : (elems - base);
            float amax = 0.0f;
            for (uint64_t j = 0; j < cnt; j++) {
                float f = 0.0f;
                memcpy(&f, src + (size_t)(base + j) * 4u, 4u);
                if (!isfinite(f)) { free(buf); return FP_ERR_INVALID; }
                float a = fabsf(f);
                if (a > amax) amax = a;
            }
            float scale = (amax > 1e-8f) ? (amax / 7.0f) : 0.0f;
            uint16_t hs = fp_f32_to_f16(scale);
            float rscale = fp_f16_to_f32(hs);
            float inv = (rscale > 0.0f) ? (1.0f / rscale) : 0.0f;

            uint8_t *gdst = dst + (size_t)g * SFT1_INT4_GROUP_BYTES;
            gdst[0] = (uint8_t)(hs & 0xFFu);
            gdst[1] = (uint8_t)(hs >> 8);
            uint8_t *nib = gdst + 2;
            memset(nib, 0x88, 16u); /* 0x88 = pair of encoded zeros (0 + 8) */
            for (uint64_t j = 0; j < cnt; j++) {
                float f = 0.0f;
                memcpy(&f, src + (size_t)(base + j) * 4u, 4u);
                long q = (inv > 0.0f) ? lroundf(f * inv) : 0L;
                if (q < -7) q = -7;
                if (q > 7) q = 7;
                uint8_t enc = (uint8_t)(q + 8);
                if ((j & 1u) == 0u) {
                    nib[j >> 1] = (uint8_t)((nib[j >> 1] & 0xF0u) | (enc & 0x0Fu));
                } else {
                    nib[j >> 1] = (uint8_t)((nib[j >> 1] & 0x0Fu) | (uint8_t)(enc << 4));
                }
            }
        }
    } else if (wire_cast == FP_WIRE_CAST_INT4_OUTLIER) {
        /* Header: uint32_t out_cnt (LE) | entries[out_cnt] (u32 idx + u16 fp16) | INT4_G32 groups */
        dst[0] = (uint8_t)(out_cnt & 0xFFu);
        dst[1] = (uint8_t)((out_cnt >> 8) & 0xFFu);
        dst[2] = (uint8_t)((out_cnt >> 16) & 0xFFu);
        dst[3] = (uint8_t)((out_cnt >> 24) & 0xFFu);
        uint8_t *op = dst + 4;
        for (uint32_t k = 0; k < out_cnt; k++) {
            uint32_t idx = out_idxs[k];
            float f = 0.0f;
            memcpy(&f, src + (size_t)idx * 4u, 4u);
            uint16_t hf = fp_f32_to_f16(f);
            op[0] = (uint8_t)(idx & 0xFFu);
            op[1] = (uint8_t)((idx >> 8) & 0xFFu);
            op[2] = (uint8_t)((idx >> 16) & 0xFFu);
            op[3] = (uint8_t)((idx >> 24) & 0xFFu);
            op[4] = (uint8_t)(hf & 0xFFu);
            op[5] = (uint8_t)(hf >> 8);
            op += SFT1_OUTLIER_ENTRY_LEN;
        }
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        for (uint64_t g = 0; g < groups; g++) {
            uint64_t base = g * SFT1_INT4_GROUP_SIZE;
            uint64_t cnt = (base + SFT1_INT4_GROUP_SIZE <= elems)
                               ? SFT1_INT4_GROUP_SIZE : (elems - base);
            float amax = 0.0f;
            for (uint64_t j = 0; j < cnt; j++) {
                if (out_mask && out_mask[base + j]) continue; /* Exclude outlier from group scale! */
                float f = 0.0f;
                memcpy(&f, src + (size_t)(base + j) * 4u, 4u);
                float a = fabsf(f);
                if (a > amax) amax = a;
            }
            float scale = (amax > 1e-8f) ? (amax / 7.0f) : 0.0f;
            uint16_t hs = fp_f32_to_f16(scale);
            float rscale = fp_f16_to_f32(hs);
            float inv = (rscale > 0.0f) ? (1.0f / rscale) : 0.0f;

            uint8_t *gdst = op + (size_t)g * SFT1_INT4_GROUP_BYTES;
            gdst[0] = (uint8_t)(hs & 0xFFu);
            gdst[1] = (uint8_t)(hs >> 8);
            uint8_t *nib = gdst + 2;
            memset(nib, 0x88, 16u);
            for (uint64_t j = 0; j < cnt; j++) {
                float f = 0.0f;
                if (!(out_mask && out_mask[base + j])) {
                    memcpy(&f, src + (size_t)(base + j) * 4u, 4u);
                }
                long q = (inv > 0.0f) ? lroundf(f * inv) : 0L;
                if (q < -7) q = -7;
                if (q > 7) q = 7;
                uint8_t enc = (uint8_t)(q + 8);
                if ((j & 1u) == 0u) {
                    nib[j >> 1] = (uint8_t)((nib[j >> 1] & 0xF0u) | (enc & 0x0Fu));
                } else {
                    nib[j >> 1] = (uint8_t)((nib[j >> 1] & 0x0Fu) | (uint8_t)(enc << 4));
                }
            }
        }
        free(out_idxs);
        free(out_mask);
    } else {
        memcpy(dst, data, payload_bytes);
    }

    *out_buf = buf;
    *out_len = total;
    return FP_OK;
}

fp_err_t fp_tensor_pack(const fp_tensor_meta_t *meta, const void *data, size_t data_len,
                        int cast_f32_to_f16, uint8_t **out_buf, size_t *out_len) {
    return fp_tensor_pack_ex(meta, data, data_len,
                             cast_f32_to_f16 ? FP_WIRE_CAST_FP16 : FP_WIRE_CAST_NONE,
                             out_buf, out_len);
}

fp_err_t fp_tensor_unpack(const uint8_t *buf, size_t len, int upcast_to_f32,
                          fp_tensor_meta_t *out_meta, uint8_t **out_data, size_t *out_data_len) {
    if (!buf || !out_meta || !out_data || !out_data_len) return FP_ERR_INVALID;
    *out_data = NULL;
    *out_data_len = 0;
    memset(out_meta, 0, sizeof(*out_meta));

    if (len < SFT1_HDR_LEN || memcmp(buf, "SFT1", 4) != 0) return FP_ERR_INVALID;
    fp_dtype_t dtype = (fp_dtype_t)buf[4];
    uint8_t ndim = buf[5];
    uint8_t flags = buf[6];
    uint8_t rsv = buf[7];
    if (rsv != 0 || (flags & ~SFT1_VALID_FLAGS) != 0) return FP_ERR_INVALID;
    /* At most one wire-quantization flag may be set */
    if ((flags & (flags - 1u)) != 0) return FP_ERR_INVALID;
    if ((flags & FP_TENSOR_FLAG_WIRE_FP16) && dtype != FP_DTYPE_FP16) return FP_ERR_INVALID;
    if ((flags & FP_TENSOR_FLAG_WIRE_BF16) && dtype != FP_DTYPE_BF16) return FP_ERR_INVALID;
    if ((flags & FP_TENSOR_FLAG_WIRE_INT8) && dtype != FP_DTYPE_INT8) return FP_ERR_INVALID;
    if ((flags & FP_TENSOR_FLAG_WIRE_INT4_G32) && dtype != FP_DTYPE_INT4_G32) return FP_ERR_INVALID;
    if ((flags & FP_TENSOR_FLAG_WIRE_INT4_OUTLIER) && dtype != FP_DTYPE_INT4_OUTLIER) return FP_ERR_INVALID;

    size_t esz = fp_dtype_size(dtype);
    if (esz == 0) return FP_ERR_INVALID;

    uint32_t dims[4];
    for (int i = 0; i < 4; i++) dims[i] = get_be32(buf + 8 + i * 4);
    uint64_t seq_id = get_be64(buf + 24);

    uint64_t elems = 0;
    fp_err_t err = compute_elem_count(ndim, dims, &elems);
    if (err != FP_OK) return err;

    const uint8_t *src = buf + SFT1_HDR_LEN;
    size_t expected_payload = 0u;
    uint32_t outlier_cnt = 0u;
    if (dtype == FP_DTYPE_INT4_G32) {
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        if (groups > ((uint64_t)SIZE_MAX - SFT1_HDR_LEN) / SFT1_INT4_GROUP_BYTES) return FP_ERR_BOUNDS;
        expected_payload = (size_t)(groups * SFT1_INT4_GROUP_BYTES);
    } else if (dtype == FP_DTYPE_INT4_OUTLIER) {
        if (len < SFT1_HDR_LEN + 4u) return FP_ERR_BOUNDS;
        outlier_cnt = (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
                      ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
        if ((uint64_t)outlier_cnt > elems ||
            (size_t)outlier_cnt > (len - SFT1_HDR_LEN - 4u) / SFT1_OUTLIER_ENTRY_LEN) {
            return FP_ERR_BOUNDS;
        }
        size_t out_bytes_hdr = 4u + (size_t)outlier_cnt * SFT1_OUTLIER_ENTRY_LEN;
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        if (groups > ((uint64_t)SIZE_MAX - SFT1_HDR_LEN - out_bytes_hdr) / SFT1_INT4_GROUP_BYTES) {
            return FP_ERR_BOUNDS;
        }
        expected_payload = out_bytes_hdr + (size_t)(groups * SFT1_INT4_GROUP_BYTES);
    } else {
        size_t prefix_bytes = (flags & FP_TENSOR_FLAG_WIRE_INT8) ? 4u : 0u;
        if (elems > ((uint64_t)SIZE_MAX - SFT1_HDR_LEN - prefix_bytes) / esz) return FP_ERR_BOUNDS;
        expected_payload = prefix_bytes + (size_t)(elems * esz);
    }
    if (len - SFT1_HDR_LEN != expected_payload) return FP_ERR_BOUNDS;

    int do_upcast_f16  = (upcast_to_f32 && dtype == FP_DTYPE_FP16);
    int do_upcast_bf16 = (upcast_to_f32 && dtype == FP_DTYPE_BF16);
    int do_upcast_i8   = (upcast_to_f32 && (flags & FP_TENSOR_FLAG_WIRE_INT8));
    int do_upcast_i4   = (upcast_to_f32 && dtype == FP_DTYPE_INT4_G32);
    int do_upcast_i4o  = (upcast_to_f32 && dtype == FP_DTYPE_INT4_OUTLIER);
    int do_upcast = do_upcast_f16 || do_upcast_bf16 || do_upcast_i8 || do_upcast_i4 || do_upcast_i4o;

    if (do_upcast && elems > (uint64_t)SIZE_MAX / 4u) return FP_ERR_BOUNDS;
    size_t out_bytes = do_upcast ? (size_t)(elems * 4u) : expected_payload;

    float i8_scale = 0.0f;
    if (do_upcast_i8) {
        uint32_t sbits = (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
                         ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
        memcpy(&i8_scale, &sbits, 4u);
        if (!isfinite(i8_scale) || i8_scale < 0.0f) return FP_ERR_INVALID;
    }

    uint8_t *payload = malloc(out_bytes > 0 ? out_bytes : 1u);
    if (!payload) return FP_ERR_NOMEM;

    if (do_upcast_f16) {
        for (uint64_t i = 0; i < elems; i++) {
            uint16_t h = (uint16_t)((uint16_t)src[(size_t)i * 2u] |
                                    ((uint16_t)src[(size_t)i * 2u + 1] << 8));
            float f = fp_f16_to_f32(h);
            memcpy(payload + (size_t)i * 4u, &f, 4u);
        }
        out_meta->dtype = FP_DTYPE_FP32;
    } else if (do_upcast_bf16) {
        for (uint64_t i = 0; i < elems; i++) {
            uint16_t b = (uint16_t)((uint16_t)src[(size_t)i * 2u] |
                                    ((uint16_t)src[(size_t)i * 2u + 1] << 8));
            float f = fp_bf16_to_f32(b);
            memcpy(payload + (size_t)i * 4u, &f, 4u);
        }
        out_meta->dtype = FP_DTYPE_FP32;
    } else if (do_upcast_i8) {
        const int8_t *qsrc = (const int8_t *)(src + 4);
        for (uint64_t i = 0; i < elems; i++) {
            float f = (float)qsrc[i] * i8_scale;
            memcpy(payload + (size_t)i * 4u, &f, 4u);
        }
        out_meta->dtype = FP_DTYPE_FP32;
    } else if (do_upcast_i4) {
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        for (uint64_t g = 0; g < groups; g++) {
            const uint8_t *gsrc = src + (size_t)g * SFT1_INT4_GROUP_BYTES;
            uint16_t hs = (uint16_t)((uint16_t)gsrc[0] | ((uint16_t)gsrc[1] << 8));
            float scale = fp_f16_to_f32(hs);
            if (!isfinite(scale) || scale < 0.0f) { free(payload); return FP_ERR_INVALID; }
            const uint8_t *nib = gsrc + 2;
            uint64_t base = g * SFT1_INT4_GROUP_SIZE;
            uint64_t cnt = (base + SFT1_INT4_GROUP_SIZE <= elems)
                               ? SFT1_INT4_GROUP_SIZE : (elems - base);
            for (uint64_t j = 0; j < cnt; j++) {
                uint8_t b = nib[j >> 1];
                int q = (int)((j & 1u) == 0u ? (b & 0x0Fu) : (b >> 4)) - 8;
                float f = (float)q * scale;
                memcpy(payload + (size_t)(base + j) * 4u, &f, 4u);
            }
        }
        out_meta->dtype = FP_DTYPE_FP32;
    } else if (do_upcast_i4o) {
        const uint8_t *op = src + 4;
        const uint8_t *gbase = op + (size_t)outlier_cnt * SFT1_OUTLIER_ENTRY_LEN;
        uint64_t groups = (elems + SFT1_INT4_GROUP_SIZE - 1u) / SFT1_INT4_GROUP_SIZE;
        for (uint64_t g = 0; g < groups; g++) {
            const uint8_t *gsrc = gbase + (size_t)g * SFT1_INT4_GROUP_BYTES;
            uint16_t hs = (uint16_t)((uint16_t)gsrc[0] | ((uint16_t)gsrc[1] << 8));
            float scale = fp_f16_to_f32(hs);
            if (!isfinite(scale) || scale < 0.0f) { free(payload); return FP_ERR_INVALID; }
            const uint8_t *nib = gsrc + 2;
            uint64_t base = g * SFT1_INT4_GROUP_SIZE;
            uint64_t cnt = (base + SFT1_INT4_GROUP_SIZE <= elems)
                               ? SFT1_INT4_GROUP_SIZE : (elems - base);
            for (uint64_t j = 0; j < cnt; j++) {
                uint8_t b = nib[j >> 1];
                int q = (int)((j & 1u) == 0u ? (b & 0x0Fu) : (b >> 4)) - 8;
                float f = (float)q * scale;
                memcpy(payload + (size_t)(base + j) * 4u, &f, 4u);
            }
        }
        /* Restore exact FP16 outlier channels */
        for (uint32_t k = 0; k < outlier_cnt; k++) {
            const uint8_t *e = op + (size_t)k * SFT1_OUTLIER_ENTRY_LEN;
            uint32_t idx = (uint32_t)e[0] | ((uint32_t)e[1] << 8) |
                           ((uint32_t)e[2] << 16) | ((uint32_t)e[3] << 24);
            uint16_t hf  = (uint16_t)((uint16_t)e[4] | ((uint16_t)e[5] << 8));
            if ((uint64_t)idx >= elems) { free(payload); return FP_ERR_BOUNDS; }
            float fv = fp_f16_to_f32(hf);
            if (!isfinite(fv)) { free(payload); return FP_ERR_INVALID; }
            memcpy(payload + (size_t)idx * 4u, &fv, 4u);
        }
        out_meta->dtype = FP_DTYPE_FP32;
    } else {
        memcpy(payload, src, expected_payload);
        out_meta->dtype = dtype;
    }
    out_meta->ndim = ndim;
    out_meta->flags = flags;
    for (int i = 0; i < 4; i++) out_meta->dims[i] = dims[i];
    out_meta->seq_id = seq_id;

    *out_data = payload;
    *out_data_len = out_bytes;
    return FP_OK;
}

fp_err_t fp_session_send_tensor_ex(fp_session_t *sess, uint8_t tag,
                                   const fp_tensor_meta_t *meta,
                                   const void *data, size_t data_len,
                                   fp_wire_cast_t wire_cast, fp_dna_t *out_dna) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    fp_err_t err = fp_tensor_pack_ex(meta, data, data_len, wire_cast, &wire, &wire_len);
    if (err != FP_OK) return err;
    err = fp_session_send_verified(sess, tag, wire, wire_len, out_dna);
    free(wire);
    return err;
}

fp_err_t fp_session_send_tensor(fp_session_t *sess, uint8_t tag,
                                const fp_tensor_meta_t *meta,
                                const void *data, size_t data_len,
                                int cast_f32_to_f16, fp_dna_t *out_dna) {
    return fp_session_send_tensor_ex(sess, tag, meta, data, data_len,
                                     cast_f32_to_f16 ? FP_WIRE_CAST_FP16 : FP_WIRE_CAST_NONE,
                                     out_dna);
}

fp_err_t fp_session_recv_tensor(fp_session_t *sess, size_t max_bytes,
                                int upcast_to_f32, uint8_t *out_tag,
                                fp_tensor_meta_t *out_meta,
                                uint8_t **out_data, size_t *out_data_len,
                                fp_dna_t *out_dna) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    fp_err_t err = fp_session_recv_verified(sess, max_bytes, out_tag, &wire, &wire_len, out_dna);
    if (err != FP_OK) return err;
    err = fp_tensor_unpack(wire, wire_len, upcast_to_f32, out_meta, out_data, out_data_len);
    free(wire);
    return err;
}

fp_err_t fp_udp_session_send_tensor(fp_udp_session_t *sess, uint8_t tag,
                                    const fp_tensor_meta_t *meta,
                                    const void *data, size_t data_len,
                                    fp_wire_cast_t wire_cast, fp_dna_t *out_dna) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    fp_err_t err = fp_tensor_pack_ex(meta, data, data_len, wire_cast, &wire, &wire_len);
    if (err != FP_OK) return err;
    err = fp_udp_session_send_verified(sess, tag, wire, wire_len, out_dna);
    free(wire);
    return err;
}

fp_err_t fp_udp_session_recv_tensor(fp_udp_session_t *sess, size_t max_bytes,
                                    int upcast_to_f32, uint8_t *out_tag,
                                    fp_tensor_meta_t *out_meta,
                                    uint8_t **out_data, size_t *out_data_len,
                                    fp_dna_t *out_dna) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    fp_err_t err = fp_udp_session_recv_verified(sess, max_bytes, out_tag, &wire, &wire_len, out_dna);
    if (err != FP_OK) return err;
    err = fp_tensor_unpack(wire, wire_len, upcast_to_f32, out_meta, out_data, out_data_len);
    free(wire);
    return err;
}
