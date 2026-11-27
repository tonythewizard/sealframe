#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <blake3.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static uint64_t chunks_for_size(uint64_t sz) {
    return sz == 0 ? 0u : (1u + (sz - 1u) / FP_CHUNK_SIZE);
}

static void put_be32(uint8_t dst[4], uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v);
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

static void hash_leaf(uint64_t index, const uint8_t *chunk, uint32_t len, uint8_t out[FP_DNA_LEN]) {
    static const uint8_t tag[9] = "FP1/LEAF";
    uint8_t meta[12];
    put_be64(meta, index);
    put_be32(meta + 8, len);

    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, meta, sizeof(meta));
    if (len > 0) {
        blake3_hasher_update(&h, chunk, len);
    }
    blake3_hasher_finalize(&h, out, FP_DNA_LEN);
}

static void hash_node(const uint8_t left[FP_DNA_LEN], const uint8_t right[FP_DNA_LEN],
                      uint8_t out[FP_DNA_LEN]) {
    static const uint8_t tag[9] = "FP1/NODE";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, left, FP_DNA_LEN);
    blake3_hasher_update(&h, right, FP_DNA_LEN);
    blake3_hasher_finalize(&h, out, FP_DNA_LEN);
}

static void hash_empty_root(uint8_t out[FP_DNA_LEN]) {
    static const uint8_t tag[10] = "FP1/EMPTY";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_finalize(&h, out, FP_DNA_LEN);
}

static void hash_dna_root(uint64_t total_size, const uint8_t root[FP_DNA_LEN], fp_dna_t *out) {
    static const uint8_t tag[8] = "FP1/DNA";
    uint8_t sz[8];
    put_be64(sz, total_size);

    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, sz, sizeof(sz));
    blake3_hasher_update(&h, root, FP_DNA_LEN);
    blake3_hasher_finalize(&h, out->bytes, FP_DNA_LEN);
}

typedef struct {
    uint8_t hash[FP_DNA_LEN];
    uint8_t level;
} merkle_entry_t;

typedef struct {
    merkle_entry_t stack[FP_MAX_PROOF_DEPTH + 1];
    size_t         top;
    uint64_t       chunks;
    uint64_t       total_size;
} merkle_stream_t;

static void stream_init(merkle_stream_t *s) {
    s->top = 0;
    s->chunks = 0;
    s->total_size = 0;
}

static fp_err_t stream_push(merkle_stream_t *s, const uint8_t *chunk, uint32_t len) {
    if (s->top >= FP_MAX_PROOF_DEPTH) {
        return FP_ERR_BOUNDS;
    }
    uint8_t cur[FP_DNA_LEN];
    hash_leaf(s->chunks, chunk, len, cur);
    uint8_t lvl = 0;

    while (s->top > 0 && s->stack[s->top - 1].level == lvl) {
        uint8_t combined[FP_DNA_LEN];
        hash_node(s->stack[s->top - 1].hash, cur, combined);
        memcpy(cur, combined, FP_DNA_LEN);
        s->top--;
        lvl++;
    }
    memcpy(s->stack[s->top].hash, cur, FP_DNA_LEN);
    s->stack[s->top].level = lvl;
    s->top++;
    s->chunks++;
    s->total_size += len;
    return FP_OK;
}

static void stream_finish(merkle_stream_t *s, fp_dna_t *out_dna) {
    uint8_t root[FP_DNA_LEN];
    if (s->top == 0) {
        hash_empty_root(root);
    } else {
        memcpy(root, s->stack[s->top - 1].hash, FP_DNA_LEN);
        for (size_t i = s->top - 1; i > 0; i--) {
            uint8_t combined[FP_DNA_LEN];
            hash_node(s->stack[i - 1].hash, root, combined);
            memcpy(root, combined, FP_DNA_LEN);
        }
    }
    hash_dna_root(s->total_size, root, out_dna);
}

static uint64_t largest_pow2_lt(uint64_t n) {
    uint64_t p = 1;
    while (p < n && (p << 1) < n) {
        p <<= 1;
    }
    return p;
}

static void subtree_root_and_proof(const uint8_t *data, size_t len,
                                   uint64_t lo, uint64_t hi,
                                   uint64_t target, int collect,
                                   fp_merkle_proof_t *proof,
                                   uint8_t out_hash[FP_DNA_LEN]) {
    uint64_t count = hi - lo;
    if (count == 1) {
        size_t offset = (size_t)(lo * (uint64_t)FP_CHUNK_SIZE);
        size_t rem = len - offset;
        uint32_t clen = (uint32_t)(rem > FP_CHUNK_SIZE ? FP_CHUNK_SIZE : rem);
        hash_leaf(lo, data + offset, clen, out_hash);
        if (collect && proof) {
            proof->chunk_len = clen;
        }
        return;
    }

    uint64_t split = lo + largest_pow2_lt(count);
    uint8_t left[FP_DNA_LEN];
    uint8_t right[FP_DNA_LEN];

    if (collect && target < split) {
        subtree_root_and_proof(data, len, lo, split, target, 1, proof, left);
        subtree_root_and_proof(data, len, split, hi, target, 0, NULL, right);
        if (proof && proof->depth < FP_MAX_PROOF_DEPTH) {
            memcpy(proof->siblings[proof->depth], right, FP_DNA_LEN);
            proof->is_right[proof->depth] = 1;
            proof->depth++;
        }
    } else if (collect && target >= split) {
        subtree_root_and_proof(data, len, lo, split, target, 0, NULL, left);
        subtree_root_and_proof(data, len, split, hi, target, 1, proof, right);
        if (proof && proof->depth < FP_MAX_PROOF_DEPTH) {
            memcpy(proof->siblings[proof->depth], left, FP_DNA_LEN);
            proof->is_right[proof->depth] = 0;
            proof->depth++;
        }
    } else {
        subtree_root_and_proof(data, len, lo, split, target, 0, NULL, left);
        subtree_root_and_proof(data, len, split, hi, target, 0, NULL, right);
    }

    hash_node(left, right, out_hash);
}

fp_err_t fp_init(void) {
    if (sodium_init() < 0) {
        return FP_ERR_INVALID;
    }
    return FP_OK;
}

const char *fp_strerror(fp_err_t err) {
    switch (err) {
        case FP_OK:              return "ok";
        case FP_ERR_INVALID:     return "invalid argument";
        case FP_ERR_NOMEM:       return "out of memory";
        case FP_ERR_BOUNDS:      return "bounds exceeded";
        case FP_ERR_INTEGRITY:   return "canonical DNA integrity mismatch";
        case FP_ERR_SIGNATURE:   return "cryptographic signature rejected";
        case FP_ERR_MISSING_REF: return "required reference atom missing or mismatched";
        case FP_ERR_EXPIRED:     return "event expired (anti-freeze check)";
        case FP_ERR_CHAIN:       return "event chain gap, replay, or equivocation";
        case FP_ERR_REVOKED:     return "target DNA is revoked";
        case FP_ERR_POLICY:      return "policy or authorization violation";
        case FP_ERR_CODEC:       return "morph codec failure";
        case FP_ERR_IO:          return "filesystem or I/O error";
        case FP_ERR_NOT_FOUND:   return "object or state not found";
        default:                 return "unknown error";
    }
}

int fp_dna_equal(const fp_dna_t *a, const fp_dna_t *b) {
    if (!a || !b) {
        return 0;
    }
    return sodium_memcmp(a->bytes, b->bytes, FP_DNA_LEN) == 0;
}

int fp_dna_is_zero(const fp_dna_t *a) {
    if (!a) {
        return 0;
    }
    return sodium_is_zero(a->bytes, FP_DNA_LEN) == 1;
}

void fp_hex_encode(const uint8_t *in, size_t len, char *out_hex) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2]     = hex[(in[i] >> 4) & 0x0Fu];
        out_hex[i * 2 + 1] = hex[in[i] & 0x0Fu];
    }
    out_hex[len * 2] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

fp_err_t fp_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || !out) {
        return FP_ERR_INVALID;
    }
    if (strlen(hex) != out_len * 2) {
        return FP_ERR_INVALID;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return FP_ERR_INVALID;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return FP_OK;
}

fp_err_t fp_dna_compute(const uint8_t *data, size_t len, fp_dna_t *out_dna) {
    if (!out_dna || (len > 0 && !data)) {
        return FP_ERR_INVALID;
    }
    fp_dna_stream_t st;
    fp_dna_stream_init(&st);
    fp_err_t err = fp_dna_stream_update(&st, data, len);
    if (err != FP_OK) return err;
    return fp_dna_stream_finish(&st, out_dna, NULL);
}

void fp_dna_stream_init(fp_dna_stream_t *st) {
    memset(st, 0, sizeof(*st));
}

static fp_err_t dna_stream_push_chunk(fp_dna_stream_t *st, const uint8_t *chunk, uint32_t len) {
    if (st->stack_top >= FP_MAX_PROOF_DEPTH) {
        return FP_ERR_BOUNDS;
    }
    uint8_t cur[FP_DNA_LEN];
    hash_leaf(st->chunks, chunk, len, cur);
    uint8_t lvl = 0;

    while (st->stack_top > 0 && st->stack_level[st->stack_top - 1] == lvl) {
        uint8_t combined[FP_DNA_LEN];
        hash_node(st->stack_hash[st->stack_top - 1], cur, combined);
        memcpy(cur, combined, FP_DNA_LEN);
        st->stack_top--;
        lvl++;
    }
    memcpy(st->stack_hash[st->stack_top], cur, FP_DNA_LEN);
    st->stack_level[st->stack_top] = lvl;
    st->stack_top++;
    st->chunks++;
    st->total_size += len;
    return FP_OK;
}

fp_err_t fp_dna_stream_update(fp_dna_stream_t *st, const uint8_t *data, size_t len) {
    if (!st || (len > 0 && !data)) return FP_ERR_INVALID;
    size_t pos = 0;
    if (st->partial_len > 0) {
        size_t need = FP_CHUNK_SIZE - st->partial_len;
        size_t take = len < need ? len : need;
        memcpy(st->partial + st->partial_len, data, take);
        st->partial_len += take;
        pos += take;
        if (st->partial_len == FP_CHUNK_SIZE) {
            fp_err_t err = dna_stream_push_chunk(st, st->partial, FP_CHUNK_SIZE);
            if (err != FP_OK) return err;
            st->partial_len = 0;
        }
    }
    while (len - pos >= FP_CHUNK_SIZE) {
        fp_err_t err = dna_stream_push_chunk(st, data + pos, FP_CHUNK_SIZE);
        if (err != FP_OK) return err;
        pos += FP_CHUNK_SIZE;
    }
    if (pos < len) {
        size_t rem = len - pos;
        memcpy(st->partial, data + pos, rem);
        st->partial_len = rem;
    }
    return FP_OK;
}

fp_err_t fp_dna_stream_finish(fp_dna_stream_t *st, fp_dna_t *out_dna, uint64_t *out_size) {
    if (!st || !out_dna) return FP_ERR_INVALID;
    if (st->partial_len > 0) {
        fp_err_t err = dna_stream_push_chunk(st, st->partial, (uint32_t)st->partial_len);
        if (err != FP_OK) return err;
        st->partial_len = 0;
    }
    uint8_t root[FP_DNA_LEN];
    if (st->stack_top == 0) {
        hash_empty_root(root);
    } else {
        memcpy(root, st->stack_hash[st->stack_top - 1], FP_DNA_LEN);
        for (size_t i = st->stack_top - 1; i > 0; i--) {
            uint8_t combined[FP_DNA_LEN];
            hash_node(st->stack_hash[i - 1], root, combined);
            memcpy(root, combined, FP_DNA_LEN);
        }
    }
    hash_dna_root(st->total_size, root, out_dna);
    if (out_size) *out_size = st->total_size;
    return FP_OK;
}

fp_err_t fp_dna_compute_file(const char *path, fp_dna_t *out_dna, uint64_t *out_size) {
    if (!path || !out_dna) {
        return FP_ERR_INVALID;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        return FP_ERR_IO;
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(f);
        return FP_ERR_IO;
    }
    uint8_t buf[FP_CHUNK_SIZE];
    merkle_stream_t s;
    stream_init(&s);

    for (;;) {
        size_t got = fread(buf, 1, sizeof(buf), f);
        if (got > 0) {
            fp_err_t err = stream_push(&s, buf, (uint32_t)got);
            if (err != FP_OK) {
                fclose(f);
                return err;
            }
        }
        if (got < sizeof(buf)) {
            if (ferror(f)) {
                fclose(f);
                return FP_ERR_IO;
            }
            break;
        }
    }
    fclose(f);
    stream_finish(&s, out_dna);
    if (out_size) {
        *out_size = s.total_size;
    }
    return FP_OK;
}

typedef struct {
    uint8_t  hash[FP_DNA_LEN];
    uint32_t left;
    uint32_t right;
} mnode_t;

struct fp_merkle_tree {
    uint64_t total_size;
    uint64_t nchunks;
    fp_dna_t dna;
    uint32_t used;
    uint32_t cap;
    mnode_t *nodes;
};

static uint32_t build_tree_rec(fp_merkle_tree_t *t, const uint8_t *data, size_t len,
                               uint64_t lo, uint64_t hi) {
    uint32_t id = t->used++;
    uint64_t count = hi - lo;
    if (count == 1) {
        size_t off = (size_t)(lo * (uint64_t)FP_CHUNK_SIZE);
        size_t rem = len - off;
        uint32_t clen = (uint32_t)(rem > FP_CHUNK_SIZE ? FP_CHUNK_SIZE : rem);
        hash_leaf(lo, data + off, clen, t->nodes[id].hash);
        t->nodes[id].left = UINT32_MAX;
        t->nodes[id].right = UINT32_MAX;
        return id;
    }
    uint64_t split = lo + largest_pow2_lt(count);
    uint32_t l = build_tree_rec(t, data, len, lo, split);
    uint32_t r = build_tree_rec(t, data, len, split, hi);
    t->nodes[id].left = l;
    t->nodes[id].right = r;
    hash_node(t->nodes[l].hash, t->nodes[r].hash, t->nodes[id].hash);
    return id;
}

fp_merkle_tree_t *fp_merkle_tree_build(const uint8_t *data, size_t len) {
    if (len == 0 || !data) return NULL;
    uint64_t nchunks = chunks_for_size((uint64_t)len);
    if (nchunks > (UINT32_MAX / 2u)) return NULL;
    uint32_t cap = (uint32_t)(2u * nchunks - 1u);

    fp_merkle_tree_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->nodes = malloc((size_t)cap * sizeof(mnode_t));
    if (!t->nodes) { free(t); return NULL; }
    t->total_size = (uint64_t)len;
    t->nchunks = nchunks;
    t->cap = cap;
    t->used = 0;

    build_tree_rec(t, data, len, 0, nchunks);
    hash_dna_root(t->total_size, t->nodes[0].hash, &t->dna);
    return t;
}

static uint32_t build_tree_from_leaves(fp_merkle_tree_t *t,
                                       const uint8_t *leaves_flat,
                                       uint64_t lo, uint64_t hi) {
    uint32_t id = t->used++;
    uint64_t count = hi - lo;
    if (count == 1) {
        memcpy(t->nodes[id].hash, leaves_flat + (size_t)lo * FP_DNA_LEN, FP_DNA_LEN);
        t->nodes[id].left = UINT32_MAX;
        t->nodes[id].right = UINT32_MAX;
        return id;
    }
    uint64_t split = lo + largest_pow2_lt(count);
    uint32_t l = build_tree_from_leaves(t, leaves_flat, lo, split);
    uint32_t r = build_tree_from_leaves(t, leaves_flat, split, hi);
    t->nodes[id].left = l;
    t->nodes[id].right = r;
    hash_node(t->nodes[l].hash, t->nodes[r].hash, t->nodes[id].hash);
    return id;
}

fp_merkle_tree_t *fp_merkle_tree_build_file(const char *path, uint64_t *out_size) {
    if (!path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        fclose(f);
        return NULL;
    }

    uint64_t total_size = (uint64_t)st.st_size;
    uint64_t nchunks = chunks_for_size(total_size);
    if (nchunks > (UINT32_MAX / 2u)) { fclose(f); return NULL; }

    uint8_t *leaves = malloc((size_t)nchunks * FP_DNA_LEN);
    if (!leaves) { fclose(f); return NULL; }

    /* Stream file in a single fixed 16 KiB stack buffer (zero file-size malloc!) */
    uint8_t chunk_buf[FP_CHUNK_SIZE];
    uint64_t ci = 0;
    uint64_t read_total = 0;
    for (; ci < nchunks; ci++) {
        size_t want = (total_size - read_total > FP_CHUNK_SIZE)
            ? FP_CHUNK_SIZE : (size_t)(total_size - read_total);
        if (fread(chunk_buf, 1, want, f) != want) {
            free(leaves);
            fclose(f);
            return NULL;
        }
        hash_leaf(ci, chunk_buf, (uint32_t)want, leaves + (size_t)ci * FP_DNA_LEN);
        read_total += want;
    }
    fclose(f);

    uint32_t cap = (uint32_t)(2u * nchunks - 1u);
    fp_merkle_tree_t *t = calloc(1, sizeof(*t));
    if (!t) { free(leaves); return NULL; }
    t->nodes = malloc((size_t)cap * sizeof(mnode_t));
    if (!t->nodes) { free(t); free(leaves); return NULL; }
    t->total_size = total_size;
    t->nchunks = nchunks;
    t->cap = cap;
    t->used = 0;

    build_tree_from_leaves(t, leaves, 0, nchunks);
    free(leaves);
    hash_dna_root(t->total_size, t->nodes[0].hash, &t->dna);
    if (out_size) *out_size = total_size;
    return t;
}

fp_dna_t fp_merkle_tree_dna(const fp_merkle_tree_t *tree) {
    fp_dna_t z;
    memset(&z, 0, sizeof(z));
    return tree ? tree->dna : z;
}

void fp_merkle_tree_free(fp_merkle_tree_t *tree) {
    if (!tree) return;
    free(tree->nodes);
    free(tree);
}

fp_err_t fp_merkle_tree_prove(const fp_merkle_tree_t *tree, uint64_t chunk_index,
                              fp_merkle_proof_t *out_proof) {
    if (!tree || !out_proof) return FP_ERR_INVALID;
    if (chunk_index >= tree->nchunks) return FP_ERR_BOUNDS;

    uint8_t tmp_sib[FP_MAX_PROOF_DEPTH][FP_DNA_LEN];
    uint8_t tmp_right[FP_MAX_PROOF_DEPTH];
    uint32_t depth = 0;

    uint32_t cur = 0;
    uint64_t lo = 0, hi = tree->nchunks;
    while (hi - lo > 1) {
        if (depth >= FP_MAX_PROOF_DEPTH) return FP_ERR_BOUNDS;
        uint64_t split = lo + largest_pow2_lt(hi - lo);
        if (chunk_index < split) {
            memcpy(tmp_sib[depth], tree->nodes[tree->nodes[cur].right].hash, FP_DNA_LEN);
            tmp_right[depth] = 1;
            cur = tree->nodes[cur].left;
            hi = split;
        } else {
            memcpy(tmp_sib[depth], tree->nodes[tree->nodes[cur].left].hash, FP_DNA_LEN);
            tmp_right[depth] = 0;
            cur = tree->nodes[cur].right;
            lo = split;
        }
        depth++;
    }

    memset(out_proof, 0, sizeof(*out_proof));
    out_proof->chunk_index = chunk_index;
    out_proof->total_size = tree->total_size;
    uint64_t off = chunk_index * FP_CHUNK_SIZE;
    uint64_t rem = tree->total_size - off;
    out_proof->chunk_len = (uint32_t)(rem > FP_CHUNK_SIZE ? FP_CHUNK_SIZE : rem);
    out_proof->depth = depth;
    /* Reverse root-to-leaf stack into leaf-to-root order */
    for (uint32_t i = 0; i < depth; i++) {
        memcpy(out_proof->siblings[i], tmp_sib[depth - 1u - i], FP_DNA_LEN);
        out_proof->is_right[i] = tmp_right[depth - 1u - i];
    }
    return FP_OK;
}

fp_err_t fp_merkle_prove(const uint8_t *data, size_t len, uint64_t chunk_index,
                         fp_merkle_proof_t *out_proof, fp_dna_t *out_dna) {
    if (!out_proof || (len > 0 && !data)) {
        return FP_ERR_INVALID;
    }
    if (len == 0) {
        return FP_ERR_BOUNDS;
    }
    uint64_t nchunks = chunks_for_size((uint64_t)len);
    if (chunk_index >= nchunks) {
        return FP_ERR_BOUNDS;
    }
    memset(out_proof, 0, sizeof(*out_proof));
    out_proof->chunk_index = chunk_index;
    out_proof->total_size = (uint64_t)len;

    uint8_t root[FP_DNA_LEN];
    subtree_root_and_proof(data, len, 0, nchunks, chunk_index, 1, out_proof, root);
    if (out_dna) {
        hash_dna_root((uint64_t)len, root, out_dna);
    }
    return FP_OK;
}

fp_err_t fp_merkle_verify(const fp_dna_t *expected_dna, const fp_merkle_proof_t *proof,
                          const uint8_t *chunk_data, size_t chunk_len) {
    if (!expected_dna || !proof || (!chunk_data && chunk_len > 0)) {
        return FP_ERR_INVALID;
    }
    if (proof->total_size == 0 || proof->depth > FP_MAX_PROOF_DEPTH) {
        return FP_ERR_BOUNDS;
    }
    if (chunk_len != proof->chunk_len || chunk_len == 0 || chunk_len > FP_CHUNK_SIZE) {
        return FP_ERR_BOUNDS;
    }
    uint64_t nchunks = chunks_for_size(proof->total_size);
    if (proof->chunk_index >= nchunks) {
        return FP_ERR_BOUNDS;
    }
    uint64_t expected_len = (proof->chunk_index + 1u == nchunks)
        ? (proof->total_size - proof->chunk_index * FP_CHUNK_SIZE)
        : FP_CHUNK_SIZE;
    if (chunk_len != expected_len) {
        return FP_ERR_INTEGRITY;
    }

    uint8_t cur[FP_DNA_LEN];
    hash_leaf(proof->chunk_index, chunk_data, (uint32_t)chunk_len, cur);
    for (uint32_t i = 0; i < proof->depth; i++) {
        uint8_t next[FP_DNA_LEN];
        if (proof->is_right[i]) {
            hash_node(cur, proof->siblings[i], next);
        } else {
            hash_node(proof->siblings[i], cur, next);
        }
        memcpy(cur, next, FP_DNA_LEN);
    }

    fp_dna_t computed;
    hash_dna_root(proof->total_size, cur, &computed);
    return fp_dna_equal(&computed, expected_dna) ? FP_OK : FP_ERR_INTEGRITY;
}
