/* SealFrame — 15-line C Quickstart (links directly to libsealframe.so) */
#include "sealframe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    if (fp_init() != FP_OK) return 1;
    fp_morph_ctx_t *ctx = fp_morph_ctx_new();

    const uint8_t v1[] = "SealFrame v1: immutable DNA, adaptive Delta, atomic State!";
    const uint8_t v2[] = "SealFrame v2: immutable DNA, adaptive Delta, atomic State!";

    /* Encode v2 as a cryptographic DELTA against v1, then materialize & verify */
    uint8_t *wire = NULL, *restored = NULL;
    size_t wire_len = 0, restored_len = 0;
    fp_dna_t dna;

    if (fp_morph_encode(ctx, FP_MORPH_DELTA, v2, sizeof(v2), v1, sizeof(v1), 3, &wire, &wire_len) != FP_OK) return 1;
    if (fp_morph_materialize(ctx, wire, wire_len, v1, sizeof(v1), 1024, &restored, &restored_len, &dna) != FP_OK) return 1;

    char hex[65];
    fp_hex_encode(dna.bytes, FP_DNA_LEN, hex);
    printf("[C Quickstart] OK! dna=%.16s... canonical=%zu B delta_wire=%zu B exact=%d\n",
           hex, restored_len, wire_len, memcmp(restored, v2, sizeof(v2)) == 0);

    free(wire); free(restored); fp_morph_ctx_free(ctx);
    return 0;
}
