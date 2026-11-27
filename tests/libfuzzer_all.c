/* Coverage-guided libFuzzer + ASan + UBSan harness covering all SealFrame binary parsers
 * and cryptographic verification entrypoints (EU CRA Annex VII / Phase 3 SDLC evidence).
 *
 * Build & run via:
 *   make libfuzzer                    (default 15s coverage-guided run)
 *   make libfuzzer FUZZ_SECS=3600     (1-hour continuous campaign)
 */

#include "fp.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int g_inited = 0;
static fp_morph_ctx_t *g_mctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_inited) {
        if (fp_init() != FP_OK) return 0;
        g_mctx = fp_morph_ctx_new();
        g_inited = 1;
    }
    if (size < 2u) return 0;

    uint8_t selector = data[0] % 8u;
    const uint8_t *payload = data + 1;
    size_t plen = size - 1u;

    switch (selector) {
        case 0: {
            /* FP01 Morph Wire header + bounded materialization */
            fp_wire_header_t hdr;
            if (fp_wire_parse_header(payload, plen, &hdr) == FP_OK && g_mctx) {
                uint8_t *out = NULL;
                size_t out_len = 0;
                fp_dna_t dna;
                if (fp_morph_materialize(g_mctx, payload, plen, NULL, 0,
                                         256u * 1024u, &out, &out_len, &dna) == FP_OK) {
                    free(out);
                }
            }
            break;
        }
        case 1: {
            /* FPE1 Signed Lineage Event decoder */
            fp_event_t ev;
            (void)fp_event_decode(payload, plen, &ev);
            break;
        }
        case 2: {
            /* FPD1 Signed Derivation decoder */
            fp_derivation_t drv;
            (void)fp_derivation_decode(payload, plen, &drv);
            break;
        }
        case 3: {
            /* FPB1 Composite Particle Bundle decoder */
            fp_bundle_t b;
            (void)fp_bundle_decode(payload, plen, &b);
            break;
        }
        case 4: {
            /* FPR1 Multi-Sig Root Trust document decoder + self-verify */
            fp_root_doc_t root;
            if (fp_root_decode(payload, plen, &root) == FP_OK) {
                (void)fp_root_verify_self(&root, 1700000000ull);
            }
            break;
        }
        case 5: {
            /* FPC1 FastCDC cut + chunk ID + DNA compute */
            (void)fp_fastcdc_cut(payload, plen);
            fp_dna_t id;
            (void)fp_cdc_chunk_id(payload, plen, &id);
            (void)fp_dna_compute(payload, plen, &id);
            break;
        }
        case 6: {
            /* Merkle inclusion proof verifier under arbitrary adversarial proof structs
             * (including UINT64_MAX near-overflow total_size and out-of-bounds depth) */
            if (plen >= sizeof(fp_dna_t) + 20u) {
                fp_dna_t root_dna;
                memcpy(root_dna.bytes, payload, FP_DNA_LEN);
                fp_merkle_proof_t proof;
                memset(&proof, 0, sizeof(proof));
                proof.chunk_index = payload[32];
                if (payload[33] == 0xFFu) {
                    proof.total_size = UINT64_MAX - (uint64_t)payload[34];
                } else {
                    proof.total_size = (uint64_t)payload[33] * 1024u + payload[34];
                }
                proof.depth = payload[35] % (FP_MAX_PROOF_DEPTH + 2u);
                const uint8_t *chunk = payload + 36;
                size_t clen = plen - 36u;
                proof.chunk_len = (uint32_t)clen;
                (void)fp_merkle_verify(&root_dna, &proof, chunk, clen);
            }
            break;
        }
        case 7: {
            /* SFT1 Verified Tensor codec + IEEE-754 FP16 converter */
            if (plen >= 5u) {
                int upcast = payload[0] & 1;
                fp_tensor_meta_t meta;
                uint8_t *out = NULL;
                size_t out_len = 0;
                if (fp_tensor_unpack(payload + 1, plen - 1u, upcast, &meta, &out, &out_len) == FP_OK) {
                    free(out);
                }
                float f = 0.0f;
                memcpy(&f, payload + 1, 4u);
                uint16_t h = fp_f32_to_f16(f);
                volatile float rt = fp_f16_to_f32(h);
                uint16_t b = fp_f32_to_bf16(f);
                volatile float rtb = fp_bf16_to_f32(b);
                (void)rt;
                (void)rtb;
            }
            break;
        }
        default:
            break;
    }
    return 0;
}
