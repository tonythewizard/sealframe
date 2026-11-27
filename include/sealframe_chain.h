/*
 * SealFrame Blockchain Anchor & Verifiable Compute Adapters (Pure ISO C11)
 *
 * Implements the chain-agnostic fp_anchor_ops_t interface (include/fp.h) across 4 targets:
 *   1. SF_CHAIN_GENERIC : Standard JSON-RPC 2.0 (any custom L1 / rollup / enterprise ledger)
 *   2. SF_CHAIN_EVM     : Ethereum / Base / Arbitrum / Polygon (real Keccak-256 ABI calldata)
 *   3. SF_CHAIN_SOLANA  : Solana (Anchor SHA-256 discriminator + Borsh + Base58/Base64 + Ed25519)
 *   4. SF_CHAIN_KERYX   : Keryx BlockDAG + OPoI Phase-2 deterministic fixed-point binding
 *
 * Zero Python, zero C++, zero OpenSSL, zero libcurl. Pure ISO C11 + libsodium + POSIX sockets.
 */
#ifndef SEALFRAME_CHAIN_H
#define SEALFRAME_CHAIN_H

#include "fp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SF_CHAIN_GENERIC = 1,
    SF_CHAIN_EVM     = 2,
    SF_CHAIN_SOLANA  = 3,
    SF_CHAIN_KERYX   = 4
} sf_chain_kind_t;

typedef struct {
    sf_chain_kind_t     kind;
    const char         *rpc_url;        /* e.g. "http://127.0.0.1:8545" */
    const char         *contract_addr;  /* EVM 0x..40hex, Solana base58 program/PDA, Keryx address */
    const char         *sender_addr;    /* Optional EVM from-address or Solana fee-payer pubkey */
    const char         *bearer_token;   /* Optional HTTP Authorization Bearer token */
    const fp_keypair_t *signer_kp;      /* Optional Ed25519 keypair (Solana / Keryx / Generic signing) */
    uint64_t            keryx_nonce;    /* Keryx OPoI Phase-2 nonce (0 = auto-derive from commitment) */
    int                 io_timeout_ms;  /* Default: 10000 ms */
} sf_chain_cfg_t;

typedef struct {
    sf_chain_cfg_t cfg;
    char           last_tx_id[160];     /* Last tx hash / signature returned by RPC */
    uint8_t        last_opoi_tag[8];    /* Last Keryx OPoI Phase-2 8-byte tag */
} sf_chain_ctx_t;

/* Initialize a chain adapter context and populate fp_anchor_ops_t (publish + verify). */
fp_err_t sf_chain_adapter_init(sf_chain_ctx_t *ctx, const sf_chain_cfg_t *cfg,
                               fp_anchor_ops_t *out_ops);

/* Submit an Ed25519-signed FPD1 derivation / fraud-proof receipt to the configured chain. */
fp_err_t sf_chain_submit_derivation(sf_chain_ctx_t *ctx, const fp_derivation_t *drv,
                                    const fp_dna_t *expected_result_dna);

/* --- Low-level cryptographic & encoding primitives (exposed for testing & integrators) --- */

/* Ethereum Keccak-256 (original Keccak padding 0x01, NOT NIST SHA3-256 0x06) */
void     sf_keccak256(const uint8_t *data, size_t len, uint8_t out[32]);
void     sf_evm_selector(const char *signature, uint8_t out[4]);

/* Build exact EVM ABI calldata for anchor(bytes32,bytes32,uint64) -> 100 bytes */
void     sf_evm_encode_anchor(const fp_anchor_commitment_t *c, uint8_t out[100]);
/* Build exact EVM ABI calldata for isAnchored(bytes32) -> 36 bytes */
void     sf_evm_encode_is_anchored(const fp_dna_t *commitment, uint8_t out[36]);

/* Solana Anchor 8-byte discriminator + Borsh payload (144 bytes) + Base58/Base64 helpers */
void     sf_solana_encode_anchor_ix(const fp_anchor_commitment_t *c, uint8_t out[144]);
size_t   sf_base58_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);
size_t   sf_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap);

/* Keryx OPoI Phase-2 bit-exact deterministic fixed-point MLP (matches keryx-node opoi.rs) */
void     sf_keryx_opoi_forward_nonce(uint64_t raw_nonce, uint8_t out32[32]);
void     sf_keryx_opoi_tag(uint64_t nonce, uint8_t out8[8], char out_hex16[17]);
/* Build 76-byte Keryx BlockDAG payload: "SF1\0" | commitment(32) | opoi_tag(8) | target_dna(32) */
void     sf_keryx_encode_payload(const fp_anchor_commitment_t *c, uint64_t nonce,
                                 uint8_t out[76], uint8_t out_tag[8]);

/* Pure-C11 RFC 6455 WebSocket wRPC-JSON client for live keryxd (--rpclisten-json ws://host:port) */
fp_err_t sf_keryx_wrpc_call(const char *ws_url, const char *method, const char *params_json,
                            int timeout_ms, char *resp_buf, size_t resp_cap);

#ifdef __cplusplus
}
#endif

#endif /* SEALFRAME_CHAIN_H */
