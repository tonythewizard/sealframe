#ifndef FP_H
#define FP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FP_VERSION_MAJOR    0
#define FP_VERSION_MINOR    5
#define FP_DNA_LEN          32u
#define FP_PK_LEN           32u
#define FP_SK_LEN           64u
#define FP_SIG_LEN          64u
#define FP_CHUNK_SIZE       16384u
#define FP_MAX_PROOF_DEPTH  64u
#define FP_MAX_REASON       128u
#define FP_MAX_HISTORY      1024u
#define FP_WIRE_HEADER_BASE 56u
#define FP_WIRE_FLAG_REF    0x01u

typedef enum {
    FP_OK              = 0,
    FP_ERR_INVALID     = -1,
    FP_ERR_NOMEM       = -2,
    FP_ERR_BOUNDS      = -3,
    FP_ERR_INTEGRITY   = -4,
    FP_ERR_SIGNATURE   = -5,
    FP_ERR_MISSING_REF = -6,
    FP_ERR_EXPIRED     = -7,
    FP_ERR_CHAIN       = -8,
    FP_ERR_REVOKED     = -9,
    FP_ERR_POLICY      = -10,
    FP_ERR_CODEC       = -11,
    FP_ERR_IO          = -12,
    FP_ERR_NOT_FOUND   = -13
} fp_err_t;

typedef struct {
    uint8_t bytes[FP_DNA_LEN];
} fp_dna_t;

typedef struct {
    uint8_t pk[FP_PK_LEN];
    uint8_t sk[FP_SK_LEN];
} fp_keypair_t;

/* --- Initialization & Utilities --- */

fp_err_t    fp_init(void);
const char *fp_strerror(fp_err_t err);
int         fp_dna_equal(const fp_dna_t *a, const fp_dna_t *b);
int         fp_dna_is_zero(const fp_dna_t *a);
void        fp_hex_encode(const uint8_t *in, size_t len, char *out_hex);
fp_err_t    fp_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/* --- Law 1: DNA & Merkle Verified Streaming (16 KiB chunks, BLAKE3) --- */

typedef struct {
    uint64_t chunk_index;
    uint64_t total_size;
    uint32_t chunk_len;
    uint32_t depth;
    uint8_t  siblings[FP_MAX_PROOF_DEPTH][FP_DNA_LEN];
    uint8_t  is_right[FP_MAX_PROOF_DEPTH];
} fp_merkle_proof_t;

typedef struct fp_merkle_tree fp_merkle_tree_t;

typedef struct {
    uint8_t  stack_hash[FP_MAX_PROOF_DEPTH + 1][FP_DNA_LEN];
    uint8_t  stack_level[FP_MAX_PROOF_DEPTH + 1];
    size_t   stack_top;
    uint64_t chunks;
    uint64_t total_size;
    uint8_t  partial[FP_CHUNK_SIZE];
    size_t   partial_len;
} fp_dna_stream_t;

void     fp_dna_stream_init(fp_dna_stream_t *st);
fp_err_t fp_dna_stream_update(fp_dna_stream_t *st, const uint8_t *data, size_t len);
fp_err_t fp_dna_stream_finish(fp_dna_stream_t *st, fp_dna_t *out_dna, uint64_t *out_size);

fp_err_t fp_dna_compute(const uint8_t *data, size_t len, fp_dna_t *out_dna);
fp_err_t fp_dna_compute_file(const char *path, fp_dna_t *out_dna, uint64_t *out_size);
fp_merkle_tree_t *fp_merkle_tree_build(const uint8_t *data, size_t len);
fp_merkle_tree_t *fp_merkle_tree_build_file(const char *path, uint64_t *out_size);
fp_dna_t fp_merkle_tree_dna(const fp_merkle_tree_t *tree);
void     fp_merkle_tree_free(fp_merkle_tree_t *tree);
fp_err_t fp_merkle_tree_prove(const fp_merkle_tree_t *tree, uint64_t chunk_index,
                              fp_merkle_proof_t *out_proof);
fp_err_t fp_merkle_prove(const uint8_t *data, size_t len, uint64_t chunk_index,
                         fp_merkle_proof_t *out_proof, fp_dna_t *out_dna);
fp_err_t fp_merkle_verify(const fp_dna_t *expected_dna, const fp_merkle_proof_t *proof,
                          const uint8_t *chunk_data, size_t chunk_len);

/* --- Law 2: Morph Engine (RAW, ZSTD, DELTA, REF, COMPUTE) --- */

typedef enum {
    FP_MORPH_RAW     = 0,
    FP_MORPH_ZSTD    = 1,
    FP_MORPH_DELTA   = 2,
    FP_MORPH_REF     = 3,
    FP_MORPH_COMPUTE = 4
} fp_morph_kind_t;

typedef struct fp_morph_ctx fp_morph_ctx_t;

typedef fp_err_t (*fp_compute_skill_fn)(
    const uint8_t *ref_data, size_t ref_len,
    const uint8_t *params, size_t params_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

typedef struct {
    fp_morph_kind_t kind;
    uint8_t         flags;
    uint64_t        canonical_size;
    uint64_t        payload_size;
    fp_dna_t        dna;
    fp_dna_t        ref_dna;
    size_t          header_size;
} fp_wire_header_t;

fp_morph_ctx_t *fp_morph_ctx_new(void);
void            fp_morph_ctx_free(fp_morph_ctx_t *ctx);
fp_err_t        fp_morph_register_skill(fp_morph_ctx_t *ctx, uint32_t skill_id,
                                        fp_compute_skill_fn fn);
fp_err_t        fp_wire_parse_header(const uint8_t *wire, size_t wire_len,
                                     fp_wire_header_t *out);

fp_err_t fp_morph_encode(fp_morph_ctx_t *ctx, fp_morph_kind_t kind,
                         const uint8_t *canonical, size_t canonical_len,
                         const uint8_t *ref_data, size_t ref_len,
                         int zstd_level,
                         uint8_t **out_wire, size_t *out_wire_len);

fp_err_t fp_morph_encode_compute(fp_morph_ctx_t *ctx,
                                 const uint8_t *canonical, size_t canonical_len,
                                 const uint8_t *ref_data, size_t ref_len,
                                 uint32_t skill_id,
                                 const uint8_t *params, size_t params_len,
                                 uint8_t **out_wire, size_t *out_wire_len);

fp_err_t fp_morph_materialize(fp_morph_ctx_t *ctx,
                              const uint8_t *wire, size_t wire_len,
                              const uint8_t *ref_data, size_t ref_len,
                              size_t max_output,
                              uint8_t **out_canonical, size_t *out_len,
                              fp_dna_t *out_dna);

fp_err_t fp_morph_materialize_fallback(fp_morph_ctx_t *ctx,
                                       const uint8_t *preferred_wire, size_t preferred_len,
                                       const uint8_t *raw_wire, size_t raw_len,
                                       const uint8_t *ref_data, size_t ref_len,
                                       size_t max_output,
                                       uint8_t **out_canonical, size_t *out_len,
                                       fp_dna_t *out_dna, int *used_fallback);

/* --- Law 3: Lineage (Signed Events, Anti-Freeze, Derivations) --- */

typedef enum {
    FP_ACTION_INSTALL  = 1,
    FP_ACTION_ROLLBACK = 2,
    FP_ACTION_REVOKE   = 3
} fp_action_t;

typedef struct {
    uint16_t    version;
    fp_action_t action;
    fp_dna_t    repo_id;
    uint64_t    serial;
    fp_dna_t    prev_event_hash;
    uint64_t    timestamp_unix;
    uint64_t    expires_unix;
    fp_dna_t    target_dna;
    uint64_t    target_size;
    uint8_t     signer_pk[FP_PK_LEN];
    char        reason[FP_MAX_REASON];
    uint8_t     sig[FP_SIG_LEN];
    fp_dna_t    event_hash;
} fp_event_t;

typedef struct {
    uint16_t version;
    fp_dna_t parent_dna;
    fp_dna_t op_dna;
    fp_dna_t result_dna;
    uint64_t result_size;
    uint64_t timestamp_unix;
    uint8_t  signer_pk[FP_PK_LEN];
    uint8_t  sig[FP_SIG_LEN];
} fp_derivation_t;

fp_err_t fp_keygen(fp_keypair_t *out_kp);
fp_err_t fp_random_id(fp_dna_t *out_id);

fp_err_t fp_event_sign(fp_event_t *ev, const fp_keypair_t *kp);
fp_err_t fp_event_verify(const fp_event_t *ev,
                         const uint8_t expected_pk[FP_PK_LEN],
                         const fp_dna_t *expected_repo,
                         uint64_t now_unix);
fp_err_t fp_event_encode(const fp_event_t *ev, uint8_t **out_buf, size_t *out_len);
fp_err_t fp_event_decode(const uint8_t *buf, size_t len, fp_event_t *out_ev);

fp_err_t fp_derivation_sign(fp_derivation_t *drv, const fp_keypair_t *kp);
fp_err_t fp_derivation_verify(const fp_derivation_t *drv,
                              const uint8_t expected_pk[FP_PK_LEN]);
fp_err_t fp_derivation_encode(const fp_derivation_t *drv, uint8_t **out_buf, size_t *out_len);
fp_err_t fp_derivation_decode(const uint8_t *buf, size_t len, fp_derivation_t *out_drv);

/* --- Atomic Crash-Safe Content-Addressed Store --- */

typedef struct {
    fp_dna_t repo_id;
    uint8_t  signer_pk[FP_PK_LEN];
    uint64_t serial;
    fp_dna_t last_event_hash;
    uint8_t  has_current;
    fp_dna_t current_dna;
    uint32_t installed_count;
    fp_dna_t installed[FP_MAX_HISTORY];
    uint32_t revoked_count;
    fp_dna_t revoked[FP_MAX_HISTORY];
} fp_store_state_t;

fp_err_t fp_store_put_object(const char *root, const uint8_t *data, size_t len,
                             fp_dna_t *out_dna);
fp_err_t fp_store_put_file(const char *root, const char *src_path,
                           fp_dna_t *out_dna, uint64_t *out_size);
fp_err_t fp_store_get_object(const char *root, const fp_dna_t *dna, size_t max_size,
                             uint8_t **out_data, size_t *out_len);
int      fp_store_has_object(const char *root, const fp_dna_t *dna, uint64_t *out_size);
int      fp_store_open_object_fd(const char *root, const fp_dna_t *dna,
                                 char *out_path, size_t out_path_cap, uint64_t *out_size);
fp_err_t fp_store_load_state(const char *root, fp_store_state_t *out_state);
fp_err_t fp_store_apply_event(const char *root, const fp_event_t *ev,
                              const uint8_t expected_pk[FP_PK_LEN],
                              const fp_dna_t *expected_repo,
                              uint64_t now_unix,
                              const uint8_t *payload_data, size_t payload_len);

/* --- M1: FP-NET v1 Encrypted Transport, Autonomous Morph & Merkle Streaming --- */

#define FP_NET_MAX_REFS 8u

typedef enum {
    FP_NET_MODE_REF           = 1, /* 0-byte payload: receiver already owns target_dna */
    FP_NET_MODE_DELTA         = 2, /* Zstd refPrefix+LDM delta against negotiated ref_dna */
    FP_NET_MODE_ZSTD          = 3, /* Single-frame Zstd morph */
    FP_NET_MODE_MERKLE_STREAM = 4  /* Pipelined 16 KiB Merkle verified streaming + resume */
} fp_net_mode_t;

typedef struct {
    const char         *bind_addr;       /* e.g. "127.0.0.1" or "0.0.0.0" */
    uint16_t            port;            /* 0 = ephemeral port */
    const char         *store_dir;       /* Store root serving objects */
    const fp_keypair_t *server_kp;       /* Server static Ed25519 identity */
    const uint8_t      *allowed_peer_pk; /* Optional 32B client pin (NULL = any authenticated) */
    uint32_t            max_requests;    /* 0 = serve forever */
    int                 io_timeout_ms;   /* 0 = default (10000 ms) */
    uint64_t            fault_drop_after_chunks; /* Test hook: drop TCP after N chunks (0 = off) */
    uint64_t            fault_corrupt_chunk;     /* Test hook: flip 1 bit in chunk N+1 (0 = off) */
} fp_net_server_cfg_t;

typedef struct {
    const char         *host;            /* Server IPv4/hostname */
    uint16_t            port;            /* Server port */
    const char         *store_dir;       /* Local Store root */
    const fp_keypair_t *client_kp;       /* Client static Ed25519 identity */
    const uint8_t      *expected_srv_pk; /* Required 32B pinned server Ed25519 pubkey */
    fp_dna_t            target_dna;      /* Desired canonical DNA */
    fp_dna_t            extra_refs[FP_NET_MAX_REFS];
    size_t              extra_ref_count;
    int                 force_merkle_stream; /* 1 = force chunked Merkle streaming (skip delta/zstd) */
    int                 io_timeout_ms;   /* 0 = default (10000 ms) */
    size_t              max_output;      /* 0 = default (128 MiB) */
} fp_net_pull_cfg_t;

typedef struct {
    fp_net_mode_t mode;
    fp_dna_t      dna;
    fp_dna_t      negotiated_ref;
    uint64_t      canonical_size;
    uint64_t      wire_bytes;        /* Encrypted application bytes transferred */
    uint64_t      resumed_chunks;    /* Verified 16 KiB chunks skipped on resume */
    uint64_t      received_chunks;   /* Verified 16 KiB chunks received in this session */
    uint64_t      elapsed_ns;
} fp_net_stats_t;

int      fp_net_listen(const char *bind_addr, uint16_t port, uint16_t *out_port);
fp_err_t fp_net_serve_fd(int listen_fd, const fp_net_server_cfg_t *cfg);
fp_err_t fp_net_pull(const fp_net_pull_cfg_t *cfg, fp_net_stats_t *out_stats);

/* Persistent Authenticated Encrypted Streaming Session (1-RTT X25519+Ed25519,
 * XChaCha20-Poly1305 AEAD + BLAKE3 canonical DNA verification per message, zero disk I/O). */
typedef struct fp_session fp_session_t;

fp_err_t fp_session_connect(const char *host, uint16_t port,
                            const fp_keypair_t *client_kp,
                            const uint8_t expected_srv_pk[FP_PK_LEN],
                            int io_timeout_ms,
                            fp_session_t **out_sess);
fp_err_t fp_session_accept(int listen_fd,
                           const fp_keypair_t *server_kp,
                           const uint8_t allowed_peer_pk[FP_PK_LEN],
                           int io_timeout_ms,
                           fp_session_t **out_sess);
fp_err_t fp_session_send_verified(fp_session_t *sess, uint8_t tag,
                                  const uint8_t *data, size_t len,
                                  fp_dna_t *out_dna);
fp_err_t fp_session_recv_verified(fp_session_t *sess, size_t max_bytes,
                                  uint8_t *out_tag,
                                  uint8_t **out_data, size_t *out_len,
                                  fp_dna_t *out_dna);
void     fp_session_stats(const fp_session_t *sess, uint64_t *out_tx, uint64_t *out_rx);
void     fp_session_close(fp_session_t *sess);

/* --- SFT1: Verified Tensor & KV-Cache Slice Streaming (Edge AI / Mixed Inference) --- */

typedef enum {
    FP_DTYPE_FP32         = 1,
    FP_DTYPE_FP16         = 2,
    FP_DTYPE_INT8         = 3,
    FP_DTYPE_UINT8        = 4,
    FP_DTYPE_INT32        = 5,
    FP_DTYPE_BF16         = 6,
    FP_DTYPE_INT4_G32     = 7,
    FP_DTYPE_INT4_OUTLIER = 8
} fp_dtype_t;

typedef enum {
    FP_WIRE_CAST_NONE         = 0,
    FP_WIRE_CAST_FP16         = 1,
    FP_WIRE_CAST_BF16         = 2,
    FP_WIRE_CAST_INT8         = 3,
    FP_WIRE_CAST_INT4_G32     = 4, /* Group-32 symmetric INT4 (18B/32 elems, -86% wire) */
    FP_WIRE_CAST_INT4_OUTLIER = 5  /* Group-32 INT4 + sparse Top-1% FP16 outliers (-84% wire, high SQNR) */
} fp_wire_cast_t;

#define FP_TENSOR_FLAG_WIRE_FP16         0x01u
#define FP_TENSOR_FLAG_WIRE_BF16         0x02u
#define FP_TENSOR_FLAG_WIRE_INT8         0x04u
#define FP_TENSOR_FLAG_WIRE_INT4_G32     0x08u
#define FP_TENSOR_FLAG_WIRE_INT4_OUTLIER 0x10u

typedef struct {
    fp_dtype_t dtype;
    uint8_t    ndim;     /* 1..4 */
    uint8_t    flags;
    uint32_t   dims[4];  /* unused trailing dims must be 0 */
    uint64_t   seq_id;   /* sequence/token position or frame index */
} fp_tensor_meta_t;

size_t   fp_dtype_size(fp_dtype_t dtype);
uint16_t fp_f32_to_f16(float f);
float    fp_f16_to_f32(uint16_t h);
uint16_t fp_f32_to_bf16(float f);
float    fp_bf16_to_f32(uint16_t b);

fp_err_t fp_tensor_pack_ex(const fp_tensor_meta_t *meta, const void *data, size_t data_len,
                           fp_wire_cast_t wire_cast, uint8_t **out_buf, size_t *out_len);
fp_err_t fp_tensor_pack(const fp_tensor_meta_t *meta, const void *data, size_t data_len,
                        int cast_f32_to_f16, uint8_t **out_buf, size_t *out_len);
fp_err_t fp_tensor_unpack(const uint8_t *buf, size_t len, int upcast_to_f32,
                          fp_tensor_meta_t *out_meta, uint8_t **out_data, size_t *out_data_len);
fp_err_t fp_session_send_tensor_ex(fp_session_t *sess, uint8_t tag,
                                   const fp_tensor_meta_t *meta,
                                   const void *data, size_t data_len,
                                   fp_wire_cast_t wire_cast, fp_dna_t *out_dna);
fp_err_t fp_session_send_tensor(fp_session_t *sess, uint8_t tag,
                                const fp_tensor_meta_t *meta,
                                const void *data, size_t data_len,
                                int cast_f32_to_f16, fp_dna_t *out_dna);
fp_err_t fp_session_recv_tensor(fp_session_t *sess, size_t max_bytes,
                                int upcast_to_f32, uint8_t *out_tag,
                                fp_tensor_meta_t *out_meta,
                                uint8_t **out_data, size_t *out_data_len,
                                fp_dna_t *out_dna);

/* --- M2: Cross-File FastCDC Chunk Composition (O(1) RAM) --- */

#define FP_CDC_MIN 4096u
#define FP_CDC_AVG 16384u
#define FP_CDC_MAX 65536u

typedef struct {
    fp_dna_t dna;
    uint64_t canonical_size;
    uint64_t total_chunks;
    uint64_t new_chunks;
    uint64_t dedup_chunks;
    uint64_t stored_bytes;     /* Net new chunk bytes written to pool */
    uint64_t reused_bytes;     /* Bytes satisfied by already-resident chunks */
    uint64_t elapsed_ns;
} fp_cdc_stats_t;

size_t   fp_fastcdc_cut(const uint8_t *data, size_t len);
fp_err_t fp_cdc_chunk_id(const uint8_t *chunk, size_t len, fp_dna_t *out_id);
fp_err_t fp_cdc_ingest_file(const char *store_dir, const char *file_path,
                            fp_cdc_stats_t *out_stats);
fp_err_t fp_cdc_reconstruct_file(const char *store_dir, const fp_dna_t *dna,
                                 const char *out_path, uint64_t *out_bytes);
fp_err_t fp_cdc_recipe_missing(const char *store_dir, const fp_dna_t *recipe_dna,
                               const char *target_store_dir,
                               uint64_t *out_total_chunks, uint64_t *out_missing_chunks,
                               uint64_t *out_missing_bytes);

/* --- M3: Composite State Transitions (Particle Bundle FPB1 + SQLite Session) --- */

#define FP_BUNDLE_MAX_ENTRIES 64u
#define FP_BUNDLE_MAX_PATH    256u

typedef enum {
    FP_ROLE_FILE             = 1,
    FP_ROLE_SQLITE_CHANGESET = 2
} fp_bundle_role_t;

typedef struct {
    fp_bundle_role_t role;
    uint32_t         mode; /* POSIX file mode, e.g. 0644 or 0755 */
    uint64_t         size;
    fp_dna_t         dna;
    char             path[FP_BUNDLE_MAX_PATH]; /* Relative POSIX path or SQLite table name */
} fp_bundle_entry_t;

typedef struct {
    uint16_t          version;
    uint16_t          entry_count;
    fp_bundle_entry_t entries[FP_BUNDLE_MAX_ENTRIES];
} fp_bundle_t;

typedef struct fp_sql_ctx fp_sql_ctx_t;

fp_err_t fp_sql_open(const char *db_path, fp_sql_ctx_t **out_ctx);
void     fp_sql_close(fp_sql_ctx_t *ctx);
fp_err_t fp_sql_exec(fp_sql_ctx_t *ctx, const char *sql);
fp_err_t fp_sql_capture_changeset(fp_sql_ctx_t *ctx, const char *table_name,
                                  const char *sql,
                                  uint8_t **out_cs, size_t *out_len);
fp_err_t fp_sql_state_digest(fp_sql_ctx_t *ctx, const char *table_name, fp_dna_t *out_dna);

fp_err_t fp_bundle_encode(const fp_bundle_t *b, uint8_t **out_buf, size_t *out_len);
fp_err_t fp_bundle_decode(const uint8_t *buf, size_t len, fp_bundle_t *out_b);
fp_err_t fp_bundle_pack(const char *store_dir, const fp_bundle_t *b, fp_dna_t *out_bundle_dna);

/* Fault-injection modes for fp_bundle_apply():
 *   0 = normal operation
 *   1 = SIGKILL before SQLite COMMIT
 *   2 = SIGKILL after SQLite COMMIT and before atomic `current` symlink flip
 *   3 = SIGKILL after `current` flip and before journal COMMITTED seal */
fp_err_t fp_bundle_apply(const char *store_dir, const fp_dna_t *bundle_dna,
                         const char *target_dir, fp_sql_ctx_t *sql_ctx,
                         uint64_t expected_seq, int fault_mode);

/* Deterministic crash-recovery for any incomplete composite bundle transaction
 * recorded in `<target_dir>/.sf_tx_journal`. Reconciles forward if SQLite already
 * committed, or cleans up safely if interrupted prior to commit. */
fp_err_t fp_bundle_recover(const char *store_dir, const char *target_dir,
                           fp_sql_ctx_t *sql_ctx);

fp_err_t fp_bundle_rollback(const char *store_dir,
                            const fp_dna_t *current_bundle_dna,
                            const fp_dna_t *prev_bundle_dna,
                            const char *target_dir, fp_sql_ctx_t *sql_ctx);

/* --- M4: Industrial Security (TUF-style Root Multi-Sig k-of-n & Key Rotation) --- */

#define FP_MAX_ROOT_KEYS    8u
#define FP_MAX_REVOKED_KEYS 32u
#define FP_MAX_ROOT_SIGS    16u

typedef struct {
    uint8_t signer_pk[FP_PK_LEN];
    uint8_t sig[FP_SIG_LEN];
} fp_root_sig_t;

typedef struct {
    uint16_t      version;
    uint64_t      root_version;
    fp_dna_t      repo_id;
    uint64_t      timestamp_unix;
    uint64_t      expires_unix;
    uint8_t       root_threshold;
    uint8_t       root_key_count;
    uint8_t       root_keys[FP_MAX_ROOT_KEYS][FP_PK_LEN];
    uint8_t       release_pk[FP_PK_LEN];
    uint8_t       revoked_key_count;
    uint8_t       revoked_keys[FP_MAX_REVOKED_KEYS][FP_PK_LEN];
    uint8_t       sig_count;
    fp_root_sig_t sigs[FP_MAX_ROOT_SIGS];
    fp_dna_t      doc_hash;
} fp_root_doc_t;

fp_err_t fp_root_add_sig(fp_root_doc_t *doc, const fp_keypair_t *root_kp);
fp_err_t fp_root_verify_self(const fp_root_doc_t *doc, uint64_t now_unix);
fp_err_t fp_root_verify_rotation(const fp_root_doc_t *prev, const fp_root_doc_t *next,
                                 uint64_t now_unix);
fp_err_t fp_root_encode(const fp_root_doc_t *doc, uint8_t **out_buf, size_t *out_len);
fp_err_t fp_root_decode(const uint8_t *buf, size_t len, fp_root_doc_t *out_doc);

fp_err_t fp_event_verify_with_root(const fp_event_t *ev, const fp_root_doc_t *root,
                                   uint64_t now_unix);
fp_err_t fp_store_apply_event_with_root(const char *root_dir, const fp_event_t *ev,
                                        const fp_root_doc_t *trusted_root,
                                        uint64_t now_unix,
                                        const uint8_t *payload_data, size_t payload_len);

/* --- M5: Multi-Peer Verified Swarm & WireGuard-style Encrypted UDP Transport --- */

#define FP_SWARM_MAX_PEERS 16u

typedef struct {
    const char    *host;
    uint16_t       port;
    const uint8_t *expected_pk; /* Optional 32B server pin; NULL = trust root DNA via Merkle */
} fp_swarm_peer_t;

typedef struct {
    const char            *store_dir;
    const fp_keypair_t    *client_kp;
    fp_dna_t               target_dna;
    const fp_swarm_peer_t *peers;
    size_t                 peer_count;
    size_t                 max_output;
    int                    io_timeout_ms;
} fp_swarm_cfg_t;

typedef struct {
    uint64_t canonical_size;
    uint64_t total_chunks;
    uint64_t wire_bytes;
    uint32_t peers_used;
    uint32_t peers_banned;
    uint64_t per_peer_chunks[FP_SWARM_MAX_PEERS];
    uint8_t  peer_banned[FP_SWARM_MAX_PEERS];
    uint64_t elapsed_ns;
} fp_swarm_stats_t;

fp_err_t fp_swarm_pull(const fp_swarm_cfg_t *cfg, fp_swarm_stats_t *out_stats);

typedef struct {
    const char         *bind_addr;
    uint16_t            port;
    const char         *store_dir;
    const fp_keypair_t *server_kp;
    uint32_t            max_sessions;    /* 0 = serve forever */
    int                 io_timeout_ms;
    uint32_t            fault_drop_pct;  /* Test hook: drop N% of outgoing UDP packets */
} fp_udp_server_cfg_t;

typedef struct {
    const char         *host;
    uint16_t            port;
    const char         *store_dir;
    const fp_keypair_t *client_kp;
    const uint8_t      *expected_srv_pk; /* Optional 32B server pin */
    fp_dna_t            target_dna;
    size_t              max_output;
    int                 io_timeout_ms;
    uint64_t            test_migrate_at_chunk; /* Test hook: rebind to new UDP port mid-stream */
} fp_udp_pull_cfg_t;

typedef struct {
    uint64_t canonical_size;
    uint64_t total_chunks;
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint64_t retransmits;
    uint32_t migrations;
    uint32_t final_cwnd;
    uint64_t srtt_us;
    uint64_t elapsed_ns;
} fp_udp_stats_t;

int      fp_udp_bind(const char *bind_addr, uint16_t port, uint16_t *out_port);
fp_err_t fp_udp_serve_fd(int udp_fd, const fp_udp_server_cfg_t *cfg);
fp_err_t fp_udp_pull(const fp_udp_pull_cfg_t *cfg, fp_udp_stats_t *out_stats);

/* Persistent Authenticated Encrypted UDP Session (FP-UDP1, 1-RTT X25519+Ed25519,
 * XChaCha20-Poly1305 AEAD, selective fragment NACK/retransmit, zero TCP HoL blocking). */
typedef struct fp_udp_session fp_udp_session_t;

fp_err_t fp_udp_session_connect(const char *host, uint16_t port,
                                const fp_keypair_t *client_kp,
                                const uint8_t expected_srv_pk[FP_PK_LEN],
                                int io_timeout_ms, uint32_t fault_drop_pct,
                                fp_udp_session_t **out_sess);
fp_err_t fp_udp_session_accept(int udp_fd,
                               const fp_keypair_t *server_kp,
                               const uint8_t allowed_peer_pk[FP_PK_LEN],
                               int io_timeout_ms, uint32_t fault_drop_pct,
                               fp_udp_session_t **out_sess);
fp_err_t fp_udp_session_send_verified(fp_udp_session_t *sess, uint8_t tag,
                                      const uint8_t *data, size_t len,
                                      fp_dna_t *out_dna);
fp_err_t fp_udp_session_recv_verified(fp_udp_session_t *sess, size_t max_bytes,
                                      uint8_t *out_tag,
                                      uint8_t **out_data, size_t *out_len,
                                      fp_dna_t *out_dna);
fp_err_t fp_udp_session_send_tensor(fp_udp_session_t *sess, uint8_t tag,
                                    const fp_tensor_meta_t *meta,
                                    const void *data, size_t data_len,
                                    fp_wire_cast_t wire_cast, fp_dna_t *out_dna);
fp_err_t fp_udp_session_recv_tensor(fp_udp_session_t *sess, size_t max_bytes,
                                    int upcast_to_f32, uint8_t *out_tag,
                                    fp_tensor_meta_t *out_meta,
                                    uint8_t **out_data, size_t *out_data_len,
                                    fp_dna_t *out_dna);
void     fp_udp_session_stats(const fp_udp_session_t *sess,
                              uint64_t *out_tx_bytes, uint64_t *out_rx_bytes,
                              uint64_t *out_retransmits);
uint64_t fp_udp_session_fec_recoveries(const fp_udp_session_t *sess);
/* FEC mode: 0 = off, 1 = always on (default), 2 = adaptive (on only after loss) */
void     fp_udp_session_set_fec(fp_udp_session_t *sess, int fec_mode);
void     fp_udp_session_close(fp_udp_session_t *sess);

/* --- Optional Transparency Anchor Interface (Off-Path 32B Commitment) --- */

typedef struct {
    fp_dna_t repo_id;
    uint64_t serial;
    fp_dna_t event_hash;
    fp_dna_t target_dna;
    fp_dna_t commitment;
} fp_anchor_commitment_t;

typedef struct {
    fp_err_t (*publish)(void *user_ctx, const fp_anchor_commitment_t *c);
    fp_err_t (*verify)(void *user_ctx, const fp_anchor_commitment_t *c);
    void *user_ctx;
} fp_anchor_ops_t;

fp_err_t fp_anchor_compute(const fp_event_t *ev, fp_anchor_commitment_t *out);
fp_err_t fp_anchor_local_publish(const char *log_path, const fp_anchor_commitment_t *c);
fp_err_t fp_anchor_local_verify(const char *log_path, const fp_anchor_commitment_t *c);

#ifdef __cplusplus
}
#endif

#endif /* FP_H */
