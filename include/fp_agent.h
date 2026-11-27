#ifndef FP_AGENT_H
#define FP_AGENT_H

#include "fp.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Minimal Zero-Dependency HTTP/1.1 Range Client (C11 POSIX) --- */

typedef struct {
    int      status_code;
    size_t   body_len;
    uint8_t *body; /* heap-allocated, caller frees */
} fp_http_resp_t;

/* Perform HTTP/1.1 GET (max_bytes ceiling, fail-closed). */
fp_err_t fp_http_get(const char *url, size_t max_bytes, int timeout_ms,
                     fp_http_resp_t *out_resp);

/* Perform HTTP/1.1 POST with application/json body (best-effort telemetry/heartbeat). */
fp_err_t fp_http_post_json(const char *url, const char *json_body,
                           int timeout_ms, int *out_status);

/* Perform HTTP/1.1 POST with Ed25519 signature headers (X-FP-Device-PubKey + X-FP-Signature). */
fp_err_t fp_http_post_json_signed(const char *url, const char *json_body,
                                  const fp_keypair_t *device_kp,
                                  int timeout_ms, int *out_status);

/* Stream-download an object from HTTP URL with automatic `Range: bytes=<off>-` resume
 * into `<store_dir>/objects/<dna_hex>`, verifying full BLAKE3 Content DNA before atomic rename.
 * Zero file-size malloc (fixed 16 KiB streaming buffer). */
fp_err_t fp_http_pull_object(const char *url, const char *store_dir,
                             const fp_dna_t *expected_dna, uint64_t expected_size,
                             int timeout_ms, uint64_t *out_resumed_bytes);

void fp_http_resp_free(fp_http_resp_t *resp);

/* --- Edge Agent Core (Multi-Sig + Hybrid LAN FP-NET/HTTP + Health-Check + Auto-Rollback) --- */

typedef enum {
    FP_AGENT_UP_TO_DATE   = 0,
    FP_AGENT_UPDATED      = 1,
    FP_AGENT_ROLLED_BACK  = 2,
    FP_AGENT_REVOKED      = 3,
    FP_AGENT_REJECTED     = 4
} fp_agent_outcome_t;

typedef struct {
    const char         *device_id;          /* Unique edge device identifier */
    const char         *repo_url;           /* Base HTTP URL, e.g. "http://192.168.1.12:8080" */
    const char         *channel;            /* Rollout channel, e.g. "stable" or "canary" */
    const char         *store_dir;          /* Local Content-Addressed Store directory */
    const char         *target_dir;         /* Live deployment target directory (managed atomically) */
    const char         *db_path;            /* Optional SQLite DB path for composite bundles */
    const char         *root_path;          /* Pinned trusted Root FPR1 file (updated on verified rotation) */
    const char         *health_cmd;         /* Optional shell command to verify app health after apply */
    int                 health_timeout_sec; /* Watchdog timeout for health_cmd (0 = default 15s) */
    int                 io_timeout_ms;      /* Network timeout (0 = default 10000 ms) */
    int                 report_heartbeat;   /* 1 = POST /api/v1/heartbeat after cycle */
    const fp_keypair_t *device_kp;          /* Optional Ed25519 device identity (signs heartbeats + FP-NET) */
    const char         *lan_peer_host;      /* Optional LAN FP-NET peer host (tried BEFORE HTTP WAN!) */
    uint16_t            lan_peer_port;      /* Optional LAN FP-NET peer TCP port */
    const uint8_t      *lan_peer_pk;        /* Required 32B pinned pubkey when lan_peer_host is set */
} fp_agent_cfg_t;

typedef struct {
    fp_agent_outcome_t outcome;
    uint64_t           active_serial;
    fp_dna_t           active_bundle_dna;
    uint64_t           attempted_serial;
    fp_dna_t           attempted_bundle_dna;
    uint64_t           root_version;
    uint64_t           bytes_downloaded;    /* Bytes fetched via HTTP/1.1 Range */
    uint64_t           bytes_from_lan;      /* Bytes satisfied by LAN FP-NET encrypted peer */
    uint64_t           bytes_resumed;       /* Bytes saved via HTTP 206 or Merkle resume */
    int                health_exit_code;
    uint64_t           elapsed_ns;
    char               detail[256];
} fp_agent_report_t;

/* Execute one full, crash-safe reconciliation cycle against the Control Plane. */
fp_err_t fp_agent_sync_once(const fp_agent_cfg_t *cfg, fp_agent_report_t *out_report);

/* Run health-check command with hard SIGKILL watchdog timeout.
 * Returns 0 on healthy (exit 0), >0 on non-zero exit, -1 on timeout/signal. */
int fp_agent_run_health_check(const char *cmd, int timeout_sec);

const char *fp_agent_outcome_name(fp_agent_outcome_t o);

#ifdef __cplusplus
}
#endif

#endif /* FP_AGENT_H */
