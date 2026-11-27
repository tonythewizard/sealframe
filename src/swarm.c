#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <arpa/inet.h>
#include <blake3.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define SWARM_BATCH_CHUNKS    8u
#define SWARM_DEFAULT_MAX_OUT (128u << 20)
#define SWARM_MAX_PT          (128u << 10)
#define SWARM_HELLO_LEN       148u
#define SWARM_AEAD_ABYTES     crypto_aead_xchacha20poly1305_ietf_ABYTES

enum {
    SMSG_OFFER       = 2,
    SMSG_CHUNK       = 4,
    SMSG_DONE        = 5,
    SMSG_ACK         = 6,
    SMSG_ERR         = 7,
    SMSG_SWARM_OPEN  = 8,
    SMSG_SWARM_RANGE = 9
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void put_be32(uint8_t dst[4], uint32_t v) {
    dst[0] = (uint8_t)(v >> 24); dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);  dst[3] = (uint8_t)(v);
}

static uint32_t get_be32(const uint8_t src[4]) {
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  | ((uint32_t)src[3]);
}

static void put_be64(uint8_t dst[8], uint64_t v) {
    dst[0] = (uint8_t)(v >> 56); dst[1] = (uint8_t)(v >> 48);
    dst[2] = (uint8_t)(v >> 40); dst[3] = (uint8_t)(v >> 32);
    dst[4] = (uint8_t)(v >> 24); dst[5] = (uint8_t)(v >> 16);
    dst[6] = (uint8_t)(v >> 8);  dst[7] = (uint8_t)(v);
}

static uint64_t get_be64(const uint8_t src[8]) {
    return ((uint64_t)src[0] << 56) | ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) | ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) | ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  | ((uint64_t)src[7]);
}

/* Minimal encrypted client channel matching FP-NET v1 */
typedef struct {
    int      fd;
    uint8_t  tx_key[32];
    uint8_t  rx_key[32];
    uint64_t tx_seq;
    uint64_t rx_seq;
    uint64_t wire_bytes;
} schan_t;

static fp_err_t s_send_all(int fd, const uint8_t *buf, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = send(fd, buf + pos, len - pos, MSG_NOSIGNAL);
        if (n < 0) { if (errno == EINTR) continue; return FP_ERR_IO; }
        if (n == 0) return FP_ERR_IO;
        pos += (size_t)n;
    }
    return FP_OK;
}

static fp_err_t s_recv_all(int fd, uint8_t *buf, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = recv(fd, buf + pos, len - pos, 0);
        if (n < 0) { if (errno == EINTR) continue; return FP_ERR_IO; }
        if (n == 0) return FP_ERR_IO;
        pos += (size_t)n;
    }
    return FP_OK;
}

static fp_err_t schan_connect(schan_t *ch, const fp_swarm_peer_t *peer,
                              const fp_keypair_t *ckp, int timeout_ms) {
    memset(ch, 0, sizeof(*ch));
    ch->fd = -1;

    char pstr[16];
    snprintf(pstr, sizeof(pstr), "%u", (unsigned)peer->port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(peer->host, pstr, &hints, &res) != 0 || !res) return FP_ERR_IO;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return FP_ERR_IO; }

    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int ms = timeout_ms > 0 ? timeout_ms : 5000;
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return FP_ERR_IO;
    }
    freeaddrinfo(res);
    ch->fd = fd;

    /* FP-NET v1 X25519 + Ed25519 handshake */
    uint8_t c_eph_pk[32], c_eph_sk[32], c_nonce[16];
    randombytes_buf(c_eph_sk, sizeof(c_eph_sk));
    crypto_scalarmult_base(c_eph_pk, c_eph_sk);
    randombytes_buf(c_nonce, sizeof(c_nonce));

    uint8_t c_msg[13 + 32 + 32 + 16];
    memcpy(c_msg, "FPN1/C_HELLO", 13);
    memcpy(c_msg + 13, ckp->pk, 32);
    memcpy(c_msg + 45, c_eph_pk, 32);
    memcpy(c_msg + 77, c_nonce, 16);

    uint8_t hello[SWARM_HELLO_LEN];
    memcpy(hello, "FPN1", 4);
    memcpy(hello + 4, ckp->pk, 32);
    memcpy(hello + 36, c_eph_pk, 32);
    memcpy(hello + 68, c_nonce, 16);
    unsigned long long siglen = 0;
    crypto_sign_ed25519_detached(hello + 84, &siglen, c_msg, sizeof(c_msg), ckp->sk);

    if (s_send_all(fd, hello, sizeof(hello)) != FP_OK) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        return FP_ERR_IO;
    }
    ch->wire_bytes += sizeof(hello);

    uint8_t srv[SWARM_HELLO_LEN];
    if (s_recv_all(fd, srv, sizeof(srv)) != FP_OK || memcmp(srv, "FPN1", 4) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        return FP_ERR_IO;
    }
    ch->wire_bytes += sizeof(srv);

    const uint8_t *s_pk = srv + 4, *s_eph_pk = srv + 36, *s_nonce = srv + 68, *s_sig = srv + 84;
    if (peer->expected_pk && sodium_memcmp(s_pk, peer->expected_pk, FP_PK_LEN) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        return FP_ERR_SIGNATURE;
    }

    uint8_t shared[32];
    if (crypto_scalarmult(shared, c_eph_sk, s_eph_pk) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        return FP_ERR_SIGNATURE;
    }
    sodium_memzero(c_eph_sk, sizeof(c_eph_sk));

    blake3_hasher h;
    uint8_t th[32];
    static const uint8_t t_tag[16] = "FPN1/TRANSCRIPT";
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, t_tag, sizeof(t_tag));
    blake3_hasher_update(&h, ckp->pk, 32);
    blake3_hasher_update(&h, c_eph_pk, 32);
    blake3_hasher_update(&h, c_nonce, 16);
    blake3_hasher_update(&h, s_pk, 32);
    blake3_hasher_update(&h, s_eph_pk, 32);
    blake3_hasher_update(&h, s_nonce, 16);
    blake3_hasher_finalize(&h, th, 32);

    uint8_t s_msg[13 + 32];
    memcpy(s_msg, "FPN1/S_HELLO", 13);
    memcpy(s_msg + 13, th, 32);
    if (crypto_sign_ed25519_verify_detached(s_sig, s_msg, sizeof(s_msg), s_pk) != 0) {
        sodium_memzero(shared, sizeof(shared));
        return FP_ERR_SIGNATURE;
    }

    static const uint8_t k1[11] = "FPN1/K_C2S";
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, k1, sizeof(k1));
    blake3_hasher_update(&h, shared, 32);
    blake3_hasher_update(&h, th, 32);
    blake3_hasher_finalize(&h, ch->tx_key, 32);

    static const uint8_t k2[11] = "FPN1/K_S2C";
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, k2, sizeof(k2));
    blake3_hasher_update(&h, shared, 32);
    blake3_hasher_update(&h, th, 32);
    blake3_hasher_finalize(&h, ch->rx_key, 32);
    sodium_memzero(shared, sizeof(shared));
    return FP_OK;
}

static void schan_close(schan_t *ch) {
    if (ch->fd >= 0) { close(ch->fd); ch->fd = -1; }
    sodium_memzero(ch->tx_key, sizeof(ch->tx_key));
    sodium_memzero(ch->rx_key, sizeof(ch->rx_key));
}

static fp_err_t schan_send(schan_t *ch, uint8_t type, const uint8_t *body, size_t blen) {
    size_t pt_len = 1u + blen;
    uint8_t *pt = malloc(pt_len);
    uint8_t *fr = malloc(4u + pt_len + SWARM_AEAD_ABYTES);
    if (!pt || !fr) { free(pt); free(fr); return FP_ERR_NOMEM; }
    pt[0] = type;
    if (blen > 0) memcpy(pt + 1, body, blen);

    uint8_t nonce[24] = {0}, ad[12];
    put_be64(nonce, ch->tx_seq);
    put_be64(ad, ch->tx_seq);
    put_be32(ad + 8, (uint32_t)pt_len);

    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        fr + 4, &ct_len, pt, pt_len, ad, sizeof(ad), NULL, nonce, ch->tx_key);
    free(pt);
    put_be32(fr, (uint32_t)ct_len);
    fp_err_t err = s_send_all(ch->fd, fr, 4u + (size_t)ct_len);
    free(fr);
    if (err == FP_OK) { ch->tx_seq++; ch->wire_bytes += 4u + (uint64_t)ct_len; }
    return err;
}

static fp_err_t schan_recv(schan_t *ch, uint8_t *type, uint8_t **body, size_t *blen) {
    *body = NULL; *blen = 0;
    uint8_t lbuf[4];
    fp_err_t err = s_recv_all(ch->fd, lbuf, 4);
    if (err != FP_OK) return err;
    uint32_t ct_len = get_be32(lbuf);
    if (ct_len < SWARM_AEAD_ABYTES + 1u || ct_len > SWARM_MAX_PT + SWARM_AEAD_ABYTES) {
        return FP_ERR_BOUNDS;
    }
    uint8_t *ct = malloc(ct_len);
    size_t pt_cap = ct_len - SWARM_AEAD_ABYTES;
    uint8_t *pt = malloc(pt_cap);
    if (!ct || !pt) { free(ct); free(pt); return FP_ERR_NOMEM; }

    err = s_recv_all(ch->fd, ct, ct_len);
    if (err != FP_OK) { free(ct); free(pt); return err; }
    ch->wire_bytes += 4u + (uint64_t)ct_len;

    uint8_t nonce[24] = {0}, ad[12];
    put_be64(nonce, ch->rx_seq);
    put_be64(ad, ch->rx_seq);
    put_be32(ad + 8, (uint32_t)pt_cap);

    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &pt_len, NULL, ct, ct_len, ad, sizeof(ad), nonce, ch->rx_key) != 0 || pt_len < 1u) {
        free(ct); free(pt);
        return FP_ERR_SIGNATURE;
    }
    free(ct);
    ch->rx_seq++;
    *type = pt[0];
    size_t n = (size_t)pt_len - 1u;
    if (n > 0) { memmove(pt, pt + 1, n); *body = pt; }
    else { free(pt); *body = NULL; }
    *blen = n;
    return FP_OK;
}

static fp_err_t decode_swarm_chunk(const uint8_t *buf, size_t len,
                                   fp_merkle_proof_t *proof, const uint8_t **out_data) {
    if (len < 21u) return FP_ERR_INVALID;
    memset(proof, 0, sizeof(*proof));
    size_t p = 0;
    proof->chunk_index = get_be64(buf + p); p += 8;
    proof->total_size = get_be64(buf + p); p += 8;
    proof->chunk_len = get_be32(buf + p); p += 4;
    proof->depth = buf[p++];
    if (proof->depth > FP_MAX_PROOF_DEPTH) return FP_ERR_BOUNDS;
    size_t hdr = p + proof->depth + (size_t)proof->depth * FP_DNA_LEN;
    if (len < hdr || len - hdr != proof->chunk_len) return FP_ERR_BOUNDS;
    for (uint32_t i = 0; i < proof->depth; i++) proof->is_right[i] = buf[p++];
    for (uint32_t i = 0; i < proof->depth; i++) {
        memcpy(proof->siblings[i], buf + p, FP_DNA_LEN);
        p += FP_DNA_LEN;
    }
    *out_data = buf + p;
    return FP_OK;
}

/* Chunk state in coordinator bitmap */
enum { CHUNK_TODO = 0, CHUNK_INFLIGHT = 1, CHUNK_DONE = 2 };

typedef struct {
    pthread_mutex_t       mu;
    const fp_swarm_cfg_t *cfg;
    int                   out_fd;
    int                   meta_ready;
    uint64_t              canonical_size;
    uint64_t              total_chunks;
    uint64_t              done_chunks;
    uint8_t              *chunk_state;
    uint64_t              wire_bytes;
    uint64_t              per_peer_chunks[FP_SWARM_MAX_PEERS];
    uint8_t               peer_banned[FP_SWARM_MAX_PEERS];
    uint8_t               peer_used[FP_SWARM_MAX_PEERS];
} swarm_shared_t;

typedef struct {
    swarm_shared_t *sh;
    size_t          peer_idx;
} swarm_worker_arg_t;

static int claim_batch(swarm_shared_t *sh, uint64_t *out_start, uint64_t *out_count) {
    uint64_t n = sh->total_chunks;
    for (uint64_t i = 0; i < n; i++) {
        if (sh->chunk_state[i] == CHUNK_TODO) {
            uint64_t cnt = 0;
            while (cnt < SWARM_BATCH_CHUNKS && (i + cnt) < n &&
                   sh->chunk_state[i + cnt] == CHUNK_TODO) {
                sh->chunk_state[i + cnt] = CHUNK_INFLIGHT;
                cnt++;
            }
            *out_start = i;
            *out_count = cnt;
            return 1;
        }
    }
    return 0;
}

static void release_unfinished(swarm_shared_t *sh, uint64_t start, uint64_t count) {
    for (uint64_t i = start; i < start + count; i++) {
        if (sh->chunk_state[i] == CHUNK_INFLIGHT) {
            sh->chunk_state[i] = CHUNK_TODO;
        }
    }
}

static void *swarm_worker(void *arg) {
    swarm_worker_arg_t *wa = (swarm_worker_arg_t *)arg;
    swarm_shared_t *sh = wa->sh;
    size_t idx = wa->peer_idx;
    const fp_swarm_peer_t *peer = &sh->cfg->peers[idx];
    size_t max_out = sh->cfg->max_output > 0 ? sh->cfg->max_output : SWARM_DEFAULT_MAX_OUT;

    schan_t ch;
    if (schan_connect(&ch, peer, sh->cfg->client_kp, sh->cfg->io_timeout_ms) != FP_OK) {
        schan_close(&ch);
        return NULL;
    }

    if (schan_send(&ch, SMSG_SWARM_OPEN, sh->cfg->target_dna.bytes, FP_DNA_LEN) != FP_OK) {
        schan_close(&ch);
        return NULL;
    }

    uint8_t mtype = 0;
    uint8_t *obody = NULL;
    size_t olen = 0;
    if (schan_recv(&ch, &mtype, &obody, &olen) != FP_OK || mtype != SMSG_OFFER || olen != 57u) {
        free(obody);
        schan_close(&ch);
        return NULL;
    }
    uint64_t p_size = get_be64(obody + 1);
    uint64_t p_chunks = get_be64(obody + 9);
    free(obody);

    uint64_t expected_chunks = p_size > 0 ? (1u + (p_size - 1u) / FP_CHUNK_SIZE) : 0u;
    if (p_size > max_out || p_chunks != expected_chunks) {
        pthread_mutex_lock(&sh->mu);
        sh->peer_banned[idx] = 1;
        pthread_mutex_unlock(&sh->mu);
        schan_close(&ch);
        return NULL;
    }

    pthread_mutex_lock(&sh->mu);
    if (!sh->meta_ready) {
        sh->canonical_size = p_size;
        sh->total_chunks = p_chunks;
        sh->chunk_state = calloc(p_chunks > 0 ? (size_t)p_chunks : 1u, 1);
        if (sh->chunk_state && (p_size == 0 || ftruncate(sh->out_fd, (off_t)p_size) == 0)) {
            sh->meta_ready = 1;
        }
    } else if (sh->canonical_size != p_size || sh->total_chunks != p_chunks) {
        /* Lying peer claims wrong size -> ban immediately */
        sh->peer_banned[idx] = 1;
        pthread_mutex_unlock(&sh->mu);
        schan_close(&ch);
        return NULL;
    }
    int ready = sh->meta_ready;
    pthread_mutex_unlock(&sh->mu);

    if (!ready) { schan_close(&ch); return NULL; }

    int banned = 0;
    for (;;) {
        uint64_t start = 0, count = 0;
        pthread_mutex_lock(&sh->mu);
        int all_done = (sh->done_chunks >= sh->total_chunks);
        int got_work = (!all_done) && claim_batch(sh, &start, &count);
        pthread_mutex_unlock(&sh->mu);

        if (all_done) break;
        if (!got_work) {
            /* Other peers are finishing in-flight chunks: brief wait in case one fails */
            struct timespec ts = { 0, 2000000L }; /* 2 ms */
            nanosleep(&ts, NULL);
            continue;
        }

        uint8_t req[16];
        put_be64(req, start);
        put_be64(req + 8, count);
        if (schan_send(&ch, SMSG_SWARM_RANGE, req, sizeof(req)) != FP_OK) {
            pthread_mutex_lock(&sh->mu);
            release_unfinished(sh, start, count);
            pthread_mutex_unlock(&sh->mu);
            break;
        }

        uint64_t expected_idx = start;
        uint64_t batch_ok = 0;
        fp_err_t berr = FP_OK;
        while (berr == FP_OK) {
            berr = schan_recv(&ch, &mtype, &obody, &olen);
            if (berr != FP_OK) break;
            if (mtype == SMSG_DONE) { free(obody); break; }
            if (mtype != SMSG_CHUNK) { free(obody); berr = FP_ERR_INVALID; break; }

            fp_merkle_proof_t proof;
            const uint8_t *cdata = NULL;
            berr = decode_swarm_chunk(obody, olen, &proof, &cdata);
            if (berr == FP_OK) {
                if (proof.chunk_index != expected_idx || proof.total_size != sh->canonical_size) {
                    berr = FP_ERR_INTEGRITY;
                } else {
                    /* CRYPTOGRAPHIC MERKLE VERIFICATION BEFORE WRITING TO DISK! */
                    berr = fp_merkle_verify(&sh->cfg->target_dna, &proof, cdata, proof.chunk_len);
                }
            }
            if (berr == FP_OK) {
                off_t off = (off_t)(proof.chunk_index * FP_CHUNK_SIZE);
                size_t wr = 0;
                while (wr < proof.chunk_len) {
                    ssize_t n = pwrite(sh->out_fd, cdata + wr, proof.chunk_len - wr, off + (off_t)wr);
                    if (n < 0) { if (errno == EINTR) continue; berr = FP_ERR_IO; break; }
                    wr += (size_t)n;
                }
            }
            free(obody);
            if (berr != FP_OK) break;

            pthread_mutex_lock(&sh->mu);
            sh->chunk_state[expected_idx] = CHUNK_DONE;
            sh->done_chunks++;
            sh->per_peer_chunks[idx]++;
            sh->peer_used[idx] = 1;
            pthread_mutex_unlock(&sh->mu);

            expected_idx++;
            batch_ok++;
        }

        if (berr != FP_OK || batch_ok != count) {
            pthread_mutex_lock(&sh->mu);
            release_unfinished(sh, start, count);
            if (berr == FP_ERR_INTEGRITY || berr == FP_ERR_INVALID || berr == FP_ERR_BOUNDS) {
                sh->peer_banned[idx] = 1;
                banned = 1;
            }
            pthread_mutex_unlock(&sh->mu);
            break;
        }
    }

    if (!banned) (void)schan_send(&ch, SMSG_ACK, NULL, 0);

    pthread_mutex_lock(&sh->mu);
    sh->wire_bytes += ch.wire_bytes;
    pthread_mutex_unlock(&sh->mu);

    schan_close(&ch);
    return NULL;
}

static fp_err_t ensure_dir_sw(const char *p) {
    if (mkdir(p, 0700) == 0 || errno == EEXIST) return FP_OK;
    return FP_ERR_IO;
}

fp_err_t fp_swarm_pull(const fp_swarm_cfg_t *cfg, fp_swarm_stats_t *out_stats) {
    if (!cfg || !cfg->store_dir || !cfg->client_kp || !cfg->peers ||
        cfg->peer_count == 0 || cfg->peer_count > FP_SWARM_MAX_PEERS) {
        return FP_ERR_INVALID;
    }
    for (size_t i = 0; i < cfg->peer_count; i++) {
        if (!cfg->peers[i].host || cfg->peers[i].host[0] == '\0' || cfg->peers[i].port == 0) {
            return FP_ERR_INVALID;
        }
    }
    uint64_t t0 = now_ns();

    char stage_dir[PATH_MAX], stage_path[PATH_MAX], obj_dir[PATH_MAX], obj_path[PATH_MAX];
    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(cfg->target_dna.bytes, FP_DNA_LEN, hex);

    int n1 = snprintf(stage_dir, sizeof(stage_dir), "%s/staging", cfg->store_dir);
    int n2 = snprintf(stage_path, sizeof(stage_path), "%s/staging/%s.swarm", cfg->store_dir, hex);
    int n3 = snprintf(obj_dir, sizeof(obj_dir), "%s/objects", cfg->store_dir);
    int n4 = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", cfg->store_dir, hex);
    if (n1 < 0 || (size_t)n1 >= sizeof(stage_dir) || n2 < 0 || (size_t)n2 >= sizeof(stage_path) ||
        n3 < 0 || (size_t)n3 >= sizeof(obj_dir)   || n4 < 0 || (size_t)n4 >= sizeof(obj_path)) {
        return FP_ERR_BOUNDS;
    }
    if (ensure_dir_sw(cfg->store_dir) != FP_OK ||
        ensure_dir_sw(stage_dir) != FP_OK ||
        ensure_dir_sw(obj_dir) != FP_OK) {
        return FP_ERR_IO;
    }

    int fd = open(stage_path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) return FP_ERR_IO;

    swarm_shared_t sh;
    memset(&sh, 0, sizeof(sh));
    pthread_mutex_init(&sh.mu, NULL);
    sh.cfg = cfg;
    sh.out_fd = fd;

    pthread_t threads[FP_SWARM_MAX_PEERS];
    int created[FP_SWARM_MAX_PEERS];
    swarm_worker_arg_t args[FP_SWARM_MAX_PEERS];
    memset(created, 0, sizeof(created));
    for (size_t i = 0; i < cfg->peer_count; i++) {
        args[i].sh = &sh;
        args[i].peer_idx = i;
        if (pthread_create(&threads[i], NULL, swarm_worker, &args[i]) == 0) {
            created[i] = 1;
        }
    }
    for (size_t i = 0; i < cfg->peer_count; i++) {
        if (created[i]) pthread_join(threads[i], NULL);
    }

    fp_err_t err = FP_OK;
    if (!sh.meta_ready || sh.done_chunks != sh.total_chunks) {
        err = FP_ERR_IO;
    }
    if (err == FP_OK && fsync(fd) != 0) err = FP_ERR_IO;
    close(fd);

    if (err == FP_OK) {
        fp_dna_t actual;
        uint64_t actual_sz = 0;
        err = fp_dna_compute_file(stage_path, &actual, &actual_sz);
        if (err == FP_OK && (actual_sz != sh.canonical_size || !fp_dna_equal(&actual, &cfg->target_dna))) {
            err = FP_ERR_INTEGRITY;
        }
        if (err == FP_OK && rename(stage_path, obj_path) != 0) err = FP_ERR_IO;
        if (err == FP_OK) {
            int dfd = open(obj_dir, O_RDONLY | O_DIRECTORY);
            if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
        }
    }
    if (err != FP_OK) unlink(stage_path);

    if (out_stats) {
        memset(out_stats, 0, sizeof(*out_stats));
        out_stats->canonical_size = sh.canonical_size;
        out_stats->total_chunks = sh.total_chunks;
        out_stats->wire_bytes = sh.wire_bytes;
        out_stats->elapsed_ns = now_ns() - t0;
        for (size_t i = 0; i < cfg->peer_count; i++) {
            out_stats->per_peer_chunks[i] = sh.per_peer_chunks[i];
            out_stats->peer_banned[i] = sh.peer_banned[i];
            if (sh.peer_used[i]) out_stats->peers_used++;
            if (sh.peer_banned[i]) out_stats->peers_banned++;
        }
    }

    free(sh.chunk_state);
    pthread_mutex_destroy(&sh.mu);
    return err;
}
