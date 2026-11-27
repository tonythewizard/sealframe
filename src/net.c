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

#define FP_NET_DEFAULT_TIMEOUT_MS 10000
#define FP_NET_DEFAULT_MAX_OUTPUT (128u << 20)
#define FP_NET_MAX_PLAINTEXT      (128u << 10)  /* 128 KiB max AEAD record plaintext */
#define FP_NET_SLICE_SIZE         (64u << 10)   /* 64 KiB pipelined slices for DELTA/ZSTD */
#define FP_NET_FSYNC_INTERVAL     64u           /* Checkpoint fsync every 1 MiB (64 * 16 KiB) */
#define FP_NET_HELLO_LEN          (4u + 32u + 32u + 16u + 64u) /* 148 B */
#define FP_NET_AEAD_ABYTES        crypto_aead_xchacha20poly1305_ietf_ABYTES

enum {
    MSG_WANT         = 1,
    MSG_OFFER        = 2,
    MSG_DATA         = 3,
    MSG_CHUNK        = 4,
    MSG_DONE         = 5,
    MSG_ACK          = 6,
    MSG_ERR          = 7,
    MSG_SWARM_OPEN   = 8,  /* Swarm: open target_dna -> replies MSG_OFFER (meta only) */
    MSG_SWARM_RANGE  = 9,  /* Swarm: request (start_chunk, count) -> streams MSG_CHUNK + MSG_DONE */
    MSG_STREAM_FRAME = 10, /* Persistent session single-frame verified message (<= 64 KiB) */
    MSG_STREAM_BEGIN = 11, /* Persistent session multi-slice header (> 64 KiB) */
    MSG_STREAM_SLICE = 12  /* Persistent session 64 KiB AEAD slice */
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
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

static void set_socket_opts(int fd, int timeout_ms) {
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int ms = timeout_ms > 0 ? timeout_ms : FP_NET_DEFAULT_TIMEOUT_MS;
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static fp_err_t send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return FP_ERR_IO;
        }
        if (n == 0) return FP_ERR_IO;
        sent += (size_t)n;
    }
    return FP_OK;
}

static fp_err_t recv_all(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return FP_ERR_IO;
        }
        if (n == 0) return FP_ERR_IO;
        got += (size_t)n;
    }
    return FP_OK;
}

/* --- Authenticated Encrypted Channel (X25519 + Ed25519 + XChaCha20-Poly1305) --- */

typedef struct {
    int      fd;
    uint8_t  tx_key[32];
    uint8_t  rx_key[32];
    uint64_t tx_seq;
    uint64_t rx_seq;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint8_t  peer_pk[FP_PK_LEN];
} fp_chan_t;

static void chan_wipe(fp_chan_t *ch) {
    sodium_memzero(ch->tx_key, sizeof(ch->tx_key));
    sodium_memzero(ch->rx_key, sizeof(ch->rx_key));
}

static void derive_transcript_and_keys(const uint8_t c_pk[32], const uint8_t c_eph[32],
                                       const uint8_t c_nonce[16],
                                       const uint8_t s_pk[32], const uint8_t s_eph[32],
                                       const uint8_t s_nonce[16],
                                       const uint8_t shared[32],
                                       uint8_t out_th[32],
                                       uint8_t out_c2s[32],
                                       uint8_t out_s2c[32]) {
    blake3_hasher h;
    static const uint8_t t_tag[16] = "FPN1/TRANSCRIPT";
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, t_tag, sizeof(t_tag));
    blake3_hasher_update(&h, c_pk, 32);
    blake3_hasher_update(&h, c_eph, 32);
    blake3_hasher_update(&h, c_nonce, 16);
    blake3_hasher_update(&h, s_pk, 32);
    blake3_hasher_update(&h, s_eph, 32);
    blake3_hasher_update(&h, s_nonce, 16);
    blake3_hasher_finalize(&h, out_th, 32);

    if (shared && out_c2s && out_s2c) {
        static const uint8_t k1[11] = "FPN1/K_C2S";
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, k1, sizeof(k1));
        blake3_hasher_update(&h, shared, 32);
        blake3_hasher_update(&h, out_th, 32);
        blake3_hasher_finalize(&h, out_c2s, 32);

        static const uint8_t k2[11] = "FPN1/K_S2C";
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, k2, sizeof(k2));
        blake3_hasher_update(&h, shared, 32);
        blake3_hasher_update(&h, out_th, 32);
        blake3_hasher_finalize(&h, out_s2c, 32);
    }
}

static fp_err_t handshake_client(fp_chan_t *ch, const fp_keypair_t *c_kp,
                                 const uint8_t expected_s_pk[FP_PK_LEN]) {
    uint8_t c_eph_pk[32], c_eph_sk[32], c_nonce[16];
    randombytes_buf(c_eph_sk, sizeof(c_eph_sk));
    crypto_scalarmult_base(c_eph_pk, c_eph_sk);
    randombytes_buf(c_nonce, sizeof(c_nonce));

    uint8_t c_msg[13 + 32 + 32 + 16];
    memcpy(c_msg, "FPN1/C_HELLO", 13);
    memcpy(c_msg + 13, c_kp->pk, 32);
    memcpy(c_msg + 45, c_eph_pk, 32);
    memcpy(c_msg + 77, c_nonce, 16);

    uint8_t hello[FP_NET_HELLO_LEN];
    memcpy(hello, "FPN1", 4);
    memcpy(hello + 4, c_kp->pk, 32);
    memcpy(hello + 36, c_eph_pk, 32);
    memcpy(hello + 68, c_nonce, 16);
    unsigned long long siglen = 0;
    crypto_sign_ed25519_detached(hello + 84, &siglen, c_msg, sizeof(c_msg), c_kp->sk);

    fp_err_t err = send_all(ch->fd, hello, sizeof(hello));
    if (err != FP_OK) { sodium_memzero(c_eph_sk, sizeof(c_eph_sk)); return err; }
    ch->bytes_tx += sizeof(hello);

    uint8_t srv[FP_NET_HELLO_LEN];
    err = recv_all(ch->fd, srv, sizeof(srv));
    if (err != FP_OK) { sodium_memzero(c_eph_sk, sizeof(c_eph_sk)); return err; }
    ch->bytes_rx += sizeof(srv);

    if (memcmp(srv, "FPN1", 4) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        return FP_ERR_INVALID;
    }
    const uint8_t *s_pk = srv + 4;
    const uint8_t *s_eph_pk = srv + 36;
    const uint8_t *s_nonce = srv + 68;
    const uint8_t *s_sig = srv + 84;

    if (expected_s_pk && sodium_memcmp(s_pk, expected_s_pk, FP_PK_LEN) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        return FP_ERR_SIGNATURE;
    }

    uint8_t shared[32];
    if (crypto_scalarmult(shared, c_eph_sk, s_eph_pk) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        return FP_ERR_SIGNATURE;
    }
    sodium_memzero(c_eph_sk, sizeof(c_eph_sk));

    uint8_t th[32], k_c2s[32], k_s2c[32];
    derive_transcript_and_keys(c_kp->pk, c_eph_pk, c_nonce, s_pk, s_eph_pk, s_nonce,
                               shared, th, k_c2s, k_s2c);
    sodium_memzero(shared, sizeof(shared));

    uint8_t s_msg[13 + 32];
    memcpy(s_msg, "FPN1/S_HELLO", 13);
    memcpy(s_msg + 13, th, 32);
    if (crypto_sign_ed25519_verify_detached(s_sig, s_msg, sizeof(s_msg), s_pk) != 0) {
        sodium_memzero(k_c2s, sizeof(k_c2s));
        sodium_memzero(k_s2c, sizeof(k_s2c));
        return FP_ERR_SIGNATURE;
    }

    memcpy(ch->tx_key, k_c2s, 32);
    memcpy(ch->rx_key, k_s2c, 32);
    memcpy(ch->peer_pk, s_pk, 32);
    ch->tx_seq = 0;
    ch->rx_seq = 0;
    sodium_memzero(k_c2s, sizeof(k_c2s));
    sodium_memzero(k_s2c, sizeof(k_s2c));
    return FP_OK;
}

static fp_err_t handshake_server(fp_chan_t *ch, const fp_keypair_t *s_kp,
                                 const uint8_t allowed_c_pk[FP_PK_LEN]) {
    uint8_t cli[FP_NET_HELLO_LEN];
    fp_err_t err = recv_all(ch->fd, cli, sizeof(cli));
    if (err != FP_OK) return err;
    ch->bytes_rx += sizeof(cli);

    if (memcmp(cli, "FPN1", 4) != 0) return FP_ERR_INVALID;
    const uint8_t *c_pk = cli + 4;
    const uint8_t *c_eph_pk = cli + 36;
    const uint8_t *c_nonce = cli + 68;
    const uint8_t *c_sig = cli + 84;

    if (allowed_c_pk && sodium_memcmp(c_pk, allowed_c_pk, FP_PK_LEN) != 0) {
        return FP_ERR_SIGNATURE;
    }

    uint8_t c_msg[13 + 32 + 32 + 16];
    memcpy(c_msg, "FPN1/C_HELLO", 13);
    memcpy(c_msg + 13, c_pk, 32);
    memcpy(c_msg + 45, c_eph_pk, 32);
    memcpy(c_msg + 77, c_nonce, 16);
    if (crypto_sign_ed25519_verify_detached(c_sig, c_msg, sizeof(c_msg), c_pk) != 0) {
        return FP_ERR_SIGNATURE;
    }

    uint8_t s_eph_pk[32], s_eph_sk[32], s_nonce[16];
    randombytes_buf(s_eph_sk, sizeof(s_eph_sk));
    crypto_scalarmult_base(s_eph_pk, s_eph_sk);
    randombytes_buf(s_nonce, sizeof(s_nonce));

    uint8_t shared[32];
    if (crypto_scalarmult(shared, s_eph_sk, c_eph_pk) != 0) {
        sodium_memzero(s_eph_sk, sizeof(s_eph_sk));
        return FP_ERR_SIGNATURE;
    }
    sodium_memzero(s_eph_sk, sizeof(s_eph_sk));

    uint8_t th[32], k_c2s[32], k_s2c[32];
    derive_transcript_and_keys(c_pk, c_eph_pk, c_nonce, s_kp->pk, s_eph_pk, s_nonce,
                               shared, th, k_c2s, k_s2c);
    sodium_memzero(shared, sizeof(shared));

    uint8_t s_msg[13 + 32];
    memcpy(s_msg, "FPN1/S_HELLO", 13);
    memcpy(s_msg + 13, th, 32);

    uint8_t reply[FP_NET_HELLO_LEN];
    memcpy(reply, "FPN1", 4);
    memcpy(reply + 4, s_kp->pk, 32);
    memcpy(reply + 36, s_eph_pk, 32);
    memcpy(reply + 68, s_nonce, 16);
    unsigned long long siglen = 0;
    crypto_sign_ed25519_detached(reply + 84, &siglen, s_msg, sizeof(s_msg), s_kp->sk);

    err = send_all(ch->fd, reply, sizeof(reply));
    if (err != FP_OK) {
        sodium_memzero(k_c2s, sizeof(k_c2s));
        sodium_memzero(k_s2c, sizeof(k_s2c));
        return err;
    }
    ch->bytes_tx += sizeof(reply);

    memcpy(ch->tx_key, k_s2c, 32);
    memcpy(ch->rx_key, k_c2s, 32);
    memcpy(ch->peer_pk, c_pk, 32);
    ch->tx_seq = 0;
    ch->rx_seq = 0;
    sodium_memzero(k_c2s, sizeof(k_c2s));
    sodium_memzero(k_s2c, sizeof(k_s2c));
    return FP_OK;
}

static fp_err_t chan_send(fp_chan_t *ch, uint8_t msg_type,
                          const uint8_t *body, size_t body_len) {
    if (body_len + 1u > FP_NET_MAX_PLAINTEXT || ch->tx_seq == UINT64_MAX) {
        return FP_ERR_BOUNDS;
    }
    size_t pt_len = 1u + body_len;
    uint8_t *pt = malloc(pt_len);
    uint8_t *frame = malloc(4u + pt_len + FP_NET_AEAD_ABYTES);
    if (!pt || !frame) {
        free(pt); free(frame);
        return FP_ERR_NOMEM;
    }
    pt[0] = msg_type;
    if (body_len > 0) memcpy(pt + 1, body, body_len);

    uint8_t nonce[24];
    memset(nonce, 0, sizeof(nonce));
    put_be64(nonce, ch->tx_seq);

    uint8_t ad[12];
    put_be64(ad, ch->tx_seq);
    put_be32(ad + 8, (uint32_t)pt_len);

    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        frame + 4, &ct_len, pt, pt_len, ad, sizeof(ad), NULL, nonce, ch->tx_key);
    free(pt);

    put_be32(frame, (uint32_t)ct_len);
    fp_err_t err = send_all(ch->fd, frame, 4u + (size_t)ct_len);
    free(frame);
    if (err != FP_OK) return err;

    ch->tx_seq++;
    ch->bytes_tx += 4u + (uint64_t)ct_len;
    return FP_OK;
}

static fp_err_t chan_recv(fp_chan_t *ch, uint8_t *out_type,
                          uint8_t **out_body, size_t *out_len) {
    *out_body = NULL;
    *out_len = 0;

    uint8_t lbuf[4];
    fp_err_t err = recv_all(ch->fd, lbuf, 4);
    if (err != FP_OK) return err;
    uint32_t ct_len = get_be32(lbuf);
    if (ct_len < FP_NET_AEAD_ABYTES + 1u ||
        ct_len > FP_NET_MAX_PLAINTEXT + FP_NET_AEAD_ABYTES ||
        ch->rx_seq == UINT64_MAX) {
        return FP_ERR_BOUNDS;
    }

    uint8_t *ct = malloc(ct_len);
    size_t pt_cap = ct_len - FP_NET_AEAD_ABYTES;
    uint8_t *pt = malloc(pt_cap);
    if (!ct || !pt) { free(ct); free(pt); return FP_ERR_NOMEM; }

    err = recv_all(ch->fd, ct, ct_len);
    if (err != FP_OK) { free(ct); free(pt); return err; }
    ch->bytes_rx += 4u + (uint64_t)ct_len;

    uint8_t nonce[24];
    memset(nonce, 0, sizeof(nonce));
    put_be64(nonce, ch->rx_seq);

    uint8_t ad[12];
    put_be64(ad, ch->rx_seq);
    put_be32(ad + 8, (uint32_t)pt_cap);

    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &pt_len, NULL, ct, ct_len, ad, sizeof(ad), nonce, ch->rx_key) != 0 ||
        pt_len < 1u) {
        free(ct); free(pt);
        return FP_ERR_SIGNATURE;
    }
    free(ct);
    ch->rx_seq++;

    *out_type = pt[0];
    size_t blen = (size_t)pt_len - 1u;
    if (blen > 0) {
        memmove(pt, pt + 1, blen);
        *out_body = pt;
    } else {
        free(pt);
        *out_body = NULL;
    }
    *out_len = blen;
    return FP_OK;
}

/* --- Merkle Chunk Wire Encoding ---
 * chunk_index (8) | total_size (8) | chunk_len (4) | depth (1)
 * is_right[depth] | siblings[depth * 32] | chunk_bytes[chunk_len]
 */
static fp_err_t encode_chunk_msg(const fp_merkle_proof_t *proof,
                                 const uint8_t *chunk_data,
                                 uint8_t **out, size_t *out_len) {
    if (proof->depth > FP_MAX_PROOF_DEPTH) return FP_ERR_BOUNDS;
    size_t hdr = 8u + 8u + 4u + 1u + proof->depth + (size_t)proof->depth * FP_DNA_LEN;
    size_t total = hdr + proof->chunk_len;
    uint8_t *buf = malloc(total);
    if (!buf) return FP_ERR_NOMEM;
    size_t p = 0;
    put_be64(buf + p, proof->chunk_index); p += 8;
    put_be64(buf + p, proof->total_size); p += 8;
    put_be32(buf + p, proof->chunk_len); p += 4;
    buf[p++] = (uint8_t)proof->depth;
    for (uint32_t i = 0; i < proof->depth; i++) buf[p++] = proof->is_right[i];
    for (uint32_t i = 0; i < proof->depth; i++) {
        memcpy(buf + p, proof->siblings[i], FP_DNA_LEN);
        p += FP_DNA_LEN;
    }
    memcpy(buf + p, chunk_data, proof->chunk_len);
    *out = buf;
    *out_len = total;
    return FP_OK;
}

static fp_err_t decode_chunk_msg(const uint8_t *buf, size_t len,
                                 fp_merkle_proof_t *proof,
                                 const uint8_t **out_data) {
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

/* --- Server Logic: Autonomous Morph Negotiation & Pipelined Streaming --- */

static fp_err_t send_error(fp_chan_t *ch, fp_err_t code) {
    uint8_t b[4];
    put_be32(b, (uint32_t)(int32_t)code);
    return chan_send(ch, MSG_ERR, b, sizeof(b));
}

static fp_err_t pread_exact(int fd, uint8_t *buf, size_t len, off_t off) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = pread(fd, buf + pos, len - pos, off + (off_t)pos);
        if (n < 0) { if (errno == EINTR) continue; return FP_ERR_IO; }
        if (n == 0) return FP_ERR_IO;
        pos += (size_t)n;
    }
    return FP_OK;
}

static fp_err_t handle_client(int cfd, const fp_net_server_cfg_t *cfg, fp_morph_ctx_t *mctx) {
    set_socket_opts(cfd, cfg->io_timeout_ms);
    fp_chan_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fd = cfd;

    fp_err_t err = handshake_server(&ch, cfg->server_kp, cfg->allowed_peer_pk);
    if (err != FP_OK) { chan_wipe(&ch); return err; }

    uint8_t mtype = 0;
    uint8_t *body = NULL;
    size_t blen = 0;
    err = chan_recv(&ch, &mtype, &body, &blen);
    if (err != FP_OK) { chan_wipe(&ch); return err; }

    /* Handle persistent Swarm session (zero-malloc pread() Multi-GB capable!) */
    if (mtype == MSG_SWARM_OPEN) {
        if (blen != FP_DNA_LEN) {
            free(body);
            send_error(&ch, FP_ERR_INVALID);
            chan_wipe(&ch);
            return FP_ERR_INVALID;
        }
        fp_dna_t s_dna;
        memcpy(s_dna.bytes, body, FP_DNA_LEN);
        free(body);

        char spath[PATH_MAX];
        uint64_t sobj_len = 0;
        int sfd = fp_store_open_object_fd(cfg->store_dir, &s_dna, spath, sizeof(spath), &sobj_len);
        if (sfd < 0) {
            send_error(&ch, FP_ERR_NOT_FOUND);
            chan_wipe(&ch);
            return FP_ERR_NOT_FOUND;
        }
        uint64_t stotal = sobj_len > 0 ? (sobj_len + FP_CHUNK_SIZE - 1u) / FP_CHUNK_SIZE : 0;
        fp_merkle_tree_t *stree = stotal > 0 ? fp_merkle_tree_build_file(spath, NULL) : NULL;
        if (stotal > 0) {
            if (!stree) {
                close(sfd); send_error(&ch, FP_ERR_NOMEM); chan_wipe(&ch); return FP_ERR_NOMEM;
            }
            fp_dna_t check = fp_merkle_tree_dna(stree);
            if (!fp_dna_equal(&check, &s_dna)) {
                fp_merkle_tree_free(stree); close(sfd);
                send_error(&ch, FP_ERR_INTEGRITY); chan_wipe(&ch); return FP_ERR_INTEGRITY;
            }
        }

        uint8_t soffer[57];
        memset(soffer, 0, sizeof(soffer));
        soffer[0] = (uint8_t)FP_NET_MODE_MERKLE_STREAM;
        put_be64(soffer + 1, sobj_len);
        put_be64(soffer + 9, stotal);
        err = chan_send(&ch, MSG_OFFER, soffer, sizeof(soffer));

        uint8_t chunk_buf[FP_CHUNK_SIZE];
        while (err == FP_OK) {
            uint8_t rt = 0;
            uint8_t *rb = NULL;
            size_t rl = 0;
            err = chan_recv(&ch, &rt, &rb, &rl);
            if (err != FP_OK) break;
            if (rt == MSG_ACK) { free(rb); break; }
            if (rt != MSG_SWARM_RANGE || rl != 16u) {
                free(rb);
                err = FP_ERR_INVALID;
                break;
            }
            uint64_t start_c = get_be64(rb);
            uint64_t cnt = get_be64(rb + 8);
            free(rb);

            if (start_c > stotal || cnt > stotal - start_c || cnt > 64u) {
                err = FP_ERR_BOUNDS;
                break;
            }
            for (uint64_t k = 0; k < cnt && err == FP_OK; k++) {
                uint64_t ci = start_c + k;
                fp_merkle_proof_t proof;
                err = fp_merkle_tree_prove(stree, ci, &proof);
                if (err != FP_OK) break;

                err = pread_exact(sfd, chunk_buf, proof.chunk_len, (off_t)(ci * FP_CHUNK_SIZE));
                if (err != FP_OK) break;

                uint8_t *cmsg = NULL;
                size_t clen = 0;
                err = encode_chunk_msg(&proof, chunk_buf, &cmsg, &clen);
                if (err != FP_OK) break;

                if (cfg->fault_corrupt_chunk > 0 && (ci + 1u) == cfg->fault_corrupt_chunk) {
                    cmsg[clen - 1u] ^= 0x01u; /* Poisoned Byzantine peer fault */
                }
                err = chan_send(&ch, MSG_CHUNK, cmsg, clen);
                free(cmsg);
            }
            if (err == FP_OK) err = chan_send(&ch, MSG_DONE, NULL, 0);
        }

        fp_merkle_tree_free(stree);
        close(sfd);
        chan_wipe(&ch);
        return err;
    }

    /* MSG_WANT: target_dna (32) | have_chunks (8) | flags (1) | ref_count (1) | refs[ref_count*32] */
    if (mtype != MSG_WANT || blen < 42u) {
        free(body);
        send_error(&ch, FP_ERR_INVALID);
        chan_wipe(&ch);
        return FP_ERR_INVALID;
    }
    fp_dna_t target_dna;
    memcpy(target_dna.bytes, body, 32);
    uint64_t have_chunks = get_be64(body + 32);
    uint8_t want_flags = body[40];
    uint8_t ref_count = body[41];
    if (ref_count > FP_NET_MAX_REFS || blen != 42u + (size_t)ref_count * FP_DNA_LEN) {
        free(body);
        send_error(&ch, FP_ERR_INVALID);
        chan_wipe(&ch);
        return FP_ERR_INVALID;
    }
    fp_dna_t refs[FP_NET_MAX_REFS];
    for (uint8_t i = 0; i < ref_count; i++) {
        memcpy(refs[i].bytes, body + 42u + (size_t)i * FP_DNA_LEN, FP_DNA_LEN);
    }
    free(body);

    char obj_path[PATH_MAX];
    uint64_t obj_size = 0;
    int obj_fd = fp_store_open_object_fd(cfg->store_dir, &target_dna, obj_path, sizeof(obj_path), &obj_size);
    if (obj_fd < 0) {
        send_error(&ch, FP_ERR_NOT_FOUND);
        chan_wipe(&ch);
        return FP_ERR_NOT_FOUND;
    }

    int force_stream = (want_flags & 0x01u) != 0;
    uint64_t total_chunks = obj_size > 0 ? (obj_size + FP_CHUNK_SIZE - 1u) / FP_CHUNK_SIZE : 0;

    /* Autonomous Morph Selection */
    fp_net_mode_t mode = FP_NET_MODE_MERKLE_STREAM;
    fp_dna_t chosen_ref;
    memset(&chosen_ref, 0, sizeof(chosen_ref));
    uint8_t *morph_wire = NULL;
    size_t morph_wire_len = 0;

    /* 1. Check REF (client already holds exact target_dna!) */
    int has_exact = 0;
    for (uint8_t i = 0; i < ref_count; i++) {
        if (fp_dna_equal(&refs[i], &target_dna)) {
            has_exact = 1;
            break;
        }
    }

    if (has_exact && !force_stream) {
        mode = FP_NET_MODE_REF;
        chosen_ref = target_dna;
    } else if (have_chunks > 0 && have_chunks <= total_chunks) {
        /* 2. Partial verified staging exists on client -> Resume Merkle stream (zero-malloc pread)! */
        mode = FP_NET_MODE_MERKLE_STREAM;
    } else if (!force_stream && obj_size > 0 && obj_size <= FP_NET_DEFAULT_MAX_OUTPUT) {
        /* 3. For <= 128 MiB objects, check DELTA or ZSTD */
        uint8_t *obj = NULL;
        size_t obj_len = 0;
        if (fp_store_get_object(cfg->store_dir, &target_dna, FP_NET_DEFAULT_MAX_OUTPUT, &obj, &obj_len) == FP_OK) {
            for (uint8_t i = 0; i < ref_count; i++) {
                uint64_t rsz = 0;
                if (!fp_store_has_object(cfg->store_dir, &refs[i], &rsz) ||
                    rsz == 0 || rsz > FP_NET_DEFAULT_MAX_OUTPUT) {
                    continue;
                }
                uint8_t *ref_buf = NULL;
                size_t ref_len = 0;
                if (fp_store_get_object(cfg->store_dir, &refs[i], FP_NET_DEFAULT_MAX_OUTPUT,
                                        &ref_buf, &ref_len) == FP_OK) {
                    uint8_t *dw = NULL;
                    size_t dl = 0;
                    if (fp_morph_encode(mctx, FP_MORPH_DELTA, obj, obj_len,
                                        ref_buf, ref_len, 3, &dw, &dl) == FP_OK) {
                        if (dl < (obj_len * 85u) / 100u) {
                            mode = FP_NET_MODE_DELTA;
                            chosen_ref = refs[i];
                            morph_wire = dw;
                            morph_wire_len = dl;
                            free(ref_buf);
                            break;
                        }
                        free(dw);
                    }
                    free(ref_buf);
                }
            }
            if (mode == FP_NET_MODE_MERKLE_STREAM && obj_len <= (4u << 20)) {
                uint8_t *zw = NULL;
                size_t zl = 0;
                if (fp_morph_encode(mctx, FP_MORPH_ZSTD, obj, obj_len, NULL, 0, 3, &zw, &zl) == FP_OK) {
                    if (zl < (obj_len * 85u) / 100u) {
                        mode = FP_NET_MODE_ZSTD;
                        morph_wire = zw;
                        morph_wire_len = zl;
                    } else {
                        free(zw);
                    }
                }
            }
            free(obj);
        }
    }

    /* Send MSG_OFFER: mode (1) | canonical_size (8) | total_chunks (8) | wire_len (8) | ref_dna (32) */
    uint8_t offer[1u + 8u + 8u + 8u + 32u];
    offer[0] = (uint8_t)mode;
    put_be64(offer + 1, obj_size);
    put_be64(offer + 9, total_chunks);
    put_be64(offer + 17, morph_wire_len);
    memcpy(offer + 25, chosen_ref.bytes, FP_DNA_LEN);
    err = chan_send(&ch, MSG_OFFER, offer, sizeof(offer));

    if (err == FP_OK && (mode == FP_NET_MODE_DELTA || mode == FP_NET_MODE_ZSTD)) {
        size_t pos = 0;
        while (pos < morph_wire_len && err == FP_OK) {
            size_t take = morph_wire_len - pos;
            if (take > FP_NET_SLICE_SIZE) take = FP_NET_SLICE_SIZE;
            err = chan_send(&ch, MSG_DATA, morph_wire + pos, take);
            pos += take;
        }
    } else if (err == FP_OK && mode == FP_NET_MODE_MERKLE_STREAM && total_chunks > 0) {
        /* Multi-GB streaming server path: zero file-size malloc(), reads 16 KiB via pread() */
        fp_merkle_tree_t *tree = fp_merkle_tree_build_file(obj_path, NULL);
        if (!tree) {
            err = FP_ERR_NOMEM;
        } else {
            fp_dna_t actual = fp_merkle_tree_dna(tree);
            if (!fp_dna_equal(&actual, &target_dna)) {
                err = FP_ERR_INTEGRITY;
            }
            uint8_t chunk_buf[FP_CHUNK_SIZE];
            uint64_t sent_in_session = 0;
            for (uint64_t ci = have_chunks; ci < total_chunks && err == FP_OK; ci++) {
                if (cfg->fault_drop_after_chunks > 0 && sent_in_session >= cfg->fault_drop_after_chunks) {
                    err = FP_ERR_IO;
                    break;
                }
                fp_merkle_proof_t proof;
                err = fp_merkle_tree_prove(tree, ci, &proof);
                if (err != FP_OK) break;

                err = pread_exact(obj_fd, chunk_buf, proof.chunk_len, (off_t)(ci * FP_CHUNK_SIZE));
                if (err != FP_OK) break;

                uint8_t *cmsg = NULL;
                size_t clen = 0;
                err = encode_chunk_msg(&proof, chunk_buf, &cmsg, &clen);
                if (err != FP_OK) break;

                if (cfg->fault_corrupt_chunk > 0 && (ci + 1u) == cfg->fault_corrupt_chunk) {
                    cmsg[clen - 1u] ^= 0x01u;
                }
                err = chan_send(&ch, MSG_CHUNK, cmsg, clen);
                free(cmsg);
                sent_in_session++;
            }
            fp_merkle_tree_free(tree);
        }
    }

    free(morph_wire);
    close(obj_fd);

    if (err == FP_OK) {
        err = chan_send(&ch, MSG_DONE, NULL, 0);
    }
    if (err == FP_OK) {
        uint8_t ack_type = 0;
        uint8_t *ack_body = NULL;
        size_t ack_len = 0;
        err = chan_recv(&ch, &ack_type, &ack_body, &ack_len);
        free(ack_body);
        if (err == FP_OK && ack_type != MSG_ACK) err = FP_ERR_INTEGRITY;
    }

    chan_wipe(&ch);
    return err;
}

int fp_net_listen(const char *bind_addr, uint16_t port, uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!bind_addr || bind_addr[0] == '\0') {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    if (out_port) {
        socklen_t alen = sizeof(addr);
        if (getsockname(fd, (struct sockaddr *)&addr, &alen) == 0) {
            *out_port = ntohs(addr.sin_port);
        }
    }
    return fd;
}

fp_err_t fp_net_serve_fd(int listen_fd, const fp_net_server_cfg_t *cfg) {
    if (listen_fd < 0 || !cfg || !cfg->store_dir || !cfg->server_kp) {
        return FP_ERR_INVALID;
    }
    fp_morph_ctx_t *mctx = fp_morph_ctx_new();
    if (!mctx) return FP_ERR_NOMEM;

    uint32_t served = 0;
    while (cfg->max_requests == 0 || served < cfg->max_requests) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            fp_morph_ctx_free(mctx);
            return FP_ERR_IO;
        }
        (void)handle_client(cfd, cfg, mctx);
        close(cfd);
        served++;
    }
    fp_morph_ctx_free(mctx);
    return FP_OK;
}

/* --- Client Logic: Pull with Autonomous Morph & Resumable Merkle Streaming --- */

static int connect_tcp(const char *host, uint16_t port, int timeout_ms) {
    char pstr[16];
    snprintf(pstr, sizeof(pstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, pstr, &hints, &res) != 0 || !res) {
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    set_socket_opts(fd, timeout_ms);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static fp_err_t ensure_dir_net(const char *p) {
    if (mkdir(p, 0700) == 0 || errno == EEXIST) return FP_OK;
    return FP_ERR_IO;
}

static void add_unique_ref(fp_dna_t list[FP_NET_MAX_REFS], size_t *count, const fp_dna_t *dna) {
    if (*count >= FP_NET_MAX_REFS) return;
    for (size_t i = 0; i < *count; i++) {
        if (fp_dna_equal(&list[i], dna)) return;
    }
    list[(*count)++] = *dna;
}

fp_err_t fp_net_pull(const fp_net_pull_cfg_t *cfg, fp_net_stats_t *out_stats) {
    if (!cfg || !cfg->host || cfg->port == 0 || !cfg->store_dir ||
        !cfg->client_kp || !cfg->expected_srv_pk) {
        return FP_ERR_INVALID;
    }
    uint64_t t0 = now_ns();
    size_t max_out = cfg->max_output > 0 ? cfg->max_output : FP_NET_DEFAULT_MAX_OUTPUT;

    /* Collect candidate refs from local Store + caller hints */
    fp_dna_t refs[FP_NET_MAX_REFS];
    size_t ref_count = 0;
    if (fp_store_has_object(cfg->store_dir, &cfg->target_dna, NULL)) {
        add_unique_ref(refs, &ref_count, &cfg->target_dna);
    }
    for (size_t i = 0; i < cfg->extra_ref_count && i < FP_NET_MAX_REFS; i++) {
        if (fp_store_has_object(cfg->store_dir, &cfg->extra_refs[i], NULL)) {
            add_unique_ref(refs, &ref_count, &cfg->extra_refs[i]);
        }
    }
    fp_store_state_t st;
    if (fp_store_load_state(cfg->store_dir, &st) == FP_OK) {
        if (st.has_current && fp_store_has_object(cfg->store_dir, &st.current_dna, NULL)) {
            add_unique_ref(refs, &ref_count, &st.current_dna);
        }
        for (uint32_t i = st.installed_count; i > 0 && ref_count < FP_NET_MAX_REFS; i--) {
            if (fp_store_has_object(cfg->store_dir, &st.installed[i - 1], NULL)) {
                add_unique_ref(refs, &ref_count, &st.installed[i - 1]);
            }
        }
    }

    /* Check resumable staging file (staging/<dna>.part) */
    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(cfg->target_dna.bytes, FP_DNA_LEN, hex);
    char stage_dir[PATH_MAX], stage_path[PATH_MAX];
    int sn1 = snprintf(stage_dir, sizeof(stage_dir), "%s/staging", cfg->store_dir);
    int sn2 = snprintf(stage_path, sizeof(stage_path), "%s/staging/%s.part", cfg->store_dir, hex);
    if (sn1 < 0 || (size_t)sn1 >= sizeof(stage_dir) ||
        sn2 < 0 || (size_t)sn2 >= sizeof(stage_path)) {
        return FP_ERR_BOUNDS;
    }

    uint64_t have_chunks = 0;
    struct stat pst;
    if (stat(stage_path, &pst) == 0 && S_ISREG(pst.st_mode) && pst.st_size > 0) {
        have_chunks = (uint64_t)pst.st_size / FP_CHUNK_SIZE;
    }

    int fd = connect_tcp(cfg->host, cfg->port, cfg->io_timeout_ms);
    if (fd < 0) return FP_ERR_IO;

    fp_chan_t ch;
    memset(&ch, 0, sizeof(ch));
    ch.fd = fd;

    fp_err_t err = handshake_client(&ch, cfg->client_kp, cfg->expected_srv_pk);
    if (err != FP_OK) { chan_wipe(&ch); close(fd); return err; }

    /* Send MSG_WANT */
    uint8_t want[42u + FP_NET_MAX_REFS * FP_DNA_LEN];
    memcpy(want, cfg->target_dna.bytes, 32);
    put_be64(want + 32, have_chunks);
    want[40] = cfg->force_merkle_stream ? 0x01u : 0x00u;
    want[41] = (uint8_t)ref_count;
    for (size_t i = 0; i < ref_count; i++) {
        memcpy(want + 42u + i * FP_DNA_LEN, refs[i].bytes, FP_DNA_LEN);
    }
    err = chan_send(&ch, MSG_WANT, want, 42u + ref_count * FP_DNA_LEN);
    if (err != FP_OK) { chan_wipe(&ch); close(fd); return err; }

    /* Receive MSG_OFFER */
    uint8_t mtype = 0;
    uint8_t *obody = NULL;
    size_t olen = 0;
    err = chan_recv(&ch, &mtype, &obody, &olen);
    if (err != FP_OK) { chan_wipe(&ch); close(fd); return err; }

    if (mtype == MSG_ERR) {
        fp_err_t remote_err = olen == 4u ? (fp_err_t)(int32_t)get_be32(obody) : FP_ERR_IO;
        free(obody);
        chan_wipe(&ch);
        close(fd);
        return remote_err;
    }
    if (mtype != MSG_OFFER || olen != 57u) {
        free(obody);
        chan_wipe(&ch);
        close(fd);
        return FP_ERR_INVALID;
    }

    fp_net_mode_t mode = (fp_net_mode_t)obody[0];
    uint64_t canonical_size = get_be64(obody + 1);
    uint64_t total_chunks = get_be64(obody + 9);
    uint64_t morph_wire_len = get_be64(obody + 17);
    fp_dna_t ref_dna;
    memcpy(ref_dna.bytes, obody + 25, FP_DNA_LEN);
    free(obody);

    if (canonical_size > max_out) {
        chan_wipe(&ch); close(fd); return FP_ERR_BOUNDS;
    }
    uint64_t expected_chunks = canonical_size > 0
        ? (1u + (canonical_size - 1u) / FP_CHUNK_SIZE) : 0u;
    if (total_chunks != expected_chunks) {
        chan_wipe(&ch); close(fd); return FP_ERR_BOUNDS;
    }

    uint64_t received_chunks = 0;
    uint64_t resumed_chunks = 0;

    if (mode == FP_NET_MODE_REF) {
        /* Wait for MSG_DONE, then stream-verify local object in O(1) RAM (Multi-GB safe!) */
        err = chan_recv(&ch, &mtype, &obody, &olen);
        free(obody);
        if (err == FP_OK && mtype != MSG_DONE) err = FP_ERR_INVALID;
        if (err == FP_OK) {
            char local_path[PATH_MAX];
            uint64_t local_sz = 0;
            int lfd = fp_store_open_object_fd(cfg->store_dir, &cfg->target_dna,
                                              local_path, sizeof(local_path), &local_sz);
            if (lfd < 0) {
                err = FP_ERR_NOT_FOUND;
            } else {
                close(lfd);
                fp_dna_t actual;
                uint64_t verified_sz = 0;
                err = fp_dna_compute_file(local_path, &actual, &verified_sz);
                if (err == FP_OK && (verified_sz != canonical_size ||
                                     !fp_dna_equal(&actual, &cfg->target_dna))) {
                    err = FP_ERR_INTEGRITY;
                }
            }
        }
    } else if (mode == FP_NET_MODE_DELTA || mode == FP_NET_MODE_ZSTD) {
        size_t morph_cap = max_out < FP_NET_DEFAULT_MAX_OUTPUT ? max_out : FP_NET_DEFAULT_MAX_OUTPUT;
        if (morph_wire_len == 0 || morph_wire_len > (uint64_t)morph_cap + (1u << 20)) {
            chan_wipe(&ch); close(fd); return FP_ERR_BOUNDS;
        }
        uint8_t *wire = malloc((size_t)morph_wire_len);
        if (!wire) { chan_wipe(&ch); close(fd); return FP_ERR_NOMEM; }

        size_t pos = 0;
        while (err == FP_OK) {
            err = chan_recv(&ch, &mtype, &obody, &olen);
            if (err != FP_OK) break;
            if (mtype == MSG_DONE) { free(obody); break; }
            if (mtype != MSG_DATA || pos + olen > morph_wire_len) {
                free(obody);
                err = FP_ERR_BOUNDS;
                break;
            }
            memcpy(wire + pos, obody, olen);
            pos += olen;
            free(obody);
        }
        if (err == FP_OK && pos != morph_wire_len) err = FP_ERR_INTEGRITY;

        if (err == FP_OK) {
            uint8_t *ref_buf = NULL;
            size_t ref_len = 0;
            if (mode == FP_NET_MODE_DELTA) {
                err = fp_store_get_object(cfg->store_dir, &ref_dna, max_out, &ref_buf, &ref_len);
            }
            if (err == FP_OK) {
                fp_morph_ctx_t *mctx = fp_morph_ctx_new();
                uint8_t *canonical = NULL;
                size_t clen = 0;
                fp_dna_t actual;
                if (!mctx) {
                    err = FP_ERR_NOMEM;
                } else {
                    err = fp_morph_materialize(mctx, wire, (size_t)morph_wire_len,
                                               ref_buf, ref_len, max_out,
                                               &canonical, &clen, &actual);
                    fp_morph_ctx_free(mctx);
                }
                if (err == FP_OK) {
                    if (clen != canonical_size || !fp_dna_equal(&actual, &cfg->target_dna)) {
                        err = FP_ERR_INTEGRITY;
                    } else {
                        err = fp_store_put_object(cfg->store_dir, canonical, clen, NULL);
                    }
                }
                free(canonical);
            }
            free(ref_buf);
        }
        free(wire);
    } else if (mode == FP_NET_MODE_MERKLE_STREAM) {
        if (ensure_dir_net(cfg->store_dir) != FP_OK || ensure_dir_net(stage_dir) != FP_OK) {
            chan_wipe(&ch); close(fd); return FP_ERR_IO;
        }
        int sfd = open(stage_path, O_CREAT | O_RDWR, 0600);
        if (sfd < 0) { chan_wipe(&ch); close(fd); return FP_ERR_IO; }

        /* Truncate any incomplete trailing partial chunk from a prior crash */
        uint64_t resume_bytes = have_chunks * FP_CHUNK_SIZE;
        if (resume_bytes > canonical_size) {
            have_chunks = 0;
            resume_bytes = 0;
        }
        if (ftruncate(sfd, (off_t)resume_bytes) != 0 ||
            lseek(sfd, (off_t)resume_bytes, SEEK_SET) != (off_t)resume_bytes) {
            close(sfd); chan_wipe(&ch); close(fd); return FP_ERR_IO;
        }
        resumed_chunks = have_chunks;

        uint64_t expected_idx = have_chunks;
        while (err == FP_OK) {
            err = chan_recv(&ch, &mtype, &obody, &olen);
            if (err != FP_OK) break;
            if (mtype == MSG_DONE) { free(obody); break; }
            if (mtype != MSG_CHUNK) {
                free(obody);
                err = FP_ERR_INVALID;
                break;
            }
            fp_merkle_proof_t proof;
            const uint8_t *cdata = NULL;
            err = decode_chunk_msg(obody, olen, &proof, &cdata);
            if (err == FP_OK) {
                if (proof.chunk_index != expected_idx || proof.total_size != canonical_size) {
                    err = FP_ERR_INTEGRITY;
                } else {
                    /* VERIFY CHUNK AGAINST ROOT DNA BEFORE TOUCHING DISK! */
                    err = fp_merkle_verify(&cfg->target_dna, &proof, cdata, proof.chunk_len);
                }
            }
            if (err == FP_OK) {
                size_t wr = 0;
                while (wr < proof.chunk_len) {
                    ssize_t n = write(sfd, cdata + wr, proof.chunk_len - wr);
                    if (n < 0) {
                        if (errno == EINTR) continue;
                        err = FP_ERR_IO;
                        break;
                    }
                    wr += (size_t)n;
                }
            }
            free(obody);
            if (err != FP_OK) break;

            expected_idx++;
            received_chunks++;
            if ((received_chunks % FP_NET_FSYNC_INTERVAL) == 0) {
                if (fsync(sfd) != 0) { err = FP_ERR_IO; break; }
            }
        }

        if (fsync(sfd) != 0 && err == FP_OK) err = FP_ERR_IO;
        close(sfd);

        if (err == FP_OK) {
            if (expected_idx != total_chunks) {
                err = FP_ERR_INTEGRITY;
            } else {
                /* Final whole-file streaming DNA check (protects resumed prefix too!) */
                fp_dna_t final_dna;
                uint64_t final_sz = 0;
                err = fp_dna_compute_file(stage_path, &final_dna, &final_sz);
                if (err == FP_OK && (final_sz != canonical_size ||
                                     !fp_dna_equal(&final_dna, &cfg->target_dna))) {
                    unlink(stage_path); /* Poisoned staged prefix: wipe cleanly */
                    err = FP_ERR_INTEGRITY;
                }
                if (err == FP_OK) {
                    char obj_dir[PATH_MAX], obj_path[PATH_MAX];
                    int on1 = snprintf(obj_dir, sizeof(obj_dir), "%s/objects", cfg->store_dir);
                    int on2 = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", cfg->store_dir, hex);
                    if (on1 < 0 || (size_t)on1 >= sizeof(obj_dir) ||
                        on2 < 0 || (size_t)on2 >= sizeof(obj_path)) {
                        err = FP_ERR_BOUNDS;
                    } else {
                        err = ensure_dir_net(obj_dir);
                    }
                    if (err == FP_OK && rename(stage_path, obj_path) != 0) {
                        err = FP_ERR_IO;
                    }
                    if (err == FP_OK) {
                        int dfd = open(obj_dir, O_RDONLY | O_DIRECTORY);
                        if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
                    }
                }
            }
        }
    } else {
        err = FP_ERR_INVALID;
    }

    if (err == FP_OK) {
        (void)chan_send(&ch, MSG_ACK, NULL, 0);
    }

    if (out_stats) {
        out_stats->mode = mode;
        out_stats->dna = cfg->target_dna;
        out_stats->negotiated_ref = ref_dna;
        out_stats->canonical_size = canonical_size;
        out_stats->wire_bytes = ch.bytes_tx + ch.bytes_rx;
        out_stats->resumed_chunks = resumed_chunks;
        out_stats->received_chunks = received_chunks;
        out_stats->elapsed_ns = now_ns() - t0;
    }

    chan_wipe(&ch);
    close(fd);
    return err;
}

/* --- Persistent Authenticated Encrypted Streaming Session (fp_session_*) --- */

struct fp_session {
    fp_chan_t ch;
};

fp_err_t fp_session_connect(const char *host, uint16_t port,
                            const fp_keypair_t *client_kp,
                            const uint8_t expected_srv_pk[FP_PK_LEN],
                            int io_timeout_ms,
                            fp_session_t **out_sess) {
    if (!host || port == 0 || !client_kp || !expected_srv_pk || !out_sess) {
        return FP_ERR_INVALID;
    }
    *out_sess = NULL;
    int fd = connect_tcp(host, port, io_timeout_ms);
    if (fd < 0) return FP_ERR_IO;

    fp_session_t *s = calloc(1, sizeof(*s));
    if (!s) { close(fd); return FP_ERR_NOMEM; }
    s->ch.fd = fd;

    fp_err_t err = handshake_client(&s->ch, client_kp, expected_srv_pk);
    if (err != FP_OK) {
        chan_wipe(&s->ch);
        close(fd);
        free(s);
        return err;
    }
    *out_sess = s;
    return FP_OK;
}

fp_err_t fp_session_accept(int listen_fd,
                           const fp_keypair_t *server_kp,
                           const uint8_t allowed_peer_pk[FP_PK_LEN],
                           int io_timeout_ms,
                           fp_session_t **out_sess) {
    if (listen_fd < 0 || !server_kp || !out_sess) return FP_ERR_INVALID;
    *out_sess = NULL;

    int cfd = -1;
    do {
        cfd = accept(listen_fd, NULL, NULL);
    } while (cfd < 0 && errno == EINTR);
    if (cfd < 0) return FP_ERR_IO;

    set_socket_opts(cfd, io_timeout_ms);
    fp_session_t *s = calloc(1, sizeof(*s));
    if (!s) { close(cfd); return FP_ERR_NOMEM; }
    s->ch.fd = cfd;

    fp_err_t err = handshake_server(&s->ch, server_kp, allowed_peer_pk);
    if (err != FP_OK) {
        chan_wipe(&s->ch);
        close(cfd);
        free(s);
        return err;
    }
    *out_sess = s;
    return FP_OK;
}

fp_err_t fp_session_send_verified(fp_session_t *sess, uint8_t tag,
                                  const uint8_t *data, size_t len,
                                  fp_dna_t *out_dna) {
    if (!sess || (len > 0 && !data)) return FP_ERR_INVALID;

    fp_dna_t dna;
    fp_err_t err = fp_dna_compute(data, len, &dna);
    if (err != FP_OK) return err;

    /* Fast path: <= 64 KiB fits in ONE single AEAD frame (sub-ms RTT on LAN!) */
    if (len <= FP_NET_SLICE_SIZE) {
        size_t flen = 1u + 4u + FP_DNA_LEN + len;
        uint8_t *frame = malloc(flen);
        if (!frame) return FP_ERR_NOMEM;
        frame[0] = tag;
        put_be32(frame + 1, (uint32_t)len);
        memcpy(frame + 5, dna.bytes, FP_DNA_LEN);
        if (len > 0) memcpy(frame + 37, data, len);
        err = chan_send(&sess->ch, MSG_STREAM_FRAME, frame, flen);
        free(frame);
    } else {
        /* Pipelined multi-slice path for Multi-MB tensors/KV-cache */
        uint8_t hdr[1u + 8u + FP_DNA_LEN];
        hdr[0] = tag;
        put_be64(hdr + 1, (uint64_t)len);
        memcpy(hdr + 9, dna.bytes, FP_DNA_LEN);
        err = chan_send(&sess->ch, MSG_STREAM_BEGIN, hdr, sizeof(hdr));
        size_t pos = 0;
        while (err == FP_OK && pos < len) {
            size_t take = len - pos;
            if (take > FP_NET_SLICE_SIZE) take = FP_NET_SLICE_SIZE;
            err = chan_send(&sess->ch, MSG_STREAM_SLICE, data + pos, take);
            pos += take;
        }
    }
    if (err == FP_OK && out_dna) *out_dna = dna;
    return err;
}

fp_err_t fp_session_recv_verified(fp_session_t *sess, size_t max_bytes,
                                  uint8_t *out_tag,
                                  uint8_t **out_data, size_t *out_len,
                                  fp_dna_t *out_dna) {
    if (!sess || !out_data || !out_len) return FP_ERR_INVALID;
    *out_data = NULL;
    *out_len = 0;
    if (max_bytes == 0) max_bytes = FP_NET_DEFAULT_MAX_OUTPUT;

    uint8_t mtype = 0;
    uint8_t *body = NULL;
    size_t blen = 0;
    fp_err_t err = chan_recv(&sess->ch, &mtype, &body, &blen);
    if (err != FP_OK) return err;

    uint8_t tag = 0;
    fp_dna_t expected_dna;
    uint8_t *buf = NULL;
    size_t total_len = 0;

    if (mtype == MSG_STREAM_FRAME) {
        if (blen < 37u) { free(body); return FP_ERR_INVALID; }
        tag = body[0];
        uint32_t plen = get_be32(body + 1);
        if ((size_t)plen != blen - 37u || (size_t)plen > max_bytes) {
            free(body);
            return FP_ERR_BOUNDS;
        }
        memcpy(expected_dna.bytes, body + 5, FP_DNA_LEN);
        total_len = (size_t)plen;
        buf = malloc(total_len > 0 ? total_len : 1u);
        if (!buf) { free(body); return FP_ERR_NOMEM; }
        if (total_len > 0) memcpy(buf, body + 37, total_len);
        free(body);
    } else if (mtype == MSG_STREAM_BEGIN) {
        if (blen != 41u) { free(body); return FP_ERR_INVALID; }
        tag = body[0];
        uint64_t t64 = get_be64(body + 1);
        memcpy(expected_dna.bytes, body + 9, FP_DNA_LEN);
        free(body);
        if (t64 == 0 || t64 > max_bytes) return FP_ERR_BOUNDS;
        total_len = (size_t)t64;
        buf = malloc(total_len);
        if (!buf) return FP_ERR_NOMEM;

        size_t pos = 0;
        while (pos < total_len) {
            uint8_t stype = 0;
            uint8_t *sbody = NULL;
            size_t slen = 0;
            err = chan_recv(&sess->ch, &stype, &sbody, &slen);
            if (err != FP_OK) { free(buf); return err; }
            if (stype != MSG_STREAM_SLICE || slen == 0 || slen > total_len - pos) {
                free(sbody);
                free(buf);
                return FP_ERR_BOUNDS;
            }
            memcpy(buf + pos, sbody, slen);
            pos += slen;
            free(sbody);
        }
    } else {
        free(body);
        return FP_ERR_INVALID;
    }

    /* Fail-closed canonical BLAKE3 DNA verification */
    fp_dna_t actual_dna;
    err = fp_dna_compute(buf, total_len, &actual_dna);
    if (err != FP_OK || !fp_dna_equal(&actual_dna, &expected_dna)) {
        free(buf);
        return FP_ERR_INTEGRITY;
    }
    if (out_tag) *out_tag = tag;
    *out_data = buf;
    *out_len = total_len;
    if (out_dna) *out_dna = actual_dna;
    return FP_OK;
}

void fp_session_stats(const fp_session_t *sess, uint64_t *out_tx, uint64_t *out_rx) {
    if (!sess) return;
    if (out_tx) *out_tx = sess->ch.bytes_tx;
    if (out_rx) *out_rx = sess->ch.bytes_rx;
}

void fp_session_close(fp_session_t *sess) {
    if (!sess) return;
    chan_wipe(&sess->ch);
    if (sess->ch.fd >= 0) close(sess->ch.fd);
    free(sess);
}
