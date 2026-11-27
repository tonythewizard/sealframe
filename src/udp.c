#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <arpa/inet.h>
#include <blake3.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define UDP_FRAG_DATA      1152u /* MTU-safe encrypted payload (< 1280 B total datagram) */
#define UDP_MAX_FRAGS      24u   /* Covers 16 KiB chunk + up to 2 KiB Merkle proof */
#define UDP_HDR_LEN        24u   /* "FPU1"(4) | type(1) | rsv(3) | sid(8) | seq(8) */
#define UDP_AEAD_ABYTES    crypto_aead_xchacha20poly1305_ietf_ABYTES
#define UDP_MAX_DATAGRAM   1400u
#define UDP_DEFAULT_MAXOUT (128u << 20)
#define UDP_HELLO_LEN        (4u + 32u + 32u + 16u + 32u + 64u)     /* 180 B */
#define UDP_HELLO_COOKIE_LEN (UDP_HELLO_LEN + 16u)                  /* 196 B (with stateless retry cookie) */
#define UDP_RETRY_LEN        (4u + 4u + 16u + 16u)                  /* 40 B ("FPU1"|U_RETRY|0,0,0|cookie|c_nonce) */
#define UDP_WELCOME_LEN      (4u + 8u + 32u + 32u + 16u + 8u + 8u + 64u) /* 172 B */
#define UDP_MAX_WINDOW       32u   /* Max AIMD congestion window (chunks in flight) */
#define UDP_INIT_CWND        8u    /* Initial congestion window */
#define UDP_MAX_SESSIONS     16u   /* Concurrent session table (prevents single-packet DoS eviction) */

enum {
    U_HELLO          = 1,
    U_WELCOME        = 2,
    U_REQ_FRAGS      = 3,
    U_FRAG           = 4,
    U_BYE            = 5,
    U_RETRY          = 6,
    U_PATH_CHALLENGE = 7,
    U_PATH_RESPONSE  = 8
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void put_be16(uint8_t dst[2], uint16_t v) {
    dst[0] = (uint8_t)(v >> 8); dst[1] = (uint8_t)(v);
}

static uint16_t get_be16(const uint8_t src[2]) {
    return (uint16_t)(((uint16_t)src[0] << 8) | (uint16_t)src[1]);
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

static void udp_derive_keys(uint64_t sid,
                            const uint8_t c_pk[32], const uint8_t c_eph[32], const uint8_t c_nonce[16],
                            const uint8_t s_pk[32], const uint8_t s_eph[32], const uint8_t s_nonce[16],
                            const fp_dna_t *dna, const uint8_t shared[32],
                            uint8_t out_th[32], uint8_t out_c2s[32], uint8_t out_s2c[32]) {
    uint8_t sbuf[8];
    put_be64(sbuf, sid);
    blake3_hasher h;
    static const uint8_t t_tag[16] = "FPU1/TRANSCRIPT";
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, t_tag, sizeof(t_tag));
    blake3_hasher_update(&h, sbuf, 8);
    blake3_hasher_update(&h, dna->bytes, FP_DNA_LEN);
    blake3_hasher_update(&h, c_pk, 32);
    blake3_hasher_update(&h, c_eph, 32);
    blake3_hasher_update(&h, c_nonce, 16);
    blake3_hasher_update(&h, s_pk, 32);
    blake3_hasher_update(&h, s_eph, 32);
    blake3_hasher_update(&h, s_nonce, 16);
    blake3_hasher_finalize(&h, out_th, 32);

    static const uint8_t k1[11] = "FPU1/K_C2S";
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, k1, sizeof(k1));
    blake3_hasher_update(&h, shared, 32);
    blake3_hasher_update(&h, out_th, 32);
    blake3_hasher_finalize(&h, out_c2s, 32);

    static const uint8_t k2[11] = "FPU1/K_S2C";
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, k2, sizeof(k2));
    blake3_hasher_update(&h, shared, 32);
    blake3_hasher_update(&h, out_th, 32);
    blake3_hasher_finalize(&h, out_s2c, 32);
}

static size_t seal_udp_packet(uint8_t *out, uint8_t ptype, uint64_t sid, uint64_t seq,
                              const uint8_t key[32], const uint8_t *pt, size_t pt_len) {
    memcpy(out, "FPU1", 4);
    out[4] = ptype;
    out[5] = 0; out[6] = 0; out[7] = 0;
    put_be64(out + 8, sid);
    put_be64(out + 16, seq);

    uint8_t nonce[24] = {0};
    put_be64(nonce, seq);
    put_be64(nonce + 8, sid);

    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        out + UDP_HDR_LEN, &ct_len, pt, pt_len, out, UDP_HDR_LEN, NULL, nonce, key);
    return UDP_HDR_LEN + (size_t)ct_len;
}

static int open_udp_packet(const uint8_t *pkt, size_t pkt_len, uint64_t expected_sid,
                           const uint8_t key[32], uint8_t *out_type, uint64_t *out_seq,
                           uint8_t *out_pt, size_t *out_pt_len) {
    if (pkt_len < UDP_HDR_LEN + UDP_AEAD_ABYTES || memcmp(pkt, "FPU1", 4) != 0) return -1;
    uint64_t sid = get_be64(pkt + 8);
    if (sid != expected_sid) return -1;
    uint64_t seq = get_be64(pkt + 16);

    uint8_t nonce[24] = {0};
    put_be64(nonce, seq);
    put_be64(nonce + 8, sid);

    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out_pt, &pt_len, NULL, pkt + UDP_HDR_LEN, pkt_len - UDP_HDR_LEN,
            pkt, UDP_HDR_LEN, nonce, key) != 0) {
        return -1;
    }
    *out_type = pkt[4];
    *out_seq = seq;
    *out_pt_len = (size_t)pt_len;
    return 0;
}

static size_t encode_chunk_blob(const fp_merkle_proof_t *proof, const uint8_t *data,
                                uint8_t *out, size_t cap) {
    size_t hdr = 21u + proof->depth + (size_t)proof->depth * FP_DNA_LEN;
    if (hdr + proof->chunk_len > cap) return 0;
    size_t p = 0;
    put_be64(out + p, proof->chunk_index); p += 8;
    put_be64(out + p, proof->total_size); p += 8;
    put_be32(out + p, proof->chunk_len); p += 4;
    out[p++] = (uint8_t)proof->depth;
    for (uint32_t i = 0; i < proof->depth; i++) out[p++] = proof->is_right[i];
    for (uint32_t i = 0; i < proof->depth; i++) {
        memcpy(out + p, proof->siblings[i], FP_DNA_LEN);
        p += FP_DNA_LEN;
    }
    memcpy(out + p, data, proof->chunk_len);
    return p + proof->chunk_len;
}

static fp_err_t decode_chunk_blob(const uint8_t *buf, size_t len,
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

int fp_udp_bind(const char *bind_addr, uint16_t port, uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int rbuf = 2 << 20;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof(rbuf));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &rbuf, sizeof(rbuf));

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
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
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

/* --- UDP Server (multi-session anti-DoS, stateless retry cookie, AEAD path validation) --- */

typedef struct {
    int                active;
    uint64_t           sid;
    uint8_t            c_eph[32];
    uint8_t            c_nonce[16];
    uint8_t            welcome_pkt[UDP_WELCOME_LEN];
    uint8_t            tx_key[32];
    uint8_t            rx_key[32];
    uint64_t           tx_seq;
    uint64_t           rx_max_seq;
    uint64_t           rx_bitmap; /* 64-packet anti-replay sliding window */
    int                obj_fd;
    uint64_t           obj_len;
    uint64_t           total_chunks;
    fp_merkle_tree_t  *tree;
    struct sockaddr_in validated_peer;
    int                path_pending;
    struct sockaddr_in pending_peer;
    uint8_t            path_challenge[16];
    uint64_t           last_active_ns;
} udp_sess_t;

static int peer_equal(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_addr.s_addr == b->sin_addr.s_addr && a->sin_port == b->sin_port;
}

static int udp_peer_allowed(const fp_udp_server_cfg_t *cfg, const uint8_t pk[FP_PK_LEN]) {
    if (!cfg->allowed_peer_pk && cfg->allowed_peer_count == 0) return 1;
    if (cfg->allowed_peer_pk && sodium_memcmp(pk, cfg->allowed_peer_pk, FP_PK_LEN) == 0) return 1;
    for (size_t i = 0; i < cfg->allowed_peer_count; i++) {
        if (cfg->allowed_peer_pks &&
            sodium_memcmp(pk, cfg->allowed_peer_pks + i * FP_PK_LEN, FP_PK_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

static void udp_compute_retry_cookie(const uint8_t secret[32],
                                     const struct sockaddr_in *peer,
                                     const uint8_t c_nonce[16],
                                     const fp_dna_t *target_dna,
                                     uint8_t out_cookie[16]) {
    static const uint8_t tag[12] = "FPU1/COOKIE";
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, tag, sizeof(tag));
    blake3_hasher_update(&h, secret, 32);
    blake3_hasher_update(&h, &peer->sin_addr.s_addr, sizeof(peer->sin_addr.s_addr));
    blake3_hasher_update(&h, &peer->sin_port, sizeof(peer->sin_port));
    blake3_hasher_update(&h, c_nonce, 16);
    blake3_hasher_update(&h, target_dna->bytes, FP_DNA_LEN);
    blake3_hasher_finalize(&h, out_cookie, 16);
}

/* RFC 6479-style 64-bit sliding anti-replay check (blocks UDP amplification replay DoS) */
static int udp_replay_accept(uint64_t seq, uint64_t *max_seq, uint64_t *bitmap) {
    if (seq == 0) return 0;
    if (seq > *max_seq) {
        uint64_t diff = seq - *max_seq;
        if (diff >= 64u) *bitmap = 1ull;
        else *bitmap = (*bitmap << diff) | 1ull;
        *max_seq = seq;
        return 1;
    }
    uint64_t diff = *max_seq - seq;
    if (diff >= 64u) return 0;
    uint64_t bit = 1ull << diff;
    if ((*bitmap & bit) != 0) return 0;
    *bitmap |= bit;
    return 1;
}

static void udp_sess_free(udp_sess_t *s) {
    if (!s->active) return;
    sodium_memzero(s->tx_key, sizeof(s->tx_key));
    sodium_memzero(s->rx_key, sizeof(s->rx_key));
    fp_merkle_tree_free(s->tree);
    if (s->obj_fd >= 0) close(s->obj_fd);
    memset(s, 0, sizeof(*s));
    s->obj_fd = -1;
}

static fp_err_t udp_pread_exact(int fd, uint8_t *buf, size_t len, off_t off) {
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = pread(fd, buf + pos, len - pos, off + (off_t)pos);
        if (n < 0) { if (errno == EINTR) continue; return FP_ERR_IO; }
        if (n == 0) return FP_ERR_IO;
        pos += (size_t)n;
    }
    return FP_OK;
}

fp_err_t fp_udp_serve_fd(int udp_fd, const fp_udp_server_cfg_t *cfg) {
    if (udp_fd < 0 || !cfg || !cfg->store_dir || !cfg->server_kp) return FP_ERR_INVALID;

    udp_sess_t sessions[UDP_MAX_SESSIONS];
    memset(sessions, 0, sizeof(sessions));
    for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) sessions[i].obj_fd = -1;

    uint8_t cookie_secret[32];
    randombytes_buf(cookie_secret, sizeof(cookie_secret));
    uint64_t retry_window_ns = now_ns();
    uint32_t retry_sent_in_sec = 0;

    uint32_t completed = 0;
    uint64_t drop_rng = UINT64_C(0xD00D1E55A11CE001);
    int timeout_ms = cfg->io_timeout_ms > 0 ? cfg->io_timeout_ms : 5000;
    uint64_t idle_expire_ns = (uint64_t)timeout_ms * 1000000ull;

    uint8_t pkt[UDP_MAX_DATAGRAM];
    uint8_t chunk_blob[FP_CHUNK_SIZE + 4096u];

    while (cfg->max_sessions == 0 || completed < cfg->max_sessions) {
        struct pollfd pfd = { udp_fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, timeout_ms);
        if (prc < 0) {
            if (errno == EINTR) continue;
            for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) udp_sess_free(&sessions[i]);
            sodium_memzero(cookie_secret, sizeof(cookie_secret));
            return FP_ERR_IO;
        }
        uint64_t tnow = now_ns();
        if (prc == 0) {
            for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) {
                if (sessions[i].active && (tnow - sessions[i].last_active_ns) >= idle_expire_ns) {
                    udp_sess_free(&sessions[i]);
                    completed++;
                }
            }
            continue;
        }

        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        ssize_t n = recvfrom(udp_fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&peer, &plen);
        if (n <= 4 || memcmp(pkt, "FPU1", 4) != 0) continue;

        /* 1. Unencrypted U_HELLO (180 B) or U_HELLO_COOKIE (196 B) handshake */
        if ((size_t)n == UDP_HELLO_LEN || (size_t)n == UDP_HELLO_COOKIE_LEN) {
            const uint8_t *c_pk = pkt + 4;
            const uint8_t *c_eph = pkt + 36;
            const uint8_t *c_nonce = pkt + 68;
            fp_dna_t target_dna;
            memcpy(target_dna.bytes, pkt + 84, FP_DNA_LEN);
            const uint8_t *c_sig = pkt + 116;

            /* Fast ACL check BEFORE any cookie/crypto/disk work! */
            if (!udp_peer_allowed(cfg, c_pk)) {
                continue;
            }

            /* Idempotent U_HELLO deduplication across active sessions */
            int dup_found = 0;
            for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) {
                if (sessions[i].active &&
                    memcmp(sessions[i].c_eph, c_eph, 32) == 0 &&
                    memcmp(sessions[i].c_nonce, c_nonce, 16) == 0 &&
                    peer_equal(&sessions[i].validated_peer, &peer)) {
                    (void)sendto(udp_fd, sessions[i].welcome_pkt, sizeof(sessions[i].welcome_pkt), 0,
                                 (struct sockaddr *)&peer, plen);
                    sessions[i].last_active_ns = tnow;
                    dup_found = 1;
                    break;
                }
            }
            if (dup_found) continue;

            /* Stateless address-reachability verification via BLAKE3 retry cookie:
             * Required whenever server has no explicit peer ACL (open/swarm mode),
             * preventing spoofed-IP CPU/disk DoS and amplification (< 1x 40B reply). */
            int need_cookie = (!cfg->allowed_peer_pk && cfg->allowed_peer_count == 0);
            uint8_t expect_cookie[16];
            udp_compute_retry_cookie(cookie_secret, &peer, c_nonce, &target_dna, expect_cookie);
            if (need_cookie) {
                if ((size_t)n == UDP_HELLO_LEN) {
                    if (tnow - retry_window_ns >= 1000000000ull) {
                        retry_window_ns = tnow;
                        retry_sent_in_sec = 0;
                    }
                    if (retry_sent_in_sec < 128u) {
                        uint8_t rty[UDP_RETRY_LEN];
                        memcpy(rty, "FPU1", 4);
                        rty[4] = U_RETRY; rty[5] = 0; rty[6] = 0; rty[7] = 0;
                        memcpy(rty + 8, expect_cookie, 16);
                        memcpy(rty + 24, c_nonce, 16);
                        (void)sendto(udp_fd, rty, sizeof(rty), 0, (struct sockaddr *)&peer, plen);
                        retry_sent_in_sec++;
                    }
                    continue;
                }
                if (sodium_memcmp(pkt + UDP_HELLO_LEN, expect_cookie, 16) != 0) {
                    continue;
                }
            }

            /* Find free session slot (or reclaim an expired idle slot; NEVER evict active clients!) */
            int slot = -1;
            for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) {
                if (!sessions[i].active) { slot = (int)i; break; }
            }
            if (slot < 0) {
                for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) {
                    if (sessions[i].active && (tnow - sessions[i].last_active_ns) >= idle_expire_ns) {
                        udp_sess_free(&sessions[i]);
                        slot = (int)i;
                        break;
                    }
                }
            }
            if (slot < 0) continue; /* All active sessions busy: refuse without evicting! */

            uint8_t cmsg[13 + 32 + 32 + 16 + 32];
            memcpy(cmsg, "FPU1/C_HELLO", 13);
            memcpy(cmsg + 13, c_pk, 32);
            memcpy(cmsg + 45, c_eph, 32);
            memcpy(cmsg + 77, c_nonce, 16);
            memcpy(cmsg + 93, target_dna.bytes, 32);
            if (crypto_sign_ed25519_verify_detached(c_sig, cmsg, sizeof(cmsg), c_pk) != 0) {
                continue;
            }

            char obj_path[PATH_MAX];
            uint64_t obj_len = 0;
            int obj_fd = fp_store_open_object_fd(cfg->store_dir, &target_dna,
                                                 obj_path, sizeof(obj_path), &obj_len);
            if (obj_fd < 0) {
                continue;
            }
            uint64_t total_chunks = obj_len > 0 ? (obj_len + FP_CHUNK_SIZE - 1u) / FP_CHUNK_SIZE : 0;
            fp_merkle_tree_t *tree = total_chunks > 0
                ? fp_merkle_tree_build_file_cached(obj_path, &target_dna, NULL) : NULL;
            if (total_chunks > 0) {
                if (!tree) { close(obj_fd); continue; }
                fp_dna_t check = fp_merkle_tree_dna(tree);
                if (!fp_dna_equal(&check, &target_dna)) {
                    fp_merkle_tree_free(tree); close(obj_fd); continue;
                }
            }

            uint8_t s_eph_pk[32], s_eph_sk[32], s_nonce[16], shared[32];
            randombytes_buf(s_eph_sk, sizeof(s_eph_sk));
            crypto_scalarmult_base(s_eph_pk, s_eph_sk);
            randombytes_buf(s_nonce, sizeof(s_nonce));
            if (crypto_scalarmult(shared, s_eph_sk, c_eph) != 0) {
                sodium_memzero(s_eph_sk, sizeof(s_eph_sk));
                fp_merkle_tree_free(tree); close(obj_fd);
                continue;
            }
            sodium_memzero(s_eph_sk, sizeof(s_eph_sk));

            uint64_t sid = 0;
            randombytes_buf(&sid, sizeof(sid));
            if (sid == 0) sid = 1;

            uint8_t th[32], k_c2s[32], k_s2c[32];
            udp_derive_keys(sid, c_pk, c_eph, c_nonce, cfg->server_kp->pk, s_eph_pk, s_nonce,
                            &target_dna, shared, th, k_c2s, k_s2c);
            sodium_memzero(shared, sizeof(shared));

            udp_sess_t *s = &sessions[slot];
            s->active = 1;
            s->sid = sid;
            memcpy(s->c_eph, c_eph, 32);
            memcpy(s->c_nonce, c_nonce, 16);
            memcpy(s->tx_key, k_s2c, 32);
            memcpy(s->rx_key, k_c2s, 32);
            s->tx_seq = 1;
            s->obj_fd = obj_fd;
            s->obj_len = obj_len;
            s->total_chunks = total_chunks;
            s->tree = tree;
            s->validated_peer = peer;
            s->path_pending = 0;
            s->last_active_ns = tnow;
            sodium_memzero(k_c2s, sizeof(k_c2s));
            sodium_memzero(k_s2c, sizeof(k_s2c));

            uint8_t smsg[13 + 32 + 16];
            memcpy(smsg, "FPU1/S_HELLO", 13);
            memcpy(smsg + 13, th, 32);
            put_be64(smsg + 45, obj_len);
            put_be64(smsg + 53, total_chunks);

            uint8_t wel[UDP_WELCOME_LEN];
            memcpy(wel, "FPU1", 4);
            put_be64(wel + 4, sid);
            memcpy(wel + 12, cfg->server_kp->pk, 32);
            memcpy(wel + 44, s_eph_pk, 32);
            memcpy(wel + 76, s_nonce, 16);
            put_be64(wel + 92, obj_len);
            put_be64(wel + 100, total_chunks);
            unsigned long long siglen = 0;
            crypto_sign_ed25519_detached(wel + 108, &siglen, smsg, sizeof(smsg), cfg->server_kp->sk);
            memcpy(s->welcome_pkt, wel, sizeof(wel));
            (void)sendto(udp_fd, wel, sizeof(wel), 0, (struct sockaddr *)&peer, plen);
            continue;
        }

        /* 2. Authenticated Encrypted Session Packets (lookup by 64-bit sid) */
        if ((size_t)n < UDP_HDR_LEN + UDP_AEAD_ABYTES) continue;
        uint64_t pkt_sid = get_be64(pkt + 8);
        udp_sess_t *s = NULL;
        for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) {
            if (sessions[i].active && sessions[i].sid == pkt_sid) { s = &sessions[i]; break; }
        }
        if (!s) continue;

        uint8_t ptype = 0;
        uint64_t pseq = 0;
        uint8_t pt[UDP_MAX_DATAGRAM];
        size_t pt_len = 0;
        if (open_udp_packet(pkt, (size_t)n, s->sid, s->rx_key, &ptype, &pseq, pt, &pt_len) != 0) {
            continue;
        }
        if (!udp_replay_accept(pseq, &s->rx_max_seq, &s->rx_bitmap)) {
            continue;
        }
        s->last_active_ns = tnow;

        /* QUIC-style Path Validation on IP/port migration:
         * Fast path (peer == validated_peer): 0 overhead!
         * Unvalidated migrated peer: NEVER emit 24-fragment burst (~500x amplification);
         * emit a single 56 B AEAD U_PATH_CHALLENGE (~1x) and switch only after U_PATH_RESPONSE. */
        if (!peer_equal(&peer, &s->validated_peer)) {
            if (ptype == U_PATH_RESPONSE && pt_len == 16u && s->path_pending &&
                peer_equal(&peer, &s->pending_peer) &&
                sodium_memcmp(pt, s->path_challenge, 16u) == 0) {
                s->validated_peer = peer;
                s->path_pending = 0;
                continue;
            }
            if (ptype == U_BYE) {
                udp_sess_free(s);
                completed++;
                continue;
            }
            if (!s->path_pending || !peer_equal(&peer, &s->pending_peer)) {
                randombytes_buf(s->path_challenge, sizeof(s->path_challenge));
                s->pending_peer = peer;
                s->path_pending = 1;
            }
            uint8_t ch_pkt[UDP_MAX_DATAGRAM];
            size_t ch_len = seal_udp_packet(ch_pkt, U_PATH_CHALLENGE, s->sid, s->tx_seq++,
                                            s->tx_key, s->path_challenge, 16u);
            (void)sendto(udp_fd, ch_pkt, ch_len, 0, (struct sockaddr *)&peer, plen);
            continue;
        }

        if (ptype == U_BYE) {
            udp_sess_free(s);
            completed++;
            continue;
        }
        if (ptype == U_REQ_FRAGS && pt_len == 12u) {
            uint64_t ci = get_be64(pt);
            uint32_t mask = get_be32(pt + 8);
            if (ci >= s->total_chunks) continue;

            fp_merkle_proof_t proof;
            if (fp_merkle_tree_prove(s->tree, ci, &proof) != FP_OK) continue;
            uint8_t raw_chunk[FP_CHUNK_SIZE];
            if (udp_pread_exact(s->obj_fd, raw_chunk, proof.chunk_len,
                                (off_t)(ci * FP_CHUNK_SIZE)) != FP_OK) {
                continue;
            }
            size_t blen = encode_chunk_blob(&proof, raw_chunk, chunk_blob, sizeof(chunk_blob));
            if (blen == 0) continue;

            uint32_t nfrags = (uint32_t)((blen + UDP_FRAG_DATA - 1u) / UDP_FRAG_DATA);
            if (nfrags > UDP_MAX_FRAGS) continue;

            for (uint32_t f = 0; f < nfrags; f++) {
                if ((mask & (1u << f)) == 0) continue;

                /* Simulated packet loss fault injection */
                if (cfg->fault_drop_pct > 0) {
                    drop_rng ^= drop_rng >> 12;
                    drop_rng ^= drop_rng << 25;
                    drop_rng ^= drop_rng >> 27;
                    if ((drop_rng % 100u) < cfg->fault_drop_pct) continue;
                }

                size_t foff = (size_t)f * UDP_FRAG_DATA;
                size_t flen = blen - foff;
                if (flen > UDP_FRAG_DATA) flen = UDP_FRAG_DATA;

                uint8_t fpt[12u + UDP_FRAG_DATA];
                put_be64(fpt, ci);
                fpt[8] = (uint8_t)f;
                fpt[9] = (uint8_t)nfrags;
                put_be16(fpt + 10, (uint16_t)flen);
                memcpy(fpt + 12, chunk_blob + foff, flen);

                uint8_t out_pkt[UDP_MAX_DATAGRAM];
                size_t out_len = seal_udp_packet(out_pkt, U_FRAG, s->sid, s->tx_seq++,
                                                 s->tx_key, fpt, 12u + flen);
                (void)sendto(udp_fd, out_pkt, out_len, 0,
                             (struct sockaddr *)&s->validated_peer, sizeof(s->validated_peer));
            }
        }
    }

    for (size_t i = 0; i < UDP_MAX_SESSIONS; i++) udp_sess_free(&sessions[i]);
    sodium_memzero(cookie_secret, sizeof(cookie_secret));
    return FP_OK;
}

/* --- UDP Client (Selective Fragment Retransmit + Connection Migration + Merkle Verify) --- */

typedef struct {
    int      active;
    uint64_t chunk_index;
    uint8_t  frag_total;
    uint32_t got_mask;
    size_t   total_bytes;
    uint8_t  buf[UDP_MAX_FRAGS * UDP_FRAG_DATA];
    uint16_t frag_lens[UDP_MAX_FRAGS];
} chunk_slot_t;

static fp_err_t ensure_dir_u(const char *p) {
    if (mkdir(p, 0700) == 0 || errno == EEXIST) return FP_OK;
    return FP_ERR_IO;
}

fp_err_t fp_udp_pull(const fp_udp_pull_cfg_t *cfg, fp_udp_stats_t *out_stats) {
    if (!cfg || !cfg->host || cfg->port == 0 || !cfg->store_dir || !cfg->client_kp) {
        return FP_ERR_INVALID;
    }
    uint64_t t0 = now_ns();
    size_t max_out = cfg->max_output > 0 ? cfg->max_output : UDP_DEFAULT_MAXOUT;

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(cfg->port);
    if (inet_pton(AF_INET, cfg->host, &srv.sin_addr) != 1) return FP_ERR_INVALID;

    int fd = fp_udp_bind("0.0.0.0", 0, NULL);
    if (fd < 0) return FP_ERR_IO;

    /* 1-RTT Handshake with automatic retry */
    uint8_t c_eph_pk[32], c_eph_sk[32], c_nonce[16];
    randombytes_buf(c_eph_sk, sizeof(c_eph_sk));
    crypto_scalarmult_base(c_eph_pk, c_eph_sk);
    randombytes_buf(c_nonce, sizeof(c_nonce));

    uint8_t cmsg[13 + 32 + 32 + 16 + 32];
    memcpy(cmsg, "FPU1/C_HELLO", 13);
    memcpy(cmsg + 13, cfg->client_kp->pk, 32);
    memcpy(cmsg + 45, c_eph_pk, 32);
    memcpy(cmsg + 77, c_nonce, 16);
    memcpy(cmsg + 93, cfg->target_dna.bytes, 32);

    uint8_t hello[UDP_HELLO_COOKIE_LEN];
    size_t hello_len = UDP_HELLO_LEN;
    memcpy(hello, "FPU1", 4);
    memcpy(hello + 4, cfg->client_kp->pk, 32);
    memcpy(hello + 36, c_eph_pk, 32);
    memcpy(hello + 68, c_nonce, 16);
    memcpy(hello + 84, cfg->target_dna.bytes, 32);
    unsigned long long siglen = 0;
    crypto_sign_ed25519_detached(hello + 116, &siglen, cmsg, sizeof(cmsg), cfg->client_kp->sk);

    uint8_t wel[UDP_MAX_DATAGRAM];
    int got_welcome = 0;
    uint64_t pkts_sent = 0, pkts_recv = 0, retrans = 0;
    uint32_t migrations = 0;

    uint64_t hs_t0 = now_ns();
    for (int attempt = 0; attempt < 12 && !got_welcome; attempt++) {
        hs_t0 = now_ns();
        (void)sendto(fd, hello, hello_len, 0, (struct sockaddr *)&srv, sizeof(srv));
        pkts_sent++;
        struct pollfd pfd = { fd, POLLIN, 0 };
        if (poll(&pfd, 1, 500) > 0) {
            ssize_t n = recvfrom(fd, wel, sizeof(wel), 0, NULL, NULL);
            if (n > 0 && (size_t)n == UDP_RETRY_LEN &&
                memcmp(wel, "FPU1", 4) == 0 && wel[4] == U_RETRY &&
                memcmp(wel + 24, c_nonce, 16) == 0) {
                /* Server requested stateless reachability cookie: append & resend immediately */
                pkts_recv++;
                memcpy(hello + UDP_HELLO_LEN, wel + 8, 16);
                hello_len = UDP_HELLO_COOKIE_LEN;
                continue;
            }
            if (n > 0 && (size_t)n == UDP_WELCOME_LEN && memcmp(wel, "FPU1", 4) == 0) {
                pkts_recv++;
                got_welcome = 1;
            }
        }
    }
    uint64_t srtt_ns = now_ns() - hs_t0;
    if (srtt_ns < 200000ull) srtt_ns = 200000ull; /* floor 200 us */
    uint64_t rttvar_ns = srtt_ns / 2u;
    if (!got_welcome) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        close(fd);
        return FP_ERR_IO;
    }

    uint64_t sid = get_be64(wel + 4);
    const uint8_t *s_pk = wel + 12, *s_eph = wel + 44, *s_nonce = wel + 76;
    uint64_t canonical_size = get_be64(wel + 92);
    uint64_t total_chunks = get_be64(wel + 100);
    const uint8_t *s_sig = wel + 108;

    if (cfg->expected_srv_pk && sodium_memcmp(s_pk, cfg->expected_srv_pk, FP_PK_LEN) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        close(fd);
        return FP_ERR_SIGNATURE;
    }
    uint64_t expected_chunks = canonical_size > 0
        ? (1u + (canonical_size - 1u) / FP_CHUNK_SIZE) : 0u;
    if (canonical_size > max_out || total_chunks != expected_chunks) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        close(fd);
        return FP_ERR_BOUNDS;
    }

    uint8_t shared[32];
    if (crypto_scalarmult(shared, c_eph_sk, s_eph) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        close(fd);
        return FP_ERR_SIGNATURE;
    }
    sodium_memzero(c_eph_sk, sizeof(c_eph_sk));

    uint8_t th[32], tx_key[32], rx_key[32];
    udp_derive_keys(sid, cfg->client_kp->pk, c_eph_pk, c_nonce, s_pk, s_eph, s_nonce,
                    &cfg->target_dna, shared, th, tx_key, rx_key);
    sodium_memzero(shared, sizeof(shared));

    uint8_t smsg[13 + 32 + 16];
    memcpy(smsg, "FPU1/S_HELLO", 13);
    memcpy(smsg + 13, th, 32);
    put_be64(smsg + 45, canonical_size);
    put_be64(smsg + 53, total_chunks);
    if (crypto_sign_ed25519_verify_detached(s_sig, smsg, sizeof(smsg), s_pk) != 0) {
        sodium_memzero(tx_key, sizeof(tx_key));
        sodium_memzero(rx_key, sizeof(rx_key));
        close(fd);
        return FP_ERR_SIGNATURE;
    }

    char hex[65], stage_dir[PATH_MAX], stage_path[PATH_MAX], obj_dir[PATH_MAX], obj_path[PATH_MAX];
    fp_hex_encode(cfg->target_dna.bytes, FP_DNA_LEN, hex);
    int un1 = snprintf(stage_dir, sizeof(stage_dir), "%s/staging", cfg->store_dir);
    int un2 = snprintf(stage_path, sizeof(stage_path), "%s/staging/%s.udp", cfg->store_dir, hex);
    int un3 = snprintf(obj_dir, sizeof(obj_dir), "%s/objects", cfg->store_dir);
    int un4 = snprintf(obj_path, sizeof(obj_path), "%s/objects/%s", cfg->store_dir, hex);
    if (un1 < 0 || (size_t)un1 >= sizeof(stage_dir) ||
        un2 < 0 || (size_t)un2 >= sizeof(stage_path) ||
        un3 < 0 || (size_t)un3 >= sizeof(obj_dir) ||
        un4 < 0 || (size_t)un4 >= sizeof(obj_path)) {
        sodium_memzero(tx_key, sizeof(tx_key));
        sodium_memzero(rx_key, sizeof(rx_key));
        close(fd);
        return FP_ERR_BOUNDS;
    }

    if (ensure_dir_u(cfg->store_dir) != FP_OK || ensure_dir_u(stage_dir) != FP_OK ||
        ensure_dir_u(obj_dir) != FP_OK) {
        sodium_memzero(tx_key, sizeof(tx_key));
        sodium_memzero(rx_key, sizeof(rx_key));
        close(fd);
        return FP_ERR_IO;
    }

    int ofd = open(stage_path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (ofd < 0 || (canonical_size > 0 && ftruncate(ofd, (off_t)canonical_size) != 0)) {
        if (ofd >= 0) { close(ofd); unlink(stage_path); }
        sodium_memzero(tx_key, sizeof(tx_key));
        sodium_memzero(rx_key, sizeof(rx_key));
        close(fd);
        return FP_ERR_IO;
    }

    /* Adaptive AIMD (beta=0.75, RFC 6298 SRTT/RTTVAR) sliding-window selective-ARQ */
    chunk_slot_t slots[UDP_MAX_WINDOW];
    uint64_t     slot_sent_ns[UDP_MAX_WINDOW];
    memset(slots, 0, sizeof(slots));
    memset(slot_sent_ns, 0, sizeof(slot_sent_ns));
    uint32_t cwnd = UDP_INIT_CWND;
    uint32_t ssthresh = UDP_MAX_WINDOW;
    uint32_t clean_chunks = 0;
    uint64_t last_md_ns = 0;

    uint64_t next_chunk = 0;
    uint64_t done_chunks = 0;
    uint64_t tx_seq = 1;
    int migrated = 0;
    fp_err_t err = FP_OK;

    uint8_t pkt[UDP_MAX_DATAGRAM], pt[UDP_MAX_DATAGRAM];
    int rounds_no_progress = 0;

    while (done_chunks < total_chunks && err == FP_OK) {
        /* Test hook: simulate Wi-Fi -> 4G connection migration (brand new local UDP port!) */
        if (cfg->test_migrate_at_chunk > 0 && !migrated &&
            done_chunks >= cfg->test_migrate_at_chunk) {
            int new_fd = fp_udp_bind("0.0.0.0", 0, NULL);
            if (new_fd >= 0) {
                close(fd);
                fd = new_fd;
                migrated = 1;
                migrations++;
            }
        }

        uint32_t active_slots = 0;
        for (size_t s = 0; s < UDP_MAX_WINDOW; s++) {
            if (slots[s].active) active_slots++;
        }

        /* Fill up to `cwnd` slots & selectively retransmit missing fragments */
        uint32_t retrans_this_round = 0;
        for (size_t s = 0; s < UDP_MAX_WINDOW; s++) {
            if (!slots[s].active && active_slots < cwnd && next_chunk < total_chunks) {
                memset(&slots[s], 0, sizeof(slots[s]));
                slots[s].active = 1;
                slots[s].chunk_index = next_chunk++;
                slot_sent_ns[s] = now_ns();
                active_slots++;
                uint8_t rpt[12];
                put_be64(rpt, slots[s].chunk_index);
                put_be32(rpt + 8, 0xFFFFFFFFu);
                size_t olen = seal_udp_packet(pkt, U_REQ_FRAGS, sid, tx_seq++, tx_key, rpt, 12);
                (void)sendto(fd, pkt, olen, 0, (struct sockaddr *)&srv, sizeof(srv));
                pkts_sent++;
            } else if (slots[s].active) {
                uint32_t full_mask = slots[s].frag_total > 0
                    ? ((1u << slots[s].frag_total) - 1u) : 0xFFFFFFFFu;
                uint32_t missing = full_mask & ~slots[s].got_mask;
                if (missing != 0) {
                    uint8_t rpt[12];
                    put_be64(rpt, slots[s].chunk_index);
                    put_be32(rpt + 8, missing);
                    size_t olen = seal_udp_packet(pkt, U_REQ_FRAGS, sid, tx_seq++, tx_key, rpt, 12);
                    (void)sendto(fd, pkt, olen, 0, (struct sockaddr *)&srv, sizeof(srv));
                    pkts_sent++;
                    retrans++;
                    retrans_this_round++;
                }
            }
        }
        /* Congestion reaction: CUBIC-style beta=0.75, rate-limited to once per congestion epoch */
        uint64_t now_md = now_ns();
        uint64_t md_cooldown = srtt_ns > 500000ull ? (srtt_ns * 2u) : 1000000ull;
        if (retrans_this_round > 0 && cwnd > 4u && (now_md - last_md_ns) >= md_cooldown) {
            ssthresh = (cwnd * 3u) / 4u;
            if (ssthresh < 4u) ssthresh = 4u;
            cwnd = ssthresh;
            clean_chunks = 0;
            last_md_ns = now_md;
        }

        /* Adaptive RFC 6298 RTO poll timeout: clamp(SRTT + 4*RTTVAR, 2ms .. 250ms) */
        uint64_t rto_ms = (srtt_ns + 4u * rttvar_ns) / 1000000ull;
        int poll_ms = (rto_ms < 2u) ? 2 : (rto_ms > 250u ? 250 : (int)rto_ms);

        int progressed = 0;
        for (;;) {
            int all_slots_clear = 1;
            for (size_t s = 0; s < UDP_MAX_WINDOW; s++) {
                if (slots[s].active) { all_slots_clear = 0; break; }
            }
            if (all_slots_clear) break;

            struct pollfd pfd = { fd, POLLIN, 0 };
            int prc = poll(&pfd, 1, poll_ms);
            if (prc <= 0) break;

            ssize_t n = recvfrom(fd, pkt, sizeof(pkt), 0, NULL, NULL);
            if (n <= 0) continue;

            uint8_t ptype = 0; uint64_t pseq = 0; size_t pt_len = 0;
            if (open_udp_packet(pkt, (size_t)n, sid, rx_key, &ptype, &pseq, pt, &pt_len) != 0) {
                continue;
            }
            pkts_recv++;
            if (ptype == U_PATH_CHALLENGE && pt_len == 16u) {
                /* Respond immediately to server's AEAD path-validation challenge after migration */
                uint8_t rpkt[UDP_MAX_DATAGRAM];
                size_t rlen = seal_udp_packet(rpkt, U_PATH_RESPONSE, sid, tx_seq++, tx_key, pt, 16u);
                (void)sendto(fd, rpkt, rlen, 0, (struct sockaddr *)&srv, sizeof(srv));
                pkts_sent++;
                progressed = 1;
                continue;
            }
            if (ptype != U_FRAG || pt_len < 12u) continue;

            uint64_t ci = get_be64(pt);
            uint8_t fidx = pt[8], ftot = pt[9];
            uint16_t flen = get_be16(pt + 10);
            if (ftot == 0 || ftot > UDP_MAX_FRAGS || fidx >= ftot ||
                flen > UDP_FRAG_DATA || pt_len != 12u + flen ||
                (fidx + 1u < ftot && flen != UDP_FRAG_DATA)) {
                continue;
            }

            for (size_t s = 0; s < UDP_MAX_WINDOW; s++) {
                if (!slots[s].active || slots[s].chunk_index != ci) continue;
                if (slots[s].frag_total != 0 && slots[s].frag_total != ftot) {
                    break;
                }
                slots[s].frag_total = ftot;
                if ((slots[s].got_mask & (1u << fidx)) == 0) {
                    /* First fragment updates SRTT/RTTVAR (Jacobson/Karels) */
                    if (slots[s].got_mask == 0 && slot_sent_ns[s] > 0) {
                        uint64_t sample = now_ns() - slot_sent_ns[s];
                        uint64_t diff = sample > srtt_ns ? (sample - srtt_ns) : (srtt_ns - sample);
                        rttvar_ns = (3u * rttvar_ns + diff) / 4u;
                        srtt_ns = (7u * srtt_ns + sample) / 8u;
                    }
                    memcpy(slots[s].buf + (size_t)fidx * UDP_FRAG_DATA, pt + 12, flen);
                    slots[s].frag_lens[fidx] = flen;
                    slots[s].got_mask |= (1u << fidx);
                    progressed = 1;
                }
                uint32_t full_mask = (1u << ftot) - 1u;
                if (slots[s].got_mask == full_mask) {
                    size_t blen = (size_t)(ftot - 1u) * UDP_FRAG_DATA + slots[s].frag_lens[ftot - 1u];
                    fp_merkle_proof_t proof;
                    const uint8_t *cdata = NULL;
                    if (decode_chunk_blob(slots[s].buf, blen, &proof, &cdata) == FP_OK &&
                        proof.chunk_index == ci && proof.total_size == canonical_size &&
                        fp_merkle_verify(&cfg->target_dna, &proof, cdata, proof.chunk_len) == FP_OK) {
                        off_t off = (off_t)(ci * FP_CHUNK_SIZE);
                        size_t wr = 0;
                        while (wr < proof.chunk_len) {
                            ssize_t w = pwrite(ofd, cdata + wr, proof.chunk_len - wr, off + (off_t)wr);
                            if (w < 0) { if (errno == EINTR) continue; err = FP_ERR_IO; break; }
                            wr += (size_t)w;
                        }
                        slots[s].active = 0;
                        if (active_slots > 0) active_slots--;
                        done_chunks++;
                        /* AIMD Slow Start / Additive Increase */
                        if (cwnd < ssthresh && cwnd < UDP_MAX_WINDOW) {
                            cwnd++;
                        } else if (++clean_chunks >= cwnd && cwnd < UDP_MAX_WINDOW) {
                            cwnd++;
                            clean_chunks = 0;
                        }
                        /* Sliding-window continuous pipelining: refill freed slot immediately! */
                        if (err == FP_OK && active_slots < cwnd && next_chunk < total_chunks &&
                            !(cfg->test_migrate_at_chunk > 0 && !migrated &&
                              done_chunks >= cfg->test_migrate_at_chunk)) {
                            memset(&slots[s], 0, sizeof(slots[s]));
                            slots[s].active = 1;
                            slots[s].chunk_index = next_chunk++;
                            slot_sent_ns[s] = now_ns();
                            active_slots++;
                            uint8_t rpt[12];
                            put_be64(rpt, slots[s].chunk_index);
                            put_be32(rpt + 8, 0xFFFFFFFFu);
                            size_t olen = seal_udp_packet(pkt, U_REQ_FRAGS, sid, tx_seq++, tx_key, rpt, 12);
                            (void)sendto(fd, pkt, olen, 0, (struct sockaddr *)&srv, sizeof(srv));
                            pkts_sent++;
                        }
                    } else {
                        slots[s].got_mask = 0;
                    }
                }
                break;
            }
            if (cfg->test_migrate_at_chunk > 0 && !migrated &&
                done_chunks >= cfg->test_migrate_at_chunk) {
                break;
            }
        }

        if (progressed) rounds_no_progress = 0;
        else if (++rounds_no_progress > 500) { err = FP_ERR_IO; break; }
    }

    /* Send U_BYE cleanly */
    size_t blen = seal_udp_packet(pkt, U_BYE, sid, tx_seq++, tx_key, NULL, 0);
    (void)sendto(fd, pkt, blen, 0, (struct sockaddr *)&srv, sizeof(srv));
    pkts_sent++;

    sodium_memzero(tx_key, sizeof(tx_key));
    sodium_memzero(rx_key, sizeof(rx_key));
    close(fd);

    if (err == FP_OK && fsync(ofd) != 0) err = FP_ERR_IO;
    close(ofd);

    if (err == FP_OK) {
        fp_dna_t actual;
        uint64_t actual_sz = 0;
        err = fp_dna_compute_file(stage_path, &actual, &actual_sz);
        if (err == FP_OK && (actual_sz != canonical_size || !fp_dna_equal(&actual, &cfg->target_dna))) {
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
        out_stats->canonical_size = canonical_size;
        out_stats->total_chunks = total_chunks;
        out_stats->packets_sent = pkts_sent;
        out_stats->packets_recv = pkts_recv;
        out_stats->retransmits = retrans;
        out_stats->migrations = migrations;
        out_stats->final_cwnd = cwnd;
        out_stats->srtt_us = srtt_ns / 1000u;
        out_stats->elapsed_ns = now_ns() - t0;
    }
    return err;
}

/* =========================================================================
 * Persistent Authenticated Encrypted UDP Session (FP-UDP1 for Tensor/RPC)
 * ========================================================================= */

#define UDP_SESS_HELLO_LEN    (4u + 32u + 32u + 16u + 64u)        /* 148 B */
#define UDP_SESS_WELCOME_LEN  (4u + 8u + 32u + 32u + 16u + 64u)   /* 156 B */
#define UDP_SESS_FRAG_HDR     14u /* msg_id(4) | frag_idx(4) | frag_total(4) | frag_len(2) */
#define UDP_SESS_FEC_HDR      16u /* msg_id(4) | stripe_start(4) | ftot(4) | stripe_cnt(2) | xor_len(2) */
#define UDP_SESS_FEC_STRIPE   8u  /* 1 XOR parity packet per 8 data fragments (0-RTT single-drop recovery) */
#define UDP_SESS_FRAG_PAYLOAD (UDP_FRAG_DATA)
#define UDP_SESS_MAX_NACKS    64u
#define UDP_SESS_MAX_FRAGS    32768u /* Up to ~37 MiB per verified tensor message */

enum {
    U_SESS_FRAG  = 10,
    U_SESS_ACK   = 11,
    U_SESS_CLOSE = 12,
    U_SESS_FEC   = 13
};

struct fp_udp_session {
    int                fd;
    int                owns_fd;
    struct sockaddr_in peer;
    uint64_t           sid;
    uint8_t            tx_key[32];
    uint8_t            rx_key[32];
    uint64_t           tx_seq;
    uint64_t           rx_max_seq;
    uint64_t           rx_bitmap;
    uint32_t           tx_msg_id;
    uint32_t           rx_msg_id;
    int                timeout_ms;
    uint32_t           fault_drop_pct;
    uint64_t           drop_rng;
    uint64_t           tx_bytes;
    uint64_t           rx_bytes;
    uint64_t           retransmits;
    uint64_t           fec_recoveries;
    int                fec_mode;        /* 0=off, 1=always(default), 2=adaptive */
    uint32_t           fec_active_msgs; /* Remaining adaptive FEC window after loss */
};

static int udp_sess_should_drop(fp_udp_session_t *s) {
    if (s->fault_drop_pct == 0) return 0;
    uint64_t x = s->drop_rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    s->drop_rng = x;
    return (x % 100u) < (uint64_t)s->fault_drop_pct;
}

static fp_err_t udp_sess_send_pkt(fp_udp_session_t *s, uint8_t ptype,
                                  const uint8_t *pt, size_t pt_len, int allow_drop) {
    uint8_t pkt[UDP_MAX_DATAGRAM];
    if (UDP_HDR_LEN + pt_len + UDP_AEAD_ABYTES > sizeof(pkt)) return FP_ERR_BOUNDS;
    size_t plen = seal_udp_packet(pkt, ptype, s->sid, s->tx_seq++, s->tx_key, pt, pt_len);
    s->tx_bytes += plen;
    if (allow_drop && udp_sess_should_drop(s)) return FP_OK;
    ssize_t w = sendto(s->fd, pkt, plen, 0, (const struct sockaddr *)&s->peer, sizeof(s->peer));
    return (w == (ssize_t)plen) ? FP_OK : FP_ERR_IO;
}

static int udp_sess_recv_pkt(fp_udp_session_t *s, int wait_ms,
                             uint8_t *out_type, uint8_t *out_pt, size_t *out_pt_len) {
    struct pollfd pfd = { s->fd, POLLIN, 0 };
    int rc = poll(&pfd, 1, wait_ms);
    if (rc <= 0) return rc;

    uint8_t pkt[UDP_MAX_DATAGRAM];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(s->fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&from, &flen);
    if (n <= 0) return -1;

    uint64_t seq = 0;
    if (open_udp_packet(pkt, (size_t)n, s->sid, s->rx_key, out_type, &seq, out_pt, out_pt_len) != 0) {
        return 0; /* Ignore unrelated or spoofed packet */
    }
    if (!udp_replay_accept(seq, &s->rx_max_seq, &s->rx_bitmap)) {
        return 0; /* Drop replay */
    }
    s->peer = from; /* Seamless NAT / port migration */
    s->rx_bytes += (uint64_t)n;
    return 1;
}

fp_err_t fp_udp_session_connect(const char *host, uint16_t port,
                                const fp_keypair_t *client_kp,
                                const uint8_t expected_srv_pk[FP_PK_LEN],
                                int io_timeout_ms, uint32_t fault_drop_pct,
                                fp_udp_session_t **out_sess) {
    if (!host || port == 0 || !client_kp || !expected_srv_pk || !out_sess) return FP_ERR_INVALID;
    *out_sess = NULL;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    char pstr[16];
    snprintf(pstr, sizeof(pstr), "%u", (unsigned)port);
    if (getaddrinfo(host, pstr, &hints, &res) != 0 || !res) return FP_ERR_IO;

    struct sockaddr_in srv;
    memcpy(&srv, res->ai_addr, sizeof(srv));
    freeaddrinfo(res);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return FP_ERR_IO;
    int sbuf = 4 << 20;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sbuf, sizeof(sbuf));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sbuf, sizeof(sbuf));

    uint8_t c_eph_sk[32], c_eph_pk[32], c_nonce[16];
    randombytes_buf(c_eph_sk, sizeof(c_eph_sk));
    crypto_scalarmult_curve25519_base(c_eph_pk, c_eph_sk);
    randombytes_buf(c_nonce, sizeof(c_nonce));

    uint8_t hello[UDP_SESS_HELLO_LEN];
    memcpy(hello, "FPU1", 4);
    memcpy(hello + 4, client_kp->pk, 32);
    memcpy(hello + 36, c_eph_pk, 32);
    memcpy(hello + 68, c_nonce, 16);

    uint8_t msg[15u + 32u + 32u + 16u];
    memcpy(msg, "FPU1/SESS_HELLO", 15);
    memcpy(msg + 15, hello + 4, 80);
    crypto_sign_detached(hello + 84, NULL, msg, sizeof(msg), client_kp->sk);

    int timeout_ms = io_timeout_ms > 0 ? io_timeout_ms : 10000;
    uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ull;
    uint8_t wbuf[UDP_MAX_DATAGRAM];
    ssize_t wn = -1;

    while (now_ns() < deadline) {
        (void)sendto(fd, hello, sizeof(hello), 0, (const struct sockaddr *)&srv, sizeof(srv));
        struct pollfd pfd = { fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, 100);
        if (prc > 0) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            wn = recvfrom(fd, wbuf, sizeof(wbuf), 0, (struct sockaddr *)&from, &flen);
            if ((size_t)wn == UDP_SESS_WELCOME_LEN && memcmp(wbuf, "FPU1", 4) == 0) {
                srv = from;
                break;
            }
            wn = -1;
        }
    }
    if (wn != (ssize_t)UDP_SESS_WELCOME_LEN) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        close(fd);
        return FP_ERR_IO;
    }

    uint64_t sid = get_be64(wbuf + 4);
    const uint8_t *s_pk = wbuf + 12;
    const uint8_t *s_eph = wbuf + 44;
    const uint8_t *s_nonce = wbuf + 76;
    const uint8_t *s_sig = wbuf + 92;

    if (sodium_memcmp(s_pk, expected_srv_pk, 32) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        close(fd);
        return FP_ERR_SIGNATURE;
    }

    uint8_t shared[32];
    if (crypto_scalarmult_curve25519(shared, c_eph_sk, s_eph) != 0) {
        sodium_memzero(c_eph_sk, sizeof(c_eph_sk));
        close(fd);
        return FP_ERR_SIGNATURE;
    }
    sodium_memzero(c_eph_sk, sizeof(c_eph_sk));

    fp_dna_t zero_dna;
    memset(&zero_dna, 0, sizeof(zero_dna));
    uint8_t th[32], k_c2s[32], k_s2c[32];
    udp_derive_keys(sid, client_kp->pk, c_eph_pk, c_nonce, s_pk, s_eph, s_nonce,
                    &zero_dna, shared, th, k_c2s, k_s2c);
    sodium_memzero(shared, sizeof(shared));

    uint8_t wmsg[17u + 32u];
    memcpy(wmsg, "FPU1/SESS_WELCOME", 17);
    memcpy(wmsg + 17, th, 32);
    if (crypto_sign_verify_detached(s_sig, wmsg, sizeof(wmsg), s_pk) != 0) {
        sodium_memzero(k_c2s, sizeof(k_c2s));
        sodium_memzero(k_s2c, sizeof(k_s2c));
        close(fd);
        return FP_ERR_SIGNATURE;
    }

    fp_udp_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        sodium_memzero(k_c2s, sizeof(k_c2s));
        sodium_memzero(k_s2c, sizeof(k_s2c));
        close(fd);
        return FP_ERR_NOMEM;
    }
    s->fd = fd;
    s->owns_fd = 1;
    s->peer = srv;
    s->sid = sid;
    memcpy(s->tx_key, k_c2s, 32);
    memcpy(s->rx_key, k_s2c, 32);
    sodium_memzero(k_c2s, sizeof(k_c2s));
    sodium_memzero(k_s2c, sizeof(k_s2c));
    s->tx_seq = 1;
    s->tx_msg_id = 0;
    s->rx_msg_id = 1;
    s->timeout_ms = timeout_ms;
    s->fault_drop_pct = fault_drop_pct;
    s->drop_rng = UINT64_C(0xA5A5F00DBABE1234) ^ sid;
    s->tx_bytes = UDP_SESS_HELLO_LEN;
    s->rx_bytes = UDP_SESS_WELCOME_LEN;
    s->fec_mode = 1;

    *out_sess = s;
    return FP_OK;
}

fp_err_t fp_udp_session_accept(int udp_fd,
                               const fp_keypair_t *server_kp,
                               const uint8_t allowed_peer_pk[FP_PK_LEN],
                               int io_timeout_ms, uint32_t fault_drop_pct,
                               fp_udp_session_t **out_sess) {
    if (udp_fd < 0 || !server_kp || !out_sess) return FP_ERR_INVALID;
    *out_sess = NULL;

    int sbuf = 4 << 20;
    (void)setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUF, &sbuf, sizeof(sbuf));
    (void)setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUF, &sbuf, sizeof(sbuf));

    int timeout_ms = io_timeout_ms > 0 ? io_timeout_ms : 10000;
    uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ull;
    uint8_t hbuf[UDP_MAX_DATAGRAM];
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);

    while (now_ns() < deadline) {
        int rem = (int)((deadline - now_ns()) / 1000000ull);
        if (rem < 1) rem = 1;
        struct pollfd pfd = { udp_fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, rem > 200 ? 200 : rem);
        if (prc <= 0) continue;
        plen = sizeof(peer);
        ssize_t n = recvfrom(udp_fd, hbuf, sizeof(hbuf), 0, (struct sockaddr *)&peer, &plen);
        if ((size_t)n != UDP_SESS_HELLO_LEN || memcmp(hbuf, "FPU1", 4) != 0) continue;

        const uint8_t *c_pk = hbuf + 4;
        const uint8_t *c_eph = hbuf + 36;
        const uint8_t *c_nonce = hbuf + 68;
        const uint8_t *c_sig = hbuf + 84;

        if (allowed_peer_pk && sodium_memcmp(c_pk, allowed_peer_pk, 32) != 0) continue;

        uint8_t msg[15u + 32u + 32u + 16u];
        memcpy(msg, "FPU1/SESS_HELLO", 15);
        memcpy(msg + 15, hbuf + 4, 80);
        if (crypto_sign_verify_detached(c_sig, msg, sizeof(msg), c_pk) != 0) continue;

        uint8_t s_eph_sk[32], s_eph_pk[32], s_nonce[16];
        randombytes_buf(s_eph_sk, sizeof(s_eph_sk));
        crypto_scalarmult_curve25519_base(s_eph_pk, s_eph_sk);
        randombytes_buf(s_nonce, sizeof(s_nonce));
        uint64_t sid = 0;
        randombytes_buf(&sid, sizeof(sid));
        if (sid == 0) sid = 1;

        uint8_t shared[32];
        if (crypto_scalarmult_curve25519(shared, s_eph_sk, c_eph) != 0) {
            sodium_memzero(s_eph_sk, sizeof(s_eph_sk));
            continue;
        }
        sodium_memzero(s_eph_sk, sizeof(s_eph_sk));

        fp_dna_t zero_dna;
        memset(&zero_dna, 0, sizeof(zero_dna));
        uint8_t th[32], k_c2s[32], k_s2c[32];
        udp_derive_keys(sid, c_pk, c_eph, c_nonce, server_kp->pk, s_eph_pk, s_nonce,
                        &zero_dna, shared, th, k_c2s, k_s2c);
        sodium_memzero(shared, sizeof(shared));

        uint8_t welcome[UDP_SESS_WELCOME_LEN];
        memcpy(welcome, "FPU1", 4);
        put_be64(welcome + 4, sid);
        memcpy(welcome + 12, server_kp->pk, 32);
        memcpy(welcome + 44, s_eph_pk, 32);
        memcpy(welcome + 76, s_nonce, 16);

        uint8_t wmsg[17u + 32u];
        memcpy(wmsg, "FPU1/SESS_WELCOME", 17);
        memcpy(wmsg + 17, th, 32);
        crypto_sign_detached(welcome + 92, NULL, wmsg, sizeof(wmsg), server_kp->sk);

        (void)sendto(udp_fd, welcome, sizeof(welcome), 0, (const struct sockaddr *)&peer, plen);

        fp_udp_session_t *s = calloc(1, sizeof(*s));
        if (!s) {
            sodium_memzero(k_c2s, sizeof(k_c2s));
            sodium_memzero(k_s2c, sizeof(k_s2c));
            return FP_ERR_NOMEM;
        }
        s->fd = udp_fd;
        s->owns_fd = 0;
        s->peer = peer;
        s->sid = sid;
        memcpy(s->tx_key, k_s2c, 32);
        memcpy(s->rx_key, k_c2s, 32);
        sodium_memzero(k_c2s, sizeof(k_c2s));
        sodium_memzero(k_s2c, sizeof(k_s2c));
        s->tx_seq = 1;
        s->tx_msg_id = 0;
        s->rx_msg_id = 1;
        s->timeout_ms = timeout_ms;
        s->fault_drop_pct = fault_drop_pct;
        s->drop_rng = UINT64_C(0xCAFEBABE13370001) ^ sid;
        s->tx_bytes = UDP_SESS_WELCOME_LEN;
        s->rx_bytes = UDP_SESS_HELLO_LEN;
        s->fec_mode = 1;

        *out_sess = s;
        return FP_OK;
    }
    return FP_ERR_IO;
}

static fp_err_t udp_sess_send_one_frag(fp_udp_session_t *s, uint32_t msg_id,
                                       uint32_t fidx, uint32_t ftot,
                                       const uint8_t *blob, size_t blob_len) {
    size_t off = (size_t)fidx * UDP_SESS_FRAG_PAYLOAD;
    size_t rem = (off < blob_len) ? (blob_len - off) : 0u;
    size_t flen = rem > UDP_SESS_FRAG_PAYLOAD ? UDP_SESS_FRAG_PAYLOAD : rem;
    uint8_t pt[UDP_SESS_FRAG_HDR + UDP_SESS_FRAG_PAYLOAD];
    put_be32(pt, msg_id);
    put_be32(pt + 4, fidx);
    put_be32(pt + 8, ftot);
    put_be16(pt + 12, (uint16_t)flen);
    if (flen > 0) memcpy(pt + UDP_SESS_FRAG_HDR, blob + off, flen);
    return udp_sess_send_pkt(s, U_SESS_FRAG, pt, UDP_SESS_FRAG_HDR + flen, 1);
}

static fp_err_t udp_sess_send_fec_stripe(fp_udp_session_t *s, uint32_t msg_id,
                                         uint32_t s_start, uint16_t s_cnt, uint32_t ftot,
                                         const uint8_t *blob, size_t blob_len) {
    uint8_t pt[UDP_SESS_FEC_HDR + UDP_SESS_FRAG_PAYLOAD];
    memset(pt + UDP_SESS_FEC_HDR, 0, UDP_SESS_FRAG_PAYLOAD);
    uint16_t xor_len = 0u;
    for (uint16_t k = 0; k < s_cnt; k++) {
        size_t off = (size_t)(s_start + k) * UDP_SESS_FRAG_PAYLOAD;
        size_t rem = (off < blob_len) ? (blob_len - off) : 0u;
        size_t flen = rem > UDP_SESS_FRAG_PAYLOAD ? UDP_SESS_FRAG_PAYLOAD : rem;
        xor_len ^= (uint16_t)flen;
        const uint8_t *src = blob + off;
        uint8_t *dst = pt + UDP_SESS_FEC_HDR;
        for (size_t b = 0; b < flen; b++) dst[b] ^= src[b];
    }
    put_be32(pt, msg_id);
    put_be32(pt + 4, s_start);
    put_be32(pt + 8, ftot);
    put_be16(pt + 12, s_cnt);
    put_be16(pt + 14, xor_len);
    return udp_sess_send_pkt(s, U_SESS_FEC, pt, sizeof(pt), 1);
}

fp_err_t fp_udp_session_send_verified(fp_udp_session_t *sess, uint8_t tag,
                                      const uint8_t *data, size_t len,
                                      fp_dna_t *out_dna) {
    if (!sess || (len > 0 && !data)) return FP_ERR_INVALID;
    if (len > (size_t)UDP_SESS_MAX_FRAGS * UDP_SESS_FRAG_PAYLOAD - 37u) return FP_ERR_BOUNDS;

    fp_dna_t dna;
    fp_err_t err = fp_dna_compute(data ? data : (const uint8_t *)"", len, &dna);
    if (err != FP_OK) return err;
    if (out_dna) *out_dna = dna;

    size_t blob_len = 37u + len;
    uint8_t *blob = malloc(blob_len);
    if (!blob) return FP_ERR_NOMEM;
    blob[0] = tag;
    memcpy(blob + 1, dna.bytes, FP_DNA_LEN);
    put_be32(blob + 33, (uint32_t)len);
    if (len > 0) memcpy(blob + 37, data, len);

    uint32_t ftot = (uint32_t)((blob_len + UDP_SESS_FRAG_PAYLOAD - 1u) / UDP_SESS_FRAG_PAYLOAD);
    if (ftot == 0) ftot = 1;
    uint32_t msg_id = ++sess->tx_msg_id;
    int send_fec = (sess->fec_mode == 1) || (sess->fec_mode == 2 && sess->fec_active_msgs > 0u);
    if (sess->fec_mode == 2 && sess->fec_active_msgs > 0u) sess->fec_active_msgs--;

    /* Initial burst of all fragments + optional proactive 0-RTT XOR FEC packet per stripe of 8 */
    for (uint32_t i = 0; i < ftot; i++) {
        err = udp_sess_send_one_frag(sess, msg_id, i, ftot, blob, blob_len);
        if (err != FP_OK) { free(blob); return err; }
        if (send_fec) {
            uint32_t stripe_end = ((i / UDP_SESS_FEC_STRIPE) + 1u) * UDP_SESS_FEC_STRIPE;
            if (stripe_end > ftot) stripe_end = ftot;
            if (i + 1u == stripe_end) {
                uint32_t s_start = (i / UDP_SESS_FEC_STRIPE) * UDP_SESS_FEC_STRIPE;
                uint16_t s_cnt = (uint16_t)(stripe_end - s_start);
                if (s_cnt >= 2u) {
                    err = udp_sess_send_fec_stripe(sess, msg_id, s_start, s_cnt, ftot, blob, blob_len);
                    if (err != FP_OK) { free(blob); return err; }
                }
            }
        }
        /* Tiny yield every 64 packets on huge tensors to keep kernel socket buffer clean */
        if (((i + 1u) & 63u) == 0u) {
            struct timespec ts = { 0, 100000 }; /* 0.1 ms */
            nanosleep(&ts, NULL);
        }
    }

    uint64_t deadline = now_ns() + (uint64_t)sess->timeout_ms * 1000000ull;
    int rto_ms = 12;
    uint8_t rpt[UDP_MAX_DATAGRAM];
    int done = 0;

    while (!done && now_ns() < deadline) {
        uint8_t ptype = 0;
        size_t rlen = 0;
        int rc = udp_sess_recv_pkt(sess, rto_ms, &ptype, rpt, &rlen);
        if (rc < 0) { err = FP_ERR_IO; break; }
        if (rc == 0) {
            /* RTO expired without ACK: retransmit up to first 32 fragments to trigger NACK/COMPLETE */
            uint32_t lim = ftot < 32u ? ftot : 32u;
            for (uint32_t i = 0; i < lim; i++) {
                (void)udp_sess_send_one_frag(sess, msg_id, i, ftot, blob, blob_len);
                sess->retransmits++;
            }
            if (rto_ms < 80) rto_ms += 8;
            continue;
        }
        if (ptype == U_SESS_CLOSE) { err = FP_ERR_IO; break; }
        if (ptype == U_SESS_ACK && rlen >= 7u) {
            uint32_t ack_id = get_be32(rpt);
            uint8_t status = rpt[4];
            uint16_t ncnt = get_be16(rpt + 5);
            if (ack_id != msg_id) continue;
            if (status == 1u) {
                done = 1;
                break;
            }
            if (status == 0u && rlen == 7u + (size_t)ncnt * 4u) {
                /* Selective fragment retransmit — only missing packets! */
                if (sess->fec_mode == 2 && ncnt > 0u) sess->fec_active_msgs = 64u;
                for (uint16_t k = 0; k < ncnt; k++) {
                    uint32_t midx = get_be32(rpt + 7u + (size_t)k * 4u);
                    if (midx < ftot) {
                        (void)udp_sess_send_one_frag(sess, msg_id, midx, ftot, blob, blob_len);
                        sess->retransmits++;
                    }
                }
                rto_ms = 12;
            }
        }
    }

    free(blob);
    return done ? FP_OK : (err != FP_OK ? err : FP_ERR_IO);
}

static void udp_sess_send_ack(fp_udp_session_t *s, uint32_t msg_id, uint8_t status,
                              const uint32_t *missing, uint16_t ncnt) {
    uint8_t pt[7u + UDP_SESS_MAX_NACKS * 4u];
    if (ncnt > UDP_SESS_MAX_NACKS) ncnt = UDP_SESS_MAX_NACKS;
    put_be32(pt, msg_id);
    pt[4] = status;
    put_be16(pt + 5, ncnt);
    for (uint16_t i = 0; i < ncnt; i++) put_be32(pt + 7u + (size_t)i * 4u, missing[i]);
    (void)udp_sess_send_pkt(s, U_SESS_ACK, pt, 7u + (size_t)ncnt * 4u, 0);
}

static void udp_try_fec_recover(fp_udp_session_t *sess, uint32_t stripe_idx, uint32_t ftot,
                                uint8_t *buf, uint8_t *got, uint16_t *frag_lens,
                                const uint8_t *fec_has, const uint16_t *fec_xor_len,
                                const uint8_t *fec_buf,
                                uint32_t *got_cnt, size_t *last_frag_len) {
    if (!fec_has[stripe_idx]) return;
    uint32_t s_start = stripe_idx * UDP_SESS_FEC_STRIPE;
    uint32_t s_end = s_start + UDP_SESS_FEC_STRIPE;
    if (s_end > ftot) s_end = ftot;
    if (s_end <= s_start + 1u) return;

    uint32_t missing_cnt = 0u, miss_idx = 0u;
    for (uint32_t i = s_start; i < s_end; i++) {
        if (!got[i]) { missing_cnt++; miss_idx = i; }
    }
    if (missing_cnt != 1u) return;

    uint16_t rec_len = fec_xor_len[stripe_idx];
    for (uint32_t i = s_start; i < s_end; i++) {
        if (i != miss_idx) rec_len ^= frag_lens[i];
    }
    if (rec_len > UDP_SESS_FRAG_PAYLOAD ||
        (miss_idx + 1u < ftot && rec_len != UDP_SESS_FRAG_PAYLOAD)) {
        return;
    }

    uint8_t *dst = buf + (size_t)miss_idx * UDP_SESS_FRAG_PAYLOAD;
    memcpy(dst, fec_buf + (size_t)stripe_idx * UDP_SESS_FRAG_PAYLOAD, UDP_SESS_FRAG_PAYLOAD);
    for (uint32_t i = s_start; i < s_end; i++) {
        if (i == miss_idx) continue;
        const uint8_t *src = buf + (size_t)i * UDP_SESS_FRAG_PAYLOAD;
        size_t fl = frag_lens[i];
        for (size_t b = 0; b < fl; b++) dst[b] ^= src[b];
    }
    got[miss_idx] = 1u;
    frag_lens[miss_idx] = rec_len;
    if (miss_idx + 1u == ftot) *last_frag_len = rec_len;
    (*got_cnt)++;
    sess->fec_recoveries++;
}

fp_err_t fp_udp_session_recv_verified(fp_udp_session_t *sess, size_t max_bytes,
                                      uint8_t *out_tag,
                                      uint8_t **out_data, size_t *out_len,
                                      fp_dna_t *out_dna) {
    if (!sess || !out_data || !out_len) return FP_ERR_INVALID;
    *out_data = NULL;
    *out_len = 0;
    if (max_bytes == 0) max_bytes = 64u << 20;

    uint64_t deadline = now_ns() + (uint64_t)sess->timeout_ms * 1000000ull;
    uint32_t expected_id = sess->rx_msg_id;
    uint32_t ftot = 0;
    uint32_t n_stripes = 0;
    uint32_t got_cnt = 0;
    size_t last_frag_len = 0;
    uint8_t *buf = NULL;
    uint8_t *got = NULL;
    uint16_t *frag_lens = NULL;
    uint8_t *fec_has = NULL;
    uint16_t *fec_xor_len = NULL;
    uint8_t *fec_buf = NULL;
    uint8_t rpt[UDP_MAX_DATAGRAM];
    fp_err_t err = FP_OK;

    while (now_ns() < deadline) {
        int wait_ms = (ftot > 0) ? 4 : 50;
        uint8_t ptype = 0;
        size_t rlen = 0;
        int rc = udp_sess_recv_pkt(sess, wait_ms, &ptype, rpt, &rlen);
        if (rc < 0) { err = FP_ERR_IO; break; }
        if (rc == 0) {
            if (ftot > 0 && got_cnt < ftot) {
                uint32_t miss[UDP_SESS_MAX_NACKS];
                uint16_t mc = 0;
                for (uint32_t i = 0; i < ftot && mc < UDP_SESS_MAX_NACKS; i++) {
                    if (!got[i]) miss[mc++] = i;
                }
                if (mc > 0) udp_sess_send_ack(sess, expected_id, 0u, miss, mc);
            }
            continue;
        }
        if (ptype == U_SESS_CLOSE) { err = FP_ERR_IO; break; }

        if (ptype == U_SESS_FEC) {
            if (rlen != UDP_SESS_FEC_HDR + UDP_SESS_FRAG_PAYLOAD) continue;
            uint32_t mid     = get_be32(rpt);
            uint32_t s_start = get_be32(rpt + 4);
            uint32_t tot     = get_be32(rpt + 8);
            uint16_t s_cnt   = get_be16(rpt + 12);
            uint16_t xlen    = get_be16(rpt + 14);
            if (mid < expected_id) { udp_sess_send_ack(sess, mid, 1u, NULL, 0); continue; }
            if (mid != expected_id) continue;
            if (tot == 0 || tot > UDP_SESS_MAX_FRAGS || (s_start % UDP_SESS_FEC_STRIPE) != 0u ||
                s_start >= tot || s_cnt < 2u || s_start + s_cnt > tot) {
                continue;
            }
            if (ftot == 0) {
                size_t max_alloc = (size_t)tot * UDP_SESS_FRAG_PAYLOAD;
                if (max_alloc > max_bytes + 37u + UDP_SESS_FRAG_PAYLOAD) { err = FP_ERR_BOUNDS; break; }
                n_stripes   = (tot + UDP_SESS_FEC_STRIPE - 1u) / UDP_SESS_FEC_STRIPE;
                buf         = malloc(max_alloc);
                got         = calloc(tot, 1u);
                frag_lens   = calloc(tot, sizeof(uint16_t));
                fec_has     = calloc(n_stripes, 1u);
                fec_xor_len = calloc(n_stripes, sizeof(uint16_t));
                fec_buf     = malloc((size_t)n_stripes * UDP_SESS_FRAG_PAYLOAD);
                if (!buf || !got || !frag_lens || !fec_has || !fec_xor_len || !fec_buf) {
                    err = FP_ERR_NOMEM; break;
                }
                ftot = tot;
            } else if (tot != ftot) {
                continue;
            }
            uint32_t sidx = s_start / UDP_SESS_FEC_STRIPE;
            if (!fec_has[sidx]) {
                fec_has[sidx] = 1u;
                fec_xor_len[sidx] = xlen;
                memcpy(fec_buf + (size_t)sidx * UDP_SESS_FRAG_PAYLOAD,
                       rpt + UDP_SESS_FEC_HDR, UDP_SESS_FRAG_PAYLOAD);
                udp_try_fec_recover(sess, sidx, ftot, buf, got, frag_lens,
                                    fec_has, fec_xor_len, fec_buf, &got_cnt, &last_frag_len);
            }
        } else if (ptype == U_SESS_FRAG && rlen >= UDP_SESS_FRAG_HDR) {
            uint32_t mid  = get_be32(rpt);
            uint32_t fidx = get_be32(rpt + 4);
            uint32_t tot  = get_be32(rpt + 8);
            uint16_t flen = get_be16(rpt + 12);

            if (mid < expected_id) {
                udp_sess_send_ack(sess, mid, 1u, NULL, 0);
                continue;
            }
            if (mid != expected_id) continue;
            if (tot == 0 || tot > UDP_SESS_MAX_FRAGS || fidx >= tot ||
                flen > UDP_SESS_FRAG_PAYLOAD || rlen != UDP_SESS_FRAG_HDR + flen ||
                (fidx + 1u < tot && flen != UDP_SESS_FRAG_PAYLOAD)) {
                continue;
            }

            if (ftot == 0) {
                size_t max_alloc = (size_t)tot * UDP_SESS_FRAG_PAYLOAD;
                if (max_alloc > max_bytes + 37u + UDP_SESS_FRAG_PAYLOAD) {
                    err = FP_ERR_BOUNDS;
                    break;
                }
                n_stripes   = (tot + UDP_SESS_FEC_STRIPE - 1u) / UDP_SESS_FEC_STRIPE;
                buf         = malloc(max_alloc);
                got         = calloc(tot, 1u);
                frag_lens   = calloc(tot, sizeof(uint16_t));
                fec_has     = calloc(n_stripes, 1u);
                fec_xor_len = calloc(n_stripes, sizeof(uint16_t));
                fec_buf     = malloc((size_t)n_stripes * UDP_SESS_FRAG_PAYLOAD);
                if (!buf || !got || !frag_lens || !fec_has || !fec_xor_len || !fec_buf) {
                    err = FP_ERR_NOMEM; break;
                }
                ftot = tot;
            } else if (tot != ftot) {
                continue;
            }

            if (!got[fidx]) {
                memcpy(buf + (size_t)fidx * UDP_SESS_FRAG_PAYLOAD, rpt + UDP_SESS_FRAG_HDR, flen);
                frag_lens[fidx] = flen;
                if (fidx + 1u == ftot) last_frag_len = flen;
                got[fidx] = 1u;
                got_cnt++;
                udp_try_fec_recover(sess, fidx / UDP_SESS_FEC_STRIPE, ftot, buf, got, frag_lens,
                                    fec_has, fec_xor_len, fec_buf, &got_cnt, &last_frag_len);
            }
        } else {
            continue;
        }

        if (ftot > 0 && got_cnt == ftot) {
            udp_sess_send_ack(sess, expected_id, 1u, NULL, 0);
            size_t blob_len = (size_t)(ftot - 1u) * UDP_SESS_FRAG_PAYLOAD + last_frag_len;
            if (blob_len < 37u) { err = FP_ERR_INVALID; break; }
            uint8_t tag = buf[0];
            fp_dna_t expected_dna, actual_dna;
            memcpy(expected_dna.bytes, buf + 1, FP_DNA_LEN);
            uint32_t mlen = get_be32(buf + 33);
            if ((size_t)mlen != blob_len - 37u || mlen > max_bytes) {
                err = FP_ERR_BOUNDS;
                break;
            }
            err = fp_dna_compute(mlen > 0 ? buf + 37 : (const uint8_t *)"", mlen, &actual_dna);
            if (err != FP_OK) break;
            if (!fp_dna_equal(&expected_dna, &actual_dna)) {
                err = FP_ERR_INTEGRITY;
                break;
            }
            uint8_t *out = malloc(mlen > 0 ? mlen : 1u);
            if (!out) { err = FP_ERR_NOMEM; break; }
            if (mlen > 0) memcpy(out, buf + 37, mlen);
            free(buf); free(got); free(frag_lens);
            free(fec_has); free(fec_xor_len); free(fec_buf);
            sess->rx_msg_id++;
            if (out_tag) *out_tag = tag;
            if (out_dna) *out_dna = actual_dna;
            *out_data = out;
            *out_len = mlen;
            return FP_OK;
        }
    }

    free(buf); free(got); free(frag_lens);
    free(fec_has); free(fec_xor_len); free(fec_buf);
    return (err != FP_OK) ? err : FP_ERR_IO;
}

void fp_udp_session_stats(const fp_udp_session_t *sess,
                          uint64_t *out_tx_bytes, uint64_t *out_rx_bytes,
                          uint64_t *out_retransmits) {
    if (!sess) return;
    if (out_tx_bytes) *out_tx_bytes = sess->tx_bytes;
    if (out_rx_bytes) *out_rx_bytes = sess->rx_bytes;
    if (out_retransmits) *out_retransmits = sess->retransmits;
}

uint64_t fp_udp_session_fec_recoveries(const fp_udp_session_t *sess) {
    return sess ? sess->fec_recoveries : 0u;
}

void fp_udp_session_set_fec(fp_udp_session_t *sess, int fec_mode) {
    if (!sess) return;
    if (fec_mode < 0 || fec_mode > 2) fec_mode = 1;
    sess->fec_mode = fec_mode;
}

void fp_udp_session_close(fp_udp_session_t *sess) {
    if (!sess) return;
    (void)udp_sess_send_pkt(sess, U_SESS_CLOSE, NULL, 0, 0);
    if (sess->owns_fd && sess->fd >= 0) close(sess->fd);
    sodium_memzero(sess->tx_key, sizeof(sess->tx_key));
    sodium_memzero(sess->rx_key, sizeof(sess->rx_key));
    free(sess);
}
