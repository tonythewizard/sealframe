#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int                 lfd;
    fp_net_server_cfg_t cfg;
} srv_thread_t;

static void *run_server(void *arg) {
    srv_thread_t *t = (srv_thread_t *)arg;
    (void)fp_net_serve_fd(t->lfd, &t->cfg);
    close(t->lfd);
    return NULL;
}

typedef struct {
    int                 lfd;
    const fp_keypair_t *skp;
    const uint8_t      *allow_pk;
} sess_srv_t;

static void *run_sess_echo(void *arg) {
    sess_srv_t *s = (sess_srv_t *)arg;
    fp_session_t *sess = NULL;
    if (fp_session_accept(s->lfd, s->skp, s->allow_pk, 5000, &sess) == FP_OK) {
        for (;;) {
            uint8_t tag = 0;
            uint8_t *buf = NULL;
            size_t len = 0;
            if (fp_session_recv_verified(sess, 1u << 20, &tag, &buf, &len, NULL) != FP_OK) break;
            fp_err_t serr = fp_session_send_verified(sess, tag, buf, len, NULL);
            free(buf);
            if (serr != FP_OK) break;
        }
        fp_session_close(sess);
    }
    close(s->lfd);
    return NULL;
}

static void fill_compressible(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t x = seed;
    for (size_t i = 0; i < len; i++) {
        if ((i & 31u) < 20u) {
            buf[i] = (uint8_t)('a' + (i % 26u));
        } else {
            x = x * 1664525u + 1013904223u;
            buf[i] = (uint8_t)(x >> 24);
        }
    }
}

static void start_srv(pthread_t *th, srv_thread_t *ctx, uint16_t *port_out,
                      const char *store, const fp_keypair_t *skp,
                      const uint8_t *allow_pk, uint32_t max_req,
                      uint64_t drop_after, uint64_t corrupt_chunk) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->lfd = fp_net_listen("127.0.0.1", 0, port_out);
    assert(ctx->lfd >= 0);
    ctx->cfg.bind_addr = "127.0.0.1";
    ctx->cfg.port = *port_out;
    ctx->cfg.store_dir = store;
    ctx->cfg.server_kp = skp;
    ctx->cfg.allowed_peer_pk = allow_pk;
    ctx->cfg.max_requests = max_req;
    ctx->cfg.fault_drop_after_chunks = drop_after;
    ctx->cfg.fault_corrupt_chunk = corrupt_chunk;
    assert(pthread_create(th, NULL, run_server, ctx) == 0);
}

int main(void) {
    assert(fp_init() == FP_OK);

    fp_keypair_t srv_kp, cli_kp, evil_kp;
    assert(fp_keygen(&srv_kp) == FP_OK);
    assert(fp_keygen(&cli_kp) == FP_OK);
    assert(fp_keygen(&evil_kp) == FP_OK);

    char s_tmpl[] = "/tmp/fp-net-srv-XXXXXX";
    char c_tmpl[] = "/tmp/fp-net-cli-XXXXXX";
    char *s_dir = mkdtemp(s_tmpl);
    char *c_dir = mkdtemp(c_tmpl);
    assert(s_dir && c_dir);

    /* Prepare 2.5 MiB v1 and v2 (256 B diff) + 1 MiB stream test object */
    const size_t BIG = (2u << 20) + 524288u;
    uint8_t *v1 = malloc(BIG);
    uint8_t *v2 = malloc(BIG);
    assert(v1 && v2);
    fill_compressible(v1, BIG, 11u);
    memcpy(v2, v1, BIG);
    for (size_t i = 0; i < 256; i++) v2[BIG / 2 + i] ^= 0x5Au;

    const size_t STRM_SZ = 1u << 20; /* 1 MiB = 64 Merkle chunks */
    uint8_t *strm = malloc(STRM_SZ);
    assert(strm != NULL);
    fill_compressible(strm, STRM_SZ, 99u);

    fp_dna_t dna_v1, dna_v2, dna_strm;
    assert(fp_store_put_object(s_dir, v1, BIG, &dna_v1) == FP_OK);
    assert(fp_store_put_object(s_dir, v2, BIG, &dna_v2) == FP_OK);
    assert(fp_store_put_object(s_dir, strm, STRM_SZ, &dna_strm) == FP_OK);

    /* --- 1. Mutual Authentication Pinning Rejection (wrong server & wrong client) --- */
    {
        pthread_t th; srv_thread_t sc; uint16_t port = 0;
        start_srv(&th, &sc, &port, s_dir, &srv_kp, cli_kp.pk, 2, 0, 0);

        fp_net_pull_cfg_t pcfg;
        memset(&pcfg, 0, sizeof(pcfg));
        pcfg.host = "127.0.0.1"; pcfg.port = port; pcfg.store_dir = c_dir;
        pcfg.client_kp = &cli_kp; pcfg.expected_srv_pk = evil_kp.pk; /* wrong server pin */
        pcfg.target_dna = dna_v1;
        assert(fp_net_pull(&pcfg, NULL) == FP_ERR_SIGNATURE);

        pcfg.client_kp = &evil_kp; pcfg.expected_srv_pk = srv_kp.pk; /* unauthorized client */
        assert(fp_net_pull(&pcfg, NULL) != FP_OK);

        pthread_join(th, NULL);
        printf("[PASS] FP-NET mutual Ed25519 pinning rejects MITM and unauthorized peers\n");
    }

    /* --- 2. Autonomous Morph: ZSTD (cold v1), REF (already resident), DELTA (v1->v2) --- */
    {
        pthread_t th; srv_thread_t sc; uint16_t port = 0;
        start_srv(&th, &sc, &port, s_dir, &srv_kp, cli_kp.pk, 3, 0, 0);

        fp_net_pull_cfg_t pcfg;
        fp_net_stats_t st;

        /* 2a: Cold pull of v1 -> negotiates ZSTD */
        memset(&pcfg, 0, sizeof(pcfg));
        pcfg.host = "127.0.0.1"; pcfg.port = port; pcfg.store_dir = c_dir;
        pcfg.client_kp = &cli_kp; pcfg.expected_srv_pk = srv_kp.pk;
        pcfg.target_dna = dna_v1;
        assert(fp_net_pull(&pcfg, &st) == FP_OK);
        assert(st.mode == FP_NET_MODE_ZSTD);
        assert(st.canonical_size == BIG && st.wire_bytes < BIG);
        uint8_t *got = NULL; size_t got_len = 0;
        assert(fp_store_get_object(c_dir, &dna_v1, BIG, &got, &got_len) == FP_OK);
        assert(got_len == BIG && memcmp(got, v1, BIG) == 0);
        free(got);

        /* 2b: Pull v1 again -> negotiates REF (0-byte payload!) */
        assert(fp_net_pull(&pcfg, &st) == FP_OK);
        assert(st.mode == FP_NET_MODE_REF);
        assert(st.wire_bytes < 600u); /* Only handshake + tiny control frames! */

        /* 2c: Pull v2 with v1 hint -> negotiates DELTA (< 4 KiB encrypted for 2.5 MiB!) */
        pcfg.target_dna = dna_v2;
        pcfg.extra_refs[0] = dna_v1;
        pcfg.extra_ref_count = 1;
        assert(fp_net_pull(&pcfg, &st) == FP_OK);
        assert(st.mode == FP_NET_MODE_DELTA);
        assert(fp_dna_equal(&st.negotiated_ref, &dna_v1));
        assert(st.wire_bytes < 4096u);
        assert(fp_store_get_object(c_dir, &dna_v2, BIG, &got, &got_len) == FP_OK);
        assert(got_len == BIG && memcmp(got, v2, BIG) == 0);
        free(got);

        pthread_join(th, NULL);
        printf("[PASS] Autonomous Morph over TCP: ZSTD -> REF (%llu B) -> DELTA (2.5 MiB in %llu B)\n",
               (unsigned long long)512, (unsigned long long)st.wire_bytes);
    }

    /* --- 3. Merkle Verified Streaming: Abrupt Drop at Chunk 20 -> Exact Resume --- */
    {
        pthread_t th1, th2; srv_thread_t sc1, sc2; uint16_t port1 = 0, port2 = 0;
        /* Server 1 drops TCP abruptly after 20 chunks */
        start_srv(&th1, &sc1, &port1, s_dir, &srv_kp, cli_kp.pk, 1, 20, 0);

        fp_net_pull_cfg_t pcfg;
        fp_net_stats_t st;
        memset(&pcfg, 0, sizeof(pcfg));
        pcfg.host = "127.0.0.1"; pcfg.port = port1; pcfg.store_dir = c_dir;
        pcfg.client_kp = &cli_kp; pcfg.expected_srv_pk = srv_kp.pk;
        pcfg.target_dna = dna_strm;
        pcfg.force_merkle_stream = 1;

        assert(fp_net_pull(&pcfg, &st) == FP_ERR_IO);
        assert(st.received_chunks == 20 && st.resumed_chunks == 0);
        pthread_join(th1, NULL);

        /* Server 2 healthy: client automatically resumes from chunk 20! */
        start_srv(&th2, &sc2, &port2, s_dir, &srv_kp, cli_kp.pk, 1, 0, 0);
        pcfg.port = port2;
        assert(fp_net_pull(&pcfg, &st) == FP_OK);
        assert(st.mode == FP_NET_MODE_MERKLE_STREAM);
        assert(st.resumed_chunks == 20 && st.received_chunks == 44);
        pthread_join(th2, NULL);

        uint8_t *got = NULL; size_t got_len = 0;
        assert(fp_store_get_object(c_dir, &dna_strm, STRM_SZ, &got, &got_len) == FP_OK);
        assert(got_len == STRM_SZ && memcmp(got, strm, STRM_SZ) == 0);
        free(got);
        printf("[PASS] Merkle Verified Streaming drop + exact resume (20 skipped + 44 received = 64 chunks)\n");
    }

    /* --- 4. In-Flight 1-Bit Chunk Corruption Rejected Immediately Before Disk --- */
    {
        char c2_tmpl[] = "/tmp/fp-net-corrupt-XXXXXX";
        char *c2_dir = mkdtemp(c2_tmpl);
        assert(c2_dir != NULL);

        pthread_t th; srv_thread_t sc; uint16_t port = 0;
        /* Corrupt chunk #7 (1-based) in flight */
        start_srv(&th, &sc, &port, s_dir, &srv_kp, cli_kp.pk, 1, 0, 7);

        fp_net_pull_cfg_t pcfg;
        fp_net_stats_t st;
        memset(&pcfg, 0, sizeof(pcfg));
        pcfg.host = "127.0.0.1"; pcfg.port = port; pcfg.store_dir = c2_dir;
        pcfg.client_kp = &cli_kp; pcfg.expected_srv_pk = srv_kp.pk;
        pcfg.target_dna = dna_strm;
        pcfg.force_merkle_stream = 1;

        assert(fp_net_pull(&pcfg, &st) == FP_ERR_INTEGRITY);
        assert(st.received_chunks == 6); /* Chunks 0..5 valid, chunk 6 rejected BEFORE write! */
        assert(!fp_store_has_object(c2_dir, &dna_strm, NULL));
        pthread_join(th, NULL);
        printf("[PASS] In-flight 1-bit chunk corruption caught instantaneously at chunk #7\n");
    }

    /* --- 5. Persistent Encrypted Verified Session (0B + 10 KiB 1-frame + 256 KiB multi-slice) --- */
    {
        uint16_t sport = 0;
        int slfd = fp_net_listen("127.0.0.1", 0, &sport);
        assert(slfd >= 0 && sport > 0);
        sess_srv_t ss = { slfd, &srv_kp, cli_kp.pk };
        pthread_t sth;
        assert(pthread_create(&sth, NULL, run_sess_echo, &ss) == 0);

        fp_session_t *cs = NULL;
        assert(fp_session_connect("127.0.0.1", sport, &cli_kp, srv_kp.pk, 5000, &cs) == FP_OK);

        const size_t sizes[3] = { 0u, 10240u, 262144u };
        for (int i = 0; i < 3; i++) {
            uint8_t *msg = malloc(sizes[i] > 0 ? sizes[i] : 1u);
            assert(msg != NULL);
            if (sizes[i] > 0) fill_compressible(msg, sizes[i], (uint32_t)(100 + i));
            fp_dna_t tx_dna, rx_dna;
            assert(fp_session_send_verified(cs, (uint8_t)(i + 1), msg, sizes[i], &tx_dna) == FP_OK);

            uint8_t rtag = 0;
            uint8_t *rbuf = NULL;
            size_t rlen = 0;
            assert(fp_session_recv_verified(cs, 1u << 20, &rtag, &rbuf, &rlen, &rx_dna) == FP_OK);
            assert(rtag == (uint8_t)(i + 1) && rlen == sizes[i]);
            assert(fp_dna_equal(&tx_dna, &rx_dna));
            if (sizes[i] > 0) assert(memcmp(rbuf, msg, sizes[i]) == 0);
            free(rbuf);
            free(msg);
        }
        uint64_t tx_b = 0, rx_b = 0;
        fp_session_stats(cs, &tx_b, &rx_b);
        assert(tx_b > 270000u && rx_b > 270000u);
        fp_session_close(cs);
        pthread_join(sth, NULL);
        printf("[PASS] Persistent encrypted verified session (0B + 10 KiB 1-frame + 256 KiB multi-slice)\n");
    }

    /* --- 6. Native SFT1 Tensor Streaming + Pure-C11 IEEE-754 FP16 Codec + Bounds Hardening --- */
    {
        /* 6a: Pure-C11 IEEE-754 FP32 <-> FP16 edge cases */
        assert(fp_f32_to_f16(0.0f) == 0x0000u && fp_f16_to_f32(0x0000u) == 0.0f);
        assert(fp_f32_to_f16(-0.0f) == 0x8000u);
        assert(fp_f32_to_f16(1.0f) == 0x3C00u && fp_f16_to_f32(0x3C00u) == 1.0f);
        assert(fp_f16_to_f32(fp_f32_to_f16(-3.5f)) == -3.5f);
        /* Subnormal round-trip */
        float sub = 3.0e-5f;
        float sub_rt = fp_f16_to_f32(fp_f32_to_f16(sub));
        assert(fabsf(sub_rt - sub) < 1e-6f);
        /* Overflow -> +/-Inf and NaN preservation */
        assert(isinf(fp_f16_to_f32(fp_f32_to_f16(1e6f))) && fp_f16_to_f32(fp_f32_to_f16(1e6f)) > 0.0f);
        assert(isinf(fp_f16_to_f32(fp_f32_to_f16(-1e6f))) && fp_f16_to_f32(fp_f32_to_f16(-1e6f)) < 0.0f);
        assert(isnan(fp_f16_to_f32(fp_f32_to_f16(NAN))));

        /* 6b: Adversarial SFT1 pack/unpack rejections */
        fp_tensor_meta_t bad_m;
        uint8_t *wbuf = NULL; size_t wlen = 0;
        uint8_t dummy[16] = {0};
        memset(&bad_m, 0, sizeof(bad_m));
        bad_m.dtype = FP_DTYPE_FP32; bad_m.ndim = 2;
        bad_m.dims[0] = 0xFFFFFFFFu; bad_m.dims[1] = 0xFFFFFFFFu;
        assert(fp_tensor_pack(&bad_m, dummy, sizeof(dummy), 0, &wbuf, &wlen) == FP_ERR_BOUNDS);
        bad_m.dims[0] = 2; bad_m.dims[1] = 2; bad_m.dims[2] = 1; /* trailing non-zero dim */
        assert(fp_tensor_pack(&bad_m, dummy, sizeof(dummy), 0, &wbuf, &wlen) == FP_ERR_INVALID);
        bad_m.dims[2] = 0; bad_m.dtype = FP_DTYPE_INT8;
        assert(fp_tensor_pack(&bad_m, dummy, 4, 1, &wbuf, &wlen) == FP_ERR_INVALID); /* cast on INT8 */
        bad_m.dtype = FP_DTYPE_FP32;
        assert(fp_tensor_pack(&bad_m, dummy, 12, 0, &wbuf, &wlen) == FP_ERR_BOUNDS); /* wrong byte len */

        /* Pack a valid 2x2 FP32 tensor then corrupt header fields */
        assert(fp_tensor_pack(&bad_m, dummy, 16, 0, &wbuf, &wlen) == FP_OK && wlen == 48u);
        fp_tensor_meta_t um; uint8_t *ud = NULL; size_t ul = 0;
        assert(fp_tensor_unpack(wbuf, wlen - 1u, 0, &um, &ud, &ul) == FP_ERR_BOUNDS);
        wbuf[6] = FP_TENSOR_FLAG_WIRE_FP16; /* flag claims FP16 while dtype is FP32 */
        assert(fp_tensor_unpack(wbuf, wlen, 0, &um, &ud, &ul) == FP_ERR_INVALID);
        wbuf[6] = 0; wbuf[0] = 'X';
        assert(fp_tensor_unpack(wbuf, wlen, 0, &um, &ud, &ul) == FP_ERR_INVALID);
        free(wbuf);

        /* 6c: Live encrypted SFT1 tensor streaming (FP32, on-the-fly FP16 wire cast, INT8 3D) */
        uint16_t tport = 0;
        int tlfd = fp_net_listen("127.0.0.1", 0, &tport);
        assert(tlfd >= 0 && tport > 0);
        sess_srv_t ts = { tlfd, &srv_kp, cli_kp.pk };
        pthread_t tth;
        assert(pthread_create(&tth, NULL, run_sess_echo, &ts) == 0);

        fp_session_t *tcs = NULL;
        assert(fp_session_connect("127.0.0.1", tport, &cli_kp, srv_kp.pk, 5000, &tcs) == FP_OK);

        const uint32_t R = 5u, C = 512u;
        float *src = malloc((size_t)R * C * sizeof(float));
        assert(src != NULL);
        for (size_t i = 0; i < (size_t)R * C; i++) {
            src[i] = ((float)((int)(i % 200) - 100)) * 0.0125f;
        }
        fp_tensor_meta_t sm;
        memset(&sm, 0, sizeof(sm));
        sm.dtype = FP_DTYPE_FP32;
        sm.ndim = 2;
        sm.dims[0] = R; sm.dims[1] = C;
        sm.seq_id = UINT64_C(0x0000020100001234);

        /* Bit-exact FP32 tensor over persistent encrypted session */
        uint64_t tx0 = 0, rx0 = 0, tx1 = 0, rx1 = 0, tx2 = 0, rx2 = 0;
        fp_session_stats(tcs, &tx0, &rx0);
        fp_dna_t tdna_tx, tdna_rx;
        assert(fp_session_send_tensor(tcs, 2, &sm, src, (size_t)R * C * sizeof(float), 0, &tdna_tx) == FP_OK);
        uint8_t rtag = 0;
        assert(fp_session_recv_tensor(tcs, 1u << 20, 0, &rtag, &um, &ud, &ul, &tdna_rx) == FP_OK);
        assert(rtag == 2 && fp_dna_equal(&tdna_tx, &tdna_rx));
        assert(um.dtype == FP_DTYPE_FP32 && um.ndim == 2 && um.dims[0] == R && um.dims[1] == C);
        assert(um.seq_id == sm.seq_id && um.flags == 0 && ul == (size_t)R * C * sizeof(float));
        assert(memcmp(ud, src, ul) == 0);
        free(ud);
        fp_session_stats(tcs, &tx1, &rx1);

        /* On-the-fly FP32 -> FP16 wire cast -> automatic FP32 upcast (-50% wire bytes!) */
        assert(fp_session_send_tensor(tcs, 3, &sm, src, (size_t)R * C * sizeof(float), 1, &tdna_tx) == FP_OK);
        assert(fp_session_recv_tensor(tcs, 1u << 20, 1, &rtag, &um, &ud, &ul, &tdna_rx) == FP_OK);
        assert(rtag == 3 && fp_dna_equal(&tdna_tx, &tdna_rx));
        assert(um.dtype == FP_DTYPE_FP32 && (um.flags & FP_TENSOR_FLAG_WIRE_FP16) != 0);
        assert(um.ndim == 2 && um.dims[0] == R && um.dims[1] == C && um.seq_id == sm.seq_id);
        assert(ul == (size_t)R * C * sizeof(float));
        const float *got_f = (const float *)ud;
        float max_err = 0.0f;
        for (size_t i = 0; i < (size_t)R * C; i++) {
            float e = fabsf(got_f[i] - src[i]);
            if (e > max_err) max_err = e;
        }
        assert(max_err < 1e-3f);
        free(ud);
        fp_session_stats(tcs, &tx2, &rx2);
        /* Verify FP16 wire traffic is strictly ~50% of FP32 wire traffic */
        assert((tx2 - tx1) * 2u < (tx1 - tx0) + 256u);

        /* Native BF16 wire cast (preserves full FP32 dynamic range, including 1e20f!) */
        assert(fp_bf16_to_f32(fp_f32_to_bf16(0.0f)) == 0.0f);
        assert(fp_bf16_to_f32(fp_f32_to_bf16(-3.5f)) == -3.5f);
        assert(isfinite(fp_bf16_to_f32(fp_f32_to_bf16(1e20f))));
        assert(isnan(fp_bf16_to_f32(fp_f32_to_bf16(NAN))));
        uint64_t tx3 = 0, rx3 = 0, tx4 = 0, rx4 = 0;
        assert(fp_session_send_tensor_ex(tcs, 4, &sm, src, (size_t)R * C * sizeof(float),
                                         FP_WIRE_CAST_BF16, &tdna_tx) == FP_OK);
        assert(fp_session_recv_tensor(tcs, 1u << 20, 1, &rtag, &um, &ud, &ul, &tdna_rx) == FP_OK);
        assert(rtag == 4 && fp_dna_equal(&tdna_tx, &tdna_rx));
        assert(um.dtype == FP_DTYPE_FP32 && (um.flags & FP_TENSOR_FLAG_WIRE_BF16) != 0 && ul == (size_t)R * C * sizeof(float));
        float max_bf = 0.0f;
        for (size_t i = 0; i < (size_t)R * C; i++) {
            float e = fabsf(((const float *)ud)[i] - src[i]);
            if (e > max_bf) max_bf = e;
        }
        assert(max_bf < 1e-2f);
        free(ud);
        fp_session_stats(tcs, &tx3, &rx3);
        assert((tx3 - tx2) * 2u < (tx1 - tx0) + 256u);

        /* Native INT8 symmetric wire cast (-75% wire traffic, seq_id preserved!) */
        assert(fp_session_send_tensor_ex(tcs, 5, &sm, src, (size_t)R * C * sizeof(float),
                                         FP_WIRE_CAST_INT8, &tdna_tx) == FP_OK);
        assert(fp_session_recv_tensor(tcs, 1u << 20, 1, &rtag, &um, &ud, &ul, &tdna_rx) == FP_OK);
        assert(rtag == 5 && fp_dna_equal(&tdna_tx, &tdna_rx));
        assert(um.dtype == FP_DTYPE_FP32 && (um.flags & FP_TENSOR_FLAG_WIRE_INT8) != 0);
        assert(um.seq_id == sm.seq_id && ul == (size_t)R * C * sizeof(float));
        float max_i8 = 0.0f;
        for (size_t i = 0; i < (size_t)R * C; i++) {
            float e = fabsf(((const float *)ud)[i] - src[i]);
            if (e > max_i8) max_i8 = e;
        }
        assert(max_i8 < 2e-2f);
        free(ud);
        fp_session_stats(tcs, &tx4, &rx4);
        assert((tx4 - tx3) * 4u < (tx1 - tx0) + 512u);

        /* 3D INT8 tensor */
        int8_t qdata[64];
        for (int i = 0; i < 64; i++) qdata[i] = (int8_t)(i - 32);
        fp_tensor_meta_t qm;
        memset(&qm, 0, sizeof(qm));
        qm.dtype = FP_DTYPE_INT8; qm.ndim = 3;
        qm.dims[0] = 2; qm.dims[1] = 4; qm.dims[2] = 8; qm.seq_id = 77;
        assert(fp_session_send_tensor(tcs, 9, &qm, qdata, sizeof(qdata), 0, NULL) == FP_OK);
        assert(fp_session_recv_tensor(tcs, 1u << 20, 1, &rtag, &um, &ud, &ul, NULL) == FP_OK);
        assert(rtag == 9 && um.dtype == FP_DTYPE_INT8 && um.ndim == 3 && ul == sizeof(qdata));
        assert(memcmp(ud, qdata, sizeof(qdata)) == 0);
        free(ud);
        free(src);

        fp_session_close(tcs);
        pthread_join(tth, NULL);
        printf("[PASS] Native SFT1 Tensor Streaming (FP32 exact, FP16 wire cast max_err=%.2e, INT8 3D)\n",
               (double)max_err);
    }

    free(v1); free(v2); free(strm);
    printf("ALL FP-NET v1 NETWORK TESTS PASSED.\n");
    return 0;
}
