#define _POSIX_C_SOURCE 200809L

#include "fp.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CLI_MAX_FILE (128u << 20) /* 128 MiB */

static int parse_u64_strict(const char *s, uint64_t *out) {
    if (!s || s[0] < '0' || s[0] > '9') return -1;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        uint64_t d = (uint64_t)(*p - '0');
        if (v > (UINT64_MAX - d) / 10u) return -1;
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

static int parse_port_strict(const char *s, int allow_zero, uint16_t *out) {
    uint64_t v = 0;
    if (parse_u64_strict(s, &v) != 0 || v > 65535u || (!allow_zero && v == 0)) return -1;
    *out = (uint16_t)v;
    return 0;
}

static int read_entire_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "fp: cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size > CLI_MAX_FILE) {
        fprintf(stderr, "fp: file '%s' invalid or exceeds 128 MiB limit\n", path);
        fclose(f);
        return -1;
    }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = malloc(sz > 0 ? sz : 1u);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (sz > 0 && fread(buf, 1, sz, f) != sz) {
        fprintf(stderr, "fp: read error on '%s'\n", path);
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = buf;
    *out_len = sz;
    return 0;
}

static int write_entire_file(const char *path, const uint8_t *data, size_t len, mode_t mode) {
    char tmp[PATH_MAX];
    int tn = snprintf(tmp, sizeof(tmp), "%s.sf-tmp-XXXXXX", path);
    if (tn < 0 || (size_t)tn >= sizeof(tmp)) {
        fprintf(stderr, "sf: output path too long '%s'\n", path);
        return -1;
    }
    int fd = mkstemp(tmp);
    if (fd < 0) {
        fprintf(stderr, "sf: cannot create temp file for '%s': %s\n", path, strerror(errno));
        return -1;
    }
    (void)fchmod(fd, mode);
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "sf: write error on '%s': %s\n", path, strerror(errno));
            close(fd);
            unlink(tmp);
            return -1;
        }
        written += (size_t)n;
    }
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);
    if (rename(tmp, path) != 0) {
        fprintf(stderr, "sf: rename error on '%s': %s\n", path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

static const char *morph_name(fp_morph_kind_t k) {
    switch (k) {
        case FP_MORPH_RAW:     return "raw";
        case FP_MORPH_ZSTD:    return "zstd";
        case FP_MORPH_DELTA:   return "delta";
        case FP_MORPH_REF:     return "ref";
        case FP_MORPH_COMPUTE: return "compute";
        default:               return "unknown";
    }
}

static void usage(void) {
    fprintf(stderr,
        "sf %d.%d — SealFrame (FP01) CLI (compat alias: fp)\n"
        "Usage:\n"
        "  fp dna <file>\n"
        "  fp put <store_dir> <file>\n"
        "  fp keygen <priv.key> <pub.key>\n"
        "  fp morph <raw|zstd|delta|ref> <input> <output.fp> [ref_file]\n"
        "  fp inspect <particle.fp>\n"
        "  fp materialize <particle.fp> <output> [ref_file]\n"
        "  fp emit --key <priv.key> --repo <hex64> --serial <n> [--prev <hex64>]\n"
        "          --action <install|rollback|revoke> [--input <file>] [--target <hex64>]\n"
        "          [--ttl <sec>] [--reason <text>] --out <event.ev>\n"
        "  fp apply <store_dir> <event.ev> --pub <pub.key> --repo <hex64> [--data <file>]\n"
        "  fp status <store_dir>\n"
        "  fp anchor <event.ev> [--log <anchor.log>] [--verify]\n"
        "  fp serve <store_dir> --key <priv.key> [--bind <ip>] [--port <n>]\n"
        "           [--allow-pub <pub.key>] [--max <n>] [--ready-file <path>]\n"
        "  fp pull <host:port> <dna_hex> <store_dir> --key <priv.key> --peer-pub <pub.key>\n"
        "          [--ref <dna_hex>] [--stream]\n"
        "  fp ingest <store_dir> <file>\n"
        "  fp reconstruct <store_dir> <dna_hex> <output_file>\n"
        "  fp bundle-pack <store_dir> --file <rel>=<path> [--changeset <table>=<path>]\n"
        "  fp bundle-apply <store_dir> <bundle_dna> <target_dir> [--db <path>] [--seq <n>]\n"
        "  fp bundle-rollback <store_dir> <cur_dna> <prev_dna> <target_dir> [--db <path>]\n"
        "  fp root-init --repo <hex64> --threshold <k> --root-pub <pk> [...] --release-pub <pk>\n"
        "               --sign <sk> [...] [--version <n>] [--ttl <sec>] --out <root.fpr>\n"
        "  fp root-verify <root.fpr> [--prev <prev.fpr>]\n"
        "  fp swarm-pull <dna_hex> <store_dir> --key <priv.key> --peer <host:port> [...]\n"
        "  fp udp-serve <store_dir> --key <priv.key> [--bind <ip>] [--port <n>] [--max <n>]\n"
        "  fp udp-pull <host:port> <dna_hex> <store_dir> --key <priv.key> [--peer-pub <pk>]\n",
        FP_VERSION_MAJOR, FP_VERSION_MINOR);
}

static int cmd_put(int argc, char **argv) {
    if (argc != 2) { usage(); return 1; }
    fp_dna_t dna;
    uint64_t len = 0;
    fp_err_t err = fp_store_put_file(argv[0], argv[1], &dna, &len);
    if (err != FP_OK) {
        fprintf(stderr, "fp put: %s\n", fp_strerror(err));
        return 1;
    }
    char hex[65];
    fp_hex_encode(dna.bytes, FP_DNA_LEN, hex);
    printf("stored=true dna=%s bytes=%llu\n", hex, (unsigned long long)len);
    return 0;
}

static int cmd_dna(int argc, char **argv) {
    if (argc != 1) { usage(); return 1; }
    fp_dna_t dna;
    uint64_t sz = 0;
    fp_err_t err = fp_dna_compute_file(argv[0], &dna, &sz);
    if (err != FP_OK) {
        fprintf(stderr, "fp dna: %s\n", fp_strerror(err));
        return 1;
    }
    char hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(dna.bytes, FP_DNA_LEN, hex);
    printf("dna=%s bytes=%llu chunks=%llu\n", hex, (unsigned long long)sz,
           (unsigned long long)(sz == 0 ? 0u : (1u + (sz - 1u) / FP_CHUNK_SIZE)));
    return 0;
}

static int cmd_keygen(int argc, char **argv) {
    if (argc != 2) { usage(); return 1; }
    fp_keypair_t kp;
    fp_dna_t repo;
    if (fp_keygen(&kp) != FP_OK || fp_random_id(&repo) != FP_OK) {
        sodium_memzero(&kp, sizeof(kp));
        fprintf(stderr, "fp keygen: failed\n");
        return 1;
    }
    int wrc = (write_entire_file(argv[0], kp.sk, FP_SK_LEN, 0600) != 0 ||
               write_entire_file(argv[1], kp.pk, FP_PK_LEN, 0644) != 0);
    char pk_hex[FP_PK_LEN * 2 + 1], repo_hex[FP_DNA_LEN * 2 + 1];
    fp_hex_encode(kp.pk, FP_PK_LEN, pk_hex);
    fp_hex_encode(repo.bytes, FP_DNA_LEN, repo_hex);
    sodium_memzero(&kp, sizeof(kp));
    if (wrc) return 1;
    printf("pubkey=%s\nrepo=%s\n", pk_hex, repo_hex);
    return 0;
}

static int cmd_morph(int argc, char **argv) {
    if (argc < 3 || argc > 4) { usage(); return 1; }
    fp_morph_kind_t kind;
    if (strcmp(argv[0], "raw") == 0)        kind = FP_MORPH_RAW;
    else if (strcmp(argv[0], "zstd") == 0)  kind = FP_MORPH_ZSTD;
    else if (strcmp(argv[0], "delta") == 0) kind = FP_MORPH_DELTA;
    else if (strcmp(argv[0], "ref") == 0)   kind = FP_MORPH_REF;
    else { fprintf(stderr, "fp morph: unknown mode '%s'\n", argv[0]); return 1; }

    uint8_t *in_buf = NULL, *ref_buf = NULL, *wire = NULL;
    size_t in_len = 0, ref_len = 0, wire_len = 0;
    if (read_entire_file(argv[1], &in_buf, &in_len) != 0) return 1;
    if (argc == 4 && read_entire_file(argv[3], &ref_buf, &ref_len) != 0) {
        free(in_buf);
        return 1;
    }

    fp_morph_ctx_t *ctx = fp_morph_ctx_new();
    if (!ctx) { free(in_buf); free(ref_buf); return 1; }

    fp_err_t err = fp_morph_encode(ctx, kind, in_buf, in_len, ref_buf, ref_len, 3,
                                   &wire, &wire_len);
    fp_morph_ctx_free(ctx);
    free(in_buf);
    free(ref_buf);

    if (err != FP_OK) {
        fprintf(stderr, "fp morph: %s\n", fp_strerror(err));
        return 1;
    }
    int rc = write_entire_file(argv[2], wire, wire_len, 0644);
    if (rc == 0) {
        fp_wire_header_t hdr;
        fp_wire_parse_header(wire, wire_len, &hdr);
        char hex[FP_DNA_LEN * 2 + 1];
        fp_hex_encode(hdr.dna.bytes, FP_DNA_LEN, hex);
        printf("morph=%s dna=%s canonical=%zu wire=%zu ratio=%.2f%%\n",
               morph_name(kind), hex, in_len, wire_len,
               in_len > 0 ? (100.0 * (double)wire_len / (double)in_len) : 0.0);
    }
    free(wire);
    return rc == 0 ? 0 : 1;
}

static int cmd_inspect(int argc, char **argv) {
    if (argc != 1) { usage(); return 1; }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (read_entire_file(argv[0], &wire, &wire_len) != 0) return 1;
    fp_wire_header_t hdr;
    fp_err_t err = fp_wire_parse_header(wire, wire_len, &hdr);
    free(wire);
    if (err != FP_OK) {
        fprintf(stderr, "fp inspect: %s\n", fp_strerror(err));
        return 1;
    }
    char dna_hex[65], ref_hex[65];
    fp_hex_encode(hdr.dna.bytes, FP_DNA_LEN, dna_hex);
    printf("format=FP01 kind=%s canonical_size=%llu payload_size=%llu header_size=%zu dna=%s",
           morph_name(hdr.kind), (unsigned long long)hdr.canonical_size,
           (unsigned long long)hdr.payload_size, hdr.header_size, dna_hex);
    if (hdr.flags & FP_WIRE_FLAG_REF) {
        fp_hex_encode(hdr.ref_dna.bytes, FP_DNA_LEN, ref_hex);
        printf(" ref_dna=%s", ref_hex);
    }
    printf("\n");
    return 0;
}

static int cmd_materialize(int argc, char **argv) {
    if (argc < 2 || argc > 3) { usage(); return 1; }
    uint8_t *wire = NULL, *ref_buf = NULL, *out_buf = NULL;
    size_t wire_len = 0, ref_len = 0, out_len = 0;
    if (read_entire_file(argv[0], &wire, &wire_len) != 0) return 1;
    if (argc == 3 && read_entire_file(argv[2], &ref_buf, &ref_len) != 0) {
        free(wire);
        return 1;
    }

    fp_morph_ctx_t *ctx = fp_morph_ctx_new();
    if (!ctx) { free(wire); free(ref_buf); return 1; }
    fp_dna_t dna;
    fp_err_t err = fp_morph_materialize(ctx, wire, wire_len, ref_buf, ref_len,
                                        CLI_MAX_FILE, &out_buf, &out_len, &dna);
    fp_morph_ctx_free(ctx);
    free(wire);
    free(ref_buf);

    if (err != FP_OK) {
        fprintf(stderr, "fp materialize: %s\n", fp_strerror(err));
        return 1;
    }
    int rc = write_entire_file(argv[1], out_buf, out_len, 0644);
    free(out_buf);
    if (rc == 0) {
        char hex[65];
        fp_hex_encode(dna.bytes, FP_DNA_LEN, hex);
        printf("verified=true dna=%s bytes=%zu\n", hex, out_len);
    }
    return rc == 0 ? 0 : 1;
}

static int cmd_emit(int argc, char **argv) {
    const char *key_path = NULL, *repo_hex = NULL, *prev_hex = NULL;
    const char *action_str = "install", *input_path = NULL, *target_hex = NULL;
    const char *reason = "", *out_path = NULL;
    uint64_t serial = 0, ttl = 86400;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo_hex = argv[++i];
        else if (strcmp(argv[i], "--serial") == 0 && i + 1 < argc) {
            if (parse_u64_strict(argv[++i], &serial) != 0) { fprintf(stderr, "sf emit: invalid --serial\n"); return 1; }
        } else if (strcmp(argv[i], "--prev") == 0 && i + 1 < argc) prev_hex = argv[++i];
        else if (strcmp(argv[i], "--action") == 0 && i + 1 < argc) action_str = argv[++i];
        else if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) input_path = argv[++i];
        else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_hex = argv[++i];
        else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
            if (parse_u64_strict(argv[++i], &ttl) != 0) { fprintf(stderr, "sf emit: invalid --ttl\n"); return 1; }
        } else if (strcmp(argv[i], "--reason") == 0 && i + 1 < argc) reason = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out_path = argv[++i];
        else { usage(); return 1; }
    }
    if (!key_path || !repo_hex || serial == 0 || !out_path) {
        usage();
        return 1;
    }

    uint8_t *sk_buf = NULL;
    size_t sk_len = 0;
    if (read_entire_file(key_path, &sk_buf, &sk_len) != 0 || sk_len != FP_SK_LEN) {
        fprintf(stderr, "fp emit: invalid Ed25519 private key\n");
        if (sk_buf) sodium_memzero(sk_buf, sk_len);
        free(sk_buf);
        return 1;
    }
    fp_keypair_t kp;
    memcpy(kp.sk, sk_buf, FP_SK_LEN);
    memcpy(kp.pk, sk_buf + 32, FP_PK_LEN);
    sodium_memzero(sk_buf, sk_len);
    free(sk_buf);

    fp_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.serial = serial;
    ev.timestamp_unix = (uint64_t)time(NULL);
    if (ttl > 0 && ttl > UINT64_MAX - ev.timestamp_unix) {
        sodium_memzero(&kp, sizeof(kp));
        fprintf(stderr, "sf emit: --ttl overflow\n");
        return 1;
    }
    ev.expires_unix = ttl > 0 ? ev.timestamp_unix + ttl : 0;

    if (fp_hex_decode(repo_hex, ev.repo_id.bytes, FP_DNA_LEN) != FP_OK) {
        fprintf(stderr, "fp emit: invalid --repo hex\n");
        return 1;
    }
    if (prev_hex && fp_hex_decode(prev_hex, ev.prev_event_hash.bytes, FP_DNA_LEN) != FP_OK) {
        fprintf(stderr, "fp emit: invalid --prev hex\n");
        return 1;
    }

    if (strcmp(action_str, "install") == 0) ev.action = FP_ACTION_INSTALL;
    else if (strcmp(action_str, "rollback") == 0) ev.action = FP_ACTION_ROLLBACK;
    else if (strcmp(action_str, "revoke") == 0) ev.action = FP_ACTION_REVOKE;
    else { fprintf(stderr, "fp emit: bad action '%s'\n", action_str); return 1; }

    if (input_path) {
        fp_err_t err = fp_dna_compute_file(input_path, &ev.target_dna, &ev.target_size);
        if (err != FP_OK) {
            fprintf(stderr, "fp emit: %s\n", fp_strerror(err));
            return 1;
        }
    } else if (target_hex) {
        if (fp_hex_decode(target_hex, ev.target_dna.bytes, FP_DNA_LEN) != FP_OK) {
            fprintf(stderr, "fp emit: invalid --target hex\n");
            return 1;
        }
    } else {
        fprintf(stderr, "fp emit: need --input or --target\n");
        return 1;
    }
    snprintf(ev.reason, sizeof(ev.reason), "%s", reason);

    fp_err_t err = fp_event_sign(&ev, &kp);
    sodium_memzero(&kp, sizeof(kp));
    if (err != FP_OK) {
        fprintf(stderr, "fp emit: %s\n", fp_strerror(err));
        return 1;
    }
    uint8_t *encoded = NULL;
    size_t enc_len = 0;
    err = fp_event_encode(&ev, &encoded, &enc_len);
    if (err != FP_OK) {
        fprintf(stderr, "fp emit: %s\n", fp_strerror(err));
        return 1;
    }
    int rc = write_entire_file(out_path, encoded, enc_len, 0644);
    free(encoded);
    if (rc == 0) {
        char ev_hex[65], t_hex[65];
        fp_hex_encode(ev.event_hash.bytes, FP_DNA_LEN, ev_hex);
        fp_hex_encode(ev.target_dna.bytes, FP_DNA_LEN, t_hex);
        printf("event=%s serial=%llu target=%s\n", ev_hex,
               (unsigned long long)ev.serial, t_hex);
    }
    return rc == 0 ? 0 : 1;
}

static int cmd_apply(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    const char *store_dir = argv[0];
    const char *ev_path = argv[1];
    const char *pub_path = NULL, *repo_hex = NULL, *data_path = NULL;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc) pub_path = argv[++i];
        else if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo_hex = argv[++i];
        else if (strcmp(argv[i], "--data") == 0 && i + 1 < argc) data_path = argv[++i];
        else { usage(); return 1; }
    }
    if (!pub_path || !repo_hex) { usage(); return 1; }

    uint8_t *ev_buf = NULL, *pk_buf = NULL, *data_buf = NULL;
    size_t ev_len = 0, pk_len = 0, data_len = 0;
    if (read_entire_file(ev_path, &ev_buf, &ev_len) != 0) return 1;
    if (read_entire_file(pub_path, &pk_buf, &pk_len) != 0 || pk_len != FP_PK_LEN) {
        free(ev_buf); free(pk_buf);
        fprintf(stderr, "fp apply: invalid pubkey\n");
        return 1;
    }
    if (data_path && read_entire_file(data_path, &data_buf, &data_len) != 0) {
        free(ev_buf); free(pk_buf);
        return 1;
    }

    fp_dna_t repo;
    fp_event_t ev;
    fp_err_t err = fp_hex_decode(repo_hex, repo.bytes, FP_DNA_LEN);
    if (err == FP_OK) err = fp_event_decode(ev_buf, ev_len, &ev);
    if (err == FP_OK) {
        err = fp_store_apply_event(store_dir, &ev, pk_buf, &repo,
                                   (uint64_t)time(NULL), data_buf, data_len);
    }
    free(ev_buf);
    free(pk_buf);
    free(data_buf);

    if (err != FP_OK) {
        fprintf(stderr, "fp apply: %s\n", fp_strerror(err));
        return 1;
    }
    char ev_hex[65];
    fp_hex_encode(ev.event_hash.bytes, FP_DNA_LEN, ev_hex);
    printf("applied=true serial=%llu event=%s\n", (unsigned long long)ev.serial, ev_hex);
    return 0;
}

static int cmd_status(int argc, char **argv) {
    if (argc != 1) { usage(); return 1; }
    fp_store_state_t st;
    fp_err_t err = fp_store_load_state(argv[0], &st);
    if (err != FP_OK) {
        fprintf(stderr, "fp status: %s\n", fp_strerror(err));
        return 1;
    }
    char cur[65], last[65];
    fp_hex_encode(st.current_dna.bytes, FP_DNA_LEN, cur);
    fp_hex_encode(st.last_event_hash.bytes, FP_DNA_LEN, last);
    printf("serial=%llu current=%s installed=%u revoked=%u last_event=%s\n",
           (unsigned long long)st.serial, st.has_current ? cur : "none",
           st.installed_count, st.revoked_count, last);
    return 0;
}

static int cmd_anchor(int argc, char **argv) {
    if (argc < 1) { usage(); return 1; }
    const char *ev_path = argv[0];
    const char *log_path = NULL;
    int do_verify = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) log_path = argv[++i];
        else if (strcmp(argv[i], "--verify") == 0) do_verify = 1;
        else { usage(); return 1; }
    }
    uint8_t *ev_buf = NULL;
    size_t ev_len = 0;
    if (read_entire_file(ev_path, &ev_buf, &ev_len) != 0) return 1;

    fp_event_t ev;
    fp_anchor_commitment_t c;
    fp_err_t err = fp_event_decode(ev_buf, ev_len, &ev);
    free(ev_buf);
    if (err == FP_OK) err = fp_anchor_compute(&ev, &c);
    if (err == FP_OK && log_path) {
        err = do_verify ? fp_anchor_local_verify(log_path, &c)
                        : fp_anchor_local_publish(log_path, &c);
    }
    if (err != FP_OK) {
        fprintf(stderr, "fp anchor: %s\n", fp_strerror(err));
        return 1;
    }
    char hex[65];
    fp_hex_encode(c.commitment.bytes, FP_DNA_LEN, hex);
    printf("anchor_commitment=%s serial=%llu\n", hex, (unsigned long long)c.serial);
    return 0;
}

static const char *net_mode_name(fp_net_mode_t m) {
    switch (m) {
        case FP_NET_MODE_REF:           return "ref";
        case FP_NET_MODE_DELTA:         return "delta";
        case FP_NET_MODE_ZSTD:          return "zstd";
        case FP_NET_MODE_MERKLE_STREAM: return "merkle-stream";
        default:                        return "unknown";
    }
}

static int cmd_serve(int argc, char **argv) {
    if (argc < 1) { usage(); return 1; }
    const char *store_dir = argv[0];
    const char *key_path = NULL, *bind_addr = "127.0.0.1";
    const char *allow_pub = NULL, *ready_file = NULL;
    uint16_t port = 7777;
    uint32_t max_req = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) bind_addr = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (parse_port_strict(argv[++i], 1, &port) != 0) { fprintf(stderr, "sf serve: invalid --port\n"); return 1; }
        } else if (strcmp(argv[i], "--allow-pub") == 0 && i + 1 < argc) allow_pub = argv[++i];
        else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc) {
            uint64_t mv = 0;
            if (parse_u64_strict(argv[++i], &mv) != 0 || mv > UINT32_MAX) { fprintf(stderr, "sf serve: invalid --max\n"); return 1; }
            max_req = (uint32_t)mv;
        } else if (strcmp(argv[i], "--ready-file") == 0 && i + 1 < argc) ready_file = argv[++i];
        else { usage(); return 1; }
    }
    if (!key_path) { usage(); return 1; }

    uint8_t *sk_buf = NULL, *allow_buf = NULL;
    size_t sk_len = 0, allow_len = 0;
    if (read_entire_file(key_path, &sk_buf, &sk_len) != 0 || sk_len != FP_SK_LEN) {
        free(sk_buf);
        fprintf(stderr, "fp serve: invalid private key\n");
        return 1;
    }
    if (allow_pub && (read_entire_file(allow_pub, &allow_buf, &allow_len) != 0 || allow_len != FP_PK_LEN)) {
        free(sk_buf); free(allow_buf);
        fprintf(stderr, "fp serve: invalid allow-pub key\n");
        return 1;
    }

    fp_keypair_t kp;
    memcpy(kp.sk, sk_buf, FP_SK_LEN);
    memcpy(kp.pk, sk_buf + 32, FP_PK_LEN);
    sodium_memzero(sk_buf, sk_len);
    free(sk_buf);

    uint16_t bound_port = 0;
    int lfd = fp_net_listen(bind_addr, port, &bound_port);
    if (lfd < 0) {
        sodium_memzero(&kp, sizeof(kp));
        free(allow_buf);
        fprintf(stderr, "fp serve: failed to listen on %s:%u\n", bind_addr, (unsigned)port);
        return 1;
    }
    if (ready_file) {
        char pbuf[16];
        int pn = snprintf(pbuf, sizeof(pbuf), "%u\n", (unsigned)bound_port);
        if (pn > 0) (void)write_entire_file(ready_file, (const uint8_t *)pbuf, (size_t)pn, 0644);
    }
    printf("listening=%s:%u\n", bind_addr, (unsigned)bound_port);
    fflush(stdout);

    fp_net_server_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bind_addr = bind_addr;
    cfg.port = bound_port;
    cfg.store_dir = store_dir;
    cfg.server_kp = &kp;
    cfg.allowed_peer_pk = allow_buf;
    cfg.max_requests = max_req;

    fp_err_t err = fp_net_serve_fd(lfd, &cfg);
    sodium_memzero(&kp, sizeof(kp));
    close(lfd);
    free(allow_buf);
    if (err != FP_OK) {
        fprintf(stderr, "fp serve: %s\n", fp_strerror(err));
        return 1;
    }
    return 0;
}

static int cmd_pull(int argc, char **argv) {
    if (argc < 3) { usage(); return 1; }
    const char *endpoint = argv[0];
    const char *dna_hex = argv[1];
    const char *store_dir = argv[2];
    const char *key_path = NULL, *peer_pub = NULL;

    fp_net_pull_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.store_dir = store_dir;
    cfg.max_output = (size_t)UINT64_C(68719476736); /* 64 GiB streaming ceiling */

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--peer-pub") == 0 && i + 1 < argc) peer_pub = argv[++i];
        else if (strcmp(argv[i], "--stream") == 0) cfg.force_merkle_stream = 1;
        else if (strcmp(argv[i], "--max-bytes") == 0 && i + 1 < argc) cfg.max_output = (size_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--ref") == 0 && i + 1 < argc) {
            if (cfg.extra_ref_count >= FP_NET_MAX_REFS ||
                fp_hex_decode(argv[++i], cfg.extra_refs[cfg.extra_ref_count].bytes, FP_DNA_LEN) != FP_OK) {
                fprintf(stderr, "fp pull: invalid --ref\n");
                return 1;
            }
            cfg.extra_ref_count++;
        } else { usage(); return 1; }
    }
    if (!key_path || !peer_pub) { usage(); return 1; }

    const char *colon = strrchr(endpoint, ':');
    if (!colon || colon == endpoint || colon[1] == '\0') {
        fprintf(stderr, "fp pull: endpoint must be host:port\n");
        return 1;
    }
    char host[256];
    size_t hlen = (size_t)(colon - endpoint);
    if (hlen >= sizeof(host)) { fprintf(stderr, "fp pull: host too long\n"); return 1; }
    memcpy(host, endpoint, hlen);
    host[hlen] = '\0';
    cfg.host = host;
    if (parse_port_strict(colon + 1, 0, &cfg.port) != 0) {
        fprintf(stderr, "sf pull: invalid port\n");
        return 1;
    }

    if (fp_hex_decode(dna_hex, cfg.target_dna.bytes, FP_DNA_LEN) != FP_OK) {
        fprintf(stderr, "fp pull: invalid target DNA hex\n");
        return 1;
    }

    uint8_t *sk_buf = NULL, *pk_buf = NULL;
    size_t sk_len = 0, pk_len = 0;
    if (read_entire_file(key_path, &sk_buf, &sk_len) != 0 || sk_len != FP_SK_LEN ||
        read_entire_file(peer_pub, &pk_buf, &pk_len) != 0 || pk_len != FP_PK_LEN) {
        free(sk_buf); free(pk_buf);
        fprintf(stderr, "fp pull: invalid key files\n");
        return 1;
    }
    fp_keypair_t kp;
    memcpy(kp.sk, sk_buf, FP_SK_LEN);
    memcpy(kp.pk, sk_buf + 32, FP_PK_LEN);
    sodium_memzero(sk_buf, sk_len);
    free(sk_buf);

    cfg.client_kp = &kp;
    cfg.expected_srv_pk = pk_buf;

    fp_net_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    fp_err_t err = fp_net_pull(&cfg, &stats);
    sodium_memzero(&kp, sizeof(kp));
    free(pk_buf);
    if (err != FP_OK) {
        fprintf(stderr, "fp pull: %s\n", fp_strerror(err));
        return 1;
    }
    printf("pulled=true mode=%s bytes=%llu wire=%llu resumed_chunks=%llu recv_chunks=%llu elapsed_ms=%.3f\n",
           net_mode_name(stats.mode), (unsigned long long)stats.canonical_size,
           (unsigned long long)stats.wire_bytes,
           (unsigned long long)stats.resumed_chunks,
           (unsigned long long)stats.received_chunks,
           (double)stats.elapsed_ns / 1e6);
    return 0;
}

static int cmd_ingest(int argc, char **argv) {
    if (argc != 2) { usage(); return 1; }
    fp_cdc_stats_t st;
    fp_err_t err = fp_cdc_ingest_file(argv[0], argv[1], &st);
    if (err != FP_OK) {
        fprintf(stderr, "fp ingest: %s\n", fp_strerror(err));
        return 1;
    }
    char hex[65];
    fp_hex_encode(st.dna.bytes, FP_DNA_LEN, hex);
    double dedup_pct = st.canonical_size > 0
        ? (100.0 * (double)st.reused_bytes / (double)st.canonical_size) : 0.0;
    printf("ingested=true dna=%s bytes=%llu chunks=%llu new=%llu dedup=%llu reused=%.2f%% elapsed_ms=%.3f\n",
           hex, (unsigned long long)st.canonical_size,
           (unsigned long long)st.total_chunks,
           (unsigned long long)st.new_chunks,
           (unsigned long long)st.dedup_chunks,
           dedup_pct, (double)st.elapsed_ns / 1e6);
    return 0;
}

static int cmd_reconstruct(int argc, char **argv) {
    if (argc != 3) { usage(); return 1; }
    fp_dna_t dna;
    if (fp_hex_decode(argv[1], dna.bytes, FP_DNA_LEN) != FP_OK) {
        fprintf(stderr, "fp reconstruct: invalid DNA hex\n");
        return 1;
    }
    uint64_t bytes = 0;
    fp_err_t err = fp_cdc_reconstruct_file(argv[0], &dna, argv[2], &bytes);
    if (err != FP_OK) {
        fprintf(stderr, "fp reconstruct: %s\n", fp_strerror(err));
        return 1;
    }
    printf("reconstructed=true dna=%s bytes=%llu\n", argv[1], (unsigned long long)bytes);
    return 0;
}

static int cmd_bundle_pack(int argc, char **argv) {
    if (argc < 3) { usage(); return 1; }
    const char *store_dir = argv[0];
    fp_bundle_t b;
    memset(&b, 0, sizeof(b));
    b.version = 1;

    for (int i = 1; i < argc; i++) {
        fp_bundle_role_t role;
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) role = FP_ROLE_FILE;
        else if (strcmp(argv[i], "--changeset") == 0 && i + 1 < argc) role = FP_ROLE_SQLITE_CHANGESET;
        else { usage(); return 1; }

        if (b.entry_count >= FP_BUNDLE_MAX_ENTRIES) {
            fprintf(stderr, "fp bundle-pack: too many entries\n");
            return 1;
        }
        const char *spec = argv[++i];
        const char *eq = strchr(spec, '=');
        if (!eq || eq == spec || eq[1] == '\0') {
            fprintf(stderr, "fp bundle-pack: expected <name>=<local_path>\n");
            return 1;
        }
        size_t nlen = (size_t)(eq - spec);
        if (nlen >= FP_BUNDLE_MAX_PATH) return 1;

        uint8_t *data = NULL;
        size_t len = 0;
        if (read_entire_file(eq + 1, &data, &len) != 0) return 1;

        fp_bundle_entry_t *e = &b.entries[b.entry_count++];
        e->role = role;
        e->mode = (role == FP_ROLE_FILE) ? 0644u : 0u;
        e->size = len;
        memcpy(e->path, spec, nlen);
        e->path[nlen] = '\0';

        fp_err_t err = fp_store_put_object(store_dir, data, len, &e->dna);
        free(data);
        if (err != FP_OK) {
            fprintf(stderr, "fp bundle-pack: %s\n", fp_strerror(err));
            return 1;
        }
    }

    fp_dna_t bdna;
    fp_err_t err = fp_bundle_pack(store_dir, &b, &bdna);
    if (err != FP_OK) {
        fprintf(stderr, "fp bundle-pack: %s\n", fp_strerror(err));
        return 1;
    }
    char hex[65];
    fp_hex_encode(bdna.bytes, FP_DNA_LEN, hex);
    printf("bundle_dna=%s entries=%u\n", hex, (unsigned)b.entry_count);
    return 0;
}

static int cmd_bundle_apply(int argc, char **argv) {
    if (argc < 3) { usage(); return 1; }
    const char *store_dir = argv[0];
    const char *dna_hex = argv[1];
    const char *target_dir = argv[2];
    const char *db_path = NULL;
    uint64_t seq = 1;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) db_path = argv[++i];
        else if (strcmp(argv[i], "--seq") == 0 && i + 1 < argc) seq = strtoull(argv[++i], NULL, 10);
        else { usage(); return 1; }
    }
    fp_dna_t bdna;
    if (fp_hex_decode(dna_hex, bdna.bytes, FP_DNA_LEN) != FP_OK) {
        fprintf(stderr, "fp bundle-apply: invalid bundle DNA\n");
        return 1;
    }
    fp_sql_ctx_t *sql = NULL;
    if (db_path && fp_sql_open(db_path, &sql) != FP_OK) {
        fprintf(stderr, "fp bundle-apply: cannot open db '%s'\n", db_path);
        return 1;
    }
    fp_err_t err = fp_bundle_apply(store_dir, &bdna, target_dir, sql, seq, 0);
    fp_sql_close(sql);
    if (err != FP_OK) {
        fprintf(stderr, "fp bundle-apply: %s\n", fp_strerror(err));
        return 1;
    }
    printf("bundle_applied=true dna=%s seq=%llu\n", dna_hex, (unsigned long long)seq);
    return 0;
}

static int cmd_bundle_rollback(int argc, char **argv) {
    if (argc < 4) { usage(); return 1; }
    const char *store_dir = argv[0];
    const char *cur_hex = argv[1];
    const char *prev_hex = argv[2];
    const char *target_dir = argv[3];
    const char *db_path = NULL;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) db_path = argv[++i];
        else { usage(); return 1; }
    }
    fp_dna_t cur_dna, prev_dna;
    if (fp_hex_decode(cur_hex, cur_dna.bytes, FP_DNA_LEN) != FP_OK ||
        fp_hex_decode(prev_hex, prev_dna.bytes, FP_DNA_LEN) != FP_OK) {
        fprintf(stderr, "fp bundle-rollback: invalid DNA\n");
        return 1;
    }
    fp_sql_ctx_t *sql = NULL;
    if (db_path && fp_sql_open(db_path, &sql) != FP_OK) {
        fprintf(stderr, "fp bundle-rollback: cannot open db '%s'\n", db_path);
        return 1;
    }
    fp_err_t err = fp_bundle_rollback(store_dir, &cur_dna, &prev_dna, target_dir, sql);
    fp_sql_close(sql);
    if (err != FP_OK) {
        fprintf(stderr, "fp bundle-rollback: %s\n", fp_strerror(err));
        return 1;
    }
    printf("bundle_rolled_back=true active_dna=%s\n", prev_hex);
    return 0;
}

static int cmd_root_init(int argc, char **argv) {
    const char *repo_hex = NULL, *rel_pub = NULL, *out_path = NULL;
    const char *sign_paths[FP_MAX_ROOT_SIGS];
    size_t sign_count = 0;
    fp_root_doc_t doc;
    memset(&doc, 0, sizeof(doc));
    doc.version = 1;
    doc.root_version = 1;
    uint64_t ttl = 86400u * 365u;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo_hex = argv[++i];
        else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
            uint64_t tv = 0;
            if (parse_u64_strict(argv[++i], &tv) != 0 || tv == 0 || tv > FP_MAX_ROOT_KEYS) {
                fprintf(stderr, "sf root-init: invalid --threshold\n");
                return 1;
            }
            doc.root_threshold = (uint8_t)tv;
        } else if (strcmp(argv[i], "--version") == 0 && i + 1 < argc) {
            if (parse_u64_strict(argv[++i], &doc.root_version) != 0 || doc.root_version == 0) {
                fprintf(stderr, "sf root-init: invalid --version\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--ttl") == 0 && i + 1 < argc) {
            if (parse_u64_strict(argv[++i], &ttl) != 0) {
                fprintf(stderr, "sf root-init: invalid --ttl\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--release-pub") == 0 && i + 1 < argc) rel_pub = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out_path = argv[++i];
        else if (strcmp(argv[i], "--root-pub") == 0 && i + 1 < argc) {
            if (doc.root_key_count >= FP_MAX_ROOT_KEYS) return 1;
            uint8_t *pk = NULL; size_t plen = 0;
            if (read_entire_file(argv[++i], &pk, &plen) != 0 || plen != FP_PK_LEN) { free(pk); return 1; }
            memcpy(doc.root_keys[doc.root_key_count++], pk, FP_PK_LEN);
            free(pk);
        } else if (strcmp(argv[i], "--revoke-pub") == 0 && i + 1 < argc) {
            if (doc.revoked_key_count >= FP_MAX_REVOKED_KEYS) return 1;
            uint8_t *pk = NULL; size_t plen = 0;
            if (read_entire_file(argv[++i], &pk, &plen) != 0 || plen != FP_PK_LEN) { free(pk); return 1; }
            memcpy(doc.revoked_keys[doc.revoked_key_count++], pk, FP_PK_LEN);
            free(pk);
        } else if (strcmp(argv[i], "--sign") == 0 && i + 1 < argc) {
            if (sign_count >= FP_MAX_ROOT_SIGS) return 1;
            sign_paths[sign_count++] = argv[++i];
        } else { usage(); return 1; }
    }
    if (!repo_hex || !rel_pub || !out_path || sign_count == 0) { usage(); return 1; }
    if (fp_hex_decode(repo_hex, doc.repo_id.bytes, FP_DNA_LEN) != FP_OK) return 1;

    uint8_t *rpk = NULL; size_t rlen = 0;
    if (read_entire_file(rel_pub, &rpk, &rlen) != 0 || rlen != FP_PK_LEN) { free(rpk); return 1; }
    memcpy(doc.release_pk, rpk, FP_PK_LEN);
    free(rpk);

    doc.timestamp_unix = (uint64_t)time(NULL);
    if (ttl > 0 && ttl > UINT64_MAX - doc.timestamp_unix) {
        fprintf(stderr, "sf root-init: --ttl overflow\n");
        return 1;
    }
    doc.expires_unix = ttl > 0 ? doc.timestamp_unix + ttl : 0;

    for (size_t i = 0; i < sign_count; i++) {
        uint8_t *sk = NULL; size_t slen = 0;
        if (read_entire_file(sign_paths[i], &sk, &slen) != 0 || slen != FP_SK_LEN) {
            if (sk) sodium_memzero(sk, slen);
            free(sk);
            return 1;
        }
        fp_keypair_t kp;
        memcpy(kp.sk, sk, FP_SK_LEN);
        memcpy(kp.pk, sk + 32, FP_PK_LEN);
        sodium_memzero(sk, slen);
        free(sk);
        fp_err_t err = fp_root_add_sig(&doc, &kp);
        sodium_memzero(&kp, sizeof(kp));
        if (err != FP_OK) {
            fprintf(stderr, "fp root-init: %s\n", fp_strerror(err));
            return 1;
        }
    }

    uint8_t *enc = NULL; size_t enc_len = 0;
    fp_err_t err = fp_root_encode(&doc, &enc, &enc_len);
    if (err != FP_OK) { fprintf(stderr, "fp root-init: %s\n", fp_strerror(err)); return 1; }
    int rc = write_entire_file(out_path, enc, enc_len, 0644);
    free(enc);
    if (rc == 0) {
        char hex[65];
        fp_hex_encode(doc.doc_hash.bytes, FP_DNA_LEN, hex);
        printf("root_version=%llu threshold=%u/%u sigs=%u doc_hash=%s\n",
               (unsigned long long)doc.root_version, (unsigned)doc.root_threshold,
               (unsigned)doc.root_key_count, (unsigned)doc.sig_count, hex);
    }
    return rc == 0 ? 0 : 1;
}

static int cmd_root_verify(int argc, char **argv) {
    if (argc < 1) { usage(); return 1; }
    const char *cur_path = argv[0];
    const char *prev_path = NULL;
    if (argc == 3 && strcmp(argv[1], "--prev") == 0) prev_path = argv[2];
    else if (argc != 1) { usage(); return 1; }

    uint8_t *cbuf = NULL; size_t clen = 0;
    if (read_entire_file(cur_path, &cbuf, &clen) != 0) return 1;
    fp_root_doc_t cur;
    fp_err_t err = fp_root_decode(cbuf, clen, &cur);
    free(cbuf);
    if (err != FP_OK) { fprintf(stderr, "fp root-verify: %s\n", fp_strerror(err)); return 1; }

    uint64_t now = (uint64_t)time(NULL);
    if (prev_path) {
        uint8_t *pbuf = NULL; size_t plen = 0;
        if (read_entire_file(prev_path, &pbuf, &plen) != 0) return 1;
        fp_root_doc_t prev;
        err = fp_root_decode(pbuf, plen, &prev);
        free(pbuf);
        if (err == FP_OK) err = fp_root_verify_rotation(&prev, &cur, now);
    } else {
        err = fp_root_verify_self(&cur, now);
    }
    if (err != FP_OK) {
        fprintf(stderr, "fp root-verify: %s\n", fp_strerror(err));
        return 1;
    }
    printf("root_verified=true version=%llu quorum=%u/%u revoked_keys=%u\n",
           (unsigned long long)cur.root_version, (unsigned)cur.root_threshold,
           (unsigned)cur.root_key_count, (unsigned)cur.revoked_key_count);
    return 0;
}

static int cmd_swarm_pull(int argc, char **argv) {
    if (argc < 4) { usage(); return 1; }
    const char *dna_hex = argv[0], *store_dir = argv[1];
    const char *key_path = NULL;
    fp_swarm_peer_t peers[FP_SWARM_MAX_PEERS];
    char hosts[FP_SWARM_MAX_PEERS][256];
    size_t pcount = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
            if (pcount >= FP_SWARM_MAX_PEERS) return 1;
            const char *ep = argv[++i];
            const char *col = strrchr(ep, ':');
            if (!col || col == ep || col[1] == '\0') return 1;
            size_t hlen = (size_t)(col - ep);
            if (hlen >= sizeof(hosts[0])) return 1;
            memcpy(hosts[pcount], ep, hlen);
            hosts[pcount][hlen] = '\0';
            peers[pcount].host = hosts[pcount];
            if (parse_port_strict(col + 1, 0, &peers[pcount].port) != 0) return 1;
            peers[pcount].expected_pk = NULL;
            pcount++;
        } else { usage(); return 1; }
    }
    if (!key_path || pcount == 0) { usage(); return 1; }

    fp_dna_t target;
    if (fp_hex_decode(dna_hex, target.bytes, FP_DNA_LEN) != FP_OK) return 1;
    uint8_t *sk = NULL; size_t slen = 0;
    if (read_entire_file(key_path, &sk, &slen) != 0 || slen != FP_SK_LEN) { free(sk); return 1; }
    fp_keypair_t kp;
    memcpy(kp.sk, sk, FP_SK_LEN); memcpy(kp.pk, sk + 32, FP_PK_LEN);
    sodium_memzero(sk, slen);
    free(sk);

    fp_swarm_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.store_dir = store_dir; cfg.client_kp = &kp;
    cfg.target_dna = target; cfg.peers = peers; cfg.peer_count = pcount;
    cfg.max_output = (size_t)UINT64_C(68719476736); /* 64 GiB */

    fp_swarm_stats_t st;
    fp_err_t err = fp_swarm_pull(&cfg, &st);
    sodium_memzero(&kp, sizeof(kp));
    if (err != FP_OK) { fprintf(stderr, "fp swarm-pull: %s\n", fp_strerror(err)); return 1; }
    printf("swarm_ok=true bytes=%llu chunks=%llu peers_used=%u peers_banned=%u wire=%llu elapsed_ms=%.3f\n",
           (unsigned long long)st.canonical_size, (unsigned long long)st.total_chunks,
           st.peers_used, st.peers_banned, (unsigned long long)st.wire_bytes,
           (double)st.elapsed_ns / 1e6);
    return 0;
}

static int cmd_udp_serve(int argc, char **argv) {
    if (argc < 1) { usage(); return 1; }
    const char *store_dir = argv[0], *key_path = NULL, *bind_addr = "127.0.0.1";
    uint16_t port = 7778; uint32_t max_sess = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) bind_addr = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (parse_port_strict(argv[++i], 1, &port) != 0) { fprintf(stderr, "sf udp-serve: invalid --port\n"); return 1; }
        } else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc) {
            uint64_t mv = 0;
            if (parse_u64_strict(argv[++i], &mv) != 0 || mv > UINT32_MAX) { fprintf(stderr, "sf udp-serve: invalid --max\n"); return 1; }
            max_sess = (uint32_t)mv;
        } else { usage(); return 1; }
    }
    if (!key_path) { usage(); return 1; }
    uint8_t *sk = NULL; size_t slen = 0;
    if (read_entire_file(key_path, &sk, &slen) != 0 || slen != FP_SK_LEN) { free(sk); return 1; }
    fp_keypair_t kp;
    memcpy(kp.sk, sk, FP_SK_LEN); memcpy(kp.pk, sk + 32, FP_PK_LEN);
    sodium_memzero(sk, slen);
    free(sk);

    uint16_t bport = 0;
    int fd = fp_udp_bind(bind_addr, port, &bport);
    if (fd < 0) { sodium_memzero(&kp, sizeof(kp)); return 1; }
    printf("udp_listening=%s:%u\n", bind_addr, (unsigned)bport);
    fflush(stdout);

    fp_udp_server_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.bind_addr = bind_addr; cfg.port = bport; cfg.store_dir = store_dir;
    cfg.server_kp = &kp; cfg.max_sessions = max_sess;
    fp_err_t err = fp_udp_serve_fd(fd, &cfg);
    sodium_memzero(&kp, sizeof(kp));
    close(fd);
    return err == FP_OK ? 0 : 1;
}

static int cmd_udp_pull(int argc, char **argv) {
    if (argc < 3) { usage(); return 1; }
    const char *ep = argv[0], *dna_hex = argv[1], *store_dir = argv[2];
    const char *key_path = NULL, *peer_pub = NULL;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--peer-pub") == 0 && i + 1 < argc) peer_pub = argv[++i];
        else { usage(); return 1; }
    }
    if (!key_path) { usage(); return 1; }
    const char *col = strrchr(ep, ':');
    if (!col || col == ep || col[1] == '\0') return 1;
    char host[256];
    size_t hlen = (size_t)(col - ep);
    if (hlen >= sizeof(host)) return 1;
    memcpy(host, ep, hlen); host[hlen] = '\0';

    fp_udp_pull_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = host;
    if (parse_port_strict(col + 1, 0, &cfg.port) != 0) {
        fprintf(stderr, "sf udp-pull: invalid port\n");
        return 1;
    }
    cfg.store_dir = store_dir;
    cfg.max_output = (size_t)UINT64_C(68719476736); /* 64 GiB */
    if (fp_hex_decode(dna_hex, cfg.target_dna.bytes, FP_DNA_LEN) != FP_OK) return 1;

    uint8_t *sk = NULL, *pk = NULL; size_t slen = 0, plen = 0;
    if (read_entire_file(key_path, &sk, &slen) != 0 || slen != FP_SK_LEN) { free(sk); return 1; }
    if (peer_pub && (read_entire_file(peer_pub, &pk, &plen) != 0 || plen != FP_PK_LEN)) {
        free(sk); free(pk); return 1;
    }
    fp_keypair_t kp;
    memcpy(kp.sk, sk, FP_SK_LEN); memcpy(kp.pk, sk + 32, FP_PK_LEN);
    sodium_memzero(sk, slen);
    free(sk);
    cfg.client_kp = &kp; cfg.expected_srv_pk = pk;

    fp_udp_stats_t st;
    fp_err_t err = fp_udp_pull(&cfg, &st);
    sodium_memzero(&kp, sizeof(kp));
    free(pk);
    if (err != FP_OK) { fprintf(stderr, "fp udp-pull: %s\n", fp_strerror(err)); return 1; }
    printf("udp_ok=true bytes=%llu chunks=%llu retrans=%llu migrations=%u cwnd=%u srtt_ms=%.2f elapsed_ms=%.3f\n",
           (unsigned long long)st.canonical_size, (unsigned long long)st.total_chunks,
           (unsigned long long)st.retransmits, st.migrations, st.final_cwnd,
           (double)st.srtt_us / 1000.0, (double)st.elapsed_ns / 1e6);
    return 0;
}

static int cmd_sign_approval(int argc, char **argv) {
    const char *key_path = NULL, *channel = "stable", *ev_path = NULL;
    uint64_t serial = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--channel") == 0 && i + 1 < argc) channel = argv[++i];
        else if (strcmp(argv[i], "--serial") == 0 && i + 1 < argc) {
            if (parse_u64_strict(argv[++i], &serial) != 0 || serial == 0) return 1;
        } else if (strcmp(argv[i], "--event") == 0 && i + 1 < argc) ev_path = argv[++i];
        else { usage(); return 1; }
    }
    if (!key_path || !ev_path || serial == 0) { usage(); return 1; }
    uint8_t *sk = NULL, *evb = NULL;
    size_t sklen = 0, evlen = 0;
    if (read_entire_file(key_path, &sk, &sklen) != 0 || sklen != FP_SK_LEN) {
        if (sk) sodium_memzero(sk, sklen);
        free(sk);
        return 1;
    }
    if (read_entire_file(ev_path, &evb, &evlen) != 0) {
        sodium_memzero(sk, sklen); free(sk);
        return 1;
    }
    fp_event_t ev;
    fp_err_t err = fp_event_decode(evb, evlen, &ev);
    free(evb);
    if (err != FP_OK || ev.serial != serial) {
        sodium_memzero(sk, sklen); free(sk);
        fprintf(stderr, "sf sign-approval: invalid event or serial mismatch\n");
        return 1;
    }
    char ev_hex[65], canonical[256];
    fp_hex_encode(ev.event_hash.bytes, FP_DNA_LEN, ev_hex);
    int cl = snprintf(canonical, sizeof(canonical), "SF_APPROVAL_V1|%s|%llu|%s",
                      channel, (unsigned long long)serial, ev_hex);
    if (cl <= 0 || (size_t)cl >= sizeof(canonical)) {
        sodium_memzero(sk, sklen); free(sk);
        return 1;
    }
    uint8_t sig[FP_SIG_LEN];
    crypto_sign_ed25519_detached(sig, NULL, (const uint8_t *)canonical, (unsigned long long)cl, sk);
    char pk_hex[65], sig_hex[129];
    fp_hex_encode(sk + 32, FP_PK_LEN, pk_hex);
    fp_hex_encode(sig, FP_SIG_LEN, sig_hex);
    sodium_memzero(sk, sklen);
    free(sk);
    printf("pubkey=%s signature=%s event_hash=%s\n", pk_hex, sig_hex, ev_hex);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGXFSZ, SIG_IGN);
    if (fp_init() != FP_OK) {
        fprintf(stderr, "fp: failed to initialize cryptography\n");
        return 1;
    }
    if (argc < 2) {
        usage();
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "dna") == 0)             return cmd_dna(argc - 2, argv + 2);
    if (strcmp(cmd, "put") == 0)             return cmd_put(argc - 2, argv + 2);
    if (strcmp(cmd, "keygen") == 0)          return cmd_keygen(argc - 2, argv + 2);
    if (strcmp(cmd, "morph") == 0)           return cmd_morph(argc - 2, argv + 2);
    if (strcmp(cmd, "inspect") == 0)         return cmd_inspect(argc - 2, argv + 2);
    if (strcmp(cmd, "materialize") == 0)     return cmd_materialize(argc - 2, argv + 2);
    if (strcmp(cmd, "emit") == 0)            return cmd_emit(argc - 2, argv + 2);
    if (strcmp(cmd, "apply") == 0)           return cmd_apply(argc - 2, argv + 2);
    if (strcmp(cmd, "status") == 0)          return cmd_status(argc - 2, argv + 2);
    if (strcmp(cmd, "anchor") == 0)          return cmd_anchor(argc - 2, argv + 2);
    if (strcmp(cmd, "serve") == 0)           return cmd_serve(argc - 2, argv + 2);
    if (strcmp(cmd, "pull") == 0)            return cmd_pull(argc - 2, argv + 2);
    if (strcmp(cmd, "ingest") == 0)          return cmd_ingest(argc - 2, argv + 2);
    if (strcmp(cmd, "reconstruct") == 0)     return cmd_reconstruct(argc - 2, argv + 2);
    if (strcmp(cmd, "bundle-pack") == 0)     return cmd_bundle_pack(argc - 2, argv + 2);
    if (strcmp(cmd, "bundle-apply") == 0)    return cmd_bundle_apply(argc - 2, argv + 2);
    if (strcmp(cmd, "bundle-rollback") == 0) return cmd_bundle_rollback(argc - 2, argv + 2);
    if (strcmp(cmd, "root-init") == 0)       return cmd_root_init(argc - 2, argv + 2);
    if (strcmp(cmd, "root-verify") == 0)     return cmd_root_verify(argc - 2, argv + 2);
    if (strcmp(cmd, "swarm-pull") == 0)      return cmd_swarm_pull(argc - 2, argv + 2);
    if (strcmp(cmd, "udp-serve") == 0)       return cmd_udp_serve(argc - 2, argv + 2);
    if (strcmp(cmd, "udp-pull") == 0)        return cmd_udp_pull(argc - 2, argv + 2);
    if (strcmp(cmd, "sign-approval") == 0)   return cmd_sign_approval(argc - 2, argv + 2);

    usage();
    return 1;
}
