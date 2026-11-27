#define _POSIX_C_SOURCE 200809L

#include "fp_agent.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void handle_stop(int sig) {
    (void)sig;
    g_stop = 1;
}

static int read_exact_key(const char *path, uint8_t *out, size_t expected_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, expected_len, f);
    int extra = fgetc(f);
    fclose(f);
    return (n == expected_len && extra == EOF) ? 0 : -1;
}

static void usage(void) {
    fprintf(stderr,
        "sf-agent %d.%d — SealFrame Edge Agent\n"
        "Usage:\n"
        "  sf-agent --repo <http://host:port> --store <dir> --target <dir> --root <root.fpr>\n"
        "           [--device <id>] [--channel <stable|canary>] [--db <sqlite.db>]\n"
        "           [--key <device.sk>] [--lan-peer <host:port> --lan-peer-pub <srv.pk>]\n"
        "           [--health-cmd <shell_cmd>] [--health-timeout <sec>]\n"
        "           [--interval <sec>] [--once] [--no-heartbeat]\n",
        FP_VERSION_MAJOR, FP_VERSION_MINOR);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGXFSZ, SIG_IGN);
    signal(SIGTERM, handle_stop);
    signal(SIGINT, handle_stop);

    if (fp_init() != FP_OK) {
        fprintf(stderr, "sf-agent: crypto init failed\n");
        return 1;
    }

    fp_agent_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.channel = "stable";
    cfg.health_timeout_sec = 15;
    cfg.io_timeout_ms = 10000;
    cfg.report_heartbeat = 1;

    char host_buf[128] = "edge-node";
    if (gethostname(host_buf, sizeof(host_buf) - 1u) == 0) {
        host_buf[sizeof(host_buf) - 1u] = '\0';
    }
    cfg.device_id = host_buf;

    const char *key_path = NULL;
    const char *lan_ep = NULL;
    const char *lan_pk_path = NULL;
    int run_once = 0;
    int interval_sec = 30;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--repo") == 0 && i + 1 < argc) cfg.repo_url = argv[++i];
        else if (strcmp(argv[i], "--store") == 0 && i + 1 < argc) cfg.store_dir = argv[++i];
        else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) cfg.target_dir = argv[++i];
        else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) cfg.root_path = argv[++i];
        else if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) cfg.device_id = argv[++i];
        else if (strcmp(argv[i], "--channel") == 0 && i + 1 < argc) cfg.channel = argv[++i];
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) cfg.db_path = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--lan-peer") == 0 && i + 1 < argc) lan_ep = argv[++i];
        else if (strcmp(argv[i], "--lan-peer-pub") == 0 && i + 1 < argc) lan_pk_path = argv[++i];
        else if (strcmp(argv[i], "--health-cmd") == 0 && i + 1 < argc) cfg.health_cmd = argv[++i];
        else if (strcmp(argv[i], "--health-timeout") == 0 && i + 1 < argc) cfg.health_timeout_sec = atoi(argv[++i]);
        else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) interval_sec = atoi(argv[++i]);
        else if (strcmp(argv[i], "--once") == 0) run_once = 1;
        else if (strcmp(argv[i], "--no-heartbeat") == 0) cfg.report_heartbeat = 0;
        else { usage(); return 1; }
    }

    if (!cfg.repo_url || !cfg.store_dir || !cfg.target_dir || !cfg.root_path) {
        usage();
        return 1;
    }

    fp_keypair_t dev_kp;
    if (key_path) {
        if (read_exact_key(key_path, dev_kp.sk, FP_SK_LEN) != 0) {
            fprintf(stderr, "sf-agent: invalid Ed25519 key '%s'\n", key_path);
            return 1;
        }
        memcpy(dev_kp.pk, dev_kp.sk + 32, FP_PK_LEN);
        cfg.device_kp = &dev_kp;
    }

    char lan_host[256];
    uint8_t lan_pk[FP_PK_LEN];
    if (lan_ep) {
        const char *col = strrchr(lan_ep, ':');
        if (!col || col == lan_ep || col[1] == '\0' || !lan_pk_path || !cfg.device_kp) {
            fprintf(stderr, "sf-agent: --lan-peer requires host:port, --lan-peer-pub and --key\n");
            return 1;
        }
        size_t hlen = (size_t)(col - lan_ep);
        if (hlen >= sizeof(lan_host)) return 1;
        memcpy(lan_host, lan_ep, hlen);
        lan_host[hlen] = '\0';
        if (read_exact_key(lan_pk_path, lan_pk, FP_PK_LEN) != 0) {
            fprintf(stderr, "sf-agent: invalid --lan-peer-pub '%s'\n", lan_pk_path);
            return 1;
        }
        cfg.lan_peer_host = lan_host;
        cfg.lan_peer_port = (uint16_t)strtoul(col + 1, NULL, 10);
        cfg.lan_peer_pk = lan_pk;
    }

    if (interval_sec < 1) interval_sec = 1;

    int last_rc = 0;
    while (!g_stop) {
        fp_agent_report_t rep;
        fp_err_t err = fp_agent_sync_once(&cfg, &rep);

        char act_hex[65];
        fp_hex_encode(rep.active_bundle_dna.bytes, FP_DNA_LEN, act_hex);
        printf("{\"device\":\"%s\",\"channel\":\"%s\",\"outcome\":\"%s\","
               "\"active_serial\":%llu,\"active_dna\":\"%.16s\","
               "\"attempted_serial\":%llu,\"root_version\":%llu,"
               "\"health_exit\":%d,\"http_bytes\":%llu,\"lan_bytes\":%llu,\"resumed\":%llu,"
               "\"elapsed_ms\":%.2f,\"detail\":\"%s\"}\n",
               cfg.device_id, cfg.channel, fp_agent_outcome_name(rep.outcome),
               (unsigned long long)rep.active_serial, act_hex,
               (unsigned long long)rep.attempted_serial,
               (unsigned long long)rep.root_version,
               rep.health_exit_code,
               (unsigned long long)rep.bytes_downloaded,
               (unsigned long long)rep.bytes_from_lan,
               (unsigned long long)rep.bytes_resumed,
               (double)rep.elapsed_ns / 1e6, rep.detail);
        fflush(stdout);

        last_rc = (err == FP_OK) ? 0 : 1;
        if (run_once) break;
        for (int s = 0; s < interval_sec && !g_stop; s++) {
            sleep(1);
        }
    }
    return last_rc;
}
