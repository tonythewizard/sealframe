#!/usr/bin/env bash
set -euo pipefail

SF_DIR="${SF_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
LLAMA_BIN="${LLAMA_BIN:-./llama.cpp/build/bin}"
MODEL="${MODEL:-./models/Qwen3.5-9B.gguf}"
WORK="${WORK:-/tmp/sf-llama-real-test}"
mkdir -p "$WORK/rpc-cache" "$WORK/sf-cache-srv" "$WORK/sf-cache-cli"
rm -rf "$WORK/sf-cache-srv"/* "$WORK/sf-cache-cli"/*

BRIDGE="$SF_DIR/bin/sf-llama-bridge"
RPC_SRV="$LLAMA_BIN/ggml-rpc-server"
LLAMA_CLI="$LLAMA_BIN/llama-cli"

PROMPT="Explain in two short sentences what cryptographic verification is."
NGL=16
NTOK=24

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
    bash /mnt/samsung120/keryx-simnet/stop_simnet.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

SRV_PK=$("$BRIDGE" --keygen "$WORK/srv.key" | awk '/PubKey/{print $3}')
CLI_PK=$("$BRIDGE" --keygen "$WORK/cli.key" | awk '/PubKey/{print $3}')

bash /mnt/samsung120/keryx-simnet/start_simnet.sh
for i in $(seq 1 20); do ss -ltn | grep -q ':26114 ' && break; sleep 0.25; done

HOME="$WORK" "$RPC_SRV" -d CUDA0 -H 127.0.0.1 -p 50053 -c >"$WORK/rpc_server.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 40); do ss -ltn | grep -q ':50053 ' && break; sleep 0.25; done

run_bridge_case() {
    local label="$1"
    local transport="$2"
    local cast="$3"
    local zstd_flag="$4" # "" or "--no-zstd"
    local use_cache="$5" # 1 or 0
    local wan_rtt="$6"
    local wan_mbps="$7"
    local extra_cli="$8"
    local log_prefix="$WORK/opt_${label}"

    echo ""
    echo "================================================================================"
    echo "  REAL QWEN3.5-9B RUN: $label (tr=$transport cast=$cast wan=${wan_rtt}ms/${wan_mbps}Mbps)"
    echo "================================================================================"

    local sc_args=() cc_args=()
    if [ "$use_cache" = "1" ]; then
        sc_args+=(--cache-dir "$WORK/sf-cache-srv")
        cc_args+=(--cache-dir "$WORK/sf-cache-cli")
    fi
    if [ -n "$zstd_flag" ]; then
        sc_args+=("$zstd_flag")
        cc_args+=("$zstd_flag")
    fi

    "$BRIDGE" --role server --bind 127.0.0.1 --port 50062 \
        --backend-host 127.0.0.1 --backend-port 50053 \
        --key "$WORK/srv.key" --allow-pk "$CLI_PK" \
        --transport "$transport" --cast "$cast" "${sc_args[@]}" \
        >"${log_prefix}_br_srv.log" 2>&1 &
    local p1=$!
    sleep 0.25
    "$BRIDGE" --role client --listen 127.0.0.1 --listen-port 50052 \
        --remote-host 127.0.0.1 --remote-port 50062 \
        --key "$WORK/cli.key" --peer-pk "$SRV_PK" \
        --transport "$transport" --cast "$cast" "${cc_args[@]}" \
        --wan-rtt-ms "$wan_rtt" --wan-mbps "$wan_mbps" \
        --keryx-ws "ws://127.0.0.1:26114" \
        >"${log_prefix}_br_cli.log" 2>&1 &
    local p2=$!
    for i in $(seq 1 20); do ss -ltn | grep -q ':50052 ' && break; sleep 0.1; done

    local t0 t1 elapsed
    t0=$(date +%s%3N)
    # shellcheck disable=SC2086
    "$LLAMA_CLI" -m "$MODEL" \
        --rpc 127.0.0.1:50052 --device RPC0 -ngl "$NGL" \
        -c 512 -n "$NTOK" --temp 0 --seed 42 --reasoning off -st \
        $extra_cli -p "$PROMPT" </dev/null >"${log_prefix}_out.txt" 2>"${log_prefix}_err.log"
    t1=$(date +%s%3N)
    elapsed=$((t1 - t0))

    kill "$p1" "$p2" 2>/dev/null || true
    wait "$p1" "$p2" 2>/dev/null || true

    echo "  Wall time: ${elapsed} ms"
    grep -E "Cryptographic|Prompt:|Generation:" "${log_prefix}_out.txt" 2>/dev/null | sed 's/^/  | /' || true
    grep "sf-llama-bridge" "${log_prefix}_br_cli.log" | tail -n 2 | sed 's/^/  | /' || true
}

# 1. Cold pass on loopback to populate SealFrame DNA dedup cache (<10 MB weights!)
run_bridge_case "1_cold_populate_cache"       "udp" "int4o" ""          1 0  0  ""
# 2. Warm pass on loopback: DNA Dedup HIT + Zstd-1 GRAPH_COMPUTE + SFT1 INT4+Outlier!
run_bridge_case "2_warm_dedup_zstd_int4o"     "udp" "int4o" ""          1 0  0  ""
# 3. REAL 20Mbps / 40ms WAN PACE — Stock-equivalent raw FP32 (no SFT1, no Zstd, no dedup)!
run_bridge_case "3_wan20m_baseline_raw_fp32"  "tcp" "raw"   "--no-zstd" 0 40 20 ""
# 4. REAL 20Mbps / 40ms WAN PACE — Full SealFrame (FP-UDP1+FEC + INT4+Outlier + Zstd + DNA Dedup)!
run_bridge_case "4_wan20m_sealframe_int4o"    "udp" "int4o" ""          1 40 20 ""
# 5. REAL 20Mbps / 40ms WAN PACE — Full SealFrame + output.weight=CPU (avoid 1MB logits over WAN)!
run_bridge_case "5_wan20m_sealframe_no_logit" "udp" "int4o" ""          1 40 20 "-ot output.weight=CPU"

echo ""
echo "ALL 5 REAL QWEN3.5-9B OPTIMIZED + WAN-PACED RUNS COMPLETED!"
