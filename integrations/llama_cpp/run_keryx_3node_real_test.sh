#!/usr/bin/env bash
set -euo pipefail

# Realistic 3-Node Heterogeneous Keryx WAN Fidelity Testbed on REAL Qwen3.5-9B (6.5 GB GGUF)
#
# Launches 3 REAL llama.cpp ggml-rpc-server nodes simultaneously (CUDA0 + CPU1 + CPU2),
# each fronted by an independent sf-llama-bridge modeling real residential/transatlantic Keryx peers:
#   - Node 0 (EU FTTC Home):    35ms +-10ms jitter,  10 Mbps UL / 40 Mbps DL, 0.5% loss
#   - Node 1 (Transatlantic):  110ms +-20ms jitter,  15 Mbps UL / 50 Mbps DL, 1.5% loss
#   - Node 2 (Relay/Straggler): 80ms +-15ms jitter, 8% P99 +250ms, 6 Mbps UL / 25 Mbps DL, 2.0% loss

SF_DIR="${SF_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
LLAMA_BIN="${LLAMA_BIN:-./llama.cpp/build/bin}"
MODEL="${MODEL:-./models/Qwen3.5-9B.gguf}"
WORK="${WORK:-/tmp/sf-keryx-3node}"
mkdir -p "$WORK/rpc0" "$WORK/rpc1" "$WORK/rpc2" \
         "$WORK/c0_s" "$WORK/c0_c" "$WORK/c1_s" "$WORK/c1_c" "$WORK/c2_s" "$WORK/c2_c"

BRIDGE="$SF_DIR/bin/sf-llama-bridge"
RPC_SRV="$LLAMA_BIN/ggml-rpc-server"
LLAMA_CLI="$LLAMA_BIN/llama-cli"

PROMPT="Explain in two short sentences what cryptographic verification is."
NGL=24
NTOK=24

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    bash /mnt/samsung120/keryx-simnet/stop_simnet.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

SRV_PK=$("$BRIDGE" --keygen "$WORK/srv.key" | awk '/PubKey/{print $3}')
CLI_PK=$("$BRIDGE" --keygen "$WORK/cli.key" | awk '/PubKey/{print $3}')

bash /mnt/samsung120/keryx-simnet/start_simnet.sh
for i in $(seq 1 20); do ss -ltn | grep -q ':26114 ' && break; sleep 0.25; done

# Launch 3 REAL ggml-rpc-server backends (Node 0 = RTX 3070 Ti CUDA0, Node 1 & 2 = CPU workers)
HOME="$WORK/rpc0" "$RPC_SRV" -d CUDA0 -H 127.0.0.1 -p 51053 -c >"$WORK/rpc0.log" 2>&1 & PIDS+=($!)
HOME="$WORK/rpc1" "$RPC_SRV" -d CPU -t 4 -H 127.0.0.1 -p 51153 -c >"$WORK/rpc1.log" 2>&1 & PIDS+=($!)
HOME="$WORK/rpc2" "$RPC_SRV" -d CPU -t 4 -H 127.0.0.1 -p 51253 -c >"$WORK/rpc2.log" 2>&1 & PIDS+=($!)
for p in 51053 51153 51253; do
    for i in $(seq 1 40); do ss -ltn | grep -q ":${p} " && break; sleep 0.25; done
done
echo "3 REAL ggml-rpc-server workers ready (Node0=CUDA0:51053, Node1=CPU:51153, Node2=CPU:51253)"

launch_3node_bridges() {
    local mode="$1" # stock | sealframe_cold | sealframe_warm
    local tag="$2"
    BR_PIDS=()

    # Node profiles: (local_port, tun_port, backend_port, rtt, jitter, p99, p99_pct, ul, dl, drop, tcp_loss, cdir_idx)
    local PROFILES=(
        "51052 51062 51053 35  10 0   0 10 40 1 0.5 0"
        "51152 51162 51153 110 20 0   0 15 50 2 1.5 1"
        "51252 51262 51253 80  15 250 8 6  25 2 2.0 2"
    )

    for line in "${PROFILES[@]}"; do
        read -r lp tp bp rtt jit p99 p99p ul dl drp tcpl idx <<< "$line"
        local tr="udp" cast="int4o" fec="auto" topk="64" zf=() cf_s=() cf_c=() drp_arg="$drp" tcpl_arg="0"
        local rtt_use="$rtt" jit_use="$jit" p99_use="$p99" p99p_use="$p99p" ul_use="$ul" dl_use="$dl"

        if [ "$mode" = "stock" ]; then
            tr="tcp"; cast="raw"; fec="off"; topk="0"; zf=(--no-zstd); drp_arg="0"; tcpl_arg="$tcpl"
        elif [ "$mode" = "sealframe_cold" ]; then
            # Fast loopback warmup pass to populate DNA dedup cache across the 3 nodes
            cf_s=(--cache-dir "$WORK/c${idx}_s"); cf_c=(--cache-dir "$WORK/c${idx}_c")
            rtt_use="0"; jit_use="0"; p99_use="0"; p99p_use="0"; ul_use="0"; dl_use="0"; drp_arg="0"
        else
            cf_s=(--cache-dir "$WORK/c${idx}_s"); cf_c=(--cache-dir "$WORK/c${idx}_c")
        fi

        "$BRIDGE" --role server --bind 127.0.0.1 --port "$tp" \
            --backend-host 127.0.0.1 --backend-port "$bp" \
            --key "$WORK/srv.key" --allow-pk "$CLI_PK" \
            --transport "$tr" --cast "$cast" --fec "$fec" --logits-topk "$topk" \
            --drop "$drp_arg" "${zf[@]}" "${cf_s[@]}" \
            >"$WORK/${tag}_n${idx}_srv.log" 2>&1 &
        BR_PIDS+=($!)
        sleep 0.15
        "$BRIDGE" --role client --listen 127.0.0.1 --listen-port "$lp" \
            --remote-host 127.0.0.1 --remote-port "$tp" \
            --key "$WORK/cli.key" --peer-pk "$SRV_PK" \
            --transport "$tr" --cast "$cast" --fec "$fec" --logits-topk "$topk" \
            --drop "$drp_arg" "${zf[@]}" "${cf_c[@]}" \
            --wan-rtt-ms "$rtt_use" --wan-jitter-ms "$jit_use" \
            --wan-p99-ms "$p99_use" --wan-p99-pct "$p99p_use" \
            --wan-ul-mbps "$ul_use" --wan-dl-mbps "$dl_use" \
            --wan-tcp-loss-pct "$tcpl_arg" \
            --keryx-ws "ws://127.0.0.1:26114" \
            >"$WORK/${tag}_n${idx}_cli.log" 2>&1 &
        BR_PIDS+=($!)
    done
    for lp in 51052 51152 51252; do
        for i in $(seq 1 20); do ss -ltn | grep -q ":${lp} " && break; sleep 0.1; done
    done
}

run_3node_case() {
    local label="$1"
    local mode="$2"
    local extra_cli="$3"
    local prompt_use="$4"
    echo ""
    echo "=========================================================================================="
    echo "  3-NODE HETEROGENEOUS KERYX WAN REAL TEST: $label (Qwen3.5-9B, 3 RPC workers)"
    echo "=========================================================================================="
    launch_3node_bridges "$mode" "$label"
    local t0 t1 elapsed
    t0=$(date +%s%3N)
    # shellcheck disable=SC2086
    "$LLAMA_CLI" -m "$MODEL" \
        --rpc 127.0.0.1:51052,127.0.0.1:51152,127.0.0.1:51252 \
        --device RPC0,RPC1,RPC2 -ngl "$NGL" \
        -c 512 -n "$NTOK" --temp 0 --seed 42 --reasoning off -st \
        $extra_cli -p "$prompt_use" </dev/null >"$WORK/${label}_out.txt" 2>"$WORK/${label}_err.log"
    t1=$(date +%s%3N)
    elapsed=$((t1 - t0))
    for p in "${BR_PIDS[@]}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done

    echo "  Total Wall Time: ${elapsed} ms"
    grep -E "Cryptographic|SealFrame|Prompt:|Generation:" "$WORK/${label}_out.txt" 2>/dev/null | tail -n 6 | sed 's/^/  | /' || true
    for idx in 0 1 2; do
        echo "  --- Node $idx Bridge Stats ---"
        grep "sf-llama-bridge" "$WORK/${label}_n${idx}_cli.log" | tail -n 2 | sed 's/^/    /' || true
    done
}

# Warm up >10MB ggml-rpc-server disk cache once directly (fast local pass),
# then warm up SealFrame <12MB DNA dedup cache across the 3 nodes!
rm -rf "$WORK"/c?_?/*
echo "=== Pre-warming 3-node ggml-rpc-server disk cache (simulates persistent Keryx nodes) ==="
"$LLAMA_CLI" -m "$MODEL" \
    --rpc 127.0.0.1:51053,127.0.0.1:51153,127.0.0.1:51253 \
    --device RPC0,RPC1,RPC2 -ngl "$NGL" \
    -c 512 -n 2 --temp 0 --seed 42 --reasoning off -st \
    -p "Hi" </dev/null >/dev/null 2>&1
run_3node_case "0_warmup_dna_cache"      "sealframe_cold" "" "$PROMPT"

# A. REALISTIC 3-NODE KERYX STOCK BASELINE (raw FP32 TCP, asymmetric UL/DL, jitter, P99, TCP loss!)
run_3node_case "1_keryx_3node_stock_raw" "stock"          "" "$PROMPT"

# B. FULL SEALFRAME v2 (FP-UDP1 + Adaptive FEC + INT4+Outlier + Top-64 Logits + Zstd + DNA Dedup!)
run_3node_case "2_keryx_3node_sealframe" "sealframe_warm" "" "$PROMPT"

# C. FULL SEALFRAME v2 + llama.cpp Native N-Gram Speculative Decoding (free 0-VRAM lookup!)
SPEC_PROMPT="Repeat this exact technical summary word for word: SealFrame accelerates Keryx split-model inference using encrypted FP-UDP1, adaptive 0-RTT XOR FEC, BLAKE3 DNA deduplication, Zstd graph compression, and Top-64 exact FP32 sparse logits. Summary:"
run_3node_case "3_keryx_3node_sf_ngram"  "sealframe_warm" "--spec-ngram-map-k-size-n 4" "$SPEC_PROMPT"

echo ""
echo "ALL 3-NODE HETEROGENEOUS KERYX WAN REAL TESTS COMPLETED!"
