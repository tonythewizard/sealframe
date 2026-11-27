#!/usr/bin/env bash
set -euo pipefail

# ======================================================================================
# 6-Shard, 6-Country Emulated Global WAN Benchmark on REAL Qwen3.5-9B (Q5_K_M, 6.1 GB)
# ======================================================================================
# Recreates the 6-shard / 6-country split-model scenario locally on 1 host using:
#   - 6 REAL llama.cpp ggml-rpc-server workers (1x CUDA0 + 5x CPU 2-thread, equal 1:1:1:1:1:1 layer split)
#   - 6 independent sf-llama-bridge tunnels with per-hop cross-country WAN shaping:
#       Shard 0 (Germany  - DE):   28ms +- 6ms,  20/80 Mbps UL/DL, 0.5% loss
#       Shard 1 (UK       - UK):   42ms +- 8ms,  15/60 Mbps UL/DL, 0.8% loss
#       Shard 2 (Poland   - PL):   55ms +-12ms,  12/50 Mbps UL/DL, 1.0% loss
#       Shard 3 (US-East  - NY):  105ms +-18ms,  15/60 Mbps UL/DL, 1.2% loss
#       Shard 4 (US-West  - CA):  155ms +-22ms,  10/40 Mbps UL/DL, 1.5% loss
#       Shard 5 (Singapore- SG):  185ms +-25ms + 6% P99 +200ms, 8/30 Mbps UL/DL, 2.0% loss
#     (Cumulative 6-hop RTT sum = 570ms, mean = 95ms/hop)
#   - Persistent llama-server measuring:
#       1) Startup / model-load time across all 6 countries (Stock TCP vs SealFrame)
#       2) N=5 sequential requests (cache_prompt=false, temp=0, seed=42),
#          n_predict = [24, 24, 32, 32, 64] (176 generated tokens total),
#          reporting Prompt processing, Generation speed ALONE, and End-to-End per request
#          with min / median / max statistics + exact output comparison.
# ======================================================================================

SF_DIR="${SF_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
LLAMA_BIN="${LLAMA_BIN:-./llama.cpp/build/bin}"
MODEL="${MODEL:-./models/Qwen3.5-9B.gguf}"
WORK="${WORK:-/tmp/sf-keryx-6node-global}"

BRIDGE="$SF_DIR/bin/sf-llama-bridge"
RPC_SRV="$LLAMA_BIN/ggml-rpc-server"
LLAMA_SRV="$LLAMA_BIN/llama-server"

rm -rf "$WORK"
mkdir -p "$WORK"
for i in 0 1 2 3 4 5; do
    mkdir -p "$WORK/rpc$i" "$WORK/c${i}_s" "$WORK/c${i}_c"
done

PIDS=()
BR_PIDS=()
SRV_PID=""

cleanup() {
    if [ -n "${SRV_PID:-}" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
    for p in "${BR_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

SRV_PK=$("$BRIDGE" --keygen "$WORK/srv.key" | awk '/PubKey/{print $3}')
CLI_PK=$("$BRIDGE" --keygen "$WORK/cli.key" | awk '/PubKey/{print $3}')

# Launch 6 REAL ggml-rpc-server workers (Shard 0 = CUDA0, Shards 1..5 = CPU 2 threads each)
HOME="$WORK/rpc0" "$RPC_SRV" -d CUDA0 -H 127.0.0.1 -p 52000 -c >"$WORK/rpc0.log" 2>&1 & PIDS+=($!)
for i in 1 2 3 4 5; do
    port=$((52000 + i))
    HOME="$WORK/rpc$i" "$RPC_SRV" -d CPU -t 2 -H 127.0.0.1 -p "$port" -c >"$WORK/rpc${i}.log" 2>&1 & PIDS+=($!)
done
for i in 0 1 2 3 4 5; do
    port=$((52000 + i))
    for _ in $(seq 1 40); do ss -ltn | grep -q ":${port} " && break; sleep 0.25; done
done
echo "6 REAL ggml-rpc-server workers ready (RPC0=CUDA0:52000, RPC1..RPC5=CPU:52001..52005)"

# 6-country hop profiles:
# idx country local_port tun_port backend_port rtt jitter p99 p99_pct ul dl udp_drop tcp_loss
PROFILES=(
    "0 DE 52100 52200 52000  28  6   0 0 20 80 1 0.5"
    "1 UK 52101 52201 52001  42  8   0 0 15 60 1 0.8"
    "2 PL 52102 52202 52002  55 12   0 0 12 50 1 1.0"
    "3 NY 52103 52203 52003 105 18   0 0 15 60 1 1.2"
    "4 CA 52104 52204 52004 155 22   0 0 10 40 2 1.5"
    "5 SG 52105 52205 52005 185 25 200 6  8 30 2 2.0"
)

launch_bridges() {
    local mode="$1" # warmup | stock | sealframe
    local tag="$2"
    BR_PIDS=()
    for line in "${PROFILES[@]}"; do
        read -r idx cc lp tp bp rtt jit p99 p99p ul dl udrp tcpl <<< "$line"
        local tr="udp" cast="int4o" fec="auto" topk="64" zf=() cf_s=() cf_c=() drp_arg="$udrp" tcpl_arg="0"
        local rtt_use="$rtt" jit_use="$jit" p99_use="$p99" p99p_use="$p99p" ul_use="$ul" dl_use="$dl"

        if [ "$mode" = "stock" ]; then
            tr="tcp"; cast="raw"; fec="off"; topk="0"; zf=(--no-zstd); drp_arg="0"; tcpl_arg="$tcpl"
        elif [ "$mode" = "warmup" ]; then
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
            >"$WORK/${tag}_n${idx}_${cc}_srv.log" 2>&1 &
        BR_PIDS+=($!)
        sleep 0.1
        "$BRIDGE" --role client --listen 127.0.0.1 --listen-port "$lp" \
            --remote-host 127.0.0.1 --remote-port "$tp" \
            --key "$WORK/cli.key" --peer-pk "$SRV_PK" \
            --transport "$tr" --cast "$cast" --fec "$fec" --logits-topk "$topk" \
            --drop "$drp_arg" "${zf[@]}" "${cf_c[@]}" \
            --wan-rtt-ms "$rtt_use" --wan-jitter-ms "$jit_use" \
            --wan-p99-ms "$p99_use" --wan-p99-pct "$p99p_use" \
            --wan-ul-mbps "$ul_use" --wan-dl-mbps "$dl_use" \
            --wan-tcp-loss-pct "$tcpl_arg" \
            >"$WORK/${tag}_n${idx}_${cc}_cli.log" 2>&1 &
        BR_PIDS+=($!)
    done
    for i in 0 1 2 3 4 5; do
        lp=$((52100 + i))
        for _ in $(seq 1 30); do ss -ltn | grep -q ":${lp} " && break; sleep 0.1; done
    done
}

stop_bridges() {
    for p in "${BR_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
    BR_PIDS=()
}

run_server_suite() {
    local tag="$1"
    local mode="$2"
    local http_port="$3"
    local do_requests="$4" # 0=warmup only, 1=full 5 requests

    echo ""
    echo "==========================================================================================="
    echo "  6-SHARD 6-COUNTRY BENCHMARK: $tag (mode=$mode)"
    echo "==========================================================================================="

    launch_bridges "$mode" "$tag"

    local t_boot0 t_boot1 load_ms
    t_boot0=$(date +%s%3N)
    "$LLAMA_SRV" -m "$MODEL" \
        --rpc 127.0.0.1:52100,127.0.0.1:52101,127.0.0.1:52102,127.0.0.1:52103,127.0.0.1:52104,127.0.0.1:52105 \
        --device RPC0,RPC1,RPC2,RPC3,RPC4,RPC5 \
        --tensor-split 1,1,1,1,1,1 -ngl 32 \
        -c 1024 -np 1 --reasoning off --no-webui \
        --host 127.0.0.1 --port "$http_port" \
        >"$WORK/${tag}_server.log" 2>&1 &
    SRV_PID=$!

    # Wait until /health returns 200 OK (model fully loaded across all 6 shards!)
    local ready=0
    for _ in $(seq 1 600); do
        if ! kill -0 "$SRV_PID" 2>/dev/null; then
            echo "ERROR: llama-server exited early! Tail of log:"
            tail -n 40 "$WORK/${tag}_server.log"
            exit 1
        fi
        if curl -sf "http://127.0.0.1:${http_port}/health" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.5
    done
    if [ "$ready" -ne 1 ]; then
        echo "ERROR: llama-server timed out waiting for /health"
        tail -n 40 "$WORK/${tag}_server.log"
        exit 1
    fi
    t_boot1=$(date +%s%3N)
    load_ms=$((t_boot1 - t_boot0))
    echo "  [Model Load / 6-Shard Startup] ${load_ms} ms ($(awk "BEGIN{printf \"%.2f\", $load_ms/1000}") s)"
    grep -E "offloaded|RPC[0-5]|load_tensors" "$WORK/${tag}_server.log" | head -n 16 | sed 's/^/    /' || true

    if [ "$do_requests" = "1" ]; then
        python3 - "$http_port" "$WORK/${tag}_results.json" "$load_ms" "$tag" <<'PYEOF'
import json, statistics, sys, time, urllib.request

port = int(sys.argv[1])
out_path = sys.argv[2]
load_ms = int(sys.argv[3])
tag = sys.argv[4]

REQUESTS = [
    ("R1_24tok", 24, "Explain in two concise sentences what cryptographic hash verification guarantees in distributed systems."),
    ("R2_24tok", 24, "List three reasons why TCP head-of-line blocking hurts latency-sensitive RPC over lossy residential internet links."),
    ("R3_32tok", 32, "Summarize how pipeline-parallel model inference splits transformer layers across remote nodes and why inter-hop latency dominates token time."),
    ("R4_32tok", 32, "Explain the trade-off between activation quantization precision and bandwidth reduction when transferring hidden states over wide-area networks."),
    ("R5_64tok", 64, "Write a clear technical paragraph explaining why forward error correction and persistent encrypted sessions improve tail latency for distributed inference across multiple countries."),
]

rows = []
for name, n_pred, prompt in REQUESTS:
    payload = json.dumps({
        "model": "qwen3.5-9b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": n_pred,
        "temperature": 0.0,
        "seed": 42,
        "cache_prompt": False,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=600) as resp:
        data = json.loads(resp.read().decode())
    wall_ms = (time.monotonic() - t0) * 1000.0
    tim = data.get("timings", {})
    p_n = int(tim.get("prompt_n", 0))
    p_ms = float(tim.get("prompt_ms", 0.0))
    p_tps = float(tim.get("prompt_per_second", 0.0))
    g_n = int(tim.get("predicted_n", 0))
    g_ms = float(tim.get("predicted_ms", 0.0))
    g_tps = float(tim.get("predicted_per_second", 0.0))
    g_ms_tok = (g_ms / g_n) if g_n > 0 else 0.0
    e2e_ms_tok = (wall_ms / g_n) if g_n > 0 else 0.0
    e2e_tps = (g_n / (wall_ms / 1000.0)) if wall_ms > 0 else 0.0
    cache_n = int(tim.get("cache_n", 0))
    txt = data["choices"][0]["message"]["content"].strip().replace("\n", " ")

    row = {
        "name": name,
        "prompt_n": p_n,
        "cache_n": cache_n,
        "prompt_ms": round(p_ms, 1),
        "prompt_tps": round(p_tps, 3),
        "gen_n": g_n,
        "gen_ms": round(g_ms, 1),
        "gen_tps": round(g_tps, 3),
        "gen_ms_per_tok": round(g_ms_tok, 1),
        "wall_ms": round(wall_ms, 1),
        "e2e_tps": round(e2e_tps, 3),
        "e2e_ms_per_tok": round(e2e_ms_tok, 1),
        "text": txt,
    }
    rows.append(row)
    print(f"  {name}: prompt={p_n}tok (cache={cache_n}) {p_ms:.0f}ms ({p_tps:.2f} t/s) | "
          f"gen={g_n}tok {g_ms:.0f}ms ({g_tps:.3f} t/s, {g_ms_tok:.0f} ms/tok) | "
          f"e2e={wall_ms:.0f}ms ({e2e_tps:.3f} t/s, {e2e_ms_tok:.0f} ms/tok)", flush=True)
    print(f"    text: {txt[:110]}", flush=True)

def stats(vals):
    return {
        "min": round(min(vals), 3),
        "median": round(statistics.median(vals), 3),
        "max": round(max(vals), 3),
    }

summary = {
    "tag": tag,
    "load_ms": load_ms,
    "requests": rows,
    "gen_tps": stats([r["gen_tps"] for r in rows]),
    "gen_ms_per_tok": stats([r["gen_ms_per_tok"] for r in rows]),
    "prompt_tps": stats([r["prompt_tps"] for r in rows]),
    "e2e_tps": stats([r["e2e_tps"] for r in rows]),
    "e2e_ms_per_tok": stats([r["e2e_ms_per_tok"] for r in rows]),
}
with open(out_path, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n  === {tag} SUMMARY (N={len(rows)} requests, persistent 6-shard server) ===", flush=True)
print(f"  Model load (6 shards):   {load_ms/1000:.2f} s", flush=True)
print(f"  Generation ALONE (t/s):  min={summary['gen_tps']['min']:.3f} / median={summary['gen_tps']['median']:.3f} / max={summary['gen_tps']['max']:.3f}", flush=True)
print(f"  Generation ms/tok:       min={summary['gen_ms_per_tok']['min']:.0f} / median={summary['gen_ms_per_tok']['median']:.0f} / max={summary['gen_ms_per_tok']['max']:.0f}", flush=True)
print(f"  Prompt eval (t/s):       min={summary['prompt_tps']['min']:.3f} / median={summary['prompt_tps']['median']:.3f} / max={summary['prompt_tps']['max']:.3f}", flush=True)
print(f"  End-to-End req (t/s):    min={summary['e2e_tps']['min']:.3f} / median={summary['e2e_tps']['median']:.3f} / max={summary['e2e_tps']['max']:.3f}", flush=True)
print(f"  End-to-End ms/tok:       min={summary['e2e_ms_per_tok']['min']:.0f} / median={summary['e2e_ms_per_tok']['median']:.0f} / max={summary['e2e_ms_per_tok']['max']:.0f}", flush=True)
PYEOF
    else
        # Single tiny warmup request so all 6 shards populate their DNA dedup caches
        curl -sf "http://127.0.0.1:${http_port}/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -d '{"model":"qwen3.5-9b","messages":[{"role":"user","content":"Hi"}],"max_tokens":4,"temperature":0,"seed":42,"cache_prompt":false}' \
            >/dev/null
        echo "  Warmup request complete (6-shard ggml-rpc disk cache + SealFrame DNA dedup cache populated)."
    fi

    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
    sleep 0.5
    stop_bridges

    echo "  --- Aggregated 6-Shard Bridge Wire Stats ($tag) ---"
    for line in "${PROFILES[@]}"; do
        read -r idx cc _ <<< "$line"
        echo "    Shard $idx ($cc):"
        grep "sf-llama-bridge" "$WORK/${tag}_n${idx}_${cc}_cli.log" | tail -n 2 | sed 's/^/      /' || true
    done
}

# 0. Fast loopback warmup (populates ggml-rpc >10MB disk cache + SealFrame <12MB DNA cache,
#    matching persistent volunteer nodes that already host the model)
run_server_suite "0_warmup_6node" "warmup" 52300 0

# 1. FULL SEALFRAME (post-fix aef25a3) across 6 countries
run_server_suite "1_sealframe_6country" "sealframe" 52301 1

# 2. STOCK RAW ggml-rpc TCP across the EXACT SAME 6 countries
run_server_suite "2_stock_tcp_6country" "stock" 52302 1

# 3. Side-by-side comparison & text fidelity check
python3 - "$WORK/2_stock_tcp_6country_results.json" "$WORK/1_sealframe_6country_results.json" <<'PYEOF'
import json, sys

stock = json.load(open(sys.argv[1]))
sf = json.load(open(sys.argv[2]))

print("\n===========================================================================================")
print("  FINAL A/B COMPARISON — 6 SHARDS / 6 COUNTRIES (Qwen3.5-9B Q5_K_M, N=5 requests)")
print("===========================================================================================")
print(f"  Startup / 6-Shard Load:   Stock={stock['load_ms']/1000:.2f}s  vs  SealFrame={sf['load_ms']/1000:.2f}s  "
      f"({stock['load_ms']/sf['load_ms']:.2f}x faster, -{(stock['load_ms']-sf['load_ms'])/1000:.2f}s)")
print(f"  Generation ALONE median:  Stock={stock['gen_tps']['median']:.3f} t/s  vs  SealFrame={sf['gen_tps']['median']:.3f} t/s  "
      f"({sf['gen_tps']['median']/stock['gen_tps']['median']:.2f}x)")
print(f"  Generation ALONE min/max: Stock={stock['gen_tps']['min']:.3f}..{stock['gen_tps']['max']:.3f}  vs  "
      f"SealFrame={sf['gen_tps']['min']:.3f}..{sf['gen_tps']['max']:.3f}")
print(f"  Prompt eval median:       Stock={stock['prompt_tps']['median']:.3f} t/s  vs  SealFrame={sf['prompt_tps']['median']:.3f} t/s  "
      f"({sf['prompt_tps']['median']/stock['prompt_tps']['median']:.2f}x)")
print(f"  End-to-End req median:    Stock={stock['e2e_tps']['median']:.3f} t/s ({stock['e2e_ms_per_tok']['median']:.0f} ms/tok)  vs  "
      f"SealFrame={sf['e2e_tps']['median']:.3f} t/s ({sf['e2e_ms_per_tok']['median']:.0f} ms/tok)")

exact = 0
for rs, rf in zip(stock["requests"], sf["requests"]):
    same = (rs["text"] == rf["text"])
    if same:
        exact += 1
    print(f"  Text match [{rs['name']}]: {'EXACT 100%' if same else 'DIFF'}")
    if not same:
        print(f"    Stock: {rs['text'][:100]}")
        print(f"    SF:    {rf['text'][:100]}")
print(f"  Exact output matches: {exact}/{len(stock['requests'])}")
PYEOF
