#!/usr/bin/env bash
set -euo pipefail

# ======================================================================================
# R&D Milestone Benchmark: Breaking 3-5+ tok/s across 6 Shards / 6 Countries (570ms RTT)
# ======================================================================================
# Model:  Qwen3-8B (Q4_K_M, 36 pure-Transformer layers -> exact 6 layers per country!)
# Draft:  Qwen3-0.6B (Q4_K_M, 400 MB, local coordinator CUDA0, 0ms network RTT)
# Links:  DE 28ms, UK 42ms, PL 55ms, US-East 105ms, US-West 155ms, SG 185ms+P99 (sum=570ms)
#
# Measures N=5 sequential requests (cache_prompt=false, cache_ram=0, temp=0, seed=42),
# n_predict = [24, 24, 32, 32, 64] (176 tokens total), comparing:
#   1) Stock raw ggml-rpc TCP (no draft)
#   2) SealFrame v4 INT8 (no draft)           — pure transport/wire + 0-RTT pipelining gain
#   3) Stock raw ggml-rpc TCP + Draft K=8     — shows why speculative alone chokes on WAN logits/TCP!
#   4) SealFrame v4 INT8  + Draft K=8         — high-fidelity target 3-5+ tok/s!
#   5) SealFrame v4 INT4o + Draft K=12        — maximum WAN throughput envelope!
# ======================================================================================

SF_DIR="${SF_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
LLAMA_BIN="${LLAMA_BIN:-./llama.cpp/build/bin}"
MODEL="${MODEL:-./models/Qwen3-8B-Q4_K_M.gguf}"
DRAFT="${DRAFT:-./models/Qwen3-1.7B-Q4_K_M.gguf}"
WORK="${WORK:-/tmp/sf-keryx-6node-qwen3}"

BRIDGE="$SF_DIR/bin/sf-llama-bridge"
RPC_SRV="$LLAMA_BIN/ggml-rpc-server"
LLAMA_SRV="$LLAMA_BIN/llama-server"

mkdir -p "$WORK"
for i in 0 1 2 3 4 5; do
    mkdir -p "$WORK/rpc$i" "$WORK/c${i}_s" "$WORK/c${i}_c"
done

PIDS=(); BR_PIDS=(); SRV_PID=""
cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
    for p in "${BR_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

SRV_PK=$("$BRIDGE" --keygen "$WORK/srv.key" | awk '/PubKey/{print $3}')
CLI_PK=$("$BRIDGE" --keygen "$WORK/cli.key" | awk '/PubKey/{print $3}')

HOME="$WORK/rpc0" "$RPC_SRV" -d CUDA0 -H 127.0.0.1 -p 52400 -c >"$WORK/rpc0.log" 2>&1 & PIDS+=($!)
for i in 1 2 3 4 5; do
    HOME="$WORK/rpc$i" "$RPC_SRV" -d CPU -t 2 -H 127.0.0.1 -p $((52400+i)) -c >"$WORK/rpc${i}.log" 2>&1 & PIDS+=($!)
done
for i in 0 1 2 3 4 5; do
    for _ in $(seq 1 40); do ss -ltn | grep -q ":$((52400+i)) " && break; sleep 0.25; done
done
echo "6 REAL ggml-rpc-server workers ready (Qwen3-8B: 36 layers = 6 layers per country)"

PROFILES=(
    "0 DE 52500 52600 52400  28  6   0 0 20 80 1 0.5"
    "1 UK 52501 52601 52401  42  8   0 0 15 60 1 0.8"
    "2 PL 52502 52602 52402  55 12   0 0 12 50 1 1.0"
    "3 NY 52503 52603 52403 105 18   0 0 15 60 1 1.2"
    "4 CA 52504 52604 52404 155 22   0 0 10 40 2 1.5"
    "5 SG 52505 52605 52405 185 25 200 6  8 30 2 2.0"
)

launch_bridges() {
    local mode="$1" # warmup | stock | int8 | int4o
    local tag="$2"
    BR_PIDS=()
    for line in "${PROFILES[@]}"; do
        read -r idx cc lp tp bp rtt jit p99 p99p ul dl udrp tcpl <<< "$line"
        local tr="udp" cast="$mode" fec="auto" topk="64" zf=() cf_s=() cf_c=() drp_arg="$udrp" tcpl_arg="0"
        local rtt_u="$rtt" jit_u="$jit" p99_u="$p99" p99p_u="$p99p" ul_u="$ul" dl_u="$dl"
        if [ "$mode" = "stock" ]; then
            tr="tcp"; cast="raw"; fec="off"; topk="0"; zf=(--no-zstd); drp_arg="0"; tcpl_arg="$tcpl"
        elif [ "$mode" = "warmup" ]; then
            cast="int8"; cf_s=(--cache-dir "$WORK/c${idx}_s"); cf_c=(--cache-dir "$WORK/c${idx}_c")
            rtt_u="0"; jit_u="0"; p99_u="0"; p99p_u="0"; ul_u="0"; dl_u="0"; drp_arg="0"
        else
            cf_s=(--cache-dir "$WORK/c${idx}_s"); cf_c=(--cache-dir "$WORK/c${idx}_c")
        fi

        "$BRIDGE" --role server --bind 127.0.0.1 --port "$tp" --backend-host 127.0.0.1 --backend-port "$bp" \
            --key "$WORK/srv.key" --allow-pk "$CLI_PK" --transport "$tr" --cast "$cast" --fec "$fec" \
            --logits-topk "$topk" --drop "$drp_arg" "${zf[@]}" "${cf_s[@]}" \
            >"$WORK/${tag}_n${idx}_${cc}_srv.log" 2>&1 & BR_PIDS+=($!)
        sleep 0.1
        "$BRIDGE" --role client --listen 127.0.0.1 --listen-port "$lp" --remote-host 127.0.0.1 --remote-port "$tp" \
            --key "$WORK/cli.key" --peer-pk "$SRV_PK" --transport "$tr" --cast "$cast" --fec "$fec" \
            --logits-topk "$topk" --drop "$drp_arg" "${zf[@]}" "${cf_c[@]}" \
            --wan-rtt-ms "$rtt_u" --wan-jitter-ms "$jit_u" --wan-p99-ms "$p99_u" --wan-p99-pct "$p99p_u" \
            --wan-ul-mbps "$ul_u" --wan-dl-mbps "$dl_u" --wan-tcp-loss-pct "$tcpl_arg" \
            >"$WORK/${tag}_n${idx}_${cc}_cli.log" 2>&1 & BR_PIDS+=($!)
    done
    for i in 0 1 2 3 4 5; do
        for _ in $(seq 1 30); do ss -ltn | grep -q ":$((52500+i)) " && break; sleep 0.1; done
    done
}

stop_bridges() {
    for p in "${BR_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
    BR_PIDS=()
}

run_case() {
    local tag="$1"
    local mode="$2"
    local http_port="$3"
    local use_draft="$4" # 0 or 1
    local d_max="$5"
    local d_pmin="$6"
    local do_reqs="$7"

    echo ""
    echo "==========================================================================================="
    echo "  6-SHARD / 6-COUNTRY QWEN3-8B: $tag (mode=$mode, draft=$use_draft K=$d_max p=$d_pmin)"
    echo "==========================================================================================="

    launch_bridges "$mode" "$tag"

    local spec_args=()
    if [ "$use_draft" = "1" ]; then
        spec_args=(
            --spec-type draft-simple
            --spec-draft-model "$DRAFT"
            --spec-draft-device CUDA0
            --spec-draft-ngl 99
            --spec-draft-n-max "$d_max"
            --spec-draft-n-min 1
            --spec-draft-p-min "$d_pmin"
        )
    fi

    local t0 t1 load_ms
    t0=$(date +%s%3N)
    "$LLAMA_SRV" -m "$MODEL" \
        --rpc 127.0.0.1:52500,127.0.0.1:52501,127.0.0.1:52502,127.0.0.1:52503,127.0.0.1:52504,127.0.0.1:52505 \
        --device RPC0,RPC1,RPC2,RPC3,RPC4,RPC5 \
        --tensor-split 1,1,1,1,1,1 -ngl 36 \
        "${spec_args[@]}" \
        -c 1024 -np 1 --cache-ram 0 --reasoning off --no-webui \
        --host 127.0.0.1 --port "$http_port" \
        >"$WORK/${tag}_server.log" 2>&1 &
    SRV_PID=$!

    local ready=0
    for _ in $(seq 1 1800); do
        if ! kill -0 "$SRV_PID" 2>/dev/null; then
            echo "ERROR: llama-server exited early!"
            tail -n 35 "$WORK/${tag}_server.log"
            exit 1
        fi
        if curl -sf "http://127.0.0.1:${http_port}/health" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 0.5
    done
    if [ "$ready" -ne 1 ]; then echo "ERROR: timeout"; exit 1; fi
    t1=$(date +%s%3N)
    load_ms=$((t1 - t0))
    echo "  [6-Shard Load] ${load_ms} ms ($(awk "BEGIN{printf \"%.2f\", $load_ms/1000}") s)"

    if [ "$do_reqs" = "1" ]; then
        python3 - "$http_port" "$WORK/${tag}_results.json" "$load_ms" "$tag" <<'PYEOF'
import json, statistics, sys, time, urllib.request
port, out_path, load_ms, tag = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
REQUESTS = [
    ("R1_24tok", 24, "Explain in two concise sentences what cryptographic hash verification guarantees in distributed systems."),
    ("R2_24tok", 24, "List three reasons why TCP head-of-line blocking hurts latency-sensitive RPC over lossy residential internet links."),
    ("R3_32tok", 32, "Summarize how pipeline-parallel model inference splits transformer layers across remote nodes and why inter-hop latency dominates token time."),
    ("R4_32tok", 32, "Explain the trade-off between activation quantization precision and bandwidth reduction when transferring hidden states over wide-area networks."),
    ("R5_64tok", 64, "Write a clear technical paragraph explaining why forward error correction and persistent encrypted sessions improve tail latency for distributed inference across multiple countries."),
]
rows = []
for name, n_pred, prompt in REQUESTS:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps({
            "model": "qwen3-8b",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": n_pred, "temperature": 0.0, "seed": 42,
            "cache_prompt": False, "stream": False,
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    t0 = time.monotonic()
    data = json.loads(urllib.request.urlopen(req, timeout=600).read().decode())
    wall_ms = (time.monotonic() - t0) * 1000.0
    tim = data.get("timings", {})
    p_n, p_ms, p_tps = int(tim.get("prompt_n", 0)), float(tim.get("prompt_ms", 0)), float(tim.get("prompt_per_second", 0))
    g_n, g_ms, g_tps = int(tim.get("predicted_n", 0)), float(tim.get("predicted_ms", 0)), float(tim.get("predicted_per_second", 0))
    d_n, d_acc = int(tim.get("draft_n", 0)), int(tim.get("draft_n_accepted", 0))
    g_ms_t = g_ms / g_n if g_n else 0.0
    e2e_tps = g_n / (wall_ms / 1000.0) if wall_ms else 0.0
    e2e_ms_t = wall_ms / g_n if g_n else 0.0
    acc_pct = (100.0 * d_acc / d_n) if d_n else 0.0
    txt = data["choices"][0]["message"]["content"].strip().replace("\n", " ")
    rows.append({
        "name": name, "prompt_n": p_n, "prompt_ms": round(p_ms, 1), "prompt_tps": round(p_tps, 3),
        "gen_n": g_n, "gen_ms": round(g_ms, 1), "gen_tps": round(g_tps, 3), "gen_ms_per_tok": round(g_ms_t, 1),
        "draft_n": d_n, "draft_acc": d_acc, "draft_acc_pct": round(acc_pct, 1),
        "wall_ms": round(wall_ms, 1), "e2e_tps": round(e2e_tps, 3), "e2e_ms_per_tok": round(e2e_ms_t, 1),
        "text": txt,
    })
    print(f"  {name}: p={p_n}t ({p_ms:.0f}ms, {p_tps:.2f}t/s) | "
          f"gen={g_n}t ({g_ms:.0f}ms, {g_tps:.3f} t/s, {g_ms_t:.0f}ms/t) | "
          f"draft={d_acc}/{d_n} ({acc_pct:.1f}%) | e2e={wall_ms:.0f}ms ({e2e_tps:.3f} t/s)", flush=True)

def stats(vals):
    return {"min": round(min(vals), 3), "median": round(statistics.median(vals), 3), "max": round(max(vals), 3)}

summary = {
    "tag": tag, "load_ms": load_ms, "requests": rows,
    "gen_tps": stats([r["gen_tps"] for r in rows]),
    "gen_ms_per_tok": stats([r["gen_ms_per_tok"] for r in rows]),
    "prompt_tps": stats([r["prompt_tps"] for r in rows]),
    "e2e_tps": stats([r["e2e_tps"] for r in rows]),
    "e2e_ms_per_tok": stats([r["e2e_ms_per_tok"] for r in rows]),
    "draft_acc_pct": stats([r["draft_acc_pct"] for r in rows]),
}
json.dump(summary, open(out_path, "w"), indent=2)
print(f"  ==> {tag} MEDIAN: Gen={summary['gen_tps']['median']:.3f} t/s ({summary['gen_tps']['min']:.3f}..{summary['gen_tps']['max']:.3f}) | "
      f"Prompt={summary['prompt_tps']['median']:.2f} t/s | E2E={summary['e2e_tps']['median']:.3f} t/s | "
      f"DraftAcc={summary['draft_acc_pct']['median']:.1f}%", flush=True)
PYEOF
    else
        curl -sf "http://127.0.0.1:${http_port}/v1/chat/completions" \
            -H "Content-Type: application/json" \
            -d '{"model":"qwen3-8b","messages":[{"role":"user","content":"Hi"}],"max_tokens":4,"temperature":0,"seed":42,"cache_prompt":false}' \
            >/dev/null
        echo "  Warmup complete."
    fi

    kill "$SRV_PID" 2>/dev/null || true; wait "$SRV_PID" 2>/dev/null || true; SRV_PID=""
    sleep 0.5
    stop_bridges

    if [ "$do_reqs" = "1" ]; then
        python3 - "$WORK" "$tag" <<'PYEOF'
import glob, re, sys
work, tag = sys.argv[1], sys.argv[2]
rpc = tx = rx = fec = retx = p99 = pipe = ahit = topk_s = sft1_s = zstd_s = dedup_s = 0
for fn in sorted(glob.glob(f"{work}/{tag}_n*_cli.log")):
    s = open(fn).read()
    lines = [l for l in s.splitlines() if "[sf-llama-bridge]" in l][-2:]
    part = "\n".join(lines)
    rpc  += sum(int(m) for m in re.findall(r"total_rpc=(\d+)", part))
    tx   += sum(int(m) for m in re.findall(r"tun_tx=(\d+)", part))
    rx   += sum(int(m) for m in re.findall(r"rx=(\d+)", part))
    fec  += sum(int(m) for m in re.findall(r"udp_fec=(\d+)", part))
    retx += sum(int(m) for m in re.findall(r"retx=(\d+)", part))
    p99  += sum(int(m) for m in re.findall(r"p99=(\d+)", part))
    pipe += sum(int(m) for m in re.findall(r"Pipe0RTT=(\d+)", part))
    ahit += sum(int(m) for m in re.findall(r"AllocHit=(\d+)", part))
    topk_s += sum(int(b)-int(a) for a,b in re.findall(r"TopK=\d+ \((\d+)/(\d+) B", part))
    sft1_s += sum(int(b)-int(a) for a,b in re.findall(r"SFT1=\d+ \((\d+)/(\d+) B", part))
    zstd_s += sum(int(b)-int(a) for a,b in re.findall(r"Zstd=\d+ \((\d+)/(\d+) B", part))
    dedup_s += sum(int(m) for m in re.findall(r"Dedup=\d+ \(-(\d+) B\)", part))
wire = tx + rx
sav = 100.0 * (1.0 - wire / rpc) if rpc > 0 else 0.0
print(f"  [6-Shard Wire] rpc={rpc/1e6:.2f}MB -> wire={wire/1e6:.2f}MB (-{sav:.1f}%) tx={tx/1e6:.2f} rx={rx/1e6:.2f} | "
      f"SFT1=-{sft1_s/1e6:.1f} TopK=-{topk_s/1e6:.1f} Zstd=-{zstd_s/1e6:.1f} Dedup=-{dedup_s/1e6:.1f} | "
      f"Pipe0RTT={pipe} AllocHit={ahit} fec={fec} retx={retx} p99={p99}")
PYEOF
    fi
}

# Warmup already cached in /mnt/samsung120/keryx-6node-qwen3 (run only if empty)
if [ ! -f "$WORK/c0_c/known_dnas.bin" ]; then
    run_case "0_warmup"              "warmup" 52700 0 0  0.00 0
fi
run_case "1_sfv4_bf16_spec10"    "bf16"   52701 1 10 0.15 1
run_case "2_sfv4_int8_spec10"    "int8"   52702 1 10 0.15 1
run_case "3_sfv4_int4o_spec12"   "int4o"  52703 1 12 0.10 1
run_case "4_sfv4_bf16_nodraft"   "bf16"   52704 0 0  0.00 1
run_case "5_stock_tcp_nodraft"   "stock"  52705 0 0  0.00 1

python3 - "$WORK" <<'PYEOF'
import json, sys
work = sys.argv[1]
base = json.load(open(f"{work}/5_stock_tcp_nodraft_results.json"))
cases = [
    ("Stock TCP (no draft)",          f"{work}/5_stock_tcp_nodraft_results.json"),
    ("SF v4 BF16  (no draft)",        f"{work}/4_sfv4_bf16_nodraft_results.json"),
    ("SF v4 BF16  + Draft 1.7B K=10", f"{work}/1_sfv4_bf16_spec10_results.json"),
    ("SF v4 INT8* + Draft 1.7B K=10", f"{work}/2_sfv4_int8_spec10_results.json"),
    ("SF v4 INT4o + Draft 1.7B K=12", f"{work}/3_sfv4_int4o_spec12_results.json"),
]
print("\n===================================================================================================================")
print("  R&D GRAND TABLE — 6 SHARDS / 6 COUNTRIES (570ms RTT sum, Qwen3-8B Q4_K_M + Qwen3-1.7B Draft, N=5 requests)")
print("===================================================================================================================")
print(f"  {'Configuration':<32} | {'Gen ALONE med (min..max)':<26} | {'vs Stock':<8} | {'Prompt med':<10} | {'E2E med':<9} | {'Exact':<5}")
print("  " + "-"*108)
for label, path in cases:
    d = json.load(open(path))
    g, p, e = d["gen_tps"], d["prompt_tps"], d["e2e_tps"]
    sp = g["median"] / base["gen_tps"]["median"]
    ex = sum(1 for a, b in zip(base["requests"], d["requests"]) if a["text"] == b["text"])
    print(f"  {label:<32} | {g['median']:5.3f} ({g['min']:.3f}..{g['max']:.3f}) t/s   | {sp:6.2f}x  | {p['median']:6.2f} t/s | {e['median']:5.3f} t/s | {ex}/{len(base['requests'])}")
PYEOF
