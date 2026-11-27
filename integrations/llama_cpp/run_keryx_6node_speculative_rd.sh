#!/usr/bin/env bash
set -euo pipefail

# ======================================================================================
# R&D Benchmark: Pushing 6-Shard / 6-Country Split-Model Inference to 3-4+ tok/s!
# ======================================================================================
# Reuses the exact 6-country profile (DE 28ms, UK 42ms, PL 55ms, NY 105ms, CA 155ms,
# SG 185ms + P99 +200ms@6%, cumulative RTT = 570ms) and exact N=5 requests on
# Qwen3.5-9B Q5_K_M (6.1 GB) + local coordinator draft Qwen3.5-0.8B Q4_K_M (508 MB).
#
# Compares:
#   A) SealFrame v3 (INT4+Outlier, Top-64 batched, RESP_ZSTD, ZERO) + Draft 0.8B (K=8, p=0.15)
#   B) SealFrame v3 (INT8 high-fidelity)                            + Draft 0.8B (K=8, p=0.15)
#   C) SealFrame v3 (INT8 high-fidelity)                            + Draft 0.8B (K=12, p=0.10)
#   D) Stock raw ggml-rpc TCP                                       + Draft 0.8B (K=8, p=0.15)
# ======================================================================================

SF_DIR="${SF_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
LLAMA_BIN="${LLAMA_BIN:-./llama.cpp/build/bin}"
MODEL="${MODEL:-./models/Qwen3.5-9B.gguf}"
DRAFT="${DRAFT:-./models/Qwen3.5-0.8B-Q4_K_M.gguf}"
WORK="${WORK:-/tmp/sf-keryx-6node-spec}"

BRIDGE="$SF_DIR/bin/sf-llama-bridge"
RPC_SRV="$LLAMA_BIN/ggml-rpc-server"
LLAMA_SRV="$LLAMA_BIN/llama-server"

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

HOME="$WORK/rpc0" "$RPC_SRV" -d CUDA0 -H 127.0.0.1 -p 52000 -c >"$WORK/rd_rpc0.log" 2>&1 & PIDS+=($!)
for i in 1 2 3 4 5; do
    port=$((52000 + i))
    HOME="$WORK/rpc$i" "$RPC_SRV" -d CPU -t 2 -H 127.0.0.1 -p "$port" -c >"$WORK/rd_rpc${i}.log" 2>&1 & PIDS+=($!)
done
for i in 0 1 2 3 4 5; do
    port=$((52000 + i))
    for _ in $(seq 1 40); do ss -ltn | grep -q ":${port} " && break; sleep 0.25; done
done
echo "6 REAL ggml-rpc-server workers ready (reusing persistent disk + DNA caches)"

PROFILES=(
    "0 DE 52100 52200 52000  28  6   0 0 20 80 1 0.5"
    "1 UK 52101 52201 52001  42  8   0 0 15 60 1 0.8"
    "2 PL 52102 52202 52002  55 12   0 0 12 50 1 1.0"
    "3 NY 52103 52203 52003 105 18   0 0 15 60 1 1.2"
    "4 CA 52104 52204 52004 155 22   0 0 10 40 2 1.5"
    "5 SG 52105 52205 52005 185 25 200 6  8 30 2 2.0"
)

launch_bridges() {
    local mode="$1" # stock | int4o | int8
    local tag="$2"
    BR_PIDS=()
    for line in "${PROFILES[@]}"; do
        read -r idx cc lp tp bp rtt jit p99 p99p ul dl udrp tcpl <<< "$line"
        local tr="udp" cast="$mode" fec="auto" topk="64" zf=() cf_s=() cf_c=() drp_arg="$udrp" tcpl_arg="0"
        if [ "$mode" = "stock" ]; then
            tr="tcp"; cast="raw"; fec="off"; topk="0"; zf=(--no-zstd); drp_arg="0"; tcpl_arg="$tcpl"
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
            --wan-rtt-ms "$rtt" --wan-jitter-ms "$jit" \
            --wan-p99-ms "$p99" --wan-p99-pct "$p99p" \
            --wan-ul-mbps "$ul" --wan-dl-mbps "$dl" \
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

run_case() {
    local tag="$1"
    local mode="$2"
    local http_port="$3"
    local d_max="$4"
    local d_pmin="$5"

    echo ""
    echo "==========================================================================================="
    echo "  R&D 6-SHARD / 6-COUNTRY: $tag (mode=$mode, draft=Qwen3.5-0.8B n_max=$d_max p_min=$d_pmin)"
    echo "==========================================================================================="

    launch_bridges "$mode" "$tag"

    local t0 t1 load_ms
    t0=$(date +%s%3N)
    "$LLAMA_SRV" -m "$MODEL" \
        --rpc 127.0.0.1:52100,127.0.0.1:52101,127.0.0.1:52102,127.0.0.1:52103,127.0.0.1:52104,127.0.0.1:52105 \
        --device RPC0,RPC1,RPC2,RPC3,RPC4,RPC5 \
        --tensor-split 1,1,1,1,1,1 -ngl 32 \
        --spec-type draft-simple \
        --spec-draft-model "$DRAFT" \
        --spec-draft-device CUDA0 --spec-draft-ngl 99 \
        --spec-draft-n-max "$d_max" --spec-draft-n-min 1 --spec-draft-p-min "$d_pmin" \
        -c 1024 -np 1 --reasoning off --no-webui \
        --host 127.0.0.1 --port "$http_port" \
        >"$WORK/${tag}_server.log" 2>&1 &
    SRV_PID=$!

    local ready=0
    for _ in $(seq 1 600); do
        if ! kill -0 "$SRV_PID" 2>/dev/null; then
            echo "ERROR: llama-server exited early! Tail:"
            tail -n 40 "$WORK/${tag}_server.log"
            exit 1
        fi
        if curl -sf "http://127.0.0.1:${http_port}/health" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 0.5
    done
    if [ "$ready" -ne 1 ]; then
        echo "ERROR: timed out waiting for /health"
        tail -n 40 "$WORK/${tag}_server.log"
        exit 1
    fi
    t1=$(date +%s%3N)
    load_ms=$((t1 - t0))
    echo "  [Model+Draft Load] ${load_ms} ms ($(awk "BEGIN{printf \"%.2f\", $load_ms/1000}") s)"

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
    d_n = int(tim.get("draft_n", 0))
    d_acc = int(tim.get("draft_n_accepted", 0))
    g_ms_tok = (g_ms / g_n) if g_n > 0 else 0.0
    e2e_ms_tok = (wall_ms / g_n) if g_n > 0 else 0.0
    e2e_tps = (g_n / (wall_ms / 1000.0)) if wall_ms > 0 else 0.0
    acc_pct = (100.0 * d_acc / d_n) if d_n > 0 else 0.0
    txt = data["choices"][0]["message"]["content"].strip().replace("\n", " ")

    row = {
        "name": name, "prompt_n": p_n, "prompt_ms": round(p_ms, 1), "prompt_tps": round(p_tps, 3),
        "gen_n": g_n, "gen_ms": round(g_ms, 1), "gen_tps": round(g_tps, 3), "gen_ms_per_tok": round(g_ms_tok, 1),
        "draft_n": d_n, "draft_acc": d_acc, "draft_acc_pct": round(acc_pct, 1),
        "wall_ms": round(wall_ms, 1), "e2e_tps": round(e2e_tps, 3), "e2e_ms_per_tok": round(e2e_ms_tok, 1),
        "text": txt,
    }
    rows.append(row)
    print(f"  {name}: p={p_n}t ({p_ms:.0f}ms, {p_tps:.2f}t/s) | "
          f"gen={g_n}t ({g_ms:.0f}ms, {g_tps:.3f} t/s, {g_ms_tok:.0f}ms/t) | "
          f"draft={d_acc}/{d_n} ({acc_pct:.1f}%) | "
          f"e2e={wall_ms:.0f}ms ({e2e_tps:.3f} t/s)", flush=True)

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
with open(out_path, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n  === {tag} SUMMARY (N={len(rows)}) ===", flush=True)
print(f"  Generation ALONE (t/s):  min={summary['gen_tps']['min']:.3f} / median={summary['gen_tps']['median']:.3f} / max={summary['gen_tps']['max']:.3f}", flush=True)
print(f"  Generation ms/tok:       min={summary['gen_ms_per_tok']['min']:.0f} / median={summary['gen_ms_per_tok']['median']:.0f} / max={summary['gen_ms_per_tok']['max']:.0f}", flush=True)
print(f"  Draft acceptance (%):    min={summary['draft_acc_pct']['min']:.1f}% / median={summary['draft_acc_pct']['median']:.1f}% / max={summary['draft_acc_pct']['max']:.1f}%", flush=True)
print(f"  End-to-End req (t/s):    min={summary['e2e_tps']['min']:.3f} / median={summary['e2e_tps']['median']:.3f} / max={summary['e2e_tps']['max']:.3f}", flush=True)
PYEOF

    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
    sleep 0.5
    stop_bridges

    python3 - "$WORK" "$tag" <<'PYEOF'
import glob, re, sys
work, tag = sys.argv[1], sys.argv[2]
rpc = tx = rx = fec = retx = p99 = topk_s = sft1_s = zstd_s = dedup_s = 0
for fn in sorted(glob.glob(f"{work}/{tag}_n*_cli.log")):
    s = open(fn).read()
    lines = [l for l in s.splitlines() if "[sf-llama-bridge]" in l][-2:]
    part = "\n".join(lines)
    rpc += sum(int(m) for m in re.findall(r"total_rpc=(\d+)", part))
    tx  += sum(int(m) for m in re.findall(r"tun_tx=(\d+)", part))
    rx  += sum(int(m) for m in re.findall(r"rx=(\d+)", part))
    fec += sum(int(m) for m in re.findall(r"udp_fec=(\d+)", part))
    retx+= sum(int(m) for m in re.findall(r"retx=(\d+)", part))
    p99 += sum(int(m) for m in re.findall(r"p99=(\d+)", part))
    topk_s += sum(int(b)-int(a) for a,b in re.findall(r"TopK=\d+ \((\d+)/(\d+) B", part))
    sft1_s += sum(int(b)-int(a) for a,b in re.findall(r"SFT1=\d+ \((\d+)/(\d+) B", part))
    zstd_s += sum(int(b)-int(a) for a,b in re.findall(r"Zstd=\d+ \((\d+)/(\d+) B", part))
    dedup_s += sum(int(m) for m in re.findall(r"Dedup=\d+ \(-(\d+) B\)", part))
wire = tx + rx
sav = 100.0 * (1.0 - wire / rpc) if rpc > 0 else 0.0
print(f"  [6-Shard Wire] total_rpc={rpc/1e6:.2f} MB | wire={wire/1e6:.2f} MB (tx={tx/1e6:.2f} rx={rx/1e6:.2f}) | saving={sav:.1f}% | "
      f"SFT1=-{sft1_s/1e6:.1f}MB TopK=-{topk_s/1e6:.1f}MB Zstd=-{zstd_s/1e6:.1f}MB Dedup/Zero=-{dedup_s/1e6:.1f}MB | fec={fec} retx={retx} p99={p99}")
PYEOF
}

run_case "rd_A_sfv3_int4o_spec8" "int4o" 52310 8  0.15
run_case "rd_B_sfv3_int8_spec8"  "int8"  52311 8  0.15
run_case "rd_C_sfv3_int8_spec12" "int8"  52312 12 0.10
run_case "rd_D_stock_tcp_spec8"  "stock" 52313 8  0.15

python3 - "$WORK" <<'PYEOF'
import json, sys
work = sys.argv[1]
base = json.load(open(f"{work}/2_stock_tcp_6country_results.json"))
cases = [
    ("Stock TCP (no draft)",  f"{work}/2_stock_tcp_6country_results.json"),
    ("SF v2 (no draft)",      f"{work}/1_sealframe_6country_results.json"),
    ("Stock TCP + Draft K=8", f"{work}/rd_D_stock_tcp_spec8_results.json"),
    ("SF v3 INT4o + Draft K=8", f"{work}/rd_A_sfv3_int4o_spec8_results.json"),
    ("SF v3 INT8  + Draft K=8", f"{work}/rd_B_sfv3_int8_spec8_results.json"),
    ("SF v3 INT8  + Draft K=12",f"{work}/rd_C_sfv3_int8_spec12_results.json"),
]
print("\n==========================================================================================================")
print("  R&D GRAND COMPARISON — 6 SHARDS / 6 COUNTRIES (570ms RTT sum, Qwen3.5-9B Q5_K_M, N=5 requests)")
print("==========================================================================================================")
print(f"  {'Configuration':<28} | {'Gen med (min..max)':<24} | {'Speedup':<8} | {'E2E med':<9} | {'Exact vs Stock':<14}")
print("  " + "-"*98)
for label, path in cases:
    d = json.load(open(path))
    g = d["gen_tps"]
    e = d["e2e_tps"]
    sp = g["median"] / base["gen_tps"]["median"]
    ex = sum(1 for a, b in zip(base["requests"], d["requests"]) if a["text"] == b["text"])
    print(f"  {label:<28} | {g['median']:5.3f} ({g['min']:.3f}..{g['max']:.3f}) t/s | {sp:6.2f}x  | {e['median']:5.3f} t/s | {ex}/{len(base['requests'])}")
PYEOF
