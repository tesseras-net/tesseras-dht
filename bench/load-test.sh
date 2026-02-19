#!/usr/bin/env bash
# load-test.sh — orchestrate a tessera-dht load test
# Usage: load-test.sh [-n nodes] [-w workers] [-d duration] [-s sizes] [--warm] [--keep] [--separate-ips]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
NUM_NODES=20
NUM_WORKERS=10
DURATION=60
SIZES="1k,10k,100k"
POW_DIFFICULTY=16
WARM=false
KEEP=false
SEPARATE_IPS=false
BASE_PORT=14433

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n) NUM_NODES="$2"; shift 2 ;;
        -w) NUM_WORKERS="$2"; shift 2 ;;
        -d) DURATION="$2"; shift 2 ;;
        -s) SIZES="$2"; shift 2 ;;
        -p) POW_DIFFICULTY="$2"; shift 2 ;;
        --warm) WARM=true; shift ;;
        --keep) KEEP=true; shift ;;
        --separate-ips) SEPARATE_IPS=true; shift ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

# Derived paths
BINARY="$PROJECT_DIR/target/release/tessera-node"
RESULTS_DIR="$SCRIPT_DIR/results"
RUN_ID=$(date +%Y-%m-%d-%H-%M-%S)
RUN_DIR="$RESULTS_DIR/$RUN_ID"
mkdir -p "$RUN_DIR"

NODE_PIDS=()
METRICS_PID=""

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    # Stop metrics collector
    if [ -n "$METRICS_PID" ] && kill -0 "$METRICS_PID" 2>/dev/null; then
        kill -TERM "$METRICS_PID" 2>/dev/null
        wait "$METRICS_PID" 2>/dev/null || true
    fi

    # Stop nodes
    for pid in "${NODE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
        fi
    done

    # Wait up to 5s for graceful shutdown
    sleep 2
    for pid in "${NODE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null
        fi
    done

    # Remove loopback aliases
    if $SEPARATE_IPS; then
        for i in $(seq 2 "$NUM_NODES"); do
            sudo ip addr del "127.0.0.$i/8" dev lo 2>/dev/null || true
        done
    fi

    # Remove temp storage
    if ! $KEEP; then
        rm -rf /tmp/tessera-node-loadtest-*
    else
        echo "Keeping node data in /tmp/tessera-node-loadtest-*"
    fi

    echo "Cleanup complete."
}

trap cleanup EXIT

echo "=== tessera-dht Load Test ==="
echo "Nodes: $NUM_NODES | Workers: $NUM_WORKERS | Duration: ${DURATION}s | Sizes: $SIZES | PoW: $POW_DIFFICULTY"
echo "Run ID: $RUN_ID"
echo ""

# --- Phase 0: Build ---
echo "=== Phase 0: Building release binary ==="
(cd "$PROJECT_DIR" && cargo build --release --features cli 2>&1)
echo "Binary: $BINARY"
echo ""

# --- Phase 0.5: Setup loopback aliases ---
if $SEPARATE_IPS; then
    echo "=== Setting up loopback aliases (requires sudo) ==="
    for i in $(seq 2 "$NUM_NODES"); do
        sudo ip addr add "127.0.0.$i/8" dev lo 2>/dev/null || true
    done
    echo "Configured IPs: 127.0.0.1 through 127.0.0.$NUM_NODES"
    echo ""
fi

# --- Phase 1: Start nodes ---
echo "=== Phase 1: Starting $NUM_NODES nodes ==="

ip_for_node() {
    local idx=$1
    if $SEPARATE_IPS; then
        echo "127.0.0.$(( idx + 1 ))"
    else
        echo "127.0.0.1"
    fi
}

PID_FILE="$RUN_DIR/pids.txt"
: > "$PID_FILE"

for i in $(seq 0 $(( NUM_NODES - 1 ))); do
    port=$(( BASE_PORT + i ))
    ip=$(ip_for_node "$i")
    storage="/tmp/tessera-node-loadtest-${RUN_ID}-${i}"
    mkdir -p "$storage"

    if $WARM && [ ! -f "$storage/metadata.db" ]; then
        # Pre-generate identity
        "$BINARY" start --listen "${ip}:${port}" --storage "$storage" --pow-difficulty "$POW_DIFFICULTY" &
        warmup_pid=$!
        # Wait for "Listening on" line which means PoW is done
        sleep 10
        kill -TERM "$warmup_pid" 2>/dev/null
        wait "$warmup_pid" 2>/dev/null || true
        echo "  Warmed up node $i"
    fi

    bootstrap_args=""
    if [ "$i" -gt 0 ]; then
        seed_ip=$(ip_for_node 0)
        bootstrap_args="--bootstrap ${seed_ip}:${BASE_PORT}"
    fi

    TESSERA_RATE_LIMIT=10000 TESSERA_RATE_BURST=1000 TESSERA_CLIENT_TIMEOUT=1 TESSERA_WRITE_RATE=10000 TESSERA_WRITE_BURST=1000 \
    "$BINARY" start \
        --listen "${ip}:${port}" \
        --storage "$storage" \
        --pow-difficulty "$POW_DIFFICULTY" \
        $bootstrap_args \
        > "$RUN_DIR/node-${i}.log" 2>&1 &

    node_pid=$!
    NODE_PIDS+=("$node_pid")
    echo "$node_pid" >> "$PID_FILE"
    echo "  Node $i: PID=$node_pid addr=${ip}:${port}"

    # Stagger node starts to avoid bootstrap contention
    # (the actor blocks inbound requests while bootstrapping)
    if [ "$i" -gt 0 ]; then
        sleep 1
    fi
done

echo ""
echo "Waiting 3s for final bootstrap convergence..."
sleep 3
echo ""

# Verify nodes are still alive
alive=0
for pid in "${NODE_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
        alive=$(( alive + 1 ))
    fi
done
echo "Nodes alive: $alive / $NUM_NODES"
if [ "$alive" -eq 0 ]; then
    echo "ERROR: No nodes survived startup. Check logs in $RUN_DIR/"
    exit 1
fi
echo ""

# --- Phase 2: Start metrics collector ---
echo "=== Phase 2: Starting metrics collector ==="
"$SCRIPT_DIR/collect-metrics.sh" \
    "$PID_FILE" 5 \
    "$RUN_DIR/metrics.csv" \
    "$RUN_DIR/resources.json" &
METRICS_PID=$!
echo "Metrics collector PID: $METRICS_PID"
echo ""

# --- Phase 3: Generate load ---
echo "=== Phase 3: Generating load (${DURATION}s, $NUM_WORKERS workers) ==="

WORKER_PIDS=()
for w in $(seq 1 "$NUM_WORKERS"); do
    "$SCRIPT_DIR/gen-load.sh" \
        "$BINARY" "$BASE_PORT" "$NUM_NODES" "$DURATION" "$SIZES" "$w" "$RUN_DIR" "$POW_DIFFICULTY" &
    WORKER_PIDS+=($!)
done

# Wait for all workers to finish
for wpid in "${WORKER_PIDS[@]}"; do
    wait "$wpid" 2>/dev/null || true
done
echo ""
echo "All workers finished."
echo ""

# --- Phase 4: Aggregate report ---
echo "=== Phase 4: Generating report ==="

# Stop metrics collector to flush summary
if kill -0 "$METRICS_PID" 2>/dev/null; then
    kill -TERM "$METRICS_PID" 2>/dev/null
    wait "$METRICS_PID" 2>/dev/null || true
fi
METRICS_PID=""

# Aggregate worker CSVs into final report
REPORT="$RUN_DIR/report.json"

python3 -c "
import csv, json, os, sys, statistics

run_dir = sys.argv[1]
config = {
    'nodes': int(sys.argv[2]),
    'workers': int(sys.argv[3]),
    'duration_s': int(sys.argv[4]),
}

store_latencies = []
get_latencies = []
store_errors = 0
get_errors = 0
checksum_ok = 0
checksum_fail = 0

for f in sorted(os.listdir(run_dir)):
    if not f.startswith('worker-') or not f.endswith('.csv'):
        continue
    with open(os.path.join(run_dir, f)) as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            dur = int(row['duration_ms'])
            ec = int(row['exit_code'])
            if row['op'] == 'store':
                if ec == 0:
                    store_latencies.append(dur)
                else:
                    store_errors += 1
            elif row['op'] == 'get':
                if ec == 0:
                    get_latencies.append(dur)
                    if row.get('checksum_ok') == 'true':
                        checksum_ok += 1
                    elif row.get('checksum_ok') == 'false':
                        checksum_fail += 1
                else:
                    get_errors += 1

def percentiles(data):
    if not data:
        return {'p50': 0, 'p95': 0, 'p99': 0}
    s = sorted(data)
    n = len(s)
    return {
        'p50': s[int(n * 0.50)],
        'p95': s[int(n * 0.95)] if n > 1 else s[-1],
        'p99': s[int(n * 0.99)] if n > 1 else s[-1],
    }

total_store = len(store_latencies) + store_errors
total_get = len(get_latencies) + get_errors

report = {
    'config': config,
    'store': {
        'total_ops': total_store,
        'successful_ops': len(store_latencies),
        'ops_per_sec': round(len(store_latencies) / config['duration_s'], 2) if config['duration_s'] > 0 else 0,
        'latency_ms': percentiles(store_latencies),
        'errors': store_errors,
        'error_rate': round(store_errors / total_store, 4) if total_store > 0 else 0,
    },
    'get': {
        'total_ops': total_get,
        'successful_ops': len(get_latencies),
        'ops_per_sec': round(len(get_latencies) / config['duration_s'], 2) if config['duration_s'] > 0 else 0,
        'latency_ms': percentiles(get_latencies),
        'errors': get_errors,
        'error_rate': round(get_errors / total_get, 4) if total_get > 0 else 0,
        'checksum_ok': checksum_ok,
        'checksum_fail': checksum_fail,
    },
}

# Merge resource metrics if available
res_file = os.path.join(run_dir, 'resources.json')
if os.path.exists(res_file):
    with open(res_file) as rf:
        report['resources'] = json.load(rf)

with open(os.path.join(run_dir, 'report.json'), 'w') as out:
    json.dump(report, out, indent=2)

print(json.dumps(report, indent=2))
" "$RUN_DIR" "$NUM_NODES" "$NUM_WORKERS" "$DURATION"

echo ""
echo "Report saved to: $REPORT"
echo "Full results in: $RUN_DIR/"
