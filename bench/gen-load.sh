#!/usr/bin/env bash
# gen-load.sh — single load worker: store + get in a loop
# Usage: gen-load.sh <binary> <base_port> <num_nodes> <duration_s> <sizes_csv> <worker_id> <output_dir> [pow_difficulty]

set -euo pipefail

BINARY="$1"
BASE_PORT="$2"
NUM_NODES="$3"
DURATION="$4"
SIZES_CSV="$5"
WORKER_ID="$6"
OUTPUT_DIR="$7"
POW_DIFFICULTY="${8:-16}"

# Per-operation timeout (seconds) — prevents workers from hanging forever
OP_TIMEOUT=15

IFS=',' read -ra SIZES <<< "$SIZES_CSV"
LOG="$OUTPUT_DIR/worker-${WORKER_ID}.csv"
echo "op,timestamp,duration_ms,size_bytes,exit_code,checksum_ok" > "$LOG"

TMPDIR=$(mktemp -d "/tmp/loadgen-worker-${WORKER_ID}-XXXX")
trap 'rm -rf "$TMPDIR"' EXIT

END_TIME=$(( $(date +%s) + DURATION ))

op_count=0
while [ "$(date +%s)" -lt "$END_TIME" ]; do
    # Pick random node port and file size
    port=$(( BASE_PORT + (RANDOM % NUM_NODES) ))
    size_label=${SIZES[ RANDOM % ${#SIZES[@]} ]}
    # Parse size label to bytes
    case "$size_label" in
        1k|1K)     size_bytes=1024 ;;
        10k|10K)   size_bytes=10240 ;;
        100k|100K) size_bytes=102400 ;;
        1m|1M)     size_bytes=1048576 ;;
        *)         size_bytes=1024 ;;
    esac

    # Generate random file
    input_file="$TMPDIR/input-${op_count}"
    dd if=/dev/urandom of="$input_file" bs="$size_bytes" count=1 status=none 2>/dev/null

    input_checksum=$(sha256sum "$input_file" | awk '{print $1}')

    # --- STORE ---
    ts_start=$(date +%s%3N)
    store_output=$(TESSERA_CLIENT_TIMEOUT=1 TESSERA_RATE_LIMIT=10000 TESSERA_RATE_BURST=1000 \
        timeout "$OP_TIMEOUT" "$BINARY" store --connect "127.0.0.1:${port}" --file "$input_file" --pow-difficulty "$POW_DIFFICULTY" 2>/dev/null) && store_exit=0 || store_exit=$?
    ts_end=$(date +%s%3N)
    store_duration=$(( ts_end - ts_start ))
    echo "store,$ts_start,$store_duration,$size_bytes,$store_exit," >> "$LOG"

    if [ "$store_exit" -ne 0 ]; then
        op_count=$(( op_count + 1 ))
        rm -f "$input_file"
        continue
    fi

    # Parse store output for retrieval metadata (stdout only, stderr discarded above)
    hashes=$(echo "$store_output" | grep -oP '(?<=--hashes )\S+' || echo "")
    data_shards=$(echo "$store_output" | grep -oP '(?<=--data-shards )\S+' || echo "")
    parity_shards=$(echo "$store_output" | grep -oP '(?<=--parity-shards )\S+' || echo "")
    original_len=$(echo "$store_output" | grep -oP '(?<=--original-len )\S+' || echo "")

    if [ -z "$hashes" ] || [ -z "$data_shards" ] || [ -z "$parity_shards" ] || [ -z "$original_len" ]; then
        op_count=$(( op_count + 1 ))
        rm -f "$input_file"
        continue
    fi

    # --- GET ---
    output_file="$TMPDIR/output-${op_count}"
    # Pick a potentially different node for get
    get_port=$(( BASE_PORT + (RANDOM % NUM_NODES) ))
    ts_start=$(date +%s%3N)
    TESSERA_CLIENT_TIMEOUT=1 TESSERA_RATE_LIMIT=10000 TESSERA_RATE_BURST=1000 \
    timeout "$OP_TIMEOUT" "$BINARY" get \
        --connect "127.0.0.1:${get_port}" \
        --hashes "$hashes" \
        --data-shards "$data_shards" \
        --parity-shards "$parity_shards" \
        --original-len "$original_len" \
        --output "$output_file" \
        --pow-difficulty "$POW_DIFFICULTY" 2>/dev/null && get_exit=0 || get_exit=$?
    ts_end=$(date +%s%3N)
    get_duration=$(( ts_end - ts_start ))

    checksum_ok=""
    if [ "$get_exit" -eq 0 ] && [ -f "$output_file" ]; then
        output_checksum=$(sha256sum "$output_file" | awk '{print $1}')
        if [ "$input_checksum" = "$output_checksum" ]; then
            checksum_ok="true"
        else
            checksum_ok="false"
        fi
    fi

    echo "get,$ts_start,$get_duration,$size_bytes,$get_exit,$checksum_ok" >> "$LOG"

    rm -f "$input_file" "$output_file"
    op_count=$(( op_count + 1 ))
done

echo "Worker $WORKER_ID completed $op_count operations"
