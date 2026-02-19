#!/usr/bin/env bash
# collect-metrics.sh — sample resource usage of tessera-node processes
# Usage: collect-metrics.sh <pid_file> <interval_s> <output_csv> <summary_json>
#
# Runs until killed (SIGTERM). On exit, writes JSON summary.
# CSV format: timestamp,pid,cpu_ticks,rss_kb,fds

set -euo pipefail

PID_FILE="$1"
INTERVAL="${2:-5}"
OUTPUT_CSV="$3"
SUMMARY_JSON="$4"

echo "timestamp,pid,cpu_ticks,rss_kb,fds" > "$OUTPUT_CSV"

cleanup() {
    # Generate summary from CSV
    if command -v jq &>/dev/null && [ -s "$OUTPUT_CSV" ]; then
        # Find peak RSS (sum across all nodes at any single timestamp)
        # Find peak FDs (sum across all nodes at any single timestamp)
        local peak_rss_kb peak_fds
        peak_rss_kb=$(tail -n +2 "$OUTPUT_CSV" | awk -F, '{ts[$1]+=$4} END {m=0; for(t in ts) if(ts[t]>m) m=ts[t]; print m}')
        peak_fds=$(tail -n +2 "$OUTPUT_CSV" | awk -F, '{ts[$1]+=$5} END {m=0; for(t in ts) if(ts[t]>m) m=ts[t]; print m}')
        local peak_rss_mb
        peak_rss_mb=$(awk "BEGIN {printf \"%.1f\", ${peak_rss_kb:-0} / 1024}")

        jq -n \
            --arg peak_rss "$peak_rss_mb" \
            --arg peak_fds "${peak_fds:-0}" \
            '{peak_rss_mb: ($peak_rss | tonumber), peak_fds: ($peak_fds | tonumber)}' \
            > "$SUMMARY_JSON"
    fi
    exit 0
}

trap cleanup SIGTERM SIGINT

while true; do
    ts=$(date +%s)
    while IFS= read -r pid; do
        [ -z "$pid" ] && continue
        # Check if process is alive
        if [ ! -d "/proc/$pid" ]; then
            continue
        fi
        # CPU ticks (utime + stime from /proc/pid/stat)
        cpu_ticks=$(awk '{print $14 + $15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
        # RSS in KB (VmRSS from /proc/pid/status)
        rss_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
        # File descriptors
        fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)

        echo "$ts,$pid,$cpu_ticks,$rss_kb,$fds" >> "$OUTPUT_CSV"
    done < "$PID_FILE"
    sleep "$INTERVAL"
done
