#!/usr/bin/env bash
set -euo pipefail
mkdir -p /results
echo "[run_benchmark] running benchmark..."
/app/build/benchmark
echo "[run_benchmark] generating plots..."
python3 /app/scripts/plot_results.py
echo "[run_benchmark] done. artifacts in /results/"
ls -la /results
