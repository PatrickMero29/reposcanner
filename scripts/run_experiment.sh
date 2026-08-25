#!/usr/bin/env bash
# Runs the benchmark pipeline end-to-end against the local classifier
# (see HANDOFF_2.md §6 for why this replaces small-sample sanity_check.py-
# style evaluation as the standard way to measure a training change).
#
# Usage:
#   ./scripts/run_experiment.sh 1
#
# Assumes the dataset has already been loaded (see README "Benchmark mode")
# and LOCAL_MODEL_CHECKPOINT_DIR points at the checkpoint you want to
# evaluate (env var, or set in .env).
#
# NOTE: Phase 3 (bench-judge) is not currently runnable -- it depends on a
# vulnscan.anthropic_client module that doesn't exist in this repo (leftover
# from before the project's "zero paid API" pivot, see HANDOFF.md §1). This
# script stops after Phase 2 until that's resolved; Phases 3-4 are left below,
# commented out, for whoever picks that decision up.

set -euo pipefail

RUN_NUMBER="${1:?Usage: run_experiment.sh <run_number>}"
DATASET_DB="${VULNSCAN_DATASET_DB:-data/cvefixes.duckdb}"
RUN_DIR="data/experiments/${RUN_NUMBER}"

mkdir -p "${RUN_DIR}"

echo "== Phase 1: analyze =="
python -m vulnscan.cli bench-analyze \
    --dataset-db "${DATASET_DB}" \
    --run-dir "${RUN_DIR}"

echo "== Phase 2: diff before/after =="
python -m vulnscan.cli bench-diff "${RUN_DIR}/analysis.json"

echo "Stopping here -- Phase 3 (bench-judge) needs the anthropic_client"
echo "decision above resolved first. vuln_only/shared/benign_only counts"
echo "are already usable on their own from ${RUN_DIR}/diff.json in the"
echo "meantime (e.g. benign_only count is a real large-sample false-positive"
echo "measurement without needing Phase 3 at all)."

# echo "== Phase 3: judge against ground truth =="
# python -m vulnscan.cli bench-judge "${RUN_DIR}/diff.json" --dataset-db "${DATASET_DB}"
#
# TOTAL_PAIRS=$(python -c "
# from vulnscan.dataset.cvefixes_loader import get_pairs
# print(len(get_pairs('${DATASET_DB}', language='python')))
# ")
#
# echo "== Phase 4: metrics (total_pairs=${TOTAL_PAIRS}) =="
# python -m vulnscan.cli bench-metrics \
#     "${RUN_DIR}/diff.json" "${RUN_DIR}/judged.json" \
#     --total-pairs "${TOTAL_PAIRS}" | tee "${RUN_DIR}/metrics.json"