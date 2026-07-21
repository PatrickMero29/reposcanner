#!/usr/bin/env bash
# Runs one full benchmark experiment end-to-end for a given justification level.
#
# Usage:
#   ./scripts/run_experiment.sh extensive_justification 1
#
# Assumes the dataset has already been loaded (see README "Benchmark mode"),
# and GEMINI_API_KEY is set (directly or via .env).

set -euo pipefail

LEVEL="${1:?Usage: run_experiment.sh <level> <run_number>  (level: no_justification|limited_justification|extensive_justification|verification_agent)}"
RUN_NUMBER="${2:?Usage: run_experiment.sh <level> <run_number>}"
DATASET_DB="${VULNSCAN_DATASET_DB:-data/cvefixes.duckdb}"
RUN_DIR="data/experiments/${LEVEL}/runs/${RUN_NUMBER}"

mkdir -p "${RUN_DIR}"

echo "== Phase 1: analyze (level=${LEVEL}) =="
python -m vulnscan.cli bench-analyze \
    --dataset-db "${DATASET_DB}" \
    --level "${LEVEL}" \
    --run-dir "${RUN_DIR}"

echo "== Phase 2: diff before/after =="
python -m vulnscan.cli bench-diff "${RUN_DIR}/analysis.json"

echo "== Phase 3: judge against ground truth =="
python -m vulnscan.cli bench-judge "${RUN_DIR}/diff.json" --dataset-db "${DATASET_DB}"

TOTAL_PAIRS=$(python -c "
from vulnscan.dataset.cvefixes_loader import get_pairs
print(len(get_pairs('${DATASET_DB}', language='python')))
")

echo "== Phase 4: metrics (total_pairs=${TOTAL_PAIRS}) =="
python -m vulnscan.cli bench-metrics \
    "${RUN_DIR}/diff.json" "${RUN_DIR}/judged.json" \
    --total-pairs "${TOTAL_PAIRS}" | tee "${RUN_DIR}/metrics.json"
