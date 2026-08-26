#!/usr/bin/env bash
# Runs the full benchmark pipeline end-to-end against the local classifier
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
# Phase 3 (bench-judge) is a local CWE-overlap heuristic, not an LLM/API call
# -- see pipeline/judge.py's module docstring for exactly how it works and
# its trade-offs versus the LLM judge this replaced.

set -euo pipefail

# Anchor to the repo root (this script's parent directory) regardless of
# where it's invoked from -- otherwise relative paths like "data/..." below
# resolve against the caller's current directory instead, e.g. running this
# from inside scripts/ silently looks for scripts/data/cvefixes.duckdb.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

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

echo "== Phase 3: judge against ground truth (local heuristic) =="
python -m vulnscan.cli bench-judge "${RUN_DIR}/diff.json" --dataset-db "${DATASET_DB}"

TOTAL_PAIRS=$(python -c "
from vulnscan.dataset.cvefixes_loader import get_pairs
print(len(get_pairs('${DATASET_DB}', language='python')))
")

echo "== Phase 4: metrics (total_pairs=${TOTAL_PAIRS}) =="
python -m vulnscan.cli bench-metrics \
    "${RUN_DIR}/diff.json" "${RUN_DIR}/judged.json" \
    --total-pairs "${TOTAL_PAIRS}" | tee "${RUN_DIR}/metrics.json"

# Append a one-line record to a running log, the same way sanity_check.py
# already keeps sanity_check_history.jsonl -- so "what was v15's recall
# again?" is a grep away instead of having to remember to check it and dig
# up the right data/experiments/<N>/metrics.json.
python -c "
import json, datetime
from vulnscan.config import settings

metrics = json.loads(open('${RUN_DIR}/metrics.json', encoding='utf-8').read())
entry = {
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'run_number': '${RUN_NUMBER}',
    # settings.local_model_checkpoint_dir reflects whatever this run
    # actually used, whether set via env var or .env (python-dotenv).
    'checkpoint_dir': settings.local_model_checkpoint_dir,
    'metrics': metrics,
}
with open('data/experiments/history.jsonl', 'a', encoding='utf-8') as f:
    f.write(json.dumps(entry) + '\n')
print(f\"Appended to data/experiments/history.jsonl ({settings.local_model_checkpoint_dir}, recall={metrics['recall']}, f1={metrics['f1']})\")
"