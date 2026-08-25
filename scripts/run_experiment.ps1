<#
.SYNOPSIS
    Runs the full benchmark pipeline end-to-end against the local classifier.
    PowerShell equivalent of run_experiment.sh -- use this one on Windows;
    the .sh version assumes a Unix-y shell with `python` already on PATH,
    which an activated .venv doesn't guarantee inside bash/WSL/Git Bash.

.USAGE
    .\scripts\run_experiment.ps1 16

    Assumes the dataset has already been loaded (see README "Benchmark
    mode") and LOCAL_MODEL_CHECKPOINT_DIR points at the checkpoint you want
    to evaluate (env var, or set in .env).

    Phase 3 (bench-judge) is a local CWE-overlap heuristic, not an LLM/API
    call -- see pipeline/judge.py's module docstring for exactly how it
    works and its trade-offs.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$RunNumber
)

$ErrorActionPreference = "Stop"

$DatasetDb = if ($env:VULNSCAN_DATASET_DB) { $env:VULNSCAN_DATASET_DB } else { "data/cvefixes.duckdb" }
$RunDir = "data/experiments/$RunNumber"

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

Write-Host "== Phase 1: analyze =="
python -m vulnscan.cli bench-analyze --dataset-db $DatasetDb --run-dir $RunDir
if ($LASTEXITCODE -ne 0) { throw "Phase 1 (bench-analyze) failed" }

Write-Host "== Phase 2: diff before/after =="
python -m vulnscan.cli bench-diff "$RunDir/analysis.json"
if ($LASTEXITCODE -ne 0) { throw "Phase 2 (bench-diff) failed" }

Write-Host "== Phase 3: judge against ground truth (local heuristic) =="
python -m vulnscan.cli bench-judge "$RunDir/diff.json" --dataset-db $DatasetDb
if ($LASTEXITCODE -ne 0) { throw "Phase 3 (bench-judge) failed" }

$TotalPairs = python -c "from vulnscan.dataset.cvefixes_loader import get_pairs; print(len(get_pairs('$DatasetDb', language='python')))"
if ($LASTEXITCODE -ne 0) { throw "Failed to count total pairs" }

Write-Host "== Phase 4: metrics (total_pairs=$TotalPairs) =="
python -m vulnscan.cli bench-metrics "$RunDir/diff.json" "$RunDir/judged.json" --total-pairs $TotalPairs |
    Tee-Object -FilePath "$RunDir/metrics.json"
if ($LASTEXITCODE -ne 0) { throw "Phase 4 (bench-metrics) failed" }