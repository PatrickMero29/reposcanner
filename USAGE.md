# vulnscan: Usage and Functionality Guide

`vulnscan` is a fully local vulnerability scanner for **Python** code. It combines a Semgrep static-analysis pre-filter with a self-trained CodeBERT classifier, then annotates results with similar historical CVEs. No LLM or paid API is called anywhere in the scan path.

This guide covers installing, configuring and running a scan, reading the output, and using the dataset, training and benchmark commands. See `README.md` for design rationale and `architecture.txt` for the longer-term vision.

---

## Contents

1. [How a scan works](#1-how-a-scan-works)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
4. [Scanning a local repo](#4-scanning-a-local-repo)
5. [Reading the report](#5-reading-the-report)
6. [Using it from Python](#6-using-it-from-python)
7. [Optional components](#7-optional-components)
8. [Building a dataset and training a model](#8-building-a-dataset-and-training-a-model)
9. [Benchmark pipeline](#9-benchmark-pipeline)
10. [Module reference](#10-module-reference)
11. [Behavior matrix and graceful degradation](#11-behavior-matrix-and-graceful-degradation)
12. [Known limitations and issues](#12-known-limitations-and-issues)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. How a scan works

```
Repository
   │
   ▼
discover_files            .py files only; skips venvs, build dirs, test files
   │
   ▼
Semgrep pre-filter        p/security-audit + semgrep_rules/supplementary_rules.yaml
   │
   ▼
chunk_source_file         one chunk per function/method (stdlib `ast`)
   │
   ▼
Local classifier          CodeBERT, sliding 512-token windows, P(vulnerable) = max
   │
   ▼
CVE enrichment            nearest historical CVEs from a local embedding index
   │
   ▼
Report                    static_findings + ai_findings → JSON and/or Markdown
```

Which functions reach the classifier depends on the Semgrep outcome:

| Semgrep outcome | What the classifier sees | Threshold |
|---|---|---|
| Ran (exit 0 or 1) with findings | Only functions whose line range overlaps a finding | Checkpoint threshold |
| Ran with **zero** findings | Nothing; the repo is treated as clean | n/a |
| Not installed, timed out, or errored | **Every** function (fail open) | `max(checkpoint threshold, 0.7)` |
| `--no-semgrep` | Every function | `max(checkpoint threshold, 0.7)` |

---

## 2. Installation

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

Install extras depending on what you want to use:

| Extra | Command | Enables |
|---|---|---|
| `semgrep` | `pip install -e ".[semgrep]"` | The static pre-filter (or put a system `semgrep` on `PATH`) |
| `ml` | `pip install -e ".[ml]"` | Classifier inference and training (torch, transformers) |
| `embeddings` | `pip install -e ".[embeddings]"` | CVE-similarity retrieval (sentence-transformers, numpy) |

Everything at once:

```bash
pip install -e ".[dev,semgrep,ml,embeddings]"
```

Verify the install:

```bash
pytest
```

> **Note:** the tests import `numpy`. If `pytest` fails at collection with `ModuleNotFoundError: No module named 'numpy'`, install the `embeddings` or `ml` extra (or `pip install numpy`) first. With numpy present, the suite is 92 tests.

No API key is needed for any part of the project.

---

## 3. Configuration

Settings are read from environment variables, and a `.env` file in the working directory is loaded automatically (`python-dotenv`). Copy `.env.example` to `.env` to start.

| Variable | Default | Purpose |
|---|---|---|
| `LOCAL_MODEL_CHECKPOINT_DIR` | `models/vuln-classifier-v20` | Which trained classifier to load. **Set this explicitly** (see below). |
| `LOCAL_MODEL_BASE` | `microsoft/codebert-base` | Base model name |
| `LOCAL_MODEL_DEVICE` | `auto` | `auto` picks CUDA if available, else CPU. Or set `cpu` / `cuda`. |
| `LOCAL_MODEL_MAX_LENGTH` | `512` | Token window size |
| `LOCAL_MODEL_CONFIDENCE_THRESHOLD` | `0.5` | Used only if the checkpoint has no `threshold.json` |
| `LOCAL_MODEL_FAILOPEN_CONFIDENCE_THRESHOLD` | `0.7` | Floor applied when the pre-filter is off or broken |
| `ENABLE_SEMGREP_PREFILTER` | `true` | Master switch for the Semgrep stage |
| `SEMGREP_CONFIG` | `p/security-audit,<repo>/semgrep_rules/supplementary_rules.yaml` | Comma-separated rulesets |
| `SEMGREP_TIMEOUT` | `300` | Seconds before Semgrep is abandoned (then fail open) |
| `ENABLE_RETRIEVAL` | `true` | Toggle CVE-similarity enrichment |
| `EMBEDDING_MODEL` | `flax-sentence-embeddings/st-codesearch-distilroberta-base` | Sentence-embedding model |
| `EMBEDDING_INDEX_DIR` | `data/cve_index` | Where the CVE index lives |
| `RETRIEVAL_TOP_K` | `5` | Number of similar CVEs to attach |
| `VULNSCAN_MAX_CONCURRENCY` | `4` | Concurrency for scan and benchmark runs |
| `VULNSCAN_DATASET_DB` | `data/cvefixes.duckdb` | Default dataset for benchmark commands |
| `VULNSCAN_OUTPUT_DIR` | `data/experiments` | Benchmark output root |

### Choose a checkpoint

The repo ships several checkpoint directories under `models/` (v18 to v22, plus `v22u`, which uses UniXcoder). `.env.example` and the project's phase notes point at **`models/vuln-classifier-v22`**, but `config.py` defaults to v20, which has no `threshold.json`. Set it explicitly:

```bash
# .env
LOCAL_MODEL_CHECKPOINT_DIR=/absolute/path/to/reposcanner/models/vuln-classifier-v22
```

Use an absolute path. A relative path is resolved against the **current working directory**, so running `vulnscan` from another folder will report "No trained model found".

Weight files (`*.safetensors`, `*.bin`, `*.pt`) are in `.gitignore`. A fresh clone contains only each checkpoint's config, tokenizer, threshold and run metadata. You must supply or train the weights before the classifier stage can run.

### Threshold selection

The operating threshold is read from the checkpoint's `threshold.json` (0.75 for v22), picked on the validation split at training time. You don't tune it at scan time. In fail-open mode the threshold is raised to at least `LOCAL_MODEL_FAILOPEN_CONFIDENCE_THRESHOLD` but never lowered below the frozen one.

---

## 4. Scanning a local repo

### Basic scan

```bash
vulnscan scan /path/to/repo
```

This writes `scan_report.json` and `scan_report.md` in the current directory and prints a one-line summary:

```
Found 3 static finding(s), 2 local-model finding(s).
```

### Options

| Flag | Default | Description |
|---|---|---|
| `repo_path` | required | Directory to scan |
| `--out NAME` | `scan_report` | Output basename; `.json` / `.md` is appended |
| `--format {json,markdown,both}` | `both` | Which report files to write |
| `--no-semgrep` | off | Skip the pre-filter and classify every function |
| `--semgrep-config RULESET` | `p/security-audit` + supplementary rules | Repeatable, or comma-separated |

### Examples

```bash
# JSON only, custom name
vulnscan scan ~/code/myapp --out reports/myapp --format json

# Classify every function, ignoring Semgrep
vulnscan scan ~/code/myapp --no-semgrep

# Combine multiple Semgrep rulesets
vulnscan scan ~/code/myapp \
  --semgrep-config p/security-audit \
  --semgrep-config p/secrets

# Same thing as one comma-separated value
vulnscan scan ~/code/myapp --semgrep-config p/security-audit,p/secrets

# Module form (equivalent entry point)
python -m vulnscan.scanner.scan_repo ~/code/myapp --out report
```

> Passing `--semgrep-config` **replaces** the default config, which includes the supplementary rules. To keep them, add the file explicitly: `--semgrep-config p/security-audit --semgrep-config semgrep_rules/supplementary_rules.yaml`.

Semgrep runs with `--metrics=off`, so nothing is sent to Semgrep's servers. Registry rulesets such as `p/security-audit` are still downloaded on first use, so Semgrep needs network access for that.

### What gets scanned

- **Included:** files ending in `.py`.
- **Excluded directories** (matched against every component of the path): `.git`, `.venv`, `venv`, `__pycache__`, `node_modules`, `build`, `dist`, `.mypy_cache`, `.pytest_cache`, `.tox`, `site-packages`, `egg-info`.
- **Excluded test files:** anything under `tests/`, `test/`, `e2e/`, `specs/`, `fixtures/`, `cypress/`, plus `test_*.py`, `*_test.py`, `conftest.py` and `*_spec.py`.
- **Excluded functions:** stubs whose bodies are only `pass`, a docstring or `...`.
- **Unparseable files:** files with syntax errors are skipped silently.
- **Nested functions:** closures are scanned as part of their enclosing function, not separately.

### Per-function scoring

For each chunk the classifier tokenizes the whole function and scores it in sliding windows of up to 512 tokens (stride 256). If Semgrep flagged a line inside the function, an extra window is centered on that line. The function's score is the **maximum** over windows. If it meets the threshold, one finding is emitted.

Severity is derived from confidence alone:

| Confidence | Severity |
|---|---|
| ≥ 0.90 | high |
| ≥ 0.70 | medium |
| below 0.70 | low |

### Logging

`vulnscan` logs at INFO level to stderr. Useful lines to look for:

- `Discovered N candidate source files` shows how many files were found.
- `Semgrep status=... failing open` means the whole repo is going to the classifier.
- `Semgrep pre-filter skipped the local model call for N function(s)` shows how much work the pre-filter saved.
- `No trained model found at ...` means the classifier stage is inactive.

---

## 5. Reading the report

The report has two independent sections. Static findings mean a rule matched a pattern. AI findings mean the classifier scored a function above threshold. Don't read them as the same kind of evidence.

### JSON (`<out>.json`)

```jsonc
{
  "static_finding_count": 1,
  "ai_finding_count": 1,
  "static_findings": [
    {
      "location": { "repo": "...", "file_path": "app/views.py",
                    "start_line": 4, "end_line": 4, "commit_sha": "abc123..." },
      "rule_id": "os-system-call",
      "message": "...",
      "severity": "high",
      "cwe_ids": ["CWE-78"]
    }
  ],
  "ai_findings": [                       // sorted by confidence, descending
    {
      "location": { "file_path": "app/views.py", "start_line": 3, "end_line": 5, "...": "..." },
      "finding": {
        "function_name": "run",
        "language": "python",
        "confidence": 0.94,
        "undesired_operation": {
          "description": "Local classifier flagged ... (confidence 94%) ...",
          "code_snippet": "def run(cmd_arg): ...",   // first 2000 chars
          "cwe_ids": [],                              // classifier never sets this
          "severity": "high",
          "closest_cve_match": { "cve_id": "CVE-...", "cwe_ids": "CWE-22", "similarity": 0.60 }
        }
      }
    }
  ]
}
```

### Markdown (`<out>.md`)

- A summary header with both counts.
- **Local Model Findings:** a severity table, then one entry per finding with file and line range, function (qualified like `Class.method`), severity, confidence, closest historical precedent, the classifier note with the similar-CVE list, and the code snippet. Entries are sorted by severity, then confidence.
- **Static Analysis Findings (semgrep):** a severity table, then one entry per rule match with rule ID, message, file, severity and CWE.
- `No findings.` if both lists are empty.

### Interpreting results

- **The classifier is binary.** It says "likely vulnerable" or not. It does not name a CWE, a source or a sink, or explain reachability. Always read the flagged code yourself.
- **`cwe_ids` on AI findings is always empty.** Any CWE you see in the description or `closest_cve_match` comes from embedding similarity to a past CVE. Treat it as a hint about similar code, not a diagnosis.
- **Similarity scores are modest.** Typical values are 0.5 to 0.6 with the default general-purpose embedding model.
- **Expect noise.** On the held-out test split, the recorded v22 numbers (from `data/experiments/phase3_summary.json`) are roughly 17% detection of vulnerable-version functions at about 43% noise on fixed-version functions. High confidence does not mean a true positive.

---

## 6. Using it from Python

```python
import asyncio
from vulnscan.scanner.scan_repo import scan_repo
from vulnscan.scanner.report_json import write_json_report
from vulnscan.scanner.report_markdown import write_markdown_report

report = asyncio.run(scan_repo(
    "/path/to/repo",
    use_semgrep_prefilter=True,                 # None -> use ENABLE_SEMGREP_PREFILTER
    semgrep_config=["p/security-audit"],        # str | list[str] | None
    max_concurrency=4,                          # None -> VULNSCAN_MAX_CONCURRENCY
))

for rf in report.ai_findings:
    print(rf.location.file_path, rf.finding.function_name, f"{rf.finding.confidence:.2f}")
for sf in report.static_findings:
    print(sf.rule_id, sf.location.file_path, sf.location.start_line)

write_json_report(report, "out.json")
write_markdown_report(report, "out.md")
```

Lower-level building blocks:

```python
from vulnscan.chunking import chunk_source_file
from vulnscan.rules.semgrep_runner import run_semgrep_ex
from vulnscan.local_model.inference import score_code, predict_detailed
from vulnscan.analyzer import analyze

# Chunk a file
chunks = chunk_source_file("app/views.py", open("app/views.py").read())

# Run Semgrep and inspect status
result = run_semgrep_ex("/path/to/repo", config="p/security-audit", timeout=300)
print(result.status, len(result.findings))      # status: ok | unavailable | timeout | error

# Score one snippet directly: returns (P(vulnerable), n_tokens)
prob, n_tokens = score_code("def f(x):\n    os.system('ls ' + x)\n")
```

`scan_repo`, `analyze` and the inference functions never raise on missing weights, missing Semgrep or a missing index. They return empty results instead.

---

## 7. Optional components

### Semgrep pre-filter

Install with `pip install -e ".[semgrep]"` or put `semgrep` on `PATH`. The supplementary rules in `semgrep_rules/supplementary_rules.yaml` exist because `p/security-audit`'s taint rules can miss sinks with no visible caller. They cover:

| Rule ID | Targets |
|---|---|
| `os-system-call` | `os.system` built from non-literal input |
| `open-dynamic-path` | `open()` on dynamically built paths, including `"/prefix/" + user_path` |
| `sql-query-string-building` | SQL built by concatenation or f-string |
| `pickle-deserialize` | `pickle.load` / `pickle.loads` |
| `yaml-unsafe-load` | `yaml.load` without a safe loader |
| `eval-exec` | `eval()` / `exec()` |
| `subprocess-shell-true` | `subprocess.*(..., shell=True)` |
| `url-string-concat` | Request URLs built by concatenation or f-string |

The project's phase 4 notes record these as verified against a must-catch / must-not-catch corpus (13/13 caught, 0/16 false positives, with real Semgrep 1.171.0).

Because Semgrep gates the classifier when it runs cleanly, **overall recall is capped by Semgrep's recall**. If a real vulnerability slips through a pre-filtered scan, the first place to look is that rules file.

### CVE-similarity retrieval

```bash
pip install -e ".[embeddings]"
vulnscan build-index --dataset-db data/cvefixes_clean.duckdb --out data/cve_index
```

The index is a numpy matrix of embeddings of the *vulnerable* functions plus a metadata file. Search is brute-force cosine similarity. Once `data/cve_index/embeddings.npy` exists, `vulnscan scan` uses it automatically. Disable with `ENABLE_RETRIEVAL=false`.

| Flag | Description |
|---|---|
| `--dataset-db` | Required. DuckDB with the `pairs` table |
| `--out` | Index directory (default `data/cve_index`) |
| `--language` | Restrict to one language |
| `--limit N` | Embed only N pairs, for a quick test |

The first run downloads the embedding model.

### Local classifier

Needs the `ml` extra plus weights in the checkpoint directory. With no weights, `vulnscan scan` still returns Semgrep findings. See [section 8](#8-building-a-dataset-and-training-a-model) to train your own.

---

## 8. Building a dataset and training a model

Training and retrieval both read one DuckDB table, `pairs` (defined in `src/vulnscan/dataset/schema.sql`):

| Column | Notes |
|---|---|
| `pair_id` | Primary key |
| `cve_id`, `cwe_ids` | `cwe_ids` is comma-separated, e.g. `CWE-89,CWE-20` |
| `language` | Required |
| `repo`, `file_path`, `function_name` | Used for grouping and filtering |
| `func_before` | Vulnerable version (required) |
| `func_after` | Fixed version (required) |
| `commit_message`, `nvd_url` | Optional |

### Step 1: Load data

Bring your own CSV (recommended). The columns must match the table above:

```bash
vulnscan bench-load --csv my_pairs.csv --dataset-db data/cvefixes.duckdb [--replace]
```

Or load from a downloaded [CVEfixes](https://github.com/secureIT-project/CVEfixes) SQLite file:

```bash
vulnscan bench-load --cvefixes-sqlite CVEfixes_meta.db --dataset-db data/cvefixes.duckdb
```

CVEfixes column names drift between releases. Check yours first with `inspect_cvefixes_schema()` from `vulnscan.dataset.cvefixes_loader`.

### Step 2: Clean

```bash
vulnscan dataset-clean --dataset-db data/cvefixes.duckdb --out data/cvefixes_clean.duckdb
# or reload from CVEfixes with fixed pair IDs, then clean:
vulnscan dataset-clean --cvefixes-sqlite CVEfixes_meta.db --out data/cvefixes_clean.duckdb
```

Drops identical before/after pairs, unparseable fragments, tiny snippets and test files. Caps pairs per CVE (`--max-per-cve`, default 20) and per repo (`--max-per-repo`, default 40), preferring diffs that touch sinks like `execute`, `eval` and `subprocess`.

### Step 3: Write splits

```bash
vulnscan write-splits --dataset-db data/cvefixes_clean.duckdb
```

Splits ~70/15/15 grouped by `(repo, cve_id)`, so all pairs from one advisory stay on one side. Writes `data/splits/{train,val,test}_pair_ids.json`. Splitting by row alone leaks near-duplicates between train and test.

### Step 4: Build the index (optional)

See [section 7](#cve-similarity-retrieval).

### Step 5: Train

```bash
pip install -e ".[ml]"
vulnscan train-model \
  --dataset-db data/cvefixes_clean.duckdb \
  --out models/vuln-classifier-v23
```

Then point `LOCAL_MODEL_CHECKPOINT_DIR` at the output directory.

The trainer uses a pairwise margin-ranking loss (the vulnerable version should outscore the fixed one) with a cross-entropy anchor, so absolute scores stay calibrated and don't drift upward together.

| Flag | Default | Description |
|---|---|---|
| `--base-model` | `microsoft/codebert-base` | Encoder to fine-tune (v22u used `microsoft/unixcoder-base`) |
| `--epochs` | 6 | |
| `--batch-size` | 8 | |
| `--learning-rate` | 2e-5 | |
| `--margin` | 1.0 | Ranking-loss margin |
| `--ce-weight` | 1.5 | Cross-entropy anchor weight. Don't set to 0. |
| `--val-fraction`, `--test-fraction` | 0.15 | Group-level holdout |
| `--split-dir` | `data/splits` | Reused if present; `--resplit` rewrites it |
| `--seed` | 42 | |
| `--generic-negatives` | `data/codesearchnet_negatives.jsonl` | Unrelated "probably safe" code |
| `--generic-negative-ratio` | 0.4 | |
| `--extra-negatives` | `data/clean_library_negatives.jsonl` | Hard negatives |
| `--hard-negative-ratio` | 0.25 | |
| `--curated-negatives` | `data/curated_negatives.jsonl` | Always trained on, never held out |
| `--curated-pairs` | `data/curated_vulnerable_pairs.jsonl` | Contrastive pairs, always trained on |
| `--no-diff-centered-crop` | off | Use old head-truncation instead of diff-centered crops |
| `--filter-truncation-collisions` | off | Drop contradictory pairs (use with `--no-diff-centered-crop`) |
| `--generic-gate` | 0.97 | See below |

How training behaves:

- **Diff-centered crops (default).** A 512-token window is centered on the first before/after difference, with a short prefix of the function signature. Without this, long functions truncate to identical inputs with opposite labels.
- **Checkpoint selection.** The saved checkpoint is the epoch that strictly improves validation detection at the validation-picked threshold, minus a small penalty on the fixed code's average P(vulnerable). An epoch is eligible only if held-out generic ranking accuracy stays at or above `--generic-gate`. The gate's default of 0.97 was calibrated on an older data mix. The current mix settles around 0.94, and the v22 run used 0.93. Lower it based on training behavior, not test results.
- **Artifacts written next to the checkpoint.** `threshold.json`, `run_meta.json` (seed, git hash, full config, best epoch), `training_history.json` and `splits/`. Two runs can be diffed config-first.
- **Training data files.** The three `--*negatives*` / `--curated-pairs` paths default to files under `data/`. Only `data/curated_vulnerable_pairs.jsonl` is in the repo. Generate the CodeSearchNet negatives with `fetch_codesearch.py`, or point the flags at your own files.

---

## 9. Benchmark pipeline

Evaluates a classifier against labeled before/after pairs. All four phases are local.

```bash
RUN=data/experiments/40

vulnscan bench-analyze --run-dir $RUN --dataset-db data/cvefixes_clean.duckdb
vulnscan bench-diff    $RUN/analysis.json
vulnscan bench-judge   $RUN/diff.json --dataset-db data/cvefixes_clean.duckdb
vulnscan bench-metrics $RUN/diff.json $RUN/judged.json \
    --total-pairs 257 --analysis-json $RUN/analysis.json --out $RUN/metrics.json
```

| Phase | Output | What it does |
|---|---|---|
| `bench-analyze` | `analysis.json` | Runs the classifier on the vulnerable and fixed version of each pair. Defaults to the **held-out test split** (`--pair-ids data/splits/test_pair_ids.json`). `--all-pairs` scores everything but is contaminated by training data. Supports `--limit`, `--language`, `--max-concurrency`. |
| `bench-diff` | `diff.json` | Buckets findings per pair: `vuln_only` (only in the vulnerable version), `shared` (both), `benign_only` (only in the fixed version) |
| `bench-judge` | `judged.json` | For `vuln_only` findings, checks CWE overlap with the pair's labeled CWE. Returns `true`, `false`, or `null` when there is no usable CWE on either side. |
| `bench-metrics` | printed / `metrics.json` | Rolls up the results (see below) |

`bench-metrics` reports two different things. Don't merge them.

- **Detection and noise** (the scan-faithful numbers, needing `--analysis-json`). A pair is a true positive if `P(before) ≥ t` and `P(after) < t`. Noise is the share of fixed versions with `P(after) ≥ t`. The threshold defaults to the checkpoint's `threshold.json`. The output includes a PR curve over thresholds 0.30 to 0.80 and breakdowns by CWE, repo and token length.
- **CWE attribution** (`retrieval_diagnostic`). Precision, recall and F1 of the CWE guesses coming from retrieval. This is a score for retrieval, not for the classifier.

`--total-pairs` is required and must match the number of pairs analyzed. Past runs and summaries are stored under `data/experiments/`.

---

## 10. Module reference

```
src/vulnscan/
├── cli.py                    `vulnscan <command>` entry point
├── config.py                 Environment-driven Settings
├── schemas.py                Finding, StaticFinding, RepoFinding, ScanReport, Severity, Language
├── analyzer.py               analyze(): classifier → enrich with CVE + Semgrep context
├── prompts.py                Legacy LLM prompt code (not on the scan path)
├── chunking/
│   ├── __init__.py           CHUNKERS_BY_EXTENSION registry, chunk_source_file()
│   ├── base.py               CodeChunk dataclass
│   └── python_chunker.py     ast-based function/method extraction, dedented
├── rules/semgrep_runner.py   run_semgrep_ex() → SemgrepRunResult(status, findings)
├── local_model/inference.py  score_code(), predict_detailed(), threshold resolution
├── embedding/
│   ├── encoder.py            sentence-transformers wrapper
│   ├── index.py              VectorIndex (numpy, cosine similarity)
│   ├── build_index.py        index builder
│   └── retrieve.py           retrieve_similar_cves()
├── dataset/
│   ├── schema.sql            `pairs` table
│   ├── cvefixes_loader.py    CSV and CVEfixes loaders, get_pairs()
│   ├── clean.py              filtering and per-CVE/per-repo caps
│   └── filters.py            test-path regex, sink regex, parseability checks
├── training/
│   ├── train.py              train_model_pairwise() and checkpoint selection
│   ├── dataset.py            PairExample, negative and curated-pair loaders
│   ├── splits.py             grouped (repo, cve_id) splits
│   └── windows.py            diff-centered crops, sliding-window offsets
├── pipeline/                 bench-analyze / diff / judge / metrics
└── scanner/
    ├── scan_repo.py          scan_repo(), discover_files()
    ├── report_json.py        write_json_report()
    ├── report_markdown.py    write_markdown_report()
    └── report_github.py      stub; raises NotImplementedError
```

The repo root also holds many one-off helper scripts (`sanity_check.py`, `find_pairs.py`, `cve_extract.py`, `ghsa_extract.py` and others) used while building the datasets and checkpoints. They are not part of the installed package.

### Adding a language

1. Write `src/vulnscan/chunking/<lang>_chunker.py` exposing `chunk_file(path, source) -> list[CodeChunk]`.
2. Register it in `CHUNKERS_BY_EXTENSION` in `chunking/__init__.py`.
3. Pass the new extension to `scan_repo(..., extensions=(".ext",))`. The CLI currently hard-codes `.py`.

The classifier itself is trained on Python, so a new chunker alone won't give meaningful AI findings until you also train on that language's data. Semgrep findings work for any language it supports.

---

## 11. Behavior matrix and graceful degradation

| Situation | Result |
|---|---|
| No `semgrep` binary | Warning, fail open. Whole repo goes to the classifier at the higher bar. |
| Semgrep timeout (`SEMGREP_TIMEOUT`) or error | Same as above |
| Semgrep clean with zero findings | Classifier is not run; empty report |
| No checkpoint at `LOCAL_MODEL_CHECKPOINT_DIR` | Logged once; static findings only |
| Checkpoint present but torch/transformers missing | Scoring fails, logged; chunk treated as not vulnerable |
| Weights corrupt or scoring raises | Chunk treated as not vulnerable, scan continues |
| No CVE index, or `sentence-transformers` missing | Retrieval returns nothing; findings are unannotated |
| Unreadable or non-UTF-8 file | Skipped |
| Analysis exception on one function | Logged, that function skipped |

A scan is designed to finish and write a report in all of these cases. The practical risk is a silent empty report, so check the log for the `No trained model found` or `failing open` lines.

---

## 12. Known limitations and issues

Verified by running or reading the code:

- **Detection is low and noisy.** See [section 5](#interpreting-results). Use findings as triage hints.
- **`discover_files` rejects repos under excluded directory names.** The exclude check runs on the absolute path, so scanning `/home/me/build/myproject` finds zero files. Move or symlink the repo, or change the check to use the path relative to the repo root.
- **Default checkpoint is v20.** Set `LOCAL_MODEL_CHECKPOINT_DIR` to v22 (or your own) explicitly. The threshold is cached after the first load, so one process uses one checkpoint's threshold.
- **Relative checkpoint path.** Resolved against the current directory, not the repo root.
- **Misleading log message.** When no checkpoint is found, the log says "scanning with Semgrep only", even if you passed `--no-semgrep`.
- **Two copies of the custom rules.** `sup_rules.yaml` at the repo root differs from `semgrep_rules/supplementary_rules.yaml`. Only the latter is loaded.
- **`--semgrep-config` replaces the defaults,** including the supplementary rules.
- **Python only.** The chunker uses `ast`. `architecture.txt` describes tree-sitter, multi-language support, CWE classification, a reasoning step and SARIF output. None of those exist yet.
- **GitHub reporting is a stub.** `report_github.py` raises `NotImplementedError`.
- **Concurrency is probably not effective.** Inference runs synchronously inside async tasks, so `--max-concurrency` likely has little effect on a single GPU. This is from reading the code and has not been benchmarked.
- **Long functions.** Only the highest-scoring window decides the result, and very long functions are scored from many windows, which raises the chance of a high max score. The recorded results show higher noise on functions over 512 tokens.

---

## 13. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `Found 0 static finding(s), 0 local-model finding(s)` on a repo you expect hits in | Check the log: `Discovered 0 candidate source files` suggests the path contains an excluded directory name or only test files. `No trained model found` means no classifier stage ran. Semgrep ran clean with no findings means nothing was classified. |
| `No trained model found at models/vuln-classifier-v20` | Wrong default or relative path. Set an absolute `LOCAL_MODEL_CHECKPOINT_DIR`. Also confirm the weight file exists in that directory. |
| `torch/transformers are not installed` | `pip install -e ".[ml]"` |
| `sentence-transformers is not installed` | `pip install -e ".[embeddings]"` or set `ENABLE_RETRIEVAL=false` |
| `Semgrep status=unavailable` | `pip install -e ".[semgrep]"` or install the `semgrep` CLI |
| Semgrep times out on a large repo | Raise `SEMGREP_TIMEOUT`, or scan a subdirectory |
| Every function gets flagged | You are in fail-open mode (`--no-semgrep` or broken Semgrep). Expect more noise. |
| `pytest` fails at collection on numpy | Install `numpy` or an extra that includes it |
| `bench-analyze` says pair-ids file not found | Run `vulnscan write-splits` or `train-model` first, or pass `--all-pairs` |
| CVEfixes load raises a missing table/column error | Your CVEfixes release has different names. Run `inspect_cvefixes_schema()` and adjust the SQL in `cvefixes_loader.py`. |