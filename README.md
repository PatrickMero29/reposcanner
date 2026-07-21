# vulnscan

A multi-language, Gemini-powered vulnerability scanner, built as a generalization of
[ZeroPath's opus-benchmark](https://github.com/ZeroPathAI/opus-benchmark). It has two modes that
share one analyzer core:

- **Scanner** — point it at any local repo, get back a report of likely vulnerabilities (no
  ground truth needed). This is the practical, day-to-day tool.
- **Benchmark** — like the original repo: run the analyzer over CVE-labeled vulnerable/fixed
  function pairs and score precision/recall, to validate and tune the analyzer's prompting
  strategy before trusting it on real code.

Currently supports **Python** only. Adding a language means writing one new chunker
(see "Adding a language" below) — nothing else in the pipeline needs to change.

## Why the architecture differs from the original repo

The original repo implements four "justification levels" (no justification / limited /
extensive / verification-agent) as four separate experiment folders with duplicated analyzer
code. Here they're modeled as one `JustificationLevel` enum plus one Pydantic schema per level
(`src/vulnscan/schemas.py`), and a single `analyze()` function
(`src/vulnscan/analyzer.py`) that picks the right prompt and schema for the requested level.
That single analyzer is what both the scanner and the benchmark call — so improvements to
prompting or verification logic benefit both at once, and there's no risk of the four levels
drifting out of sync.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env        # then edit .env and set GEMINI_API_KEY
```

Run the tests to confirm the install works (these don't call the Gemini API):

```bash
pytest
```

## Scanner mode (use this first)

```bash
vulnscan scan /path/to/some/repo --level extensive_justification --out report
```

This walks the repo, extracts Python functions (via `ast`, see
`src/vulnscan/chunking/python_chunker.py`), runs each one through Gemini at the requested
justification level, and writes `report.json` and `report.md`.

Justification levels, in increasing order of rigor (and API cost):
- `no_justification` — fastest/cheapest, most false positives.
- `limited_justification` — requires a step-by-step execution trace.
- `extensive_justification` — requires a full taint/reachability proof (recommended default).
- `verification_agent` — extensive, plus a second Gemini call independently re-checks each
  finding and discards ones that don't hold up. Slowest and most expensive, fewest false
  positives.

Reporting to GitHub issues/PR comments isn't implemented yet — see
`src/vulnscan/scanner/report_github.py` for the planned interface. For now, use the JSON/Markdown
output.

## Benchmark mode

The benchmark needs a dataset of vulnerable/fixed function pairs with CVE/CWE ground truth,
loaded into a local DuckDB table (`src/vulnscan/dataset/schema.sql`). Two ways to populate it:

**Option A — bring your own CSV** (recommended to get started; no dependency on any one
dataset's internal schema). Columns: `pair_id, cve_id, cwe_ids, language, repo, file_path,
function_name, func_before, func_after, commit_message, nvd_url`.

```bash
vulnscan bench-load --csv my_pairs.csv --dataset-db data/cvefixes.duckdb
```

**Option B — [CVEfixes](https://github.com/secureIT-project/CVEfixes)**, a public dataset of
CVE-labeled fix commits across many languages including Python. Download `CVEfixes.db` from
their releases, then:

```python
from vulnscan.dataset.cvefixes_loader import inspect_cvefixes_schema, load_from_cvefixes_sqlite

# CVEfixes' internal column names have drifted across releases — check yours first:
print(inspect_cvefixes_schema("CVEfixes.db"))

# If src/vulnscan/dataset/cvefixes_loader.py's _CVEFIXES_EXTRACT_SQL doesn't match what you
# see above, adjust the table/column names there, then:
load_from_cvefixes_sqlite("CVEfixes.db", "data/cvefixes.duckdb")
```

Then run the full four-phase pipeline (mirrors the original repo's analyze → diff → judge →
metrics flow):

```bash
./scripts/run_experiment.sh extensive_justification 1
```

Or step by step:

```bash
vulnscan bench-analyze --dataset-db data/cvefixes.duckdb --level extensive_justification \
    --run-dir data/experiments/extensive_justification/runs/1
vulnscan bench-diff data/experiments/extensive_justification/runs/1/analysis.json
vulnscan bench-judge data/experiments/extensive_justification/runs/1/diff.json \
    --dataset-db data/cvefixes.duckdb
vulnscan bench-metrics data/experiments/extensive_justification/runs/1/diff.json \
    data/experiments/extensive_justification/runs/1/judged.json --total-pairs <N>
```

`bench-metrics` prints precision/recall/F1 at the function-pair level (see docstring in
`src/vulnscan/pipeline/metrics.py` for exact definitions).

## Adding a language

1. Write `src/vulnscan/chunking/<lang>_chunker.py` exposing `chunk_file(path, source) -> list[CodeChunk]`.
2. Register it in `CHUNKERS_BY_EXTENSION` in `src/vulnscan/chunking/__init__.py`.
3. That's it — the analyzer, scanner, and benchmark pipeline are already language-agnostic
   (they dispatch on `schemas.Language`, which already includes `JAVA`, `C`, `CPP`, `JAVASCRIPT`,
   `GO` as placeholders).

## Project layout

```
src/vulnscan/
├── schemas.py          # Finding / justification-level data model — read this first
├── config.py            # env-var settings
├── prompts.py            # per-justification-level prompt text
├── gemini_client.py      # structured-output calls to Gemini, with retries
├── analyzer.py            # core analyze() — shared by scanner and benchmark
├── cli.py                  # `vulnscan <command>` entrypoint
├── chunking/               # source file -> per-function chunks (Python only so far)
├── dataset/                 # CVE-labeled dataset ingestion into DuckDB
├── pipeline/                  # benchmark: analyze -> diff -> judge -> metrics
└── scanner/                    # practical repo scanner + JSON/Markdown/(future GitHub) reports
```

## Known limitations / next steps

- Only Python chunking is implemented; Java/C/C++ chunkers are the natural next step.
- GitHub issue/PR-comment reporting is a stub (`scanner/report_github.py`) — needs a
  dedupe strategy so repeat scans don't spam duplicate issues.
- `diff_judge.py`'s before/after matching is a text-similarity + CWE-overlap heuristic, not
  an LLM judge — it's cheap and fast but the `DESCRIPTION_SIMILARITY_THRESHOLD` may need tuning
  against your actual data.
- The CVEfixes column mapping in `dataset/cvefixes_loader.py` is best-effort and may need
  adjusting to your specific downloaded release (see `inspect_cvefixes_schema()`).
