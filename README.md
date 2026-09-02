# vulnscan

A fully local, no-paid-API vulnerability scanner for Python code: a Semgrep static-analysis
pre-filter feeds a self-trained code classifier, which is enriched with local CVE-similarity
retrieval for human reviewers. No LLM API call happens anywhere in the scan path — that's a
firm design constraint, not a missing feature (see "Why no LLM API" below).

## Architecture

```
Repository
    │
    ▼
Semgrep pre-filter (free, local, fast — custom rules layered on p/security-audit)
    │  only flagged functions continue ──▶ everything else is skipped
    ▼
Local classifier (pairwise margin-ranking + cross-entropy anchor, fine-tuned CodeBERT)
    │
    ▼
CVE-retrieval enrichment (local sentence-embedding index — reference only, not fed back into the model)
    │
    ▼
Report: static_findings (Semgrep) + ai_findings (classifier), reported separately
```

Every stage fails **open**: if Semgrep isn't installed, everything goes to the classifier
instead of being silently dropped. If no classifier has been trained yet, `vulnscan scan` still
returns Semgrep's findings. If the embeddings extra isn't installed, retrieval quietly no-ops.

Currently supports **Python only**. Adding a language means writing one new chunker (see
"Adding a language" below) — nothing else in the pipeline changes.

## Why no LLM API

The project originally called Claude with prompt-engineered reasoning (justification levels,
forced tool-use, a verifier pass) as the "AI engine." That entire path has been replaced by a
classifier you train yourself and run on your own hardware. The remaining prompt-construction
code (`prompts.py`) and the old justification-level schemas are left in place for reference but
are not on the active scan path — `analyzer.py`'s only job now is enriching a classifier finding
with CVE-retrieval and Semgrep context, never feeding that context back into the model (a
fine-tuned encoder's input should match its training distribution: raw code, not code mixed with
hints it never saw during training).

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest   # confirms the install works
```

No API key is required for any part of this project.

## Scanner mode (works today, no training required)

```bash
pip install -e ".[semgrep]"
vulnscan scan /path/to/some/repo --out report --format both
```

Walks the repo, runs Semgrep, extracts flagged Python functions via `ast`
(`src/vulnscan/chunking/python_chunker.py`), and — once a model is trained — runs those through
the local classifier too. Writes `report.json` and `report.md` with static and AI findings kept
in clearly separate sections.

```bash
vulnscan scan /path/to/repo --no-semgrep                                    # skip the pre-filter, analyze every function
vulnscan scan /path/to/repo --semgrep-config p/security-audit --semgrep-config p/secrets
```

Custom Semgrep rules live in `semgrep_rules/supplementary_rules.yaml`, added because
`p/security-audit`'s taint-based rules can miss sinks with no visible caller providing taint
context (confirmed for command injection, path traversal, and SQL injection specifically —
verified 3/3 caught with 0 false positives across safe counterparts). These load automatically
alongside `p/security-audit` if the file exists.

## Training your own classifier

```bash
vulnscan bench-load --csv my_pairs.csv --dataset-db data/cvefixes.duckdb
pip install -e ".[ml]"   # torch + transformers + scikit-learn + accelerate — GPU used automatically if available
vulnscan train-model --dataset-db data/cvefixes.duckdb --out models/vuln-classifier
```

`train-model` runs `train_model_pairwise` — a pairwise margin-ranking objective with a
cross-entropy anchor term (`--margin`, `--ce-weight`), not plain independent binary
classification. That's a deliberate choice: the earlier independent-classification trainer
(kept in `train.py` for reference only) never converged.

A few things the trainer handles that are easy to get wrong with this kind of data:

- **Splits by `pair_id`, not by row**, so a function's vulnerable and fixed versions never land
  on opposite sides of train/val — a common source of inflated benchmark numbers.
- **Filters truncation collisions**: if a before/after pair's differing lines fall past
  `max_length` after tokenization, both versions collapse to an identical input with opposite
  labels — directly contradictory training data. This affects roughly 12% of a real CVEfixes
  run and is filtered out by default (`--filter-truncation-collisions`, on by default).
- **Curated negatives and contrastive pairs are always trained on, never held out** — added
  after specific, diagnosed failure modes (e.g. the model generalizing "database cursor code =
  safe" too broadly until given an explicit `sql_injection` / `sql_parameterized` contrastive
  pair). Generic CodeSearchNet-derived negatives, by contrast, are subject to the normal
  train/val split.

Once training finishes, `models/vuln-classifier/config.json` exists and `vulnscan scan`
picks it up automatically — no flag needed. Delete/move that directory to fall back to
Semgrep-only scanning.

**Known limitation:** the classifier predicts *vulnerable or not*, nothing more — no CWE
classification, no reachability explanation. Extending to multi-class CWE prediction is the
natural next step once the binary case is validated on held-out data — see `architecture.txt`.

## Benchmark harness

Training and CVE retrieval both read from the same local `pairs` table
(`src/vulnscan/dataset/schema.sql`). Evaluating the classifier against labeled ground truth is a
four-phase local pipeline — no API calls anywhere in it:

```bash
vulnscan bench-analyze --run-dir data/experiments/1 --dataset-db data/cvefixes.duckdb
vulnscan bench-diff data/experiments/1/analysis.json
vulnscan bench-judge data/experiments/1/diff.json --dataset-db data/cvefixes.duckdb
vulnscan bench-metrics data/experiments/1/diff.json data/experiments/1/judged.json
```

1. **bench-analyze** — runs the classifier over every before/after pair in the dataset.
2. **bench-diff** — buckets findings into `vuln_only` / `shared` / `benign_only` by comparing the
   before and after version of each pair.
3. **bench-judge** — decides whether each `vuln_only` finding actually matches the pair's labeled
   CVE/CWE. This used to be an LLM call; it's now a deterministic local heuristic that extracts
   `CWE-XXX` mentions via regex from the finding's enriched description text (the classifier
   itself never emits structured CWE IDs) and compares them against CVEfixes' own CWE labels —
   which are themselves incomplete (~19% of pairs use NVD's "no info" placeholders rather than a
   real CWE, handled explicitly rather than treated as a false mismatch).
4. **bench-metrics** — rolls diff + judged results up into detection rate, noise rate, and
   CWE-attribution numbers.

**Bring your own CSV** (recommended — no dependency on one dataset's internal schema). Columns:
`pair_id, cve_id, cwe_ids, language, repo, file_path, function_name, func_before, func_after,
commit_message, nvd_url`.

**Or use [CVEfixes](https://github.com/secureIT-project/CVEfixes)** directly:

```python
from vulnscan.dataset.cvefixes_loader import inspect_cvefixes_schema, load_from_cvefixes_sqlite

print(inspect_cvefixes_schema("CVEfixes.db"))  # column names drift across releases — check first
load_from_cvefixes_sqlite("CVEfixes.db", "data/cvefixes.duckdb")
```

## CVE retrieval (optional)

Annotates a positive classifier finding with similar historical CVEs via a local, free embedding
index over the loaded `pairs` table — informational context for a human reviewer only, never fed
back into the classifier.

```bash
pip install -e ".[embeddings]"
vulnscan build-index --dataset-db data/cvefixes.duckdb --out data/cve_index
```

Picked up automatically by `vulnscan scan` once built. Set `ENABLE_RETRIEVAL=false` in `.env` to
disable.

## Adding a language

1. Write `src/vulnscan/chunking/<lang>_chunker.py` exposing `chunk_file(path, source) -> list[CodeChunk]`.
2. Register it in `CHUNKERS_BY_EXTENSION` in `src/vulnscan/chunking/__init__.py`.
3. That's it — Semgrep already supports most mainstream languages, and training/inference only
   need code text.

## Project layout

```
src/vulnscan/
├── schemas.py         # Finding / StaticFinding / ScanReport data model — read this first
├── config.py           # env-var settings (no API key needed)
├── analyzer.py           # orchestrates: local classifier -> enrich with CVE/semgrep context
├── cli.py                  # `vulnscan <command>` entrypoint
├── prompts.py                # legacy LLM prompt construction — not on the active scan path
├── chunking/                   # source file -> per-function chunks (Python only so far)
├── dataset/                      # CVE-labeled dataset ingestion into DuckDB
├── embedding/                      # optional CVE similarity index for retrieval-grounded reporting
├── rules/                            # Semgrep CLI wrapper (the fast pre-filter stage)
├── local_model/                        # inference: loads a trained checkpoint, runs the classifier
├── training/                             # dataset construction + pairwise fine-tuning script
├── pipeline/                                # local 4-phase benchmark harness (no API calls)
└── scanner/                                   # repo scanner + JSON/Markdown reports (GitHub reporting is a stub)
```

## Known limitations / next steps

- Only Python chunking is implemented; Java/C/C++ chunchers are the natural next step.
- The classifier is binary only (vulnerable/not) — no CWE classification or reachability
  explanation. See "Training your own classifier" for why this isn't skipped straight to.
- GitHub issue/PR-comment reporting (`scanner/report_github.py`) is a stub — planned shape is
  documented in the file, but it needs a dedupe strategy before it's usable so repeat scans
  don't spam duplicate issues.
- The default embedding model (`flax-sentence-embeddings/st-codesearch-distilroberta-base`) is a
  general code-search model, not vulnerability-specific. Override via `EMBEDDING_MODEL` in `.env`.
- The CVEfixes column mapping in `dataset/cvefixes_loader.py` is best-effort and may need
  adjusting to your specific downloaded release (see `inspect_cvefixes_schema()`).
- There is a firm project policy against reintroducing a paid LLM API dependency at inference
  time. Improvements to output quality (CWE classification, reachability explanation) are
  expected to come from the local classifier/pipeline, not from calling out to an API.