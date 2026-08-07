# vulnscan

A multi-language vulnerability scanner with **no paid API dependency**: Semgrep runs first as a
fast, free, local pre-filter; a classifier you train yourself (fine-tuned CodeBERT, runs on your
own GPU or CPU) is the "AI engine" stage. Originally built as a generalization of
[ZeroPath's opus-benchmark](https://github.com/ZeroPathAI/opus-benchmark); the project has since
moved away from calling any LLM API at inference time — see `architecture.txt` for the full
design rationale.

Currently supports **Python** only. Adding a language means writing one new chunker (see
"Adding a language" below) — nothing else in the pipeline needs to change.

## Architecture

```
Repository
    │
    ▼
Semgrep pre-filter (free, local, fast)
    │  only flagged functions continue ──▶ everything else is skipped
    ▼
Local classifier (your trained model — see src/vulnscan/training/)
    │
    ▼
Report: static_findings (Semgrep) + ai_findings (classifier), reported separately
```

Both stages fail **open**: if Semgrep isn't installed or finds nothing, every function still
gets analyzed rather than the scan silently reporting zero results. If no classifier has been
trained yet, `vulnscan scan` still works and gives you Semgrep's findings — real, useful output
with zero setup beyond `pip install -e ".[semgrep]"`.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

No `.env` API key is required anymore — see `.env.example` for the (all optional) tuning knobs.

Run the tests to confirm the install works:

```bash
pytest
```

## Scanner mode (use this first — works today, no training required)

```bash
pip install -e ".[semgrep]"
vulnscan scan /path/to/some/repo --out report
```

This walks the repo, runs Semgrep across it, extracts Python functions (via `ast`, see
`src/vulnscan/chunking/python_chunker.py`) for whichever ones Semgrep flagged, and — once you've
trained a model (see below) — runs those through your local classifier too. Writes `report.json`
and `report.md`, each with two clearly separate sections: Semgrep's raw findings, and the
classifier's.

```bash
vulnscan scan /path/to/repo --no-semgrep                          # analyze every function, skip the pre-filter
vulnscan scan /path/to/repo --semgrep-config p/security-audit --semgrep-config p/secrets
```

## Training your own classifier

This is the part that replaces the old Claude-based "AI engine." It's a **binary** classifier
(vulnerable / not vulnerable) fine-tuned from a pretrained code encoder — deliberately narrow in
scope per the project's own design notes in `architecture.txt`: no CFG/DFG graph construction, no
multi-class CWE prediction yet, just the smallest version that could plausibly work, trained on
data you already have.

**1. Load a labeled dataset** (see "Benchmark dataset" below for where this comes from):

```bash
vulnscan bench-load --csv my_pairs.csv --dataset-db data/cvefixes.duckdb
```

**2. Train:**

```bash
pip install -e ".[ml]"   # torch + transformers + scikit-learn + accelerate — GPU used automatically if available
vulnscan train-model --dataset-db data/cvefixes.duckdb --out models/vuln-classifier
```

Runs on GPU automatically if `torch.cuda.is_available()`, falls back to CPU otherwise (slow, but
works for a quick smoke test on a tiny dataset). Splits your data by `pair_id` — not by row —
before train/val, so the vulnerable and fixed versions of the same function never end up on
opposite sides of the split (a common source of inflated benchmark numbers in this space; see the
research-critique notes in `architecture.txt`).

**3. Use it:** once training finishes, `models/vuln-classifier/config.json` exists, and
`vulnscan scan` automatically starts using it — no flag needed. Delete/move that directory to go
back to Semgrep-only scanning.

Tuning knobs (`.env`): `LOCAL_MODEL_CHECKPOINT_DIR`, `LOCAL_MODEL_BASE` (default
`microsoft/codebert-base`), `LOCAL_MODEL_CONFIDENCE_THRESHOLD` (default 0.5 — raise it to reduce
false positives, at the cost of recall).

**Known limitation, stated plainly:** this model predicts *vulnerable or not*, nothing more — no
CWE classification, no reachability explanation, no exploit narrative. That richer output was
what the old Claude-based analyzer produced via prompting; a fine-tuned classifier doesn't have
an equivalent built in. Extending to multi-class CWE prediction is the natural next step once the
binary case is validated (see `architecture.txt`'s Phase 5/6) — don't skip straight to it before
confirming the binary classifier actually generalizes on held-out data.

## Benchmark dataset

Both training and the CVE-retrieval index (below) read from the same local `pairs` table (see
`src/vulnscan/dataset/schema.sql`) — any CVE-labeled dataset gets converted into this shape
first.

**Option A — bring your own CSV** (recommended to start; no dependency on any one dataset's
internal schema). Columns: `pair_id, cve_id, cwe_ids, language, repo, file_path, function_name,
func_before, func_after, commit_message, nvd_url`.

**Option B — [CVEfixes](https://github.com/secureIT-project/CVEfixes)**, a public dataset of
CVE-labeled fix commits across many languages including Python:

```python
from vulnscan.dataset.cvefixes_loader import inspect_cvefixes_schema, load_from_cvefixes_sqlite

# CVEfixes' internal column names have drifted across releases — check yours first:
print(inspect_cvefixes_schema("CVEfixes.db"))
# If src/vulnscan/dataset/cvefixes_loader.py's _CVEFIXES_EXTRACT_SQL doesn't match what you
# see above, adjust the table/column names there, then:
load_from_cvefixes_sqlite("CVEfixes.db", "data/cvefixes.duckdb")
```

## CVE retrieval (optional)

The scanner can annotate a positive classifier finding with similar historical CVEs, via a local,
free embedding index (no API calls) over your loaded `pairs` table — purely informational context
for a human reviewer, not fed back into the classifier itself (a fine-tuned encoder's input
should match its training distribution: raw code, not code mixed with retrieved hints it never
saw during training).

```bash
pip install -e ".[embeddings]"
vulnscan build-index --dataset-db data/cvefixes.duckdb --out data/cve_index
```

Once built, `vulnscan scan` picks it up automatically. Set `ENABLE_RETRIEVAL=false` in `.env` to
turn it off.

## Adding a language

1. Write `src/vulnscan/chunking/<lang>_chunker.py` exposing `chunk_file(path, source) -> list[CodeChunk]`.
2. Register it in `CHUNKERS_BY_EXTENSION` in `src/vulnscan/chunking/__init__.py`.
3. The chunker is the only language-specific piece — Semgrep already supports most mainstream
   languages out of the box, and training/inference just need code text, so nothing else needs
   to change.

## Project layout

```
src/vulnscan/
├── schemas.py           # Finding / StaticFinding / ScanReport data model — read this first
├── config.py              # env-var settings (no API key needed anymore)
├── analyzer.py              # orchestrates: local classifier -> enrich with CVE/semgrep context
├── cli.py                     # `vulnscan <command>` entrypoint
├── chunking/                   # source file -> per-function chunks (Python only so far)
├── dataset/                     # CVE-labeled dataset ingestion into DuckDB
├── embedding/                    # optional CVE similarity index for retrieval-grounded reporting
├── rules/                         # Semgrep CLI wrapper (the fast pre-filter stage)
├── local_model/                    # inference: loads a trained checkpoint, runs the classifier
├── training/                        # dataset construction + fine-tuning script
└── scanner/                          # repo scanner + JSON/Markdown/(future GitHub) reports
```

## Known limitations / next steps

- Only Python chunking is implemented; Java/C/C++ chunkers are the natural next step.
- The classifier is binary only (vulnerable/not) — no CWE classification or reachability
  explanation yet. See "Training your own classifier" above for the reasoning behind not skipping
  straight to the more ambitious version.
- GitHub issue/PR-comment reporting is a stub (`scanner/report_github.py`) — needs a dedupe
  strategy so repeat scans don't spam duplicate issues.
- The default embedding model (`flax-sentence-embeddings/st-codesearch-distilroberta-base`) is a
  general code-search model, not vulnerability-specific. Override via `EMBEDDING_MODEL` in `.env`.
- The CVEfixes column mapping in `dataset/cvefixes_loader.py` is best-effort and may need
  adjusting to your specific downloaded release (see `inspect_cvefixes_schema()`).
- Removed entirely as of this version: any dependency on Claude, Gemini, or any other paid LLM
  API. If you're reading old conversation history or commit messages that mention `ANTHROPIC_API_KEY`,
  `anthropic_client.py`, or justification levels (`no_justification`/`extensive_justification`/
  etc.) — that's all gone. The "AI engine" is exclusively `src/vulnscan/local_model/` now.
