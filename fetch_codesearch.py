"""One-time fetch: samples diverse Python functions from CodeSearchNet to use
as generic "probably safe" negative examples for pairwise training (see
train_model_pairwise's generic_negatives_path parameter in training/train.py).

These are NOT verified vulnerability-free -- "most random GitHub functions
are safe" is a weak label, the same assumption most vulnerability-detection
training sets rely on. The goal here is diversity (teaching the model what
ordinary, unremarkable code looks like), not perfect ground truth. This is
what's missing from the current dataset: every existing "not vulnerable"
example is a specific CVE's fixed version, 1-3 lines after the bug -- never
a broadly diverse population of code that was never near a CVE.

Run once from C:\\reposcanner with the venv active:
    python fetch_codesearchnet_negatives.py

Writes data/codesearchnet_negatives.jsonl (one {"code": ...} object per line).
"""

from __future__ import annotations

import json
import os
import random

from datasets import load_dataset

OUT_PATH = "data/codesearchnet_negatives.jsonl"
TARGET_COUNT = 5000
MIN_CHARS = 40       # skip near-empty/one-line stubs -- not useful contrast
MAX_CHARS = 4000     # skip huge files that would dominate tokenization anyway
SEED = 42

# Try known-good mirrors in order. CodeSearchNet's own HF loading script is
# a legacy script-based dataset and can be flaky/blocked on recent `datasets`
# versions (trust_remote_code requirements, etc.) -- prefer plain parquet
# mirrors first, fall back to the canonical one.
_MIRRORS: list[tuple[str, str | None]] = [
    ("Nan-Do/code-search-net-python", None),
    ("code-search-net/code_search_net", "python"),
]

_CODE_FIELDS = ["code", "func_code_string", "whole_func_string", "content"]


def _load_first_working():
    last_err: Exception | None = None
    for name, config in _MIRRORS:
        try:
            print(f"Trying {name} ({config})...")
            ds = load_dataset(name, config, split="train") if config else load_dataset(name, split="train")
            print(f"Loaded {name}: {len(ds)} rows, columns={ds.column_names}")
            return ds
        except Exception as exc:  # noqa: BLE001 -- deliberately broad, trying multiple mirrors
            print(f"  failed: {exc}")
            last_err = exc
    raise RuntimeError(
        f"Could not load any CodeSearchNet mirror ({[m[0] for m in _MIRRORS]}). "
        f"Last error: {last_err}"
    )


def main() -> None:
    ds = _load_first_working()

    field = next((f for f in _CODE_FIELDS if f in ds.column_names), None)
    if field is None:
        raise RuntimeError(f"None of {_CODE_FIELDS} found in columns: {ds.column_names}")
    print(f"Using code field: {field!r}")

    rng = random.Random(SEED)
    indices = list(range(len(ds)))
    rng.shuffle(indices)

    kept: list[str] = []
    for i in indices:
        code = ds[i][field]
        if not code or not (MIN_CHARS <= len(code) <= MAX_CHARS):
            continue
        kept.append(code)
        if len(kept) >= TARGET_COUNT:
            break

    print(f"Kept {len(kept)} functions (target {TARGET_COUNT})")

    os.makedirs("data", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        for code in kept:
            f.write(json.dumps({"code": code}) + "\n")

    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()