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
# Lowered from 40 -- the original MIN_CHARS=40 systematically excluded short
# functions (getters, one-line arithmetic, tiny helpers) from BOTH the
# CodeSearchNet negatives AND, by construction, the held-out eval slice.
# direct_check.py showed the model at 94% "vulnerable" on a 2-line add()
# function despite averaging 1.7% on the (length-filtered) held-out set --
# short code was untested territory, not usefully "out of distribution" in
# some vague sense. Real codebases have plenty of short functions; the model
# needs to have actually seen some during training.
MIN_CHARS = 10
MAX_CHARS = 4000     # skip huge files that would dominate tokenization anyway
SEED = 42

# Hand-curated, genuinely trivial, unambiguously-safe functions -- guarantees
# coverage of the very-short regime regardless of how many short examples
# happen to survive random sampling from CodeSearchNet. No I/O, no
# subprocess/os/eval/exec, no string-built SQL or shell commands, no
# deserialization -- nothing that could be mistaken for a real sink.
_TRIVIAL_SAFE_EXAMPLES = [
    "def add(a, b):\n    return a + b\n",
    "def subtract(a, b):\n    return a - b\n",
    "def multiply(a, b):\n    return a * b\n",
    "def is_even(n):\n    return n % 2 == 0\n",
    "def square(x):\n    return x * x\n",
    "def max_of_two(a, b):\n    return a if a > b else b\n",
    "def get_name(self):\n    return self.name\n",
    "def set_value(self, value):\n    self.value = value\n",
    "def is_empty(items):\n    return len(items) == 0\n",
    "def first(items):\n    return items[0] if items else None\n",
    "def clamp(value, low, high):\n    return max(low, min(value, high))\n",
    "def to_upper(s):\n    return s.upper()\n",
    "def reverse_list(items):\n    return items[::-1]\n",
    "def average(numbers):\n    return sum(numbers) / len(numbers)\n",
    "def is_positive(n):\n    return n > 0\n",
    "class Point:\n    def __init__(self, x, y):\n        self.x = x\n        self.y = y\n",
    "def greet(name):\n    return f'Hello, {name}!'\n",
    "def count_items(items):\n    return len(items)\n",
    "def flatten_pair(pair):\n    return list(pair)\n",
    "def is_valid_age(age):\n    return 0 <= age <= 150\n",
]

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

    print(f"Kept {len(kept)} functions from CodeSearchNet (target {TARGET_COUNT})")
    kept.extend(_TRIVIAL_SAFE_EXAMPLES)
    print(f"Added {len(_TRIVIAL_SAFE_EXAMPLES)} hand-curated trivial-safe examples "
          f"({len(kept)} total)")

    os.makedirs("data", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        for code in kept:
            f.write(json.dumps({"code": code}) + "\n")

    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()