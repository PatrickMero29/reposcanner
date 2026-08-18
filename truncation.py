"""Diagnostic: does 512-token truncation collapse func_before/func_after into
identical inputs for a meaningful fraction of pairs?

If mc_before.code and mc_after.code differ only past token 512, truncation
makes them tokenize to the SAME sequence while keeping opposite labels
(1 vs 0) -- i.e. contradictory training examples. That alone would explain
oscillating, non-converging loss like what train.py just showed:
epoch 2 collapsed to "always predict vulnerable", epoch 3 collapsed to
"always predict not vulnerable" -- the model flipping between the two
degenerate priors because it can't find real signal in a chunk of the data.

Run from C:\\reposcanner with the venv active:
    python check_truncation.py
(as its own file, not `python -c "..."`, per the PowerShell quoting note)
"""

from __future__ import annotations

from transformers import AutoTokenizer

from vulnscan.training.dataset import build_examples
from vulnscan.dataset.cvefixes_loader import get_pairs

DATASET_DB = "data/cvefixes_v2.duckdb"
BASE_MODEL = "microsoft/codebert-base"
MAX_LENGTH = 512


def main() -> None:
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    pairs = get_pairs(DATASET_DB, language="python")
    print(f"Loaded {len(pairs)} pairs from {DATASET_DB}\n")

    over_limit = 0          # either side alone exceeds max_length before truncation
    identical_after_trunc = 0  # the actual failure mode: truncated ids are byte-identical
    checked = 0

    for p in pairs:
        before, after = p.get("func_before"), p.get("func_after")
        if not before or not after:
            continue
        checked += 1

        before_ids_full = tokenizer(before, truncation=False)["input_ids"]
        after_ids_full = tokenizer(after, truncation=False)["input_ids"]
        if len(before_ids_full) > MAX_LENGTH or len(after_ids_full) > MAX_LENGTH:
            over_limit += 1

        before_ids_trunc = tokenizer(
            before, truncation=True, max_length=MAX_LENGTH
        )["input_ids"]
        after_ids_trunc = tokenizer(
            after, truncation=True, max_length=MAX_LENGTH
        )["input_ids"]
        if before_ids_trunc == after_ids_trunc:
            identical_after_trunc += 1

    print(f"Pairs checked: {checked}")
    print(f"Pairs where at least one side exceeds {MAX_LENGTH} tokens untruncated: "
          f"{over_limit} ({100 * over_limit / checked:.1f}%)")
    print(f"Pairs that become IDENTICAL input after truncation to {MAX_LENGTH} "
          f"(contradictory label signal): {identical_after_trunc} "
          f"({100 * identical_after_trunc / checked:.1f}%)")
    print()
    if identical_after_trunc / checked > 0.05:
        print("=> Meaningful fraction of contradictory examples. This is very "
              "likely a real contributor to the non-convergence. Consider: "
              "raising max_length (up to the model's real limit, 512 for "
              "codebert-base -- so this specific model can't go higher), "
              "filtering out these pairs entirely, or truncating around the "
              "diff location instead of from the start.")
    else:
        print("=> Truncation collapse affects only a small fraction of pairs. "
              "Probably not the main driver -- worth ruling out other things "
              "(e.g. the diff-aware/paired-input architecture question) next.")


if __name__ == "__main__":
    main()