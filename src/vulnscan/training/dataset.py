"""Builds a binary vulnerable/not-vulnerable training set from the `pairs`
table (see dataset/cvefixes_loader.py) — deliberately dependency-light and
torch-free, so this module's logic is fully unit-testable without the `ml`
extra installed.

Label convention (must match local_model/inference.py's
_VULNERABLE_LABEL_INDEX = 1):
    label 0 = not vulnerable  (func_after  — the fixed version)
    label 1 = vulnerable      (func_before — the vulnerable version)

Split strategy: splitting by row would leak near-duplicate before/after
pairs of the SAME underlying function across train/val, letting the model
"cheat" by memorizing surface patterns rather than learning to generalize —
exactly the failure mode called out in architecture.txt's research-critique
notes. Splitting by pair_id keeps every (before, after) pair entirely on one
side of the split.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from ..dataset.cvefixes_loader import get_pairs


@dataclass
class Example:
    pair_id: str
    code: str
    label: int  # 0 = not vulnerable, 1 = vulnerable


def build_examples(dataset_db_path: str, *, language: str = "python") -> list[Example]:
    pairs = get_pairs(dataset_db_path, language=language)
    examples: list[Example] = []
    for p in pairs:
        if p.get("func_before"):
            examples.append(Example(pair_id=p["pair_id"], code=p["func_before"], label=1))
        if p.get("func_after"):
            examples.append(Example(pair_id=p["pair_id"], code=p["func_after"], label=0))
    return examples


def train_val_split(
    examples: list[Example], *, val_fraction: float = 0.15, seed: int = 42
) -> tuple[list[Example], list[Example]]:
    """Splits by pair_id (not by row) so a pair's vulnerable/fixed versions
    never end up on opposite sides of the split."""
    pair_ids = sorted({e.pair_id for e in examples})
    rng = random.Random(seed)
    rng.shuffle(pair_ids)

    val_count = max(1, round(len(pair_ids) * val_fraction)) if pair_ids else 0
    val_pair_ids = set(pair_ids[:val_count])

    train = [e for e in examples if e.pair_id not in val_pair_ids]
    val = [e for e in examples if e.pair_id in val_pair_ids]
    return train, val


@dataclass
class PairExample:
    """A (before, after) pair kept together, for pairwise-ranking training
    (see training/train.py's train_model_pairwise) rather than the
    independent-classification path above. Each row in the `pairs` table
    already stores both sides of the fix together, so unlike Example this
    needs no reconstruction/grouping step.
    """
    pair_id: str
    before_code: str
    after_code: str


def build_pairs(dataset_db_path: str, *, language: str = "python") -> list[PairExample]:
    pairs = get_pairs(dataset_db_path, language=language)
    return [
        PairExample(pair_id=p["pair_id"], before_code=p["func_before"], after_code=p["func_after"])
        for p in pairs
        if p.get("func_before") and p.get("func_after")
    ]


def train_val_split_pairs(
    pairs: list[PairExample], *, val_fraction: float = 0.15, seed: int = 42
) -> tuple[list[PairExample], list[PairExample]]:
    rng = random.Random(seed)
    order = list(range(len(pairs)))
    rng.shuffle(order)

    val_count = max(1, round(len(pairs) * val_fraction)) if pairs else 0
    val_idx = set(order[:val_count])

    train = [p for i, p in enumerate(pairs) if i not in val_idx]
    val = [p for i, p in enumerate(pairs) if i in val_idx]
    return train, val