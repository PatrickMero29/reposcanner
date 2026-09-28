"""Builds a binary vulnerable/not-vulnerable training set from the `pairs`
table (see dataset/cvefixes_loader.py) — deliberately dependency-light and
torch-free, so this module's logic is fully unit-testable without the `ml`
extra installed.

Label convention (must match local_model/inference.py's
_VULNERABLE_LABEL_INDEX = 1):
    label 0 = not vulnerable  (func_after  — the fixed version)
    label 1 = vulnerable      (func_before — the vulnerable version)

Split strategy: the pairwise trainer groups by (repo, cve_id) so a whole
advisory stays on one side of train/val/test (see training/splits.py).
The row-level helpers below still split by pair_id so a function's
vulnerable and fixed versions never land on opposite sides.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

from ..dataset.cvefixes_loader import get_pairs
from ..dataset.filters import contains_sink, is_test_function, is_test_path


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
    cve_id: str = ""
    cwe_ids: str = ""
    repo: str = ""
    file_path: str = ""
    function_name: str = ""
    extra: dict = field(default_factory=dict)


def build_pairs(dataset_db_path: str, *, language: str = "python") -> list[PairExample]:
    pairs = get_pairs(dataset_db_path, language=language)
    out: list[PairExample] = []
    for p in pairs:
        before, after = p.get("func_before"), p.get("func_after")
        if not before or not after:
            continue
        if before == after:
            continue
        if is_test_path(p.get("file_path")) or is_test_function(p.get("function_name")):
            continue
        out.append(PairExample(
            pair_id=p["pair_id"],
            before_code=before,
            after_code=after,
            cve_id=p.get("cve_id") or "",
            cwe_ids=p.get("cwe_ids") or "",
            repo=p.get("repo") or "",
            file_path=p.get("file_path") or "",
            function_name=p.get("function_name") or "",
        ))
    return out


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


def load_generic_negatives(path: str, *, strip_sinks: bool = True) -> list[str]:
    """Loads a jsonl file of {"code": ...} objects (see
    fetch_codesearchnet_negatives.py) -- diverse, unrelated "probably safe"
    code used to augment pairwise training with negatives that aren't just
    a specific CVE's fixed version. Weak labels, not ground truth -- see
    that script's docstring for the caveat.

    strip_sinks: drop snippets that themselves contain execute/eval/pickle/
    subprocess/etc. Weak "safe" labels that contain those sinks are not safe.
    """
    negatives: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            code = obj.get("code")
            if not code:
                continue
            if strip_sinks and contains_sink(code):
                continue
            negatives.append(code)
    return negatives


def load_curated_pairs(path: str) -> list[PairExample]:
    """Loads a jsonl file of {"vulnerable": ..., "safe": ...} objects (see
    fetch_codesearchnet_negatives.py's _CURATED_VULNERABLE_SAFE_PAIRS) --
    explicit hand-written vulnerable/safe contrasts on the SAME pattern
    (e.g. string-concatenated vs parameterized SQL), for cases where the
    model has learned the safe side of a pattern but not the vulnerable
    side (or vice versa) and needs the direct contrast rather than more
    standalone examples of whichever side it already has right.
    """
    pairs: list[PairExample] = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            pairs.append(PairExample(
                pair_id=f"curated:{i}",
                before_code=obj["vulnerable"],
                after_code=obj["safe"],
            ))
    return pairs
