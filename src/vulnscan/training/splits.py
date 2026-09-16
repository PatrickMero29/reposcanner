"""Grouped train/val/test splits by (repo, cve_id).

Splitting by pair_id still leaks: multiple functions from the same advisory
and repo can land on both sides. Grouping by (repo, cve_id) keeps a whole
advisory on one side — the Chakraborty-style leakage the README cites.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from .dataset import PairExample

SPLIT_NAMES = ("train", "val", "test")


def group_key(pair: PairExample) -> tuple[str, str]:
    repo = pair.repo or ""
    cve = pair.cve_id or pair.pair_id
    return (repo, cve)


def train_val_test_split_grouped(
    pairs: list[PairExample],
    *,
    train_fraction: float = 0.70,
    val_fraction: float = 0.15,
    seed: int = 42,
) -> tuple[list[PairExample], list[PairExample], list[PairExample]]:
    """Split unique (repo, cve_id) groups ~70/15/15. All pairs from one
    group stay on one side. Remaining mass after train+val is test."""
    groups: dict[tuple[str, str], list[PairExample]] = {}
    for p in pairs:
        groups.setdefault(group_key(p), []).append(p)

    keys = sorted(groups)
    rng = random.Random(seed)
    rng.shuffle(keys)

    n = len(keys)
    n_train = int(round(n * train_fraction)) if n else 0
    n_val = int(round(n * val_fraction)) if n else 0
    if n and n_train + n_val >= n:
        n_val = max(0, n - n_train - 1) if n_train < n else 0
        if n_train >= n and n > 1:
            n_train = n - 1
            n_val = 0
    n_test = n - n_train - n_val

    train_keys = set(keys[:n_train])
    val_keys = set(keys[n_train:n_train + n_val])
    test_keys = set(keys[n_train + n_val:n_train + n_val + n_test])

    train = [p for k in keys if k in train_keys for p in groups[k]]
    val = [p for k in keys if k in val_keys for p in groups[k]]
    test = [p for k in keys if k in test_keys for p in groups[k]]
    return train, val, test


def pair_ids(pairs: list[PairExample]) -> list[str]:
    return [p.pair_id for p in pairs]


def save_splits(
    out_dir: str | Path,
    train: list[str],
    val: list[str],
    test: list[str],
) -> Path:
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    mapping = {"train": train, "val": val, "test": test}
    for name, ids in mapping.items():
        (dest / f"{name}_pair_ids.json").write_text(
            json.dumps(ids, indent=2), encoding="utf-8",
        )
    return dest


def load_split_ids(path: str | Path) -> list[str]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("pair_ids", raw.get("ids", []))
    return [str(x) for x in raw]


def load_splits_dir(split_dir: str | Path) -> dict[str, list[str]]:
    root = Path(split_dir)
    return {
        name: load_split_ids(root / f"{name}_pair_ids.json")
        for name in SPLIT_NAMES
    }


def splits_exist(split_dir: str | Path) -> bool:
    root = Path(split_dir)
    return all((root / f"{name}_pair_ids.json").exists() for name in SPLIT_NAMES)


def apply_split_ids(
    pairs: list[PairExample], ids: list[str]
) -> list[PairExample]:
    wanted = set(ids)
    return [p for p in pairs if p.pair_id in wanted]
