"""Build the local CVE similarity index from the pairs dataset (see
dataset/cvefixes_loader.py — this reads whatever you've already loaded there,
whether from CVEfixes or a bring-your-own CSV).

Usage:
    python -m vulnscan.embedding.build_index --dataset-db data/cvefixes.duckdb --out data/cve_index
"""

from __future__ import annotations

import argparse
import logging

from ..dataset.cvefixes_loader import get_pairs
from .encoder import embed_texts
from .index import VectorIndex

logger = logging.getLogger("vulnscan.embedding.build_index")


def build_index(
    dataset_db_path: str, out_dir: str, *, language: str | None = None, limit: int | None = None
) -> str:
    pairs = get_pairs(dataset_db_path, language=language, limit=limit)
    if not pairs:
        raise ValueError(
            f"No pairs found in {dataset_db_path}"
            + (f" for language={language!r}" if language else "")
            + ". Load a dataset first (see dataset/cvefixes_loader.py)."
        )
    logger.info(
        "Embedding %d function pairs (first run downloads the model — cached afterward)...",
        len(pairs),
    )
    index = VectorIndex.build(pairs, embed_fn=embed_texts)
    index.save(out_dir)
    logger.info("Index ready at %s (%d entries).", out_dir, len(index.entries))
    return out_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the local CVE similarity index.")
    parser.add_argument("--dataset-db", required=True)
    parser.add_argument("--out", default="data/cve_index")
    parser.add_argument("--language", default=None)
    parser.add_argument("--limit", type=int, default=None, help="Cap the number of pairs embedded (useful for a quick test run).")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    build_index(args.dataset_db, args.out, language=args.language, limit=args.limit)


if __name__ == "__main__":
    main()
