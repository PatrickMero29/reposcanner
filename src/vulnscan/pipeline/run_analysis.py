"""Phase 1 of the benchmark: run the analyzer over every function in the
dataset, both the vulnerable ("before") and fixed ("after") versions of each
pair. Mirrors the original repo's `analyze.py`, generalized across languages
via `schemas.Language`.

Output: one JSON file per run under
    data/experiments/<run_number>/analysis.json
containing a flat list of {pair_id, variant: "before"|"after", findings: [...]}.

NOTE: this benchmarks the local classifier's own precision in isolation —
static_findings is left at its default (None) since there's no natural
per-pair Semgrep context in this benchmark setup, unlike the real scanner
path in scanner/scan_repo.py.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path

from ..analyzer import analyze_scored
from ..config import settings
from ..dataset.cvefixes_loader import get_pairs
from ..schemas import Finding, Language
from ..training.splits import load_split_ids

logger = logging.getLogger("vulnscan.pipeline.run_analysis")


async def _analyze_pair_variant(
    *, pair_id: str, variant: str, code: str, function_name: str,
    language: Language, semaphore: asyncio.Semaphore,
    repo: str | None = None, cwe_ids: str | None = None,
) -> dict:
    async with semaphore:
        try:
            findings: list[Finding]
            findings, prob, n_tokens = await analyze_scored(
                code=code, function_name=function_name, language=language, pair_id=pair_id
            )
            return {
                "pair_id": pair_id,
                "variant": variant,
                "findings": [f.model_dump(mode="json") for f in findings],
                "prob_vuln": prob,
                "n_tokens": n_tokens,
                "repo": repo,
                "cwe_ids": cwe_ids,
                "error": None,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception("Analysis failed for pair %s (%s)", pair_id, variant)
            return {
                "pair_id": pair_id, "variant": variant, "findings": [],
                "prob_vuln": None, "n_tokens": None, "error": str(exc),
            }


async def run_analysis(
    *,
    dataset_db_path: str,
    run_dir: str,
    language: str = "python",
    limit: int | None = None,
    max_concurrency: int | None = None,
    pair_ids_path: str | None = None,
) -> str:
    pair_ids = None
    if pair_ids_path:
        path = Path(pair_ids_path)
        if not path.exists():
            raise FileNotFoundError(
                f"pair-ids file not found: {pair_ids_path}. Run train-model first "
                "(writes data/splits/test_pair_ids.json) or pass --all-pairs."
            )
        pair_ids = load_split_ids(path)
        logger.info("Restricting bench-analyze to %d pair_ids from %s", len(pair_ids), pair_ids_path)
    pairs = get_pairs(dataset_db_path, language=language, limit=limit, pair_ids=pair_ids)
    if not pairs:
        raise ValueError(
            f"No pairs found in {dataset_db_path} for language={language!r}. "
            "Did you run the dataset loader first? See dataset/cvefixes_loader.py."
        )
    logger.info("Loaded %d pairs for language=%s", len(pairs), language)

    semaphore = asyncio.Semaphore(max_concurrency or settings.max_concurrency)
    tasks = []
    for pair in pairs:
        lang = Language(pair["language"])
        function_name = pair.get("function_name") or "unknown_function"
        tasks.append(_analyze_pair_variant(
            pair_id=pair["pair_id"], variant="before", code=pair["func_before"],
            function_name=function_name, language=lang, semaphore=semaphore,
            repo=pair.get("repo"), cwe_ids=pair.get("cwe_ids"),
        ))
        tasks.append(_analyze_pair_variant(
            pair_id=pair["pair_id"], variant="after", code=pair["func_after"],
            function_name=function_name, language=lang, semaphore=semaphore,
            repo=pair.get("repo"), cwe_ids=pair.get("cwe_ids"),
        ))

    logger.info("Running %d analyses (concurrency=%d)...", len(tasks), max_concurrency or settings.max_concurrency)
    results = await asyncio.gather(*tasks)

    out_dir = Path(run_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "analysis.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info("Wrote %d analysis records to %s", len(results), out_path)
    return str(out_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark phase 1: analyze all pairs.")
    parser.add_argument("--run-dir", required=True, help="e.g. data/experiments/1")
    parser.add_argument("--language", default="python")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dataset-db", default=None, help="Overrides VULNSCAN_DATASET_DB.")
    parser.add_argument("--pair-ids", default="data/splits/test_pair_ids.json")
    parser.add_argument("--all-pairs", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    asyncio.run(run_analysis(
        dataset_db_path=args.dataset_db or settings.dataset_db_path,
        run_dir=args.run_dir,
        language=args.language,
        limit=args.limit,
        pair_ids_path=None if args.all_pairs else args.pair_ids,
    ))


if __name__ == "__main__":
    main()