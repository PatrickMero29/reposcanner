"""Phase 1 of the benchmark: run the analyzer over every function in the
dataset, both the vulnerable ("before") and fixed ("after") versions of each
pair, at a given justification level. Mirrors the original repo's
`analyze.py`, generalized across languages via `schemas.Language`.

Output: one JSON file per run under
    data/experiments/<level>/runs/<run_number>/analysis.json
containing a flat list of {pair_id, variant: "before"|"after", findings: [...]}.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path

from ..analyzer import analyze
from ..config import settings
from ..dataset.cvefixes_loader import get_pairs
from ..schemas import Finding, JustificationLevel, Language

logger = logging.getLogger("vulnscan.pipeline.run_analysis")


async def _analyze_pair_variant(
    *, pair_id: str, variant: str, code: str, function_name: str,
    language: Language, level: JustificationLevel, semaphore: asyncio.Semaphore,
) -> dict:
    async with semaphore:
        try:
            findings: list[Finding] = await analyze(
                code=code, function_name=function_name, language=language, level=level
            )
            return {
                "pair_id": pair_id,
                "variant": variant,
                "findings": [f.model_dump(mode="json") for f in findings],
                "error": None,
            }
        except Exception as exc:  # noqa: BLE001
            logger.exception("Analysis failed for pair %s (%s)", pair_id, variant)
            return {"pair_id": pair_id, "variant": variant, "findings": [], "error": str(exc)}


async def run_analysis(
    *,
    dataset_db_path: str,
    level: JustificationLevel,
    run_dir: str,
    language: str = "python",
    limit: int | None = None,
    max_concurrency: int | None = None,
) -> str:
    pairs = get_pairs(dataset_db_path, language=language, limit=limit)
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
            function_name=function_name, language=lang, level=level, semaphore=semaphore,
        ))
        tasks.append(_analyze_pair_variant(
            pair_id=pair["pair_id"], variant="after", code=pair["func_after"],
            function_name=function_name, language=lang, level=level, semaphore=semaphore,
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
    parser.add_argument("--level", choices=[l.value for l in JustificationLevel], required=True)
    parser.add_argument("--run-dir", required=True, help="e.g. data/experiments/extensive_justification/runs/1")
    parser.add_argument("--language", default="python")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dataset-db", default=None, help="Overrides VULNSCAN_DATASET_DB.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    asyncio.run(run_analysis(
        dataset_db_path=args.dataset_db or settings.dataset_db_path,
        level=JustificationLevel(args.level),
        run_dir=args.run_dir,
        language=args.language,
        limit=args.limit,
    ))


if __name__ == "__main__":
    main()
