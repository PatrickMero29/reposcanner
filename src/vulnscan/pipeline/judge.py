"""Phase 3 of the benchmark: for every `vuln_only` finding (present in the
vulnerable version, absent from the fixed version — see diff_judge.py),
decide whether it actually corresponds to the pair's labeled CVE/CWE, using
an LLM judge with the ground-truth CWE/commit message as reference. This is
what turns "the model found *something*" into "the model found *the*
labeled vulnerability" for precision/recall purposes.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path

from pydantic import BaseModel, Field

from ..config import settings
from ..dataset.cvefixes_loader import get_pairs
from ..anthropic_client import generate_structured

logger = logging.getLogger("vulnscan.pipeline.judge")


class CVEJudgment(BaseModel):
    matches_labeled_cve: bool = Field(
        ..., description="Does this finding describe the same vulnerability as the ground-truth CVE/CWE/commit?"
    )
    reasoning: str = Field(..., description="Brief justification for the verdict.")


def _judge_prompt(*, finding: dict, cve_id: str | None, cwe_ids: str | None, commit_message: str | None) -> str:
    return f"""You are checking whether a vulnerability finding correctly identifies a known,
labeled vulnerability, or whether it's a different (possibly still valid) issue that happens
to be in the same function.

Ground truth for this function:
- CVE: {cve_id or "unknown"}
- CWE(s): {cwe_ids or "unknown"}
- Fix commit message: {commit_message or "unknown"}

Finding to judge (JSON):
{json.dumps(finding, indent=2)}

Does this finding describe the same underlying vulnerability as the ground truth above? \
Match on the type of flaw and the root cause, not on exact wording. If the ground truth is \
too sparse to tell either way, prefer `matches_labeled_cve: false` and explain why in \
`reasoning`."""


async def judge_pair(*, pair_id: str, vuln_only_findings: list[dict], ground_truth: dict) -> list[dict]:
    judged = []
    for finding in vuln_only_findings:
        prompt = _judge_prompt(
            finding=finding,
            cve_id=ground_truth.get("cve_id"),
            cwe_ids=ground_truth.get("cwe_ids"),
            commit_message=ground_truth.get("commit_message"),
        )
        try:
            result = await generate_structured(
                prompt=prompt, response_schema=CVEJudgment, model=settings.verifier_model
            )
            judged.append({"finding": finding, "is_cve_correct": result.matches_labeled_cve, "reasoning": result.reasoning})
        except Exception as exc:  # noqa: BLE001
            logger.exception("Judging failed for pair %s", pair_id)
            judged.append({"finding": finding, "is_cve_correct": None, "reasoning": f"judge_error: {exc}"})
    return judged


async def run_judge(*, diff_json_path: str, dataset_db_path: str, out_path: str, language: str = "python") -> str:
    diff_results = json.loads(Path(diff_json_path).read_text(encoding="utf-8"))
    pairs = {p["pair_id"]: p for p in get_pairs(dataset_db_path, language=language)}

    tasks = []
    pair_ids_in_order = []
    for entry in diff_results:
        pair_id = entry["pair_id"]
        vuln_only = entry.get("vuln_only", [])
        if not vuln_only:
            continue
        ground_truth = pairs.get(pair_id, {})
        tasks.append(judge_pair(pair_id=pair_id, vuln_only_findings=vuln_only, ground_truth=ground_truth))
        pair_ids_in_order.append(pair_id)

    logger.info("Judging vuln_only findings for %d pairs...", len(tasks))
    results_per_pair = await asyncio.gather(*tasks)

    output = [
        {"pair_id": pair_id, "judged_findings": judged}
        for pair_id, judged in zip(pair_ids_in_order, results_per_pair)
    ]
    Path(out_path).write_text(json.dumps(output, indent=2), encoding="utf-8")
    logger.info("Wrote judged findings to %s", out_path)
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark phase 3: judge vuln_only findings against CVE ground truth.")
    parser.add_argument("diff_json", help="Path to diff.json from diff_judge.py")
    parser.add_argument("--dataset-db", default=None)
    parser.add_argument("--language", default="python")
    parser.add_argument("--out", default=None, help="Defaults to <run_dir>/judged.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    out_path = args.out or str(Path(args.diff_json).parent / "judged.json")
    asyncio.run(run_judge(
        diff_json_path=args.diff_json,
        dataset_db_path=args.dataset_db or settings.dataset_db_path,
        out_path=out_path,
        language=args.language,
    ))


if __name__ == "__main__":
    main()
