"""Phase 2 of the benchmark: for each pair, match findings from the "before"
(vulnerable) and "after" (fixed) analysis runs to bucket them:

  * vuln_only   — found in "before" but not "after": the analyzer likely
                  caught the actual CVE (candidate true positive; judge.py
                  checks this against ground truth next).
  * shared      — found in both before and after: probably an unrelated
                  pattern in the function, not the fix-relevant vuln. Not
                  scored against the CVE.
  * benign_only — found in "after" but not "before": the analyzer flagged
                  something in the *fixed* code that wasn't there originally
                  — usually a false positive, or occasionally a real
                  regression introduced by the fix. Reported but not scored
                  as a benchmark hit.

Matching two findings is inherently fuzzy (there's no stable ID for "the same
vulnerability" across two similar-but-different code versions), so this uses
a simple, tunable heuristic: CWE overlap plus text similarity of the
description. Swap `_findings_match` for an LLM-judged match if you need
higher fidelity than that heuristic gives you.
"""

from __future__ import annotations

import argparse
import json
import logging
from difflib import SequenceMatcher
from pathlib import Path

from ..schemas import DiffCategory

logger = logging.getLogger("vulnscan.pipeline.diff_judge")

DESCRIPTION_SIMILARITY_THRESHOLD = 0.6


def _findings_match(a: dict, b: dict) -> bool:
    a_op, b_op = a["undesired_operation"], b["undesired_operation"]
    cwe_a, cwe_b = set(a_op.get("cwe_ids", [])), set(b_op.get("cwe_ids", []))
    if cwe_a and cwe_b and cwe_a & cwe_b:
        return True
    similarity = SequenceMatcher(None, a_op["description"], b_op["description"]).ratio()
    return similarity >= DESCRIPTION_SIMILARITY_THRESHOLD


def diff_pair(before_findings: list[dict], after_findings: list[dict]) -> dict[str, list[dict]]:
    matched_after_indices: set[int] = set()
    vuln_only, shared = [], []

    for bf in before_findings:
        match_found = False
        for j, af in enumerate(after_findings):
            if j in matched_after_indices:
                continue
            if _findings_match(bf, af):
                matched_after_indices.add(j)
                match_found = True
                break
        (shared if match_found else vuln_only).append(bf)

    benign_only = [af for j, af in enumerate(after_findings) if j not in matched_after_indices]

    return {
        DiffCategory.VULN_ONLY.value: vuln_only,
        DiffCategory.SHARED.value: shared,
        DiffCategory.BENIGN_ONLY.value: benign_only,
    }


def run_diff_judge(analysis_json_path: str, out_path: str) -> str:
    records = json.loads(Path(analysis_json_path).read_text(encoding="utf-8"))

    by_pair: dict[str, dict[str, list[dict]]] = {}
    for record in records:
        by_pair.setdefault(record["pair_id"], {})[record["variant"]] = record["findings"]

    results = []
    for pair_id, variants in by_pair.items():
        before = variants.get("before", [])
        after = variants.get("after", [])
        categorized = diff_pair(before, after)
        results.append({"pair_id": pair_id, **categorized})

    Path(out_path).write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info("Wrote diff results for %d pairs to %s", len(results), out_path)
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark phase 2: diff before/after findings.")
    parser.add_argument("analysis_json", help="Path to analysis.json from run_analysis.py")
    parser.add_argument("--out", default=None, help="Defaults to <run_dir>/diff.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    out_path = args.out or str(Path(args.analysis_json).parent / "diff.json")
    run_diff_judge(args.analysis_json, out_path)


if __name__ == "__main__":
    main()
