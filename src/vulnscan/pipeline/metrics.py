"""Phase 4 of the benchmark: roll judged.json + diff.json up into
precision/recall/F1 numbers for a run.

Definitions used here (function-pair level, matching the original ZeroPath
methodology):
  * True Positive  — a pair with at least one vuln_only finding judged
                      is_cve_correct == True.
  * False Negative  — a pair with zero vuln_only findings, or vuln_only
                      findings that were all judged incorrect.
  * False Positive  — a vuln_only finding judged is_cve_correct == False,
                      counted per-finding (not per-pair) since a single pair
                      can produce multiple incorrect findings.
  * benign_only findings are reported separately as "post-fix false
    positives" — informative, but not part of precision/recall since they
    have no ground truth to be judged against.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

logger = logging.getLogger("vulnscan.pipeline.metrics")


def compute_metrics(*, diff_json_path: str, judged_json_path: str, total_pairs: int) -> dict:
    diff_results = json.loads(Path(diff_json_path).read_text(encoding="utf-8"))
    judged_results = {r["pair_id"]: r["judged_findings"] for r in json.loads(Path(judged_json_path).read_text(encoding="utf-8"))}

    true_positive_pairs = 0
    false_positive_findings = 0
    benign_only_count = 0
    pairs_with_any_vuln_only_finding = 0

    for entry in diff_results:
        pair_id = entry["pair_id"]
        vuln_only = entry.get("vuln_only", [])
        benign_only_count += len(entry.get("benign_only", []))
        if vuln_only:
            pairs_with_any_vuln_only_finding += 1

        judged = judged_results.get(pair_id, [])
        pair_has_correct = any(j.get("is_cve_correct") is True for j in judged)
        false_positive_findings += sum(1 for j in judged if j.get("is_cve_correct") is False)
        if pair_has_correct:
            true_positive_pairs += 1

    false_negative_pairs = total_pairs - true_positive_pairs

    precision = (
        true_positive_pairs / (true_positive_pairs + false_positive_findings)
        if (true_positive_pairs + false_positive_findings) > 0 else 0.0
    )
    recall = true_positive_pairs / total_pairs if total_pairs > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "total_pairs": total_pairs,
        "true_positive_pairs": true_positive_pairs,
        "false_negative_pairs": false_negative_pairs,
        "false_positive_findings": false_positive_findings,
        "pairs_with_any_vuln_only_finding": pairs_with_any_vuln_only_finding,
        "benign_only_findings_total": benign_only_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark phase 4: compute precision/recall/F1.")
    parser.add_argument("diff_json")
    parser.add_argument("judged_json")
    parser.add_argument("--total-pairs", type=int, required=True, help="Total pairs evaluated in the run.")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    metrics = compute_metrics(
        diff_json_path=args.diff_json, judged_json_path=args.judged_json, total_pairs=args.total_pairs
    )
    print(json.dumps(metrics, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(metrics, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
