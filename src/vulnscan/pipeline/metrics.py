"""Phase 4 of the benchmark: roll judged.json + diff.json up into
detection/noise/CWE-attribution numbers for a run.

Two genuinely different questions get answered here, and they must not be
collapsed into one "precision" number -- confirmed empirically (see
data/experiments/20 vs earlier runs) that doing so is actively misleading:

  1. DETECTION: did the classifier flag the vulnerable version at all?
     -> detection_rate = pairs_with_any_vuln_only_finding / total_pairs
     -> noise_rate = benign_only findings / total_pairs (flagged the FIXED
        version too -- a real false-alarm signal, needs no CWE ground truth)
     These need no CWE data at all and are directly trustworthy.

  2. CWE ATTRIBUTION: of the findings we could check, did the CWE we have
     for that finding match the pair's real labeled CWE?
     -> cwe_confirmed_precision / cwe_confirmed_recall / cwe_confirmed_f1
     BUT: the local classifier (local_model/inference.py) predicts no CWE at
     all -- the CWE checked here almost always comes from CVE-retrieval
     enrichment (analyzer.py's embedding search over historical CVEs), which
     is a much weaker, noisier signal than the classifier's own vulnerable/
     not-vulnerable call. Confirmed empirically on a real run: findings
     judged "CWE mismatch" had ~the same average classifier confidence
     (0.862) as findings judged "CWE match" (0.871), and 82% of mismatches
     were still >0.7 confidence -- strong evidence these are largely correct
     detections with a wrong retrieval-guessed CWE, not bad detections. Read
     cwe_confirmed_* as "how good is our CWE guess," not "how often is the
     classifier wrong" -- that second question is what detection_rate and
     noise_rate above are for.

Definitions (function-pair level, matching the original ZeroPath
methodology):
  * True Positive  — a pair with at least one vuln_only finding judged
                      is_cve_correct == True.
  * False Negative  — a pair with zero vuln_only findings, or vuln_only
                      findings that were all judged incorrect/unconfirmed.
  * False Positive  — a vuln_only finding judged is_cve_correct == False,
                      counted per-finding (not per-pair) since a single pair
                      can produce multiple incorrect findings.
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

    detection_rate = pairs_with_any_vuln_only_finding / total_pairs if total_pairs > 0 else 0.0
    noise_rate = benign_only_count / total_pairs if total_pairs > 0 else 0.0

    cwe_confirmed_precision = (
        true_positive_pairs / (true_positive_pairs + false_positive_findings)
        if (true_positive_pairs + false_positive_findings) > 0 else 0.0
    )
    cwe_confirmed_recall = true_positive_pairs / total_pairs if total_pairs > 0 else 0.0
    cwe_confirmed_f1 = (
        2 * cwe_confirmed_precision * cwe_confirmed_recall / (cwe_confirmed_precision + cwe_confirmed_recall)
        if (cwe_confirmed_precision + cwe_confirmed_recall) > 0 else 0.0
    )

    return {
        "total_pairs": total_pairs,
        # Trustworthy on their own -- no CWE ground truth needed.
        "pairs_with_any_vuln_only_finding": pairs_with_any_vuln_only_finding,
        "detection_rate": round(detection_rate, 4),
        "benign_only_findings_total": benign_only_count,
        "noise_rate": round(noise_rate, 4),
        # CWE-attribution accuracy, conditioned on retrieval enrichment's CWE
        # guess -- NOT a general false-alarm rate. See module docstring.
        "true_positive_pairs": true_positive_pairs,
        "false_negative_pairs": false_negative_pairs,
        "false_positive_findings": false_positive_findings,
        "cwe_confirmed_precision": round(cwe_confirmed_precision, 4),
        "cwe_confirmed_recall": round(cwe_confirmed_recall, 4),
        "cwe_confirmed_f1": round(cwe_confirmed_f1, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark phase 4: compute detection/noise/CWE-attribution numbers.")
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