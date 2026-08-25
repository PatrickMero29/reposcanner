"""Phase 3 of the benchmark: for every `vuln_only` finding (present in the
vulnerable version, absent from the fixed version -- see diff_judge.py),
decide whether it actually corresponds to the pair's labeled CVE/CWE.

This is a purely local, deterministic heuristic -- NOT an LLM/API call. The
original version of this file called out to `anthropic_client.generate_structured`,
but that module was never migrated into this repo and doesn't exist here --
and more importantly, this project has a firm, explicit policy of zero paid
API dependency (see HANDOFF.md §1: "Never suggest reintroducing an LLM API
... that door is closed permanently"). So rather than build that client,
this phase is redone as a local CWE-overlap heuristic instead, matching the
same spirit (and literally the same technique) diff_judge.py already uses to
match before/after findings to each other.

Two real data-shape gotchas this has to work around (found by actually
checking the data, not assumed from the schema):

  1. `local_model/inference.py` always sets `cwe_ids=[]` on every finding --
     it's a binary vulnerable/not-vulnerable classifier with no CWE
     prediction (see that module's own docstring). So a naive check against
     `finding["undesired_operation"]["cwe_ids"]` would never find anything.
     BUT `analyzer.py`'s CVE-retrieval enrichment (when enabled and it finds
     a similar historical CVE) writes real "CWE-XXX" mentions straight into
     the finding's free-text `description` (see analyzer.py's
     `_format_cve_evidence`) -- so this pulls CWE mentions out of the full
     description text via regex as a practical stand-in for structured
     per-finding CWE data, instead of only trusting the (currently always
     empty) `cwe_ids` field.
  2. CVEfixes' own `cwe_classification` table is incomplete: some pairs have
     no row at all, and NVD represents "we don't actually know the CWE" as
     the literal strings "NVD-CWE-noinfo" / "NVD-CWE-Other" rather than
     leaving the field blank (confirmed empirically: ~19% of loaded Python
     pairs in a real run of this dataset). A naive comma-split would treat
     those placeholders as real CWE labels and report a false "mismatch"
     instead of "no usable ground truth." The same CWE-XXX regex used above
     naturally filters these out (they have no CWE-<number> substring to
     match), so this uses the one regex-based parser for both sides.

When there's no usable CWE data on either side (finding or ground truth),
this reports `is_cve_correct: None` -- "can't judge" -- rather than guessing
from surface text similarity against the classifier's largely-boilerplate
description. That guess would be dominated by fixed template wording (see
inference.py's description string) and add noise, not signal; an honest
"unjudged" is more useful than a fabricated verdict. metrics.py already
treats `None` as neither a true nor a false positive, so these pairs fall
out as false negatives -- a fair, conservative default given how little the
current binary classifier tells us. Revisit this once/if the classifier or
its enrichment reliably surfaces real CWE information (see
architecture.txt's Phase 6/7 confidence-ranked CWE classification).
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path

from ..config import settings
from ..dataset.cvefixes_loader import get_pairs

logger = logging.getLogger("vulnscan.pipeline.judge")

_CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


def _extract_cwe_ids(raw: str | list[str] | None) -> set[str]:
    """Pulls real CWE-<number> tokens out of a field that might be a list, a
    comma-separated string, or a chunk of free-text prose -- and, just as
    importantly, drops anything that *isn't* a real CWE code (NVD's
    "NVD-CWE-noinfo"/"NVD-CWE-Other" placeholders, empty strings, etc.),
    since those have no CWE-<number> substring for the regex to match.
    """
    if not raw:
        return set()
    text = ",".join(str(c) for c in raw) if isinstance(raw, list) else str(raw)
    return {m.upper() for m in _CWE_PATTERN.findall(text)}


def judge_finding(*, finding: dict, ground_truth: dict) -> dict:
    """Returns {"is_cve_correct": bool | None, "reasoning": str}."""
    undesired = finding.get("undesired_operation", {})
    description = undesired.get("description") or ""

    finding_cwes = _extract_cwe_ids(undesired.get("cwe_ids"))
    if not finding_cwes:
        # cwe_ids itself is always [] from the current classifier -- fall
        # back to whatever CVE-retrieval enrichment wrote into the
        # description (see module docstring, gotcha #1).
        finding_cwes = _extract_cwe_ids(description)

    truth_cwes = _extract_cwe_ids(ground_truth.get("cwe_ids"))

    if not truth_cwes:
        return {
            "is_cve_correct": None,
            "reasoning": "ground truth has no usable CWE label for this pair "
                         "(missing, or an NVD placeholder like NVD-CWE-noinfo) -- can't judge",
        }
    if not finding_cwes:
        return {
            "is_cve_correct": None,
            "reasoning": "finding has no CWE signal (classifier doesn't predict one, and "
                         "CVE-retrieval enrichment found nothing to extract one from) -- can't judge",
        }

    shared = finding_cwes & truth_cwes
    if shared:
        return {"is_cve_correct": True, "reasoning": f"CWE overlap: {sorted(shared)}"}
    return {
        "is_cve_correct": False,
        "reasoning": f"CWE mismatch: finding={sorted(finding_cwes)}, ground truth={sorted(truth_cwes)}",
    }


def judge_pair(*, pair_id: str, vuln_only_findings: list[dict], ground_truth: dict) -> list[dict]:
    judged = []
    for finding in vuln_only_findings:
        try:
            result = judge_finding(finding=finding, ground_truth=ground_truth)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Judging failed for pair %s", pair_id)
            result = {"is_cve_correct": None, "reasoning": f"judge_error: {exc}"}
        judged.append({"finding": finding, **result})
    return judged


def run_judge(*, diff_json_path: str, dataset_db_path: str, out_path: str, language: str = "python") -> str:
    diff_results = json.loads(Path(diff_json_path).read_text(encoding="utf-8"))
    pairs = {p["pair_id"]: p for p in get_pairs(dataset_db_path, language=language)}

    output = []
    for entry in diff_results:
        pair_id = entry["pair_id"]
        vuln_only = entry.get("vuln_only", [])
        if not vuln_only:
            continue
        ground_truth = pairs.get(pair_id, {})
        judged = judge_pair(pair_id=pair_id, vuln_only_findings=vuln_only, ground_truth=ground_truth)
        output.append({"pair_id": pair_id, "judged_findings": judged})

    logger.info("Judged vuln_only findings for %d pairs.", len(output))
    Path(out_path).write_text(json.dumps(output, indent=2), encoding="utf-8")
    logger.info("Wrote judged findings to %s", out_path)
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark phase 3: judge vuln_only findings against CVE ground truth (local CWE-overlap heuristic, no API)."
    )
    parser.add_argument("diff_json", help="Path to diff.json from diff_judge.py")
    parser.add_argument("--dataset-db", default=None)
    parser.add_argument("--language", default="python")
    parser.add_argument("--out", default=None, help="Defaults to <run_dir>/judged.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    out_path = args.out or str(Path(args.diff_json).parent / "judged.json")
    run_judge(
        diff_json_path=args.diff_json,
        dataset_db_path=args.dataset_db or settings.dataset_db_path,
        out_path=out_path,
        language=args.language,
    )


if __name__ == "__main__":
    main()