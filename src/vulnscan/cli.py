"""Unified CLI. Run with `vulnscan <command>` after `pip install -e .`, or
`python -m vulnscan.cli <command>`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from .config import settings


def _cmd_scan(args: argparse.Namespace) -> None:
    from .scanner.scan_repo import scan_repo
    from .scanner.report_json import write_json_report
    from .scanner.report_markdown import write_markdown_report

    report = asyncio.run(scan_repo(
        args.repo_path,
        use_semgrep_prefilter=not args.no_semgrep, semgrep_config=args.semgrep_config,
    ))
    print(f"Found {len(report.static_findings)} static finding(s), {len(report.ai_findings)} local-model finding(s).")
    if args.format in ("json", "both"):
        write_json_report(report, f"{args.out}.json")
        print(f"Wrote {args.out}.json")
    if args.format in ("markdown", "both"):
        write_markdown_report(report, f"{args.out}.md")
        print(f"Wrote {args.out}.md")


def _cmd_bench_load(args: argparse.Namespace) -> None:
    from .dataset.cvefixes_loader import load_from_csv, load_from_cvefixes_sqlite
    if args.csv:
        count = load_from_csv(args.csv, args.dataset_db, replace=args.replace)
    else:
        count = load_from_cvefixes_sqlite(args.cvefixes_sqlite, args.dataset_db, replace=args.replace)
    print(f"Loaded {count} pairs into {args.dataset_db}")


def _cmd_build_index(args: argparse.Namespace) -> None:
    from .embedding.build_index import build_index
    out = build_index(args.dataset_db, args.out, language=args.language, limit=args.limit)
    print(f"Index built at {out}")


def _cmd_train_model(args: argparse.Namespace) -> None:
    # train_model_pairwise() is the current, actively-used trainer (margin-
    # ranking + CE anchor). The old train_model() (independent classification)
    # never converges -- see src/vulnscan/training/train.py's module docstring
    # and HANDOFF §3 -- and is kept only for reference, not for actual use.
    from .training.train import train_model_pairwise
    out = train_model_pairwise(
        dataset_db_path=args.dataset_db, out_dir=args.out, base_model=args.base_model,
        language=args.language, epochs=args.epochs, batch_size=args.batch_size,
        learning_rate=args.learning_rate, val_fraction=args.val_fraction,
        generic_negatives_path=args.generic_negatives, generic_negative_ratio=args.generic_negative_ratio,
        curated_negatives_path=args.curated_negatives, curated_pairs_path=args.curated_pairs,
        ce_weight=args.ce_weight, margin=args.margin, seed=args.seed,
    )
    print(f"Trained model saved to {out}")


def _cmd_bench_analyze(args: argparse.Namespace) -> None:
    from .pipeline.run_analysis import run_analysis
    out = asyncio.run(run_analysis(
        dataset_db_path=args.dataset_db or settings.dataset_db_path,
        run_dir=args.run_dir, language=args.language, limit=args.limit,
        max_concurrency=args.max_concurrency,
    ))
    print(f"Wrote analysis results to {out}")


def _cmd_bench_diff(args: argparse.Namespace) -> None:
    from .pipeline.diff_judge import run_diff_judge
    out_path = args.out or str(Path(args.analysis_json).parent / "diff.json")
    out = run_diff_judge(args.analysis_json, out_path)
    print(f"Wrote diff results to {out}")


def _cmd_bench_judge(args: argparse.Namespace) -> None:
    from .pipeline.judge import run_judge
    out_path = args.out or str(Path(args.diff_json).parent / "judged.json")
    out = run_judge(
        diff_json_path=args.diff_json,
        dataset_db_path=args.dataset_db or settings.dataset_db_path,
        out_path=out_path, language=args.language,
    )
    print(f"Wrote judged findings to {out}")


def _cmd_bench_metrics(args: argparse.Namespace) -> None:
    from .pipeline.metrics import compute_metrics
    metrics = compute_metrics(
        diff_json_path=args.diff_json, judged_json_path=args.judged_json, total_pairs=args.total_pairs,
    )
    print(json.dumps(metrics, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(metrics, indent=2), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnscan")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan an arbitrary local repo for vulnerabilities.")
    p_scan.add_argument("repo_path")
    p_scan.add_argument("--out", default="scan_report")
    p_scan.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    p_scan.add_argument("--no-semgrep", action="store_true", help="Disable the semgrep pre-filter; analyze every function with the local model.")
    p_scan.add_argument(
        "--semgrep-config", action="append", default=None,
        help="Semgrep ruleset (default: 'p/security-audit', or SEMGREP_CONFIG in .env). "
             "Repeat this flag to combine multiple rulesets in one scan, e.g. "
             "--semgrep-config p/security-audit --semgrep-config p/secrets — or pass one "
             "comma-separated value.",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_load = sub.add_parser("bench-load", help="Load a labeled-vulnerability dataset into the local duckdb.")
    p_load.add_argument("--csv", default=None, help="Generic-format CSV (see dataset/cvefixes_loader.py docstring).")
    p_load.add_argument("--cvefixes-sqlite", default=None, help="Path to a downloaded CVEfixes.db.")
    p_load.add_argument("--dataset-db", required=True)
    p_load.add_argument("--replace", action="store_true")
    p_load.set_defaults(func=_cmd_bench_load)

    p_index = sub.add_parser("build-index", help="Build the local CVE similarity index for retrieval-grounded reporting.")
    p_index.add_argument("--dataset-db", required=True)
    p_index.add_argument("--out", default="data/cve_index")
    p_index.add_argument("--language", default=None)
    p_index.add_argument("--limit", type=int, default=None, help="Cap pairs embedded (useful for a quick test run).")
    p_index.set_defaults(func=_cmd_build_index)

    p_train = sub.add_parser("train-model", help="Fine-tune the local pairwise (margin-ranking + CE anchor) vulnerability classifier on your loaded dataset (runs on GPU if available).")
    p_train.add_argument("--dataset-db", required=True)
    p_train.add_argument("--out", required=True, help="e.g. models/vuln-classifier-v16 -- increment each run, per HANDOFF_2 §2.")
    p_train.add_argument("--base-model", default="microsoft/codebert-base")
    p_train.add_argument("--language", default="python")
    p_train.add_argument("--epochs", type=int, default=6)
    p_train.add_argument("--batch-size", type=int, default=8)
    p_train.add_argument("--learning-rate", type=float, default=2e-5)
    p_train.add_argument("--val-fraction", type=float, default=0.15, help="Fraction of pairs (split by pair_id, not row) held out for validation.")
    p_train.add_argument("--margin", type=float, default=1.0)
    p_train.add_argument("--ce-weight", type=float, default=1.0, help="Weight on the cross-entropy anchor term; don't set to 0 (reproduces the old calibration-drift bug, see HANDOFF_2 §3).")
    p_train.add_argument("--seed", type=int, default=42)
    p_train.add_argument("--generic-negatives", default="data/codesearchnet_negatives.jsonl", help="Path from fetch_codesearchnet_negatives.py; subject to train/val split each run.")
    p_train.add_argument("--generic-negative-ratio", type=float, default=1.0)
    p_train.add_argument("--curated-negatives", default="data/curated_negatives.jsonl", help="Always trained on, never held out -- see HANDOFF_2 §4.")
    p_train.add_argument("--curated-pairs", default="data/curated_vulnerable_pairs.jsonl", help="Always trained on, never held out -- see HANDOFF_2 §4.")
    p_train.set_defaults(func=_cmd_train_model)

    p_bench_analyze = sub.add_parser("bench-analyze", help="Benchmark phase 1: run the local classifier over every before/after pair in the dataset.")
    p_bench_analyze.add_argument("--dataset-db", default=None, help="Overrides VULNSCAN_DATASET_DB.")
    p_bench_analyze.add_argument("--run-dir", required=True, help="e.g. data/experiments/1")
    p_bench_analyze.add_argument("--language", default="python")
    p_bench_analyze.add_argument("--limit", type=int, default=None)
    p_bench_analyze.add_argument("--max-concurrency", type=int, default=None)
    p_bench_analyze.set_defaults(func=_cmd_bench_analyze)

    p_bench_diff = sub.add_parser("bench-diff", help="Benchmark phase 2: bucket before/after findings into vuln_only/shared/benign_only.")
    p_bench_diff.add_argument("analysis_json", help="Path to analysis.json from bench-analyze.")
    p_bench_diff.add_argument("--out", default=None, help="Defaults to <run_dir>/diff.json")
    p_bench_diff.set_defaults(func=_cmd_bench_diff)

    p_bench_judge = sub.add_parser(
        "bench-judge",
        help="Benchmark phase 3: judge vuln_only findings against CVE ground truth via a "
             "local CWE-overlap/text-similarity heuristic -- no API call.",
    )
    p_bench_judge.add_argument("diff_json", help="Path to diff.json from bench-diff.")
    p_bench_judge.add_argument("--dataset-db", default=None)
    p_bench_judge.add_argument("--language", default="python")
    p_bench_judge.add_argument("--out", default=None, help="Defaults to <run_dir>/judged.json")
    p_bench_judge.set_defaults(func=_cmd_bench_judge)

    p_bench_metrics = sub.add_parser("bench-metrics", help="Benchmark phase 4: roll diff.json + judged.json up into detection/noise/CWE-attribution numbers.")
    p_bench_metrics.add_argument("diff_json")
    p_bench_metrics.add_argument("judged_json")
    p_bench_metrics.add_argument("--total-pairs", type=int, required=True)
    p_bench_metrics.add_argument("--out", default=None)
    p_bench_metrics.set_defaults(func=_cmd_bench_metrics)

    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())