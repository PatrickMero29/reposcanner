"""Unified CLI. Run with `vulnscan <command>` after `pip install -e .`, or
`python -m vulnscan.cli <command>`.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .schemas import JustificationLevel


def _cmd_scan(args: argparse.Namespace) -> None:
    from .scanner.scan_repo import scan_repo
    from .scanner.report_json import write_json_report
    from .scanner.report_markdown import write_markdown_report

    report = asyncio.run(scan_repo(
        args.repo_path, level=JustificationLevel(args.level),
        use_semgrep_prefilter=not args.no_semgrep, semgrep_config=args.semgrep_config,
    ))
    print(f"Found {len(report.static_findings)} static finding(s), {len(report.ai_findings)} AI-verified finding(s).")
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


def _cmd_bench_analyze(args: argparse.Namespace) -> None:
    from .pipeline.run_analysis import run_analysis
    asyncio.run(run_analysis(
        dataset_db_path=args.dataset_db, level=JustificationLevel(args.level),
        run_dir=args.run_dir, language=args.language, limit=args.limit,
    ))


def _cmd_bench_diff(args: argparse.Namespace) -> None:
    from .pipeline.diff_judge import run_diff_judge
    from pathlib import Path
    out = args.out or str(Path(args.analysis_json).parent / "diff.json")
    run_diff_judge(args.analysis_json, out)


def _cmd_bench_judge(args: argparse.Namespace) -> None:
    from .pipeline.judge import run_judge
    from pathlib import Path
    out = args.out or str(Path(args.diff_json).parent / "judged.json")
    asyncio.run(run_judge(
        diff_json_path=args.diff_json, dataset_db_path=args.dataset_db,
        out_path=out, language=args.language,
    ))


def _cmd_build_index(args: argparse.Namespace) -> None:
    from .embedding.build_index import build_index
    out = build_index(args.dataset_db, args.out, language=args.language, limit=args.limit)
    print(f"Index built at {out}")


def _cmd_bench_metrics(args: argparse.Namespace) -> None:
    from .pipeline.metrics import compute_metrics
    import json
    metrics = compute_metrics(
        diff_json_path=args.diff_json, judged_json_path=args.judged_json, total_pairs=args.total_pairs
    )
    print(json.dumps(metrics, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnscan")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan an arbitrary local repo for vulnerabilities.")
    p_scan.add_argument("repo_path")
    p_scan.add_argument("--level", choices=[l.value for l in JustificationLevel], default=JustificationLevel.EXTENSIVE.value)
    p_scan.add_argument("--out", default="scan_report")
    p_scan.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    p_scan.add_argument("--no-semgrep", action="store_true", help="Disable the semgrep pre-filter; analyze every function with the AI engine.")
    p_scan.add_argument("--semgrep-config", default=None, help="Override the semgrep ruleset (default: 'auto', or SEMGREP_CONFIG in .env).")
    p_scan.set_defaults(func=_cmd_scan)

    p_load = sub.add_parser("bench-load", help="Load a labeled-vulnerability dataset into the local duckdb.")
    p_load.add_argument("--csv", default=None, help="Generic-format CSV (see dataset/cvefixes_loader.py docstring).")
    p_load.add_argument("--cvefixes-sqlite", default=None, help="Path to a downloaded CVEfixes.db.")
    p_load.add_argument("--dataset-db", required=True)
    p_load.add_argument("--replace", action="store_true")
    p_load.set_defaults(func=_cmd_bench_load)

    p_index = sub.add_parser("build-index", help="Build the local CVE similarity index for retrieval-grounded analysis.")
    p_index.add_argument("--dataset-db", required=True)
    p_index.add_argument("--out", default="data/cve_index")
    p_index.add_argument("--language", default=None)
    p_index.add_argument("--limit", type=int, default=None, help="Cap pairs embedded (useful for a quick test run).")
    p_index.set_defaults(func=_cmd_build_index)

    p_an = sub.add_parser("bench-analyze", help="Phase 1: analyze all pairs.")
    p_an.add_argument("--dataset-db", required=True)
    p_an.add_argument("--level", choices=[l.value for l in JustificationLevel], required=True)
    p_an.add_argument("--run-dir", required=True)
    p_an.add_argument("--language", default="python")
    p_an.add_argument("--limit", type=int, default=None)
    p_an.set_defaults(func=_cmd_bench_analyze)

    p_diff = sub.add_parser("bench-diff", help="Phase 2: diff before/after findings.")
    p_diff.add_argument("analysis_json")
    p_diff.add_argument("--out", default=None)
    p_diff.set_defaults(func=_cmd_bench_diff)

    p_judge = sub.add_parser("bench-judge", help="Phase 3: judge vuln_only findings against ground truth.")
    p_judge.add_argument("diff_json")
    p_judge.add_argument("--dataset-db", required=True)
    p_judge.add_argument("--language", default="python")
    p_judge.add_argument("--out", default=None)
    p_judge.set_defaults(func=_cmd_bench_judge)

    p_metrics = sub.add_parser("bench-metrics", help="Phase 4: compute precision/recall/F1.")
    p_metrics.add_argument("diff_json")
    p_metrics.add_argument("judged_json")
    p_metrics.add_argument("--total-pairs", type=int, required=True)
    p_metrics.set_defaults(func=_cmd_bench_metrics)

    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
