"""Unified CLI. Run with `vulnscan <command>` after `pip install -e .`, or
`python -m vulnscan.cli <command>`.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys


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
    from .training.train import train_model
    out = train_model(
        dataset_db_path=args.dataset_db, out_dir=args.out, base_model=args.base_model,
        language=args.language, epochs=args.epochs, batch_size=args.batch_size,
        learning_rate=args.learning_rate, val_fraction=args.val_fraction,
    )
    print(f"Trained model saved to {out}")


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

    p_train = sub.add_parser("train-model", help="Fine-tune a local binary vulnerability classifier on your loaded dataset (runs on GPU if available).")
    p_train.add_argument("--dataset-db", required=True)
    p_train.add_argument("--out", default="models/vuln-classifier")
    p_train.add_argument("--base-model", default="microsoft/codebert-base")
    p_train.add_argument("--language", default="python")
    p_train.add_argument("--epochs", type=int, default=3)
    p_train.add_argument("--batch-size", type=int, default=8)
    p_train.add_argument("--learning-rate", type=float, default=2e-5)
    p_train.add_argument("--val-fraction", type=float, default=0.15, help="Fraction of pairs (split by pair_id, not row) held out for validation.")
    p_train.set_defaults(func=_cmd_train_model)

    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
