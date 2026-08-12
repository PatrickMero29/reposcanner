"""Converts the hitoshura25/cvefixes HuggingFace dataset into vulnscan's
generic pairs CSV format (see src/vulnscan/dataset/cvefixes_loader.py).

Usage:
    python hf_cvefixes.py --language python --out cvefixes_python.csv

This is a THIRD-PARTY MIRROR of the official CVEfixes dataset, not the
original maintainers' data — spot-check a few rows against
https://github.com/secureIT-project/CVEfixes before fully trusting it for
training. That said, the schema lines up cleanly with our pairs format:
vulnerable_code -> func_before, fixed_code -> func_after.
"""

from __future__ import annotations

import argparse
import csv


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--language", default=None, help="Filter to one language, e.g. 'python' (case-insensitive). Omit for all languages.")
    parser.add_argument("--out", default="cvefixes_converted.csv")
    parser.add_argument("--limit", type=int, default=None, help="Cap the number of rows written (useful for a quick test run).")
    args = parser.parse_args()

    from datasets import load_dataset

    print("Downloading/loading hitoshura25/cvefixes")
    dataset = load_dataset("hitoshura25/cvefixes")["train"]
    print(f"Loaded {len(dataset)} raw rows.")

    fieldnames = [
        "pair_id", "cve_id", "cwe_ids", "language", "repo", "file_path",
        "function_name", "func_before", "func_after", "commit_message", "nvd_url",
    ]

    written = 0
    skipped_empty = 0
    skipped_language = 0

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for i, row in enumerate(dataset):
            lang = (row.get("language") or "").strip()
            if args.language and lang.lower() != args.language.lower():
                skipped_language += 1
                continue

            vulnerable_code = (row.get("vulnerable_code") or "").strip()
            fixed_code = (row.get("fixed_code") or "").strip()
            if not vulnerable_code or not fixed_code:
                skipped_empty += 1
                continue

            file_paths = row.get("file_paths") or []
            file_path = file_paths[0] if file_paths else ""

            writer.writerow({
                "pair_id": f"{row.get('hash', 'unknown')}-{i}",
                "cve_id": row.get("cve_id", ""),
                "cwe_ids": row.get("cwe_id", "") or "",
                "language": lang.lower(),
                "repo": row.get("repo_url", ""),
                "file_path": file_path,
                "function_name": "",  # not provided at this granularity by this dataset
                "func_before": vulnerable_code,
                "func_after": fixed_code,
                "commit_message": row.get("commit_message", "") or "",
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{row['cve_id']}" if row.get("cve_id") else "",
            })
            written += 1
            if args.limit and written >= args.limit:
                break

    print(f"Wrote {written} pairs to {args.out}")
    print(f"Skipped {skipped_empty} rows with empty vulnerable_code/fixed_code")
    if args.language:
        print(f"Skipped {skipped_language} rows not matching language={args.language!r}")


if __name__ == "__main__":
    main()