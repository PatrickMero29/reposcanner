"""Pulls the pairs the local classifier completely missed -- i.e. its
"before" (vulnerable) run produced zero findings at all -- and dumps their
actual source, ground truth, and tokenized length to a markdown file for
manual review.

A pair with zero `before` findings has empty vuln_only AND empty shared in
diff.json (vuln_only + shared together are literally all of the before-run's
findings; if both are empty, the model flagged nothing on the vulnerable
code, full stop). This is different from -- and a much bigger bucket than --
the vuln_only-but-not-CWE-confirmed pairs judge.py reports on: this script
looks at total misses, not judging misses.

Usage:
    python find_missed_pairs.py data/experiments/18/diff.json --limit 30

Sorted by tokenized length (ascending) so the genuinely-short, comfortably-
fitting misses -- the ones that can't be explained by truncation -- show up
first. Anything over local_model_max_length (512 tokens) is flagged inline
as [TRUNCATED] rather than excluded, so you can still see it, but shortest-
first means you'll hit the real misses before scrolling past those.
"""

import argparse
import json
from pathlib import Path

import duckdb
from transformers import AutoTokenizer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("diff_json", help="Path to diff.json from bench-diff")
    parser.add_argument("--dataset-db", default="data/cvefixes.duckdb")
    parser.add_argument("--language", default="python")
    parser.add_argument("--max-length", type=int, default=512, help="Should match LOCAL_MODEL_MAX_LENGTH")
    parser.add_argument("--limit", type=int, default=30, help="How many missed pairs to dump (shortest first)")
    parser.add_argument("--out", default=None, help="Defaults to <diff_json's dir>/missed_pairs.md")
    args = parser.parse_args()

    diff_results = json.loads(Path(args.diff_json).read_text(encoding="utf-8"))
    missed_pair_ids = {
        r["pair_id"] for r in diff_results
        if not r.get("vuln_only") and not r.get("shared")
    }
    print(f"Total pairs in diff.json: {len(diff_results)}")
    print(f"Completely missed (zero findings on 'before' at all): {len(missed_pair_ids)}")

    con = duckdb.connect(args.dataset_db, read_only=True)
    rows = con.execute(
        "SELECT pair_id, cve_id, cwe_ids, commit_message, func_before "
        "FROM pairs WHERE language = ?", [args.language],
    ).fetchall()
    con.close()
    by_id = {r[0]: r for r in rows}

    tok = AutoTokenizer.from_pretrained("microsoft/codebert-base")

    missed = []
    for pid in missed_pair_ids:
        row = by_id.get(pid)
        if row is None:
            continue
        _, cve_id, cwe_ids, commit_message, func_before = row
        n_tokens = len(tok.encode(func_before))
        missed.append({
            "pair_id": pid, "cve_id": cve_id, "cwe_ids": cwe_ids,
            "commit_message": (commit_message or "").strip(),
            "func_before": func_before, "n_tokens": n_tokens,
        })

    missed.sort(key=lambda m: m["n_tokens"])
    truncated_count = sum(1 for m in missed if m["n_tokens"] > args.max_length)
    print(f"Of those, truncated at max_length={args.max_length}: {truncated_count} "
          f"({100 * truncated_count / len(missed):.1f}%)" if missed else "No missed pairs found.")

    out_path = args.out or str(Path(args.diff_json).parent / "missed_pairs.md")
    lines = [
        f"# Completely missed pairs ({len(missed)} of {len(missed_pair_ids)} found in dataset, "
        f"showing shortest {min(args.limit, len(missed))})\n",
    ]
    for m in missed[: args.limit]:
        flag = " [TRUNCATED]" if m["n_tokens"] > args.max_length else ""
        lines.append(f"## {m['pair_id']} -- {m['cve_id']} ({m['cwe_ids'] or 'no CWE label'}) "
                     f"-- {m['n_tokens']} tokens{flag}")
        lines.append(f"**Fix commit message:** {m['commit_message']}\n")
        lines.append(f"```python\n{m['func_before']}\n```\n")

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {min(args.limit, len(missed))} missed pairs to {out_path}")


if __name__ == "__main__":
    main()