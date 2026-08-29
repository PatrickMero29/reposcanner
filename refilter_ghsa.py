"""Re-applies the broadened test-path filter to an already-extracted GHSA
CSV, without re-hitting the GitHub API. Use this after ghsa_extract.py's
test-path filter gets broadened (like it just did to catch cypress/e2e/,
conftest.py, spec/, etc.) -- the fetched data is fine, it just needs a
stricter filter re-applied.

Usage: python refilter_ghsa.py data/ghsa_python.csv data/ghsa_python_clean.csv
"""
import csv
import sys

sys.path.insert(0, "src")
from ghsa_extract import _is_test_path, _is_test_function  # noqa: E402

csv.field_size_limit(10_000_000)

in_path, out_path = sys.argv[1], sys.argv[2]
with open(in_path, encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

kept = [r for r in rows if not _is_test_path(r["file_path"]) and not _is_test_function(r["function_name"])]
dropped = len(rows) - len(kept)

print(f"kept: {len(kept)}, dropped as test-related: {dropped} ({100*dropped/len(rows):.1f}%)")

with open(out_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()), quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(kept)
print(f"Wrote {len(kept)} rows to {out_path}")