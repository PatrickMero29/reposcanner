"""One-time fixup for cvefixes_real_python.csv: pair_id was set to
method_change_id alone, but a single method-level change can legitimately
fix more than one CVE at once (confirmed: e.g. method_change_id
181420005546013 has two real rows, one for CVE-2012-3360/CWE-22 and one for
CVE-2012-3361/CWE-264 -- same commit, same code, two distinct labels).
Since pairs.pair_id is the primary key, loading the CSV as-is silently drops
550 of these genuinely distinct, correctly-labeled rows via INSERT OR
REPLACE. This rewrites pair_id as "<method_change_id>-<cve_id>" so every
real row survives the load.

Usage: python fix_pair_ids.py cvefixes_real_python.csv cvefixes_real_python_fixed.csv
"""
import csv
import sys

csv.field_size_limit(10_000_000)

in_path, out_path = sys.argv[1], sys.argv[2]

with open(in_path, encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

seen = set()
for r in rows:
    new_id = f"{r['pair_id']}-{r['cve_id']}"
    # extremely rare residual collision (same method_change_id AND same cve_id
    # appearing twice) gets a numeric suffix so it still isn't silently dropped
    base, n = new_id, 2
    while new_id in seen:
        new_id = f"{base}-{n}"
        n += 1
    seen.add(new_id)
    r["pair_id"] = new_id

with open(out_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys(), quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows with de-duplicated pair_ids to {out_path}")