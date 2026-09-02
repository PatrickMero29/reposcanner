import csv
import random

csv.field_size_limit(10_000_000)
with open("data/ghsa_python_v2.csv", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

print("total rows:", len(rows))
ids = [r["pair_id"] for r in rows]
print("unique pair_ids:", len(set(ids)), "(should equal total rows)")

empty_name = sum(1 for r in rows if not r["function_name"])
non_py = sum(1 for r in rows if not r["file_path"].endswith(".py"))
short_before = sum(1 for r in rows if len(r["func_before"]) < 50)
no_cwe = sum(1 for r in rows if not r["cwe_ids"])
identical = sum(1 for r in rows if r["func_before"] == r["func_after"])

print(f"empty function_name: {empty_name} ({100*empty_name/len(rows):.1f}%)")
print(f"non-.py file_path: {non_py} ({100*non_py/len(rows):.1f}%)")
print(f"func_before under 50 chars: {short_before} ({100*short_before/len(rows):.1f}%)")
print(f"no CWE label: {no_cwe} ({100*no_cwe/len(rows):.1f}%)")
print(f"before == after (should be 0, these shouldn't have been kept): {identical}")

print("\n--- 3 random samples ---")
random.seed(1)
for r in random.sample(rows, 3):
    print("=" * 60)
    print("pair_id:", r["pair_id"], "| cve:", r["cve_id"], "| cwe:", r["cwe_ids"])
    print("repo:", r["repo"], "| file:", r["file_path"], "| function:", r["function_name"])
    print("--- func_before ---")
    print(r["func_before"][:300])