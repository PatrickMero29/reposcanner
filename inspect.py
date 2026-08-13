from vulnscan.dataset.cvefixes_loader import get_pairs

pairs = get_pairs("data/cvefixes.duckdb", language="python", limit=3)

for p in pairs:
    print("=" * 70)
    print("pair_id:", p["pair_id"], "| cve_id:", p["cve_id"], "| cwe_ids:", p["cwe_ids"])
    print("-" * 70)
    print("func_before (should be VULNERABLE):")
    print(repr(p["func_before"][:500]))
    print("-" * 70)
    print("func_after (should be FIXED):")
    print(repr(p["func_after"][:500]))
    print()