import duckdb, random

con = duckdb.connect('data/cvefixes.duckdb', read_only=True)
# GHSA-origin pair_ids look like "GHSA-xxxx-...-<cve or nocve>-<function>[-n]"
# per ghsa_extract.py's _pair_id(); CVEfixes-origin ones are "<method_change_id>-<cve_id>".
rows = con.execute("SELECT pair_id, function_name, file_path, func_before FROM pairs WHERE pair_id LIKE 'GHSA-%'").fetchall()
con.close()

print(f"total GHSA-origin rows in db: {len(rows)}")
random.seed(2)
for pair_id, function_name, file_path, func_before in random.sample(rows, min(5, len(rows))):
    print("=" * 60)
    print("pair_id:", pair_id)
    print("file_path:", file_path, "| function:", function_name)
    print(func_before[:250])