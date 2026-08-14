import sqlite3

con = sqlite3.connect("CVEfixes_meta.db")
cursor = con.cursor()

print("--- file_change columns ---")
for col in cursor.execute("PRAGMA table_info(file_change)").fetchall():
    print(" ", col[1], col[2])

print("\n--- distinct programming_language-ish values (first column that looks like it) ---")
cols = [c[1] for c in cursor.execute("PRAGMA table_info(file_change)").fetchall()]
# Print distinct values for every text column so we can spot the language field for certain,
# rather than guessing from column name alone.
for col_name in cols:
    try:
        distinct_vals = cursor.execute(
            f"SELECT DISTINCT {col_name} FROM file_change LIMIT 15"
        ).fetchall()
        sample = [str(v[0])[:30] for v in distinct_vals]
        # Only print columns with a small, language-like set of distinct short values.
        if 1 < len(sample) <= 15 and all(len(s) < 30 for s in sample):
            print(f"  {col_name}: {sample}")
    except sqlite3.Error:
        pass

print("\n--- row count ---")
print(" ", cursor.execute("SELECT COUNT(*) FROM file_change").fetchone()[0])

con.close()