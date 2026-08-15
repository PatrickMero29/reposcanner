import sqlite3

con = sqlite3.connect("CVEfixes_meta.db")
cursor = con.cursor()

for table in ["fixes", "commits", "cve", "cwe_classification", "repository"]:
    print(f"--- {table} ---")
    try:
        for col in cursor.execute(f"PRAGMA table_info({table})").fetchall():
            print(" ", col[1], col[2])
        count = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  ({count} rows)")
        print("  sample:")
        for row in cursor.execute(f"SELECT * FROM {table} LIMIT 2").fetchall():
            print("   ", row)
    except sqlite3.Error as e:
        print("  ERROR:", e)
    print()

con.close()