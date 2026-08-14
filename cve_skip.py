import gzip
import os
import re
import shutil
import sqlite3
import sys

# The huge one — full source code for every changed method, every language.
# We deliberately skip it in this pass; it's handled separately (pass 2) once
# we know which file_change_ids are actually Python, so we never have to
# materialize the non-Python rows at all.
SKIP_TABLES = {"method_change"}

INSERT_TABLE_RE = re.compile(r"^\s*INSERT\s+INTO\s+[`\"\[]?(\w+)[`\"\]]?", re.IGNORECASE)


def table_name_from_insert(statement: str) -> str | None:
    match = INSERT_TABLE_RE.match(statement)
    return match.group(1).lower() if match else None


def run_pass1(sql_gz_path: str = "CVEfixes_v1.0.8.sql.gz", db_path: str = "CVEfixes_meta.db") -> None:
    if os.path.exists(db_path):
        print(f"Removing existing {db_path}...")
        os.remove(db_path)

    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    buffer = ""
    statement_count = 0
    skipped_count = 0
    error_count = 0

    print("Pass 1: importing everything except method_change (the huge code-blob table)...")
    with gzip.open(sql_gz_path, "rt", encoding="utf-8") as f:
        for line in f:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("--"):
                continue

            buffer += line

            if sqlite3.complete_statement(buffer):
                stripped_buffer = buffer.strip()
                table = table_name_from_insert(stripped_buffer)

                if table in SKIP_TABLES:
                    skipped_count += 1
                    buffer = ""
                    continue

                try:
                    cursor.execute(buffer)
                    statement_count += 1
                    if statement_count % 20000 == 0:
                        free_gb = shutil.disk_usage(".").free / 1e9
                        print(f"  ...{statement_count} statements executed, {skipped_count} skipped, {free_gb:.1f} GB free")
                        if free_gb < 2.0:
                            print("Free space critically low — stopping before we hit the wall again.")
                            con.commit()
                            con.close()
                            sys.exit(1)
                except sqlite3.Error as e:
                    error_count += 1
                    if "disk" in str(e).lower() and "full" in str(e).lower():
                        print(f"\nFATAL: {e}")
                        con.close()
                        sys.exit(1)
                    if error_count <= 10:
                        print(f"  Error on statement {statement_count}: {e}")

                buffer = ""

    print("Committing...")
    con.commit()

    print("\n--- Tables imported ---")
    tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    for (name,) in tables:
        count = cursor.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        print(f"  {name}: {count} rows")

    if "file_change" in {t[0] for t in tables}:
        print("\n--- file_change columns (needed to identify the language filter) ---")
        cols = cursor.execute("PRAGMA table_info(file_change)").fetchall()
        for col in cols:
            print(" ", col[1], col[2])
        print("\nSample file_change rows:")
        for row in cursor.execute("SELECT * FROM file_change LIMIT 3").fetchall():
            print(" ", row)

    con.close()
    print(f"\nTotal executed: {statement_count} | skipped (method_change): {skipped_count} | errors: {error_count}")
    print(f"Result: {db_path} — should be a small fraction of the full dump's size.")
    print(f"Size on disk: {os.path.getsize(db_path) / 1e9:.2f} GB")


if __name__ == "__main__":
    run_pass1()