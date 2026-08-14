import gzip
import re
import shutil
import sqlite3
import sys

INSERT_TABLE_RE = re.compile(r"^\s*INSERT\s+INTO\s+[`\"\[]?(\w+)[`\"\]]?", re.IGNORECASE)


def table_name_from_insert(statement: str) -> str | None:
    match = INSERT_TABLE_RE.match(statement)
    return match.group(1).lower() if match else None


def run_pass2(sql_gz_path: str = "CVEfixes_v1.0.8.sql.gz", db_path: str = "CVEfixes_meta.db") -> None:
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    # Clear out any partial method_change data from a previous attempt.
    cursor.execute("DELETE FROM method_change")
    con.commit()

    print("Loading the set of Python-linked file_change_ids...")
    python_ids = {
        row[0] for row in cursor.execute(
            "SELECT file_change_id FROM file_change WHERE programming_language = 'Python'"
        ).fetchall()
    }
    print(f"  {len(python_ids)} Python file_change rows found.")

    buffer = ""
    inserted = 0
    rejected = 0
    other_skipped = 0
    error_count = 0

    print("\nPass 2: streaming the dump again, importing only Python-linked method_change rows...")
    with gzip.open(sql_gz_path, "rt", encoding="utf-8") as f:
        for line in f:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("--"):
                continue

            buffer += line

            if sqlite3.complete_statement(buffer):
                table = table_name_from_insert(buffer.strip())

                if table != "method_change":
                    other_skipped += 1
                    buffer = ""
                    continue

                try:
                    cursor.execute(buffer)
                    # Let SQLite's real parser have handled the row; now check
                    # in Python whether it's actually one we want to keep.
                    row = cursor.execute(
                        "SELECT rowid, file_change_id FROM method_change WHERE rowid = last_insert_rowid()"
                    ).fetchone()
                    if row is None:
                        # Multi-row VALUES(...),(...) statement — last_insert_rowid()
                        # only gives us the last row in that case, so fall back to
                        # checking (and potentially trimming) the whole recently
                        # inserted batch by file_change_id in one go.
                        cursor.execute(
                            "DELETE FROM method_change WHERE file_change_id NOT IN "
                            f"({','.join('?' * len(python_ids))}) AND rowid > "
                            "(SELECT COALESCE(MAX(rowid), 0) FROM method_change) - 1000",
                            list(python_ids),
                        )
                    else:
                        rowid, file_change_id = row
                        if file_change_id in python_ids:
                            inserted += 1
                        else:
                            cursor.execute("DELETE FROM method_change WHERE rowid = ?", (rowid,))
                            rejected += 1

                    if (inserted + rejected) % 20000 == 0 and (inserted + rejected) > 0:
                        free_gb = shutil.disk_usage(".").free / 1e9
                        print(f"  ...{inserted} kept, {rejected} rejected, {free_gb:.1f} GB free")
                        con.commit()
                        if free_gb < 2.0:
                            print("Free space critically low — stopping.")
                            con.commit()
                            con.close()
                            sys.exit(1)
                except sqlite3.Error as e:
                    error_count += 1
                    if error_count <= 10:
                        print(f"  Error: {e}")

                buffer = ""

    print("Committing...")
    con.commit()

    final_count = cursor.execute("SELECT COUNT(*) FROM method_change").fetchone()[0]
    print(f"\nDone. method_change now has {final_count} rows (Python only).")
    print(f"Kept: {inserted} | rejected (non-Python): {rejected} | other tables skipped: {other_skipped} | errors: {error_count}")
    print(f"Final DB size: {__import__('os').path.getsize(db_path) / 1e9:.2f} GB")

    print("\n--- Sample method_change rows, to confirm before/after pairing convention ---")
    for row in cursor.execute(
        "SELECT method_change_id, file_change_id, name, before_change FROM method_change LIMIT 10"
    ).fetchall():
        print(" ", row)

    con.close()


if __name__ == "__main__":
    run_pass2()