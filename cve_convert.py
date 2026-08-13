import gzip
import os
import shutil
import sqlite3
import sys


def convert_cve_db(sql_gz_path: str = "CVEfixes_v1.0.8.sql.gz", db_path: str = "CVEfixes.db") -> None:
    # Rough disk-space sanity check before doing anything — the decompressed
    # SQL + SQLite's own indices typically need 5-10x the compressed size.
    compressed_size = os.path.getsize(sql_gz_path)
    free_space = shutil.disk_usage(".").free
    recommended = compressed_size * 8
    print(f"Compressed dump: {compressed_size / 1e9:.2f} GB")
    print(f"Free disk space: {free_space / 1e9:.2f} GB")
    print(f"Recommended free space: ~{recommended / 1e9:.2f} GB")
    if free_space < recommended:
        print(
            "\nWARNING: free space looks tight for this conversion. Continuing anyway "
            "will very likely fail partway through again, the same way it did last time. "
            "Consider freeing up space or using a different drive before proceeding."
        )
        response = input("Continue anyway? [y/N]: ").strip().lower()
        if response != "y":
            print("Aborted.")
            sys.exit(1)

    if os.path.exists(db_path):
        print(f"Removing existing (possibly incomplete) {db_path}...")
        os.remove(db_path)

    print("Connecting to database...")
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    buffer = ""
    statement_count = 0
    error_count = 0
    errors: list[str] = []

    print("Decompressing and executing SQL script...")
    with gzip.open(sql_gz_path, "rt", encoding="utf-8") as f:
        for line in f:
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("--"):
                continue

            buffer += line

            if sqlite3.complete_statement(buffer):
                try:
                    cursor.execute(buffer)
                    statement_count += 1
                    if statement_count % 50000 == 0:
                        print(f"  ...{statement_count} statements executed so far")
                except sqlite3.Error as e:
                    error_count += 1
                    errors.append(str(e))
                    # A disk-full error means every subsequent statement will
                    # also fail (no space to write anything) — stop immediately
                    # instead of grinding through the rest of a multi-GB file
                    # producing thousands of identical errors.
                    if "disk" in str(e).lower() and "full" in str(e).lower():
                        print(f"\nFATAL: {e}")
                        print("Disk full — stopping immediately rather than continuing to fail silently.")
                        con.close()
                        sys.exit(1)
                    if error_count <= 10:
                        print(f"  Error on statement {statement_count}: {e}")

                buffer = ""

    print("Committing changes...")
    con.commit()

    # Real verification: list what tables actually exist and how many rows
    # each has, instead of just declaring success unconditionally.
    print("\n--- Verification ---")
    tables = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    expected_tables = {"cve", "cwe", "cwe_classification", "commits", "fixes", "file_change", "method_change", "repository"}
    found_tables = {t[0] for t in tables}

    for table_name in sorted(found_tables):
        count = cursor.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        print(f"  {table_name}: {count} rows")

    missing = expected_tables - found_tables
    con.close()

    print(f"\nTotal statements executed: {statement_count}")
    print(f"Total errors: {error_count}")
    if missing:
        print(f"\nMISSING EXPECTED TABLES: {sorted(missing)}")
        print("The conversion is INCOMPLETE. Do not proceed to load this into vulnscan yet.")
        sys.exit(1)
    else:
        print("\nAll expected tables present. Conversion looks complete.")


if __name__ == "__main__":
    convert_cve_db()