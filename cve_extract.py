import csv
import sqlite3

EXTRACT_SQL = """
SELECT
    mc_before.method_change_id AS pair_id,
    f.cve_id AS cve_id,
    cwe.cwe_ids AS cwe_ids,
    'python' AS language,
    f.repo_url AS repo,
    fc.filename AS file_path,
    mc_before.name AS function_name,
    mc_before.code AS func_before,
    mc_after.code AS func_after,
    co.msg AS commit_message,
    ('https://nvd.nist.gov/vuln/detail/' || f.cve_id) AS nvd_url
FROM method_change mc_before
JOIN method_change mc_after
    ON mc_before.file_change_id = mc_after.file_change_id
    AND mc_before.name = mc_after.name
    AND mc_before.before_change = 'True'
    AND mc_after.before_change = 'False'
JOIN file_change fc ON mc_before.file_change_id = fc.file_change_id
JOIN commits co ON fc.hash = co.hash
JOIN fixes f ON fc.hash = f.hash
LEFT JOIN (
    SELECT cve_id, GROUP_CONCAT(cwe_id, ',') AS cwe_ids
    FROM cwe_classification
    GROUP BY cve_id
) cwe ON f.cve_id = cwe.cve_id
WHERE fc.programming_language = 'Python'
  AND mc_before.code IS NOT NULL AND mc_before.code != ''
  AND mc_after.code IS NOT NULL AND mc_after.code != ''
"""

FIELDNAMES = [
    "pair_id", "cve_id", "cwe_ids", "language", "repo", "file_path",
    "function_name", "func_before", "func_after", "commit_message", "nvd_url",
]


def main(db_path: str = "CVEfixes_meta.db", out_csv: str = "cvefixes_real_python.csv") -> None:
    con = sqlite3.connect(db_path)
    cursor = con.cursor()

    print("Running extraction query...")
    rows = cursor.execute(EXTRACT_SQL).fetchall()
    print(f"Extracted {len(rows)} real vulnerable/fixed pairs.")

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(zip(FIELDNAMES, row)))

    print(f"Wrote {out_csv}")

    # Show a few for a manual sanity check before trusting this for training.
    print("\n--- Sample extracted pairs ---")
    for row in rows[:3]:
        d = dict(zip(FIELDNAMES, row))
        print("=" * 70)
        print("pair_id:", d["pair_id"], "| cve_id:", d["cve_id"], "| cwe_ids:", d["cwe_ids"])
        print("function_name:", d["function_name"], "| file_path:", d["file_path"])
        print("-" * 70)
        print("func_before:", repr(d["func_before"][:300]))
        print("-" * 70)
        print("func_after:", repr(d["func_after"][:300]))
        print()

    con.close()


if __name__ == "__main__":
    main()