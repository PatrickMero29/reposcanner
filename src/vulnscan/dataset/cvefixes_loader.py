"""Populate the generic `pairs` table (see schema.sql) from an upstream
labeled-vulnerability dataset.

Two loaders are provided:

  * `load_from_csv` — bring-your-own dataset. This is the recommended path
    to get started, since it has zero dependency on any one dataset's exact
    internal schema. Expected columns:
        pair_id, cve_id, cwe_ids, language, repo, file_path, function_name,
        func_before, func_after, commit_message, nvd_url
    (cve_id/cwe_ids/repo/file_path/function_name/commit_message/nvd_url may
    be blank; func_before/func_after/language/pair_id are required.)

  * `load_from_cvefixes_sqlite` — converts Fabio Massacci et al.'s CVEfixes
    dataset (distributed as a SQLite DB, see
    https://github.com/secureIT-project/CVEfixes) into the generic shape.
    CVEfixes' schema has changed across releases, so the column names below
    are a best-effort mapping — run `inspect_cvefixes_schema()` first against
    your actual downloaded file and adjust the SELECT in
    `_CVEFIXES_EXTRACT_SQL` if your version's table/column names differ.
"""

from __future__ import annotations

import logging
from pathlib import Path

import duckdb

from .schema_path import SCHEMA_SQL_PATH

logger = logging.getLogger("vulnscan.dataset")


def _ensure_schema(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(SCHEMA_SQL_PATH.read_text(encoding="utf-8"))


def open_db(duckdb_path: str) -> duckdb.DuckDBPyConnection:
    Path(duckdb_path).parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(duckdb_path)
    _ensure_schema(con)
    return con


def load_from_csv(csv_path: str, duckdb_path: str, *, replace: bool = False) -> int:
    """Load a generic-format CSV into the pairs table. Returns row count loaded."""
    con = open_db(duckdb_path)
    if replace:
        con.execute("DELETE FROM pairs")
    con.execute(
        f"""
        INSERT OR REPLACE INTO pairs
        SELECT
            pair_id, cve_id, cwe_ids, language, repo, file_path, function_name,
            func_before, func_after, commit_message, nvd_url
        FROM read_csv_auto('{csv_path}', HEADER=TRUE)
        """
    )
    count = con.execute("SELECT count(*) FROM pairs").fetchone()[0]
    con.close()
    logger.info("Loaded pairs table from %s — %d total rows.", csv_path, count)
    return count


def inspect_cvefixes_schema(sqlite_path: str) -> dict[str, list[str]]:
    """Utility: list tables and columns in a downloaded CVEfixes.db so you can
    verify/adjust `_CVEFIXES_EXTRACT_SQL` before running the real import."""
    con = duckdb.connect()
    con.execute("INSTALL sqlite; LOAD sqlite;")
    con.execute(f"ATTACH '{sqlite_path}' AS cvefixes (TYPE sqlite)")
    tables = con.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_catalog = 'cvefixes'"
    ).fetchall()
    schema: dict[str, list[str]] = {}
    for (table_name,) in tables:
        cols = con.execute(
            f"SELECT column_name FROM information_schema.columns "
            f"WHERE table_catalog = 'cvefixes' AND table_name = '{table_name}'"
        ).fetchall()
        schema[table_name] = [c[0] for c in cols]
    con.close()
    return schema


# Best-effort mapping for the CVEfixes public release schema (method_change /
# file_change / fixes / cve / commits tables). VERIFY against your actual file
# with inspect_cvefixes_schema() first — column names have drifted across
# CVEfixes releases.
_CVEFIXES_EXTRACT_SQL = """
SELECT
    mc.method_change_id                                    AS pair_id,
    f.cve_id                                                AS cve_id,
    cc.cwe_id                                               AS cwe_ids,
    'python'                                                AS language,
    r.repo_url                                              AS repo,
    fc.filename                                             AS file_path,
    mc.name                                                 AS function_name,
    mc.code                                                 AS func_before,
    mc.code_after                                           AS func_after,
    co.msg                                                  AS commit_message,
    'https://nvd.nist.gov/vuln/detail/' || f.cve_id          AS nvd_url
FROM cvefixes.method_change mc
JOIN cvefixes.file_change fc ON mc.file_change_id = fc.file_change_id
JOIN cvefixes.fixes f ON fc.hash = f.hash
JOIN cvefixes.commits co ON fc.hash = co.hash
JOIN cvefixes.repository r ON co.repo_url = r.repo_url
LEFT JOIN cvefixes.cwe_classification cc ON f.cve_id = cc.cve_id
WHERE fc.programming_language = 'Python'
  AND mc.code IS NOT NULL AND mc.code_after IS NOT NULL
"""


def load_from_cvefixes_sqlite(sqlite_path: str, duckdb_path: str, *, replace: bool = False) -> int:
    """Best-effort converter from a downloaded CVEfixes.db into the generic
    pairs table. If this raises a duckdb.CatalogException/BinderException
    about a missing table/column, run inspect_cvefixes_schema(sqlite_path)
    and fix the table/column names in _CVEFIXES_EXTRACT_SQL above to match
    your release."""
    con = open_db(duckdb_path)
    con.execute("INSTALL sqlite; LOAD sqlite;")
    con.execute(f"ATTACH '{sqlite_path}' AS cvefixes (TYPE sqlite)")
    if replace:
        con.execute("DELETE FROM pairs")
    con.execute(f"INSERT OR REPLACE INTO pairs {_CVEFIXES_EXTRACT_SQL}")
    count = con.execute("SELECT count(*) FROM pairs").fetchone()[0]
    con.close()
    logger.info("Loaded pairs table from CVEfixes at %s — %d Python rows.", sqlite_path, count)
    return count


def get_pairs(duckdb_path: str, *, language: str | None = None, limit: int | None = None) -> list[dict]:
    con = duckdb.connect(duckdb_path, read_only=True)
    query = "SELECT * FROM pairs"
    params: list = []
    if language:
        query += " WHERE language = ?"
        params.append(language)
    if limit:
        query += f" LIMIT {int(limit)}"
    rows = con.execute(query, params).fetchall()
    columns = [d[0] for d in con.description]
    con.close()
    return [dict(zip(columns, row)) for row in rows]
