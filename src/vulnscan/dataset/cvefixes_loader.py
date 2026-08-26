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
    The extraction SQL below (`_CVEFIXES_EXTRACT_SQL`) is verified against
    real data from CVEfixes_v1.0.8 (empirically confirmed via
    `inspect_cvefixes_schema()` + direct row inspection, not guessed from
    documentation — see HANDOFF.md Section 2.10 for the full story,
    including why the schema can't be trusted from docs alone). If you're on
    a different CVEfixes release and this fails or produces empty/wrong
    results, run `inspect_cvefixes_schema()` against your file first and
    diff its table/column names against the SELECT below.
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
    """Load a generic-format CSV into the pairs table. Returns row count loaded.

    Uses read_csv() with an explicit column/dialect declaration rather than
    read_csv_auto()'s sniffer. The sniffer samples a chunk of the file to
    guess the header row and dialect, and multi-line quoted fields (a
    function body spanning several lines inside one quoted CSV cell — the
    normal case here) can throw off that guess, silently falling back to
    generic column0/column1/... names. Declaring the schema up front makes
    this immune to that.
    """
    con = open_db(duckdb_path)
    if replace:
        con.execute("DELETE FROM pairs")
    columns = ", ".join(
        f"'{col}': 'VARCHAR'" for col in (
            "pair_id", "cve_id", "cwe_ids", "language", "repo", "file_path",
            "function_name", "func_before", "func_after", "commit_message", "nvd_url",
        )
    )
    con.execute(
        f"""
        INSERT OR REPLACE INTO pairs
        SELECT
            pair_id, cve_id, cwe_ids, language, repo, file_path, function_name,
            func_before, func_after, commit_message, nvd_url
        FROM read_csv(
            '{csv_path}',
            auto_detect = false,
            header = true,
            columns = {{{columns}}},
            quote = '"',
            escape = '"',
            delim = ','
        )
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


# Verified, empirically-confirmed extraction SQL (see HANDOFF.md Section 2.10).
# `method_change` stores ONE row per (function, state) — the vulnerable and
# fixed versions of a function are two separate rows sharing
# (file_change_id, name), distinguished by before_change = 'True'/'False'
# (a TEXT column, not a real boolean). This self-joins those two states back
# into a single before/after pair per row. Confirmed against real data
# (e.g. CVE-2021-32633's `traverse()`), and matches cve_extract_final.py,
# the standalone script this was ported from. Produced 2,993 real,
# manually-spot-checked-correct pairs when run against CVEfixes_meta.db.
_CVEFIXES_EXTRACT_SQL = """
SELECT
    mc_before.method_change_id                              AS pair_id,
    f.cve_id                                                 AS cve_id,
    cwe.cwe_ids                                              AS cwe_ids,
    'python'                                                 AS language,
    f.repo_url                                               AS repo,
    fc.filename                                              AS file_path,
    mc_before.name                                           AS function_name,
    mc_before.code                                           AS func_before,
    mc_after.code                                            AS func_after,
    co.msg                                                   AS commit_message,
    ('https://nvd.nist.gov/vuln/detail/' || f.cve_id)        AS nvd_url
FROM cvefixes.method_change mc_before
JOIN cvefixes.method_change mc_after
    ON mc_before.file_change_id = mc_after.file_change_id
    AND mc_before.name = mc_after.name
    AND mc_before.before_change = 'True'
    AND mc_after.before_change = 'False'
JOIN cvefixes.file_change fc ON mc_before.file_change_id = fc.file_change_id
JOIN cvefixes.commits co ON fc.hash = co.hash
JOIN cvefixes.fixes f ON fc.hash = f.hash
LEFT JOIN (
    SELECT cve_id, GROUP_CONCAT(cwe_id, ',') AS cwe_ids
    FROM cvefixes.cwe_classification GROUP BY cve_id
) cwe ON f.cve_id = cwe.cve_id
WHERE fc.programming_language = 'Python'
  AND mc_before.code IS NOT NULL AND mc_before.code != ''
  AND mc_after.code IS NOT NULL AND mc_after.code != ''
"""


def load_from_cvefixes_sqlite(sqlite_path: str, duckdb_path: str, *, replace: bool = False) -> int:
    """Converter from a downloaded CVEfixes.db into the generic pairs table,
    using the verified self-join extraction SQL (see module docstring and
    HANDOFF.md Section 2.10). If this raises a
    duckdb.CatalogException/BinderException about a missing table/column,
    you're likely on a CVEfixes release with different table/column names —
    run inspect_cvefixes_schema(sqlite_path) and adjust
    _CVEFIXES_EXTRACT_SQL above to match."""
    con = open_db(duckdb_path)
    try:
        con.execute("INSTALL sqlite; LOAD sqlite;")
        # DETACH first: this function never used to clean up its own ATTACH,
        # so a prior run that errored out (or was interrupted) between ATTACH
        # and the normal end of this function leaves "cvefixes" attached to
        # duckdb_path's catalog -- and DuckDB persists that across
        # reconnects, so the next run's plain ATTACH fails with "database
        # with name \"cvefixes\" already exists" even though nothing is
        # currently running. IF EXISTS makes this safe to call unconditionally.
        con.execute("DETACH DATABASE IF EXISTS cvefixes")
        con.execute(f"ATTACH '{sqlite_path}' AS cvefixes (TYPE sqlite)")
        if replace:
            con.execute("DELETE FROM pairs")
        con.execute(f"INSERT OR REPLACE INTO pairs {_CVEFIXES_EXTRACT_SQL}")
        count = con.execute("SELECT count(*) FROM pairs").fetchone()[0]
    finally:
        con.execute("DETACH DATABASE IF EXISTS cvefixes")
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