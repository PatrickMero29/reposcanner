"""Filter and downsample the pairs table into a clean training DuckDB.

Drops identical before/after, unparseable fragments, tiny snippets, and
test files; caps per-CVE / per-repo mass; prefers diffs that hit sinks.
"""

from __future__ import annotations

import logging
import random
from collections import defaultdict

from .cvefixes_loader import get_pairs, load_from_cvefixes_sqlite, open_db
from .filters import (
    dedent_code,
    diff_hits_sink,
    is_parseable_function,
    is_test_function,
    is_test_path,
)

logger = logging.getLogger("vulnscan.dataset.clean")

DEFAULT_MAX_PER_CVE = 20
DEFAULT_MAX_PER_REPO = 40

_PAIR_COLUMNS = (
    "pair_id", "cve_id", "cwe_ids", "language", "repo", "file_path",
    "function_name", "func_before", "func_after", "commit_message", "nvd_url",
)


def _row_copy(p: dict, *, func_before: str, func_after: str) -> dict:
    return {k: p.get(k) for k in _PAIR_COLUMNS} | {
        "func_before": func_before,
        "func_after": func_after,
    }


def filter_pairs(pairs: list[dict]) -> tuple[list[dict], dict[str, int]]:
    stats = defaultdict(int)
    kept: list[dict] = []
    for p in pairs:
        stats["input"] += 1
        before = p.get("func_before") or ""
        after = p.get("func_after") or ""
        if before == after:
            stats["identical_before_after"] += 1
            continue
        before_d = dedent_code(before)
        after_d = dedent_code(after)
        if before_d == after_d:
            stats["identical_after_dedent"] += 1
            continue
        if not is_parseable_function(before_d) or not is_parseable_function(after_d):
            stats["unparseable"] += 1
            continue
        if is_test_path(p.get("file_path")) or is_test_function(p.get("function_name")):
            stats["test_path_or_name"] += 1
            continue
        kept.append(_row_copy(p, func_before=before_d, func_after=after_d))
        stats["kept_pre_cap"] += 1
    return kept, dict(stats)


def cap_pairs(
    pairs: list[dict],
    *,
    max_per_cve: int = DEFAULT_MAX_PER_CVE,
    max_per_repo: int = DEFAULT_MAX_PER_REPO,
    seed: int = 42,
) -> tuple[list[dict], dict[str, int]]:
    rng = random.Random(seed)

    def _score(p: dict) -> tuple[int, int]:
        sink = 1 if diff_hits_sink(p["func_before"], p["func_after"]) else 0
        length = len((p["func_before"] or "").split())
        return (sink, length)

    by_cve: dict[str, list[dict]] = defaultdict(list)
    for p in pairs:
        by_cve[p.get("cve_id") or p["pair_id"]].append(p)

    after_cve: list[dict] = []
    dropped_cve = 0
    for _cve, group in by_cve.items():
        group = sorted(group, key=_score, reverse=True)
        if len(group) > max_per_cve:
            tied = group[:max_per_cve]
            extra = group[max_per_cve:]
            dropped_cve += len(extra)
            after_cve.extend(tied)
        else:
            after_cve.extend(group)

    by_repo: dict[str, list[dict]] = defaultdict(list)
    for p in after_cve:
        by_repo[p.get("repo") or ""].append(p)

    kept: list[dict] = []
    dropped_repo = 0
    for _repo, group in by_repo.items():
        group = sorted(group, key=_score, reverse=True)
        if len(group) > max_per_repo:
            dropped_repo += len(group) - max_per_repo
            kept.extend(group[:max_per_repo])
        else:
            kept.extend(group)

    rng.shuffle(kept)
    return kept, {
        "dropped_cve_cap": dropped_cve,
        "dropped_repo_cap": dropped_repo,
        "kept": len(kept),
    }


def write_pairs(pairs: list[dict], duckdb_path: str) -> int:
    con = open_db(duckdb_path)
    try:
        con.execute("DELETE FROM pairs")
        if not pairs:
            return 0
        placeholders = ", ".join(["?"] * len(_PAIR_COLUMNS))
        cols = ", ".join(_PAIR_COLUMNS)
        rows = [tuple(p.get(c) for c in _PAIR_COLUMNS) for p in pairs]
        con.executemany(f"INSERT OR REPLACE INTO pairs ({cols}) VALUES ({placeholders})", rows)
        count = con.execute("SELECT count(*) FROM pairs").fetchone()[0]
        return int(count)
    finally:
        con.close()


def clean_dataset(
    *,
    source_db: str | None = None,
    cvefixes_sqlite: str | None = None,
    out_path: str,
    max_per_cve: int = DEFAULT_MAX_PER_CVE,
    max_per_repo: int = DEFAULT_MAX_PER_REPO,
    language: str = "python",
    seed: int = 42,
) -> dict:
    if cvefixes_sqlite:
        logger.info("Reloading from CVEfixes sqlite %s (pair_id = method_change_id-cve_id)", cvefixes_sqlite)
        load_from_cvefixes_sqlite(cvefixes_sqlite, out_path, replace=True)
        source_db = out_path
    if not source_db:
        raise ValueError("Pass --dataset-db and/or --cvefixes-sqlite")

    pairs = get_pairs(source_db, language=language)
    filtered, filter_stats = filter_pairs(pairs)
    capped, cap_stats = cap_pairs(
        filtered, max_per_cve=max_per_cve, max_per_repo=max_per_repo, seed=seed,
    )
    n = write_pairs(capped, out_path)
    summary = {
        "source_db": source_db,
        "cvefixes_sqlite": cvefixes_sqlite,
        "out_path": out_path,
        "filter": filter_stats,
        "cap": cap_stats,
        "written": n,
    }
    logger.info("Clean dataset: %s", summary)
    return summary
