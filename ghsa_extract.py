"""Phase 3 dataset expansion: extract before/after vulnerable function pairs
from GitHub Security Advisories (GHSA) -- the same generic pairs shape as
cvefixes_real_python.csv (see schema.sql), so it loads through the existing
load_from_csv() path with zero changes downstream.

Unlike CVEfixes (a frozen, one-time academic snapshot), GHSA is GitHub's own
continuously-updated advisory database -- a free, public, read-only REST API
call, not an LLM/inference service, so this stays consistent with the
project's zero-paid-API-dependency policy.

Requires a GITHUB_TOKEN env var for any real-scale run: unauthenticated API
requests are capped at 60/hour, and this needs one /commits/{sha} call per
advisory on top of the /advisories listing calls. A token is free -- GitHub
Settings -> Developer settings -> Personal access tokens -- no special
scopes needed for public repos. Raw file content (the bulk of the fetching)
comes from raw.githubusercontent.com, a *separate* host with no such limit,
so only the commit-metadata lookups are actually rate-limited.

Approach per advisory:
  1. Pull CVE id + CWE ids + summary directly from the GHSA record.
  2. Find a github.com/<owner>/<repo>/commit/<sha> reference -- most
     "reviewed" GHSA advisories with a linked fix have one.
  3. Hit /repos/{owner}/{repo}/commits/{sha} for the changed-files list and
     the parent commit's sha.
  4. For each changed .py file, fetch full content before (parent sha) and
     after (this sha) via raw.githubusercontent.com.
  5. Reuse chunking.python_chunker.chunk_file() -- already tested, already
     has the nested-closure fix -- on both versions, and pair up chunks by
     function_name where the code actually differs. This is the same "find
     the changed function" job CVEfixes did once upstream for its own
     dataset; doing it locally here means GHSA needs no separate paired-
     diffing tool of its own.

Usage:
    export GITHUB_TOKEN=ghp_...      # or $env:GITHUB_TOKEN on Windows
    python ghsa_extract.py --ecosystem pip --limit 200 --out data/ghsa_python.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from vulnscan.chunking.python_chunker import chunk_file  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("ghsa_extract")

API_ROOT = "https://api.github.com"
RAW_ROOT = "https://raw.githubusercontent.com"
COMMIT_URL_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
# Security-fix commits routinely touch test files alongside the real fix.
# Without filtering these out, a test method that merely happens to change
# in the same commit gets labeled with the advisory's CWE just like the
# actual vulnerable code would -- confirmed empirically: 2 of the first 3
# real extracted pairs were test methods (TestX.test_y), not vulnerable
# application code at all. Filtered at both the file-path level (skips the
# whole file, cheaper) and the function-name level (catches a test method
# living in a non-conventionally-named file, or a helper test class).
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|e2e|specs?|__tests__|fixtures|cypress)/"
    r"|(^|/)(test_[^/]+|conftest|[^/]+_spec|spec_[^/]+)\.py$"
    r"|_test\.py$"
)
TEST_NAME_RE = re.compile(r"(^|\.)test_|^Test")


def _is_test_path(path: str) -> bool:
    return bool(TEST_PATH_RE.search(path))


def _is_test_function(function_name: str) -> bool:
    return bool(TEST_NAME_RE.search(function_name))


def _get(url: str, token: str | None, *, retries: int = 3) -> dict | list:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vulnscan-ghsa-extract"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 403 and "rate limit" in e.read().decode("utf-8", errors="ignore").lower():
                logger.error(
                    "GitHub API rate limit hit. Set GITHUB_TOKEN for a much higher limit "
                    "(free -- Settings > Developer settings > Personal access tokens)."
                )
                raise
            if e.code == 404:
                return {}
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise
    return {}


def _fetch_raw(owner: str, repo: str, sha: str, path: str) -> str | None:
    url = f"{RAW_ROOT}/{owner}/{repo}/{sha}/{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-ghsa-extract"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError:
        return None


def _list_advisories(ecosystem: str, limit: int, token: str | None) -> list[dict]:
    advisories: list[dict] = []
    page = 1
    while len(advisories) < limit:
        per_page = min(100, limit - len(advisories))
        url = f"{API_ROOT}/advisories?ecosystem={ecosystem}&type=reviewed&per_page={per_page}&page={page}"
        batch = _get(url, token)
        if not batch:
            break
        advisories.extend(batch)
        if len(batch) < per_page:
            break
        page += 1
    return advisories[:limit]


def _find_commit_ref(advisory: dict) -> tuple[str, str, str] | None:
    """Returns (owner, repo, sha) from the first commit URL found in
    references, or None if this advisory has no linked commit."""
    for ref in advisory.get("references", []):
        m = COMMIT_URL_RE.search(ref)
        if m:
            return m.group(1), m.group(2), m.group(3)
    return None


def _pair_id(ghsa_id: str, cve_id: str | None, function_name: str, n: int) -> str:
    # Same lesson as CVEfixes' pair_id fix earlier: uniquely key by
    # (advisory, function), not just advisory, since one fix commit can
    # touch multiple functions -- and dedupe defensively with a counter.
    base = f"{ghsa_id}-{cve_id or 'nocve'}-{function_name}"
    return f"{base}-{n}" if n else base


def extract_advisory(advisory: dict, token: str | None) -> list[dict]:
    ghsa_id = advisory["ghsa_id"]
    cve_id = advisory.get("cve_id")
    cwe_ids = ",".join(c["cwe_id"] for c in advisory.get("cwes", []) or [])
    ref = _find_commit_ref(advisory)
    if ref is None:
        return []
    owner, repo, sha = ref

    commit = _get(f"{API_ROOT}/repos/{owner}/{repo}/commits/{sha}", token)
    if not commit or not commit.get("parents"):
        return []
    parent_sha = commit["parents"][0]["sha"]
    commit_message = (commit.get("commit", {}) or {}).get("message", advisory.get("summary", ""))

    rows: list[dict] = []
    seen_names: dict[str, int] = {}
    for f in commit.get("files", []):
        path = f["filename"]
        if not path.endswith(".py") or f.get("status") not in ("modified", "renamed"):
            continue
        if _is_test_path(path):
            continue
        before_path = f.get("previous_filename", path)
        after_src = _fetch_raw(owner, repo, sha, path)
        before_src = _fetch_raw(owner, repo, parent_sha, before_path)
        if after_src is None or before_src is None:
            continue

        before_chunks = {c.function_name: c.code for c in chunk_file(before_path, before_src)}
        after_chunks = {c.function_name: c.code for c in chunk_file(path, after_src)}

        for name, before_code in before_chunks.items():
            if _is_test_function(name):
                continue
            after_code = after_chunks.get(name)
            if after_code is None or after_code == before_code:
                continue  # function didn't survive to the after state unchanged/at all, or is identical (no real change)
            n = seen_names.get(name, 0)
            seen_names[name] = n + 1
            rows.append({
                "pair_id": _pair_id(ghsa_id, cve_id, name, n),
                "cve_id": cve_id or ghsa_id,
                "cwe_ids": cwe_ids,
                "language": "python",
                "repo": f"https://github.com/{owner}/{repo}",
                "file_path": path,
                "function_name": name,
                "func_before": before_code,
                "func_after": after_code,
                "commit_message": commit_message,
                "nvd_url": f"https://github.com/advisories/{ghsa_id}",
            })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ecosystem", default="pip")
    parser.add_argument("--limit", type=int, default=200, help="Max advisories to scan (not pairs extracted)")
    parser.add_argument("--out", default="data/ghsa_python.csv")
    parser.add_argument("--token", default=None, help="Overrides GITHUB_TOKEN env var")
    args = parser.parse_args()

    import os
    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.warning(
            "No GITHUB_TOKEN set -- limited to 60 API requests/hour. Fine for a small --limit, "
            "will hit rate limits fast otherwise."
        )

    try:
        advisories = _list_advisories(args.ecosystem, args.limit, token)
    except urllib.error.HTTPError as e:
        logger.error("Failed to fetch the advisories list (HTTP %s). See the rate-limit "
                     "message above if there was one, or check --ecosystem is valid.", e.code)
        return
    logger.info("Fetched %d advisories with a linked commit candidate to check.", len(advisories))

    all_rows: list[dict] = []
    skipped_no_commit = 0
    for i, adv in enumerate(advisories, start=1):
        try:
            rows = extract_advisory(adv, token)
        except urllib.error.HTTPError:
            logger.error("Stopping early at advisory %d/%d due to a fetch error above.", i, len(advisories))
            break
        if not rows:
            skipped_no_commit += 1
        all_rows.extend(rows)
        if i % 25 == 0:
            logger.info("Processed %d/%d advisories, %d pairs extracted so far.", i, len(advisories), len(all_rows))

    logger.info(
        "Done: %d pairs from %d advisories (%d had no usable linked commit or no .py changes).",
        len(all_rows), len(advisories), skipped_no_commit,
    )

    if not all_rows:
        logger.warning("No pairs extracted -- nothing written.")
        return

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(all_rows)
    logger.info("Wrote %d pairs to %s", len(all_rows), args.out)


if __name__ == "__main__":
    main()