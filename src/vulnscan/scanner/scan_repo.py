"""Scan an arbitrary local repo directory for vulnerabilities using the same
analyzer core as the benchmark, minus the CVE-ground-truth machinery.

Usage (also exposed via cli.py):
    python -m vulnscan.scanner.scan_repo /path/to/repo --level extensive
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
from pathlib import Path

from ..analyzer import analyze
from ..chunking import chunk_source_file
from ..schemas import JustificationLevel, RepoFinding, RepoLocation
from ..config import settings
from .report_json import write_json_report
from .report_markdown import write_markdown_report

logger = logging.getLogger("vulnscan.scanner")

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist",
    ".mypy_cache", ".pytest_cache", ".tox", "site-packages", "egg-info",
}


def _current_commit_sha(repo_path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_path,
            capture_output=True, text=True, timeout=5, check=True,
        )
        return result.stdout.strip()
    except Exception:  # noqa: BLE001 - not a git repo, or git unavailable; not fatal
        return None


def discover_files(repo_path: Path, extensions: tuple[str, ...] = (".py",)) -> list[Path]:
    files: list[Path] = []
    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        if any(part in DEFAULT_EXCLUDE_DIRS for part in path.parts):
            continue
        if path.suffix in extensions:
            files.append(path)
    return files


async def scan_repo(
    repo_path: str,
    *,
    level: JustificationLevel = JustificationLevel.EXTENSIVE,
    extensions: tuple[str, ...] = (".py",),
    max_concurrency: int | None = None,
) -> list[RepoFinding]:
    repo = Path(repo_path).resolve()
    if not repo.exists():
        raise FileNotFoundError(f"Repo path does not exist: {repo}")

    commit_sha = _current_commit_sha(repo)
    files = discover_files(repo, extensions=extensions)
    logger.info("Discovered %d candidate source files under %s", len(files), repo)

    semaphore = asyncio.Semaphore(max_concurrency or settings.max_concurrency)
    results: list[RepoFinding] = []

    async def _analyze_chunk(chunk) -> None:  # noqa: ANN001
        async with semaphore:
            try:
                findings = await analyze(
                    code=chunk.code,
                    function_name=chunk.function_name,
                    language=chunk.language,
                    level=level,
                )
            except Exception:
                logger.exception("Analysis failed for %s::%s — skipping", chunk.file_path, chunk.function_name)
                return
            for finding in findings:
                results.append(RepoFinding(
                    location=RepoLocation(
                        repo=str(repo),
                        file_path=str(Path(chunk.file_path).relative_to(repo)),
                        start_line=chunk.start_line,
                        end_line=chunk.end_line,
                        commit_sha=commit_sha,
                    ),
                    finding=finding,
                ))

    tasks = []
    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for chunk in chunk_source_file(str(file_path), source):
            tasks.append(_analyze_chunk(chunk))

    logger.info("Analyzing %d function chunks (concurrency=%d)...", len(tasks), max_concurrency or settings.max_concurrency)
    await asyncio.gather(*tasks)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a local repo for vulnerabilities with Gemini.")
    parser.add_argument("repo_path", help="Path to the repo to scan.")
    parser.add_argument(
        "--level", choices=[l.value for l in JustificationLevel],
        default=JustificationLevel.EXTENSIVE.value,
        help="How rigorous a reachability proof to require (default: extensive).",
    )
    parser.add_argument("--out", default="scan_report", help="Output file basename (no extension).")
    parser.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    findings = asyncio.run(scan_repo(args.repo_path, level=JustificationLevel(args.level)))

    logger.info("Found %d findings.", len(findings))
    if args.format in ("json", "both"):
        write_json_report(findings, f"{args.out}.json")
    if args.format in ("markdown", "both"):
        write_markdown_report(findings, f"{args.out}.md")


if __name__ == "__main__":
    main()
