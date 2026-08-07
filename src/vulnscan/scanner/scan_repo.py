"""Scan an arbitrary local repo directory for vulnerabilities using a
two-stage pipeline: Semgrep runs first as a fast, free, local pre-filter;
only functions it flags get sent to your locally-trained classifier (see
src/vulnscan/local_model/) for the AI-engine stage. No paid API involved
anywhere in this path.

Usage (also exposed via cli.py):
    python -m vulnscan.scanner.scan_repo /path/to/repo
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import subprocess
from pathlib import Path

from ..analyzer import analyze
from ..chunking import chunk_source_file
from ..config import settings
from ..rules.semgrep_runner import SemgrepFinding, run_semgrep
from ..schemas import RepoFinding, RepoLocation, ScanReport, Severity, StaticFinding
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


def _relative_path(path_str: str, repo: Path) -> str:
    try:
        return str(Path(path_str).resolve().relative_to(repo))
    except ValueError:
        return path_str  # not under repo somehow — report as-is rather than erroring


def _group_semgrep_findings_by_file(findings: list[SemgrepFinding]) -> dict[str, list[SemgrepFinding]]:
    grouped: dict[str, list[SemgrepFinding]] = {}
    for f in findings:
        try:
            key = str(Path(f.file_path).resolve())
        except OSError:
            key = f.file_path
        grouped.setdefault(key, []).append(f)
    return grouped


def _findings_overlapping_chunk(
    chunk_start: int, chunk_end: int, file_findings: list[SemgrepFinding]
) -> list[SemgrepFinding]:
    return [f for f in file_findings if f.start_line <= chunk_end and chunk_start <= f.end_line]


async def scan_repo(
    repo_path: str,
    *,
    extensions: tuple[str, ...] = (".py",),
    max_concurrency: int | None = None,
    use_semgrep_prefilter: bool | None = None,
    semgrep_config: str | list[str] | None = None,
) -> ScanReport:
    repo = Path(repo_path).resolve()
    if not repo.exists():
        raise FileNotFoundError(f"Repo path does not exist: {repo}")

    commit_sha = _current_commit_sha(repo)
    files = discover_files(repo, extensions=extensions)
    logger.info("Discovered %d candidate source files under %s", len(files), repo)

    # --- Stage 1: Semgrep pre-filter (fast, free, local) ---
    use_semgrep_prefilter = settings.enable_semgrep_prefilter if use_semgrep_prefilter is None else use_semgrep_prefilter
    semgrep_findings: list[SemgrepFinding] = []
    if use_semgrep_prefilter:
        semgrep_findings = run_semgrep(
            str(repo),
            config=semgrep_config or settings.semgrep_config,
            timeout=settings.semgrep_timeout,
        )

    # Only narrow which functions reach the AI engine when semgrep actually
    # produced signal. If it's unavailable, timed out, or genuinely found
    # nothing, fail OPEN (analyze everything) rather than silently reporting
    # zero findings — a broken/misconfigured semgrep should never look
    # identical to "this repo is clean".
    prefilter_active = len(semgrep_findings) > 0
    semgrep_by_file = _group_semgrep_findings_by_file(semgrep_findings)

    static_findings = [
        StaticFinding(
            location=RepoLocation(
                repo=str(repo),
                file_path=_relative_path(sf.file_path, repo),
                start_line=sf.start_line,
                end_line=sf.end_line,
                commit_sha=commit_sha,
            ),
            rule_id=sf.rule_id,
            message=sf.message,
            severity=Severity(sf.severity),
            cwe_ids=sf.cwe_ids,
        )
        for sf in semgrep_findings
    ]

    # --- Stage 2: local classifier, only on flagged functions (when prefilter is active) ---
    semaphore = asyncio.Semaphore(max_concurrency or settings.max_concurrency)
    ai_findings: list[RepoFinding] = []
    skipped_count = 0

    async def _analyze_chunk(chunk) -> None:  # noqa: ANN001
        nonlocal skipped_count
        file_findings = semgrep_by_file.get(str(Path(chunk.file_path).resolve()), [])
        matching = _findings_overlapping_chunk(chunk.start_line, chunk.end_line, file_findings)

        if prefilter_active and not matching:
            skipped_count += 1
            return  # semgrep ran and found nothing here — skip the local model call entirely

        async with semaphore:
            try:
                findings = await analyze(
                    code=chunk.code,
                    function_name=chunk.function_name,
                    language=chunk.language,
                    static_findings=matching or None,
                )
            except Exception:
                logger.exception("Analysis failed for %s::%s — skipping", chunk.file_path, chunk.function_name)
                return
            for finding in findings:
                ai_findings.append(RepoFinding(
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

    if prefilter_active:
        logger.info(
            "Semgrep flagged %d location(s); analyzing %d function chunks with the local model "
            "(concurrency=%d)...",
            len(semgrep_findings), len(tasks), max_concurrency or settings.max_concurrency,
        )
    else:
        logger.info(
            "No semgrep pre-filter signal — analyzing all %d function chunks with the local model "
            "(concurrency=%d)...",
            len(tasks), max_concurrency or settings.max_concurrency,
        )

    await asyncio.gather(*tasks)

    if prefilter_active and skipped_count:
        logger.info("Semgrep pre-filter skipped the local model call for %d function(s) it did not flag.", skipped_count)

    return ScanReport(static_findings=static_findings, ai_findings=ai_findings)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan a local repo for vulnerabilities with a semgrep pre-filter + your local model.")
    parser.add_argument("repo_path", help="Path to the repo to scan.")
    parser.add_argument("--out", default="scan_report", help="Output file basename (no extension).")
    parser.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    parser.add_argument("--no-semgrep", action="store_true", help="Disable the semgrep pre-filter; analyze every function.")
    parser.add_argument(
        "--semgrep-config", action="append", default=None,
        help="Semgrep ruleset (default: 'p/security-audit', or SEMGREP_CONFIG in .env). "
             "Repeat this flag to combine multiple rulesets in one scan, or pass one "
             "comma-separated value.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    report = asyncio.run(scan_repo(
        args.repo_path,
        use_semgrep_prefilter=not args.no_semgrep, semgrep_config=args.semgrep_config,
    ))

    logger.info(
        "Found %d static finding(s) and %d local-model finding(s).",
        len(report.static_findings), len(report.ai_findings),
    )
    if args.format in ("json", "both"):
        write_json_report(report, f"{args.out}.json")
    if args.format in ("markdown", "both"):
        write_markdown_report(report, f"{args.out}.md")


if __name__ == "__main__":
    main()