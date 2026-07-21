"""Placeholder for reporting findings directly to GitHub as issues or PR review
comments. Not implemented yet — for now, use report_json.py / report_markdown.py
and paste/attach the output manually.

Planned shape (using PyGithub or the REST API directly via `requests`/`httpx`):

    def create_issues_for_findings(
        findings: list[RepoFinding],
        *, repo_full_name: str, github_token: str,
        min_severity: Severity = Severity.HIGH,
        dedupe_label: str = "vulnscan",
    ) -> list[str]:
        '''Create one GitHub issue per finding at/above min_severity, tagged with
        dedupe_label, skipping any finding whose (file_path, function_name,
        cwe_ids) signature already has an open issue with that label.'''
        ...

    def post_pr_review_comments(
        findings: list[RepoFinding],
        *, repo_full_name: str, pr_number: int, github_token: str,
    ) -> None:
        '''Post inline review comments on a PR diff, anchored to the changed
        lines that overlap a finding's location.'''
        ...

Design notes for when this gets built:
  - Need a stable per-finding signature to dedupe across repeated scans
    (e.g. hash of file_path + function_name + cwe_ids + a normalized
    description) so re-running the scanner doesn't spam duplicate issues.
  - Respect GitHub API rate limits — batch/backoff similar to gemini_client.py.
  - Probably want a `--dry-run` flag that prints what *would* be created.
"""

from __future__ import annotations

from ..schemas import RepoFinding


def create_issues_for_findings(findings: list[RepoFinding], **kwargs) -> None:  # noqa: ANN003
    raise NotImplementedError(
        "GitHub issue reporting isn't implemented yet. Use report_json.write_json_report "
        "or report_markdown.write_markdown_report for now."
    )
