from __future__ import annotations

from pathlib import Path

from ..schemas import RepoFinding, ScanReport, Severity, StaticFinding

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def _severity_counts(items, get_severity) -> dict[Severity, int]:  # noqa: ANN001
    counts: dict[Severity, int] = {}
    for item in items:
        sev = get_severity(item)
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _write_severity_table(lines: list[str], counts: dict[Severity, int]) -> None:
    if not counts:
        return
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        if sev in counts:
            lines.append(f"| {sev.value} | {counts[sev]} |")
    lines.append("")


def _write_static_finding(lines: list[str], i: int, sf: StaticFinding) -> None:
    loc = sf.location
    lines.append(f"## {i}. [{sf.rule_id}] {sf.message}")
    lines.append("")
    lines.append(f"- **File:** `{loc.file_path}` (lines {loc.start_line}-{loc.end_line})")
    lines.append(f"- **Severity:** {sf.severity.value}")
    if sf.cwe_ids:
        lines.append(f"- **CWE:** {', '.join(sf.cwe_ids)}")
    if loc.commit_sha:
        lines.append(f"- **Commit:** `{loc.commit_sha}`")
    lines.append("")
    lines.append("_Static rule match — not yet reviewed by the AI engine. Verify manually or "
                  "re-run with AI analysis enabled._")
    lines.append("")
    lines.append("---")
    lines.append("")


def _write_ai_finding(lines: list[str], i: int, rf: RepoFinding) -> None:
    op = rf.finding.undesired_operation
    loc = rf.location
    lines.append(f"## {i}. {op.description}")
    lines.append("")
    lines.append(f"- **File:** `{loc.file_path}` (lines {loc.start_line}-{loc.end_line})")
    lines.append(f"- **Function:** `{rf.finding.function_name}`")
    lines.append(f"- **Severity:** {op.severity.value}")
    if op.cwe_ids:
        lines.append(f"- **CWE:** {', '.join(op.cwe_ids)}")
    lines.append(f"- **Confidence:** {rf.finding.confidence:.2f}")
    if loc.commit_sha:
        lines.append(f"- **Commit:** `{loc.commit_sha}`")
    if op.impact:
        lines.append("")
        lines.append(f"**Impact:** {op.impact}")
    lines.append("")
    lines.append("**Unsafe code:**")
    lines.append(f"```{rf.finding.language.value}")
    lines.append(op.code_snippet)
    lines.append("```")
    if rf.verification is not None:
        lines.append("")
        lines.append(f"_Verified by verifier agent: {rf.verification.verdict}_")
        if rf.verification.notes:
            lines.append(f"_Verifier notes: {rf.verification.notes}_")
    lines.append("")
    lines.append("---")
    lines.append("")


def write_markdown_report(report: ScanReport, path: str) -> None:
    lines: list[str] = ["# Vulnerability Scan Report", ""]

    lines.append(f"**AI-verified findings:** {len(report.ai_findings)}")
    lines.append(f"**Static (semgrep) findings:** {len(report.static_findings)}")
    lines.append("")

    if report.ai_findings:
        lines.append("## AI-Verified Findings")
        lines.append("")
        lines.append("Reachability-verified by the AI engine (Claude), grounded in static-analysis "
                      "context and/or similar known CVEs where available.")
        lines.append("")
        _write_severity_table(lines, _severity_counts(report.ai_findings, lambda rf: rf.finding.undesired_operation.severity))
        ai_sorted = sorted(report.ai_findings, key=lambda rf: _SEVERITY_ORDER.get(rf.finding.undesired_operation.severity, 99))
        for i, rf in enumerate(ai_sorted, start=1):
            _write_ai_finding(lines, i, rf)

    if report.static_findings:
        lines.append("## Static Analysis Findings (semgrep)")
        lines.append("")
        lines.append("Raw rule matches from the free, local pre-filter. These have **not** been "
                      "reviewed by the AI engine — some may be false positives, and this section "
                      "is what you get even with zero API budget.")
        lines.append("")
        _write_severity_table(lines, _severity_counts(report.static_findings, lambda sf: sf.severity))
        static_sorted = sorted(report.static_findings, key=lambda sf: _SEVERITY_ORDER.get(sf.severity, 99))
        for i, sf in enumerate(static_sorted, start=1):
            _write_static_finding(lines, i, sf)

    if not report.ai_findings and not report.static_findings:
        lines.append("No findings.")

    Path(path).write_text("\n".join(lines), encoding="utf-8")
