from __future__ import annotations

from pathlib import Path

from ..schemas import RepoFinding, Severity

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def write_markdown_report(findings: list[RepoFinding], path: str) -> None:
    findings_sorted = sorted(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.finding.undesired_operation.severity, 99)
    )

    lines: list[str] = []
    lines.append("# Vulnerability Scan Report")
    lines.append("")
    lines.append(f"**Total findings:** {len(findings)}")
    lines.append("")

    counts: dict[Severity, int] = {}
    for f in findings:
        sev = f.finding.undesired_operation.severity
        counts[sev] = counts.get(sev, 0) + 1
    if counts:
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            if sev in counts:
                lines.append(f"| {sev.value} | {counts[sev]} |")
        lines.append("")

    for i, rf in enumerate(findings_sorted, start=1):
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

    Path(path).write_text("\n".join(lines), encoding="utf-8")
