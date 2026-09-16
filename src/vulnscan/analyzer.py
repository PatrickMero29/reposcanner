"""Core analysis function: (code, language) -> Finding[].

This used to call Claude with prompt-engineered reasoning (justification
levels, forced tool-use, a verifier pass). All of that is gone now, per the
project's pivot away from any paid API: the "AI engine" stage is now
src/vulnscan/local_model/inference.py, a locally-runnable classifier you
train yourself (see src/vulnscan/training/). This function's remaining job
is just to enrich a positive classifier finding with CVE-retrieval evidence
and Semgrep's own flag reason for a human reviewer — it doesn't feed that
context INTO the classifier (a fine-tuned code classifier's input should
match its training distribution — raw code — not a mix of code plus
free-text hints it never saw during training).

NOTE: JustificationLevel/LimitedJustification/ExtensiveJustification/
VerificationResult still exist in schemas.py but are no longer used on this
path — they were prompt-engineering knobs specific to asking an LLM for a
reachability proof, which a binary classifier has no equivalent of. Left in
place since they may be relevant again if a future local reasoning/
explanation pass is added (see architecture.txt Phase 7).
"""

from __future__ import annotations

import logging

from .config import settings
from .embedding.index import IndexEntry
from .embedding.retrieve import retrieve_similar_cves
from .local_model.inference import predict_detailed
from .rules.semgrep_runner import SemgrepFinding
from .schemas import ClosestCVEMatch, Finding, Language

logger = logging.getLogger("vulnscan.analyzer")


def _format_cve_evidence(matches: list[tuple[IndexEntry, float]]) -> str | None:
    if not matches:
        return None
    lines = ["Similar historical vulnerabilities found via embedding search (reference only):"]
    for i, (entry, score) in enumerate(matches, start=1):
        cve = entry.cve_id or "unknown CVE"
        cwe = entry.cwe_ids or "unknown CWE"
        lines.append(f"{i}. {cve} ({cwe}) — similarity {score:.2f}")
    return "\n".join(lines)


def _format_static_context(findings: list[SemgrepFinding] | None) -> str | None:
    if not findings:
        return None
    lines = ["Also flagged by semgrep:"]
    for f in findings:
        lines.append(f"- [{f.rule_id}] line {f.start_line}: {f.message}")
    return "\n".join(lines)


def enrich_findings(
    findings: list[Finding],
    *,
    code: str,
    static_findings: list[SemgrepFinding] | None = None,
    pair_id: str | None = None,
) -> list[Finding]:
    if not findings:
        return findings
    extra_parts: list[str] = []
    if settings.enable_retrieval:
        matches = retrieve_similar_cves(code, exclude_pair_id=pair_id)
        cve_text = _format_cve_evidence(matches)
        if cve_text:
            extra_parts.append(cve_text)
        if matches:
            top_entry, top_score = matches[0]
            clamped_score = max(0.0, min(1.0, top_score))
            for finding in findings:
                finding.undesired_operation.closest_cve_match = ClosestCVEMatch(
                    cve_id=top_entry.cve_id or "unknown CVE",
                    cwe_ids=top_entry.cwe_ids or "unknown CWE",
                    similarity=clamped_score,
                )
    static_text = _format_static_context(static_findings)
    if static_text:
        extra_parts.append(static_text)
    if extra_parts:
        addendum = "\n\n" + "\n\n".join(extra_parts)
        for finding in findings:
            finding.undesired_operation.description += addendum
    return findings


async def analyze(
    *,
    code: str,
    function_name: str,
    language: Language,
    static_findings: list[SemgrepFinding] | None = None,
    pair_id: str | None = None,
    chunk_start_line: int = 1,
    confidence_threshold: float | None = None,
    fail_open: bool = False,
) -> list[Finding]:
    """Run the local classifier on one function, then enrich any positive
    finding with CVE-retrieval and Semgrep context for a human reviewer.
    Never raises — see local_model/inference.py for the degradation story.

    pair_id: only set by run_analysis.py (the benchmark), which knows which
    dataset row it's analyzing and needs to exclude that row from its own
    retrieval results — see retrieve_similar_cves' docstring. Real scans
    leave this None.
    """
    center_lines = None
    if static_findings:
        center_lines = [
            max(1, f.start_line - chunk_start_line + 1) for f in static_findings
        ]
    result = predict_detailed(
        code=code,
        function_name=function_name,
        language=language,
        confidence_threshold=confidence_threshold,
        center_lines=center_lines,
        fail_open=fail_open,
    )
    return enrich_findings(
        result.findings, code=code, static_findings=static_findings, pair_id=pair_id,
    )


async def analyze_scored(
    *,
    code: str,
    function_name: str,
    language: Language,
    static_findings: list[SemgrepFinding] | None = None,
    pair_id: str | None = None,
    chunk_start_line: int = 1,
    confidence_threshold: float | None = None,
    fail_open: bool = False,
) -> tuple[list[Finding], float, int]:
    center_lines = None
    if static_findings:
        center_lines = [
            max(1, f.start_line - chunk_start_line + 1) for f in static_findings
        ]
    result = predict_detailed(
        code=code,
        function_name=function_name,
        language=language,
        confidence_threshold=confidence_threshold,
        center_lines=center_lines,
        fail_open=fail_open,
    )
    findings = enrich_findings(
        result.findings, code=code, static_findings=static_findings, pair_id=pair_id,
    )
    return findings, result.prob_vuln, result.n_tokens