"""Core analysis function: (code, language, justification level) -> Finding[].

This is the single piece of logic reused by both the benchmark pipeline
(src/vulnscan/pipeline/run_analysis.py, which runs it over CVE-labeled
function pairs) and the repo scanner (src/vulnscan/scanner/scan_repo.py,
which runs it over arbitrary chunks pulled from a target repository).
"""

from __future__ import annotations

import json
import logging

from .anthropic_client import generate_structured
from .embedding.index import IndexEntry
from .embedding.retrieve import retrieve_similar_cves
from .prompts import build_analysis_prompt, build_verification_prompt
from .schemas import (
    Finding,
    FindingList,
    JustificationLevel,
    Language,
    VerificationResult,
    VerifiedFinding,
)
from .config import settings

logger = logging.getLogger("vulnscan.analyzer")

MAX_VERIFICATION_ATTEMPTS = 2


def _format_evidence(matches: list[tuple[IndexEntry, float]]) -> str | None:
    if not matches:
        return None
    lines = [
        "Similar historical vulnerabilities found via embedding search over known CVEs "
        "(reference only — verify against the actual code below, do not assume an exact match):"
    ]
    for i, (entry, score) in enumerate(matches, start=1):
        cve = entry.cve_id or "unknown CVE"
        cwe = entry.cwe_ids or "unknown CWE"
        lines.append(f"{i}. {cve} ({cwe}) — similarity {score:.2f}")
        location = entry.function_name or "unknown function"
        if entry.repo:
            location += f" in {entry.repo}"
        lines.append(f"   Function: {location}")
        if entry.commit_message:
            lines.append(f"   Fix commit message: {entry.commit_message}")
        lines.append(f"   Vulnerable snippet preview: {entry.snippet_preview}")
    return "\n".join(lines)


async def analyze_function(
    *,
    code: str,
    function_name: str,
    language: Language,
    level: JustificationLevel = JustificationLevel.EXTENSIVE,
) -> list[Finding]:
    """Run one function through the analyzer at the given justification level."""
    evidence_text = None
    if settings.enable_retrieval:
        matches = retrieve_similar_cves(code)
        evidence_text = _format_evidence(matches)

    prompt = build_analysis_prompt(
        code=code, function_name=function_name, language=language, level=level,
        evidence_text=evidence_text,
    )
    result = await generate_structured(prompt=prompt, response_schema=FindingList)
    return result.findings


async def verify_finding(*, code: str, finding: Finding) -> VerificationResult:
    """Run one finding through the verifier-agent pass (level = VERIFIED only)."""
    prompt = build_verification_prompt(code=code, finding_json=finding.model_dump_json())
    return await generate_structured(
        prompt=prompt,
        response_schema=VerificationResult,
        model=settings.verifier_model,
    )


async def analyze_function_verified(
    *,
    code: str,
    function_name: str,
    language: Language,
) -> list[VerifiedFinding]:
    """Full pipeline for the VERIFICATION_AGENT level: analyze, then verify each
    finding, discarding any that fail verification after MAX_VERIFICATION_ATTEMPTS
    attempts (matching the original benchmark's "up to 2 verification attempts,
    unverified findings are discarded" behavior).
    """
    findings = await analyze_function(
        code=code, function_name=function_name, language=language,
        level=JustificationLevel.VERIFIED,
    )

    kept: list[VerifiedFinding] = []
    for finding in findings:
        verification: VerificationResult | None = None
        for attempt in range(MAX_VERIFICATION_ATTEMPTS):
            verification = await verify_finding(code=code, finding=finding)
            if verification.verdict:
                break
            logger.info(
                "Finding for %s rejected on verification attempt %d/%d: %s",
                function_name, attempt + 1, MAX_VERIFICATION_ATTEMPTS, verification.notes,
            )
        if verification and verification.verdict:
            kept.append(VerifiedFinding(finding=finding, verification=verification))

    return kept


async def analyze(
    *,
    code: str,
    function_name: str,
    language: Language,
    level: JustificationLevel,
) -> list[Finding]:
    """Dispatch to the right pipeline for the requested level. This is the one
    function both the benchmark runner and the scanner should call."""
    if level == JustificationLevel.VERIFIED:
        verified = await analyze_function_verified(
            code=code, function_name=function_name, language=language
        )
        return [vf.finding for vf in verified]
    return await analyze_function(
        code=code, function_name=function_name, language=language, level=level
    )
