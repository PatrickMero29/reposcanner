"""Core analysis function: (code, language, justification level) -> Finding[].

This is the single piece of logic reused by both the benchmark pipeline
(src/vulnscan/pipeline/run_analysis.py, which runs it over CVE-labeled
function pairs) and the repo scanner (src/vulnscan/scanner/scan_repo.py,
which runs it over arbitrary chunks pulled from a target repository).
"""

from __future__ import annotations

import json
import logging

from .gemini_client import generate_structured
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


async def analyze_function(
    *,
    code: str,
    function_name: str,
    language: Language,
    level: JustificationLevel = JustificationLevel.EXTENSIVE,
) -> list[Finding]:
    """Run one function through the analyzer at the given justification level."""
    prompt = build_analysis_prompt(
        code=code, function_name=function_name, language=language, level=level
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
