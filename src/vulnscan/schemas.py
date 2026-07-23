"""
Structured-output schemas for vulnerability findings.

Design note
-----------
The original ZeroPath benchmark implemented four justification levels as four
separate experiment folders with largely duplicated analyzer code. Here the
levels are modeled as a single Pydantic hierarchy (JustificationLevel enum +
one schema per level) and the analyzer picks which schema to hand to the
model as `response_schema`. This means:

  * Adding a language doesn't touch this file at all.
  * Adding a fifth justification level is one new class + one enum member.
  * The scanner (arbitrary repos) and the benchmark (CVE ground truth) share
    exactly the same Finding objects; the benchmark just additionally knows
    which findings are "correct" via the judge.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Language(str, Enum):
    PYTHON = "python"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    JAVASCRIPT = "javascript"
    GO = "go"


class JustificationLevel(str, Enum):
    NONE = "no_justification"
    LIMITED = "limited_justification"
    EXTENSIVE = "extensive_justification"
    VERIFIED = "verification_agent"  # extensive + a verifier pass


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------

class UndesiredOperation(BaseModel):
    """The concrete bad thing that happens (e.g. the sink in a taint path)."""

    description: str = Field(..., description="Plain-language description of the unsafe operation.")
    code_snippet: str = Field(..., description="The exact line(s) of code where the unsafe operation occurs.")
    cwe_ids: list[str] = Field(default_factory=list, description="Applicable CWE identifiers, e.g. ['CWE-89'].")
    severity: Severity = Field(..., description="Estimated severity if exploited.")
    impact: Optional[str] = Field(None, description="What an attacker could achieve, in one or two sentences.")


class ProgramStep(BaseModel):
    """One step of an execution trace (used by LIMITED level)."""

    line_or_location: str = Field(..., description="Line number, function name, or other locator for this step.")
    description: str = Field(..., description="What happens at this step.")
    variable_state: Optional[str] = Field(None, description="Relevant variable values/types at this point, if known.")


class DataTransformation(BaseModel):
    """A step where tainted/attacker-controlled data changes form (EXTENSIVE level)."""

    location: str = Field(..., description="Where this transformation happens (line/function).")
    in_state: str = Field(..., description="Variable/data state entering this step.")
    out_state: str = Field(..., description="Variable/data state leaving this step.")
    note: Optional[str] = Field(None, description="Why this transformation preserves or worsens the risk.")


class ConditionalStep(BaseModel):
    """A branch that must be proven reachable for the vuln to trigger (EXTENSIVE level)."""

    location: str = Field(..., description="Where this conditional is (line/function).")
    condition: str = Field(..., description="The branch condition being evaluated.")
    branch_taken: str = Field(..., description="Which branch is taken and why, given current state.")
    justification: str = Field(..., description="Why this branch is provably taken given prior state.")


# ---------------------------------------------------------------------------
# Justification payloads (one per level)
# ---------------------------------------------------------------------------

class NoJustification(BaseModel):
    """Level 1: just the claim, no proof of reachability."""
    pass


class LimitedJustification(BaseModel):
    """Level 2: a step-by-step execution trace from entry to the undesired operation."""

    step_by_step_execution: list[ProgramStep] = Field(
        ..., min_length=1,
        description="Ordered trace of program steps from function entry to the undesired operation.",
    )


class ExtensiveJustification(BaseModel):
    """Level 3: full reachability proof with data flow and branch justification."""

    initial_state: str = Field(..., description="Variable/parameter state at function entry, including untrusted inputs.")
    data_transformations: list[DataTransformation] = Field(
        default_factory=list, description="Trace of how tainted data moves/changes through the function."
    )
    conditional_steps: list[ConditionalStep] = Field(
        default_factory=list, description="Every branch that must be taken for the vuln to trigger, with proof."
    )


class VerificationResult(BaseModel):
    """Result of the Sonnet/verifier-agent pass over an EXTENSIVE finding."""

    is_real_operation: bool = Field(..., description="Is the undesired operation actually present and unsafe?")
    is_initial_state_correct: bool = Field(..., description="Is the claimed initial state accurate?")
    steps_follow_logically: bool = Field(..., description="Does each transformation/conditional follow from the last?")
    conditionals_justified: bool = Field(..., description="Is each branch-taken claim actually justified?")
    final_state_matches_precondition: bool = Field(..., description="Does the trace actually reach the undesired operation's precondition?")
    verdict: bool = Field(..., description="Overall: should this finding be kept?")
    notes: Optional[str] = Field(None, description="Reasoning behind the verdict, especially if rejected.")


# ---------------------------------------------------------------------------
# Top-level Finding — this is what response_schema resolves to at analysis time
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """One vulnerability finding for one function, at a given justification level.

    NOTE: justification is split into one strongly-typed optional field per
    level (rather than a single freeform `dict`) because the Gemini
    Developer API (as opposed to Vertex/Enterprise) rejects JSON schemas
    with open-ended objects (`additionalProperties`). Only the field
    matching the requested JustificationLevel will be populated; the others
    stay None. NO_JUSTIFICATION populates neither.
    """

    function_name: str = Field(..., description="Name of the function being analyzed.")
    language: Language
    undesired_operation: UndesiredOperation
    limited_justification: Optional[LimitedJustification] = Field(
        None, description="Populated only when analyzed at LIMITED level."
    )
    extensive_justification: Optional[ExtensiveJustification] = Field(
        None, description="Populated only when analyzed at EXTENSIVE or VERIFIED level."
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model's confidence this is a true positive, 0-1.")


class FindingList(BaseModel):
    """Wrapper so the model can return zero or more findings for a function."""

    findings: list[Finding] = Field(default_factory=list)


class VerifiedFinding(BaseModel):
    finding: Finding
    verification: VerificationResult


# ---------------------------------------------------------------------------
# Benchmark-only: ground truth + judged outcomes
# ---------------------------------------------------------------------------

class GroundTruth(BaseModel):
    pair_id: str
    cve_id: Optional[str] = None
    cwe_ids: list[str] = Field(default_factory=list)
    nvd_url: Optional[str] = None
    commit_message: Optional[str] = None
    repo: Optional[str] = None
    language: Language = Language.PYTHON


class DiffCategory(str, Enum):
    VULN_ONLY = "vuln_only"
    BENIGN_ONLY = "benign_only"
    SHARED = "shared"


class JudgedFinding(BaseModel):
    finding: Finding
    category: DiffCategory
    is_cve_correct: Optional[bool] = None  # filled in by judge.py, only meaningful for vuln_only


# ---------------------------------------------------------------------------
# Scanner-only: a finding located in an arbitrary repo (no ground truth)
# ---------------------------------------------------------------------------

class RepoLocation(BaseModel):
    repo: str
    file_path: str
    start_line: int
    end_line: int
    commit_sha: Optional[str] = None


class RepoFinding(BaseModel):
    location: RepoLocation
    finding: Finding
    verification: Optional[VerificationResult] = None
