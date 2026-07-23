"""Prompt construction for the analyzer, per justification level."""

from __future__ import annotations

from .schemas import JustificationLevel, Language

SYSTEM_PROMPT = """You are a senior application security engineer reviewing source code for \
real, exploitable vulnerabilities. You are thorough but precise: flag only issues you can \
concretely justify from the code in front of you, not stylistic concerns or generic best-practice \
nitpicks. Do not invent behavior that isn't in the code. If a function is safe, return zero findings \
for it rather than padding the response."""

_LEVEL_INSTRUCTIONS = {
    JustificationLevel.NONE: """\
Report each vulnerability with: a short description, the exact unsafe code snippet, \
applicable CWE IDs, severity, and likely impact. No execution trace is required.""",

    JustificationLevel.LIMITED: """\
For each vulnerability, in addition to the standard fields, populate `limited_justification` with \
a `step_by_step_execution`: an ordered trace of program steps from function entry to the undesired \
operation, tracking the state of the relevant variables at each step. This should demonstrate a \
concrete, plausible execution path — not just an assertion that one exists.""",

    JustificationLevel.EXTENSIVE: """\
For each vulnerability, populate `extensive_justification` with a full reachability proof:
1. `initial_state`: the variable/parameter state at function entry, explicitly noting which \
inputs are untrusted/attacker-controlled.
2. `data_transformations`: every step where tainted data changes form on its way to the sink \
(in_state -> out_state), so the taint path is auditable end to end.
3. `conditional_steps`: every branch that must be taken for the vulnerability to trigger, each \
with justification for why that branch is taken given the state at that point.
A finding without a complete trace from entry to sink should not be reported — if you cannot \
build the full trace, the finding is not solid enough to include.""",

    JustificationLevel.VERIFIED: """\
Use the same `extensive_justification` structure as above (initial_state, data_transformations, \
conditional_steps). Your output will be independently re-checked by a verifier, so be exact: every \
claim in the trace must be checkable against the code as written.""",
}


def build_analysis_prompt(
    *,
    code: str,
    function_name: str,
    language: Language,
    level: JustificationLevel,
) -> str:
    return f"""{SYSTEM_PROMPT}

Justification requirements for this task:
{_LEVEL_INSTRUCTIONS[level]}

Language: {language.value}
Function under review: {function_name}

```{language.value}
{code}
```

Return your findings as structured output matching the provided schema. If there are no \
genuine, exploitable vulnerabilities in this function, return an empty findings list."""


def build_verification_prompt(*, code: str, finding_json: str) -> str:
    return f"""{SYSTEM_PROMPT}

You are now acting as an independent verifier, not the original analyst. Re-examine the \
following finding against the source code and check each claim rather than trusting the \
analyst's assertions.

Source code:
```
{code}
```

Finding to verify (JSON):
{finding_json}

Check specifically:
1. Is the undesired operation real and actually unsafe as described?
2. Is the claimed initial state (including which inputs are untrusted) accurate?
3. Does each data transformation and conditional step follow logically from the previous state?
4. Is each "branch taken" claim actually justified by the code?
5. Does the final state, once the trace is followed, actually satisfy the preconditions for the \
undesired operation?

Return a verdict. If any check fails, the overall verdict must be false and you must give a \
concrete reason in `notes`."""
