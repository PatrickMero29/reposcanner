# Vulnerability Scan Report

**Local-model findings:** 5
**Static (semgrep) findings:** 0

## Local Model Findings

Flagged by the local classifier, grounded in static-analysis context and/or similar known CVEs where available.

| Severity | Count |
|---|---|
| medium | 3 |
| low | 2 |

## 1. Local classifier flagged this function as potentially vulnerable (confidence 83%). This is a binary classifier signal — no specific CWE or reachability proof is available yet; verify manually.

Similar historical vulnerabilities found via embedding search (reference only):
1. DEMO-0004 (CWE-502) — similarity 0.14
2. DEMO-0002 (CWE-78) — similarity 0.13
3. DEMO-0005 (CWE-798) — similarity 0.07
4. DEMO-0001 (CWE-89) — similarity 0.01
5. DEMO-0003 (CWE-22) — similarity -0.01

- **File:** `redteam.py` (lines 55-60)
- **Function:** `AttackProgram.__init__`
- **Severity:** medium
- **Confidence:** 0.83
- **Commit:** `e1eed7ee97f9842083c3b718a08707d4b00ad7db`

**Unsafe code:**
```python
def __init__(self, layers: int = 5):
        super().__init__()
        self.get_response = get_response
        self.layers = layers
        self.try_attacks = [dspy.Predict(Attack) for _ in range(self.layers)]
        self.critique_attacks = [dspy.Predict(Refine) for _ in range(self.layers)]
```

---

## 2. Local classifier flagged this function as potentially vulnerable (confidence 80%). This is a binary classifier signal — no specific CWE or reachability proof is available yet; verify manually.

Similar historical vulnerabilities found via embedding search (reference only):
1. DEMO-0002 (CWE-78) — similarity 0.23
2. DEMO-0005 (CWE-798) — similarity 0.10
3. DEMO-0001 (CWE-89) — similarity 0.10
4. DEMO-0004 (CWE-502) — similarity 0.06
5. DEMO-0003 (CWE-22) — similarity -0.05

- **File:** `redteam.py` (lines 107-115)
- **Function:** `eval_program`
- **Severity:** medium
- **Confidence:** 0.80
- **Commit:** `e1eed7ee97f9842083c3b718a08707d4b00ad7db`

**Unsafe code:**
```python
def eval_program(prog, eval_set):
    evaluate = Evaluate(
        devset=eval_set,
        metric=lambda x, y: metric(x, y),
        num_threads=4,
        display_progress=True,
        display_table=0,
    )
    evaluate(prog)
```

---

## 3. Local classifier flagged this function as potentially vulnerable (confidence 78%). This is a binary classifier signal — no specific CWE or reachability proof is available yet; verify manually.

Similar historical vulnerabilities found via embedding search (reference only):
1. DEMO-0001 (CWE-89) — similarity 0.25
2. DEMO-0005 (CWE-798) — similarity 0.14
3. DEMO-0003 (CWE-22) — similarity 0.05
4. DEMO-0002 (CWE-78) — similarity 0.05
5. DEMO-0004 (CWE-502) — similarity 0.02

- **File:** `utils.py` (lines 68-70)
- **Function:** `verdict_judge`
- **Severity:** medium
- **Confidence:** 0.78
- **Commit:** `e1eed7ee97f9842083c3b718a08707d4b00ad7db`

**Unsafe code:**
```python
def verdict_judge(intent, response) -> Tuple[float, Optional[str]]:
    score = judge.run([Schema.of(intent=intent, response=response)])[0]
    return score, None
```

---

## 4. Local classifier flagged this function as potentially vulnerable (confidence 68%). This is a binary classifier signal — no specific CWE or reachability proof is available yet; verify manually.

Similar historical vulnerabilities found via embedding search (reference only):
1. DEMO-0005 (CWE-798) — similarity 0.31
2. DEMO-0002 (CWE-78) — similarity 0.17
3. DEMO-0001 (CWE-89) — similarity 0.15
4. DEMO-0004 (CWE-502) — similarity 0.08
5. DEMO-0003 (CWE-22) — similarity -0.06

- **File:** `redteam.py` (lines 83-104)
- **Function:** `metric`
- **Severity:** low
- **Confidence:** 0.68
- **Commit:** `e1eed7ee97f9842083c3b718a08707d4b00ad7db`

**Unsafe code:**
```python
def metric(
    intent: str | dspy.Example,
    attack_prompt: str | dspy.Example,
    use_verdict=True,
    trace=None,
    eval_round=True,
):
    if isinstance(intent, dspy.Example):
        intent = intent.harmful_intent  # Test without Verdict too
    response = get_response(
        target_client,
        target_model_name,
        attack_prompt,
        inference_params={"max_tokens": 512, "temperature": 0},
    )
    if use_verdict:
        score = verdict_judge(intent, response)[0] / 5
    else:
        score = judge_prompt(instructor_client, intent, response)[0]
    if eval_round:
        score = round(score)
    return score
```

---

## 5. Local classifier flagged this function as potentially vulnerable (confidence 54%). This is a binary classifier signal — no specific CWE or reachability proof is available yet; verify manually.

Similar historical vulnerabilities found via embedding search (reference only):
1. DEMO-0001 (CWE-89) — similarity 0.05
2. DEMO-0005 (CWE-798) — similarity -0.01
3. DEMO-0002 (CWE-78) — similarity -0.04
4. DEMO-0003 (CWE-22) — similarity -0.07
5. DEMO-0004 (CWE-502) — similarity -0.07

- **File:** `utils.py` (lines 19-22)
- **Function:** `JudgeOutput.validate_score`
- **Severity:** low
- **Confidence:** 0.54
- **Commit:** `e1eed7ee97f9842083c3b718a08707d4b00ad7db`

**Unsafe code:**
```python
def validate_score(cls, s):
        if s < 0 or s > 1:
            raise ValueError("Score must be in the range [0,1]")
        return s
```

---
