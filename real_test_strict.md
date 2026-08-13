# Vulnerability Scan Report

**Local-model findings:** 3
**Static (semgrep) findings:** 0

## Local Model Findings

Flagged by the local classifier, grounded in static-analysis context and/or similar known CVEs where available.

| Severity | Count |
|---|---|
| medium | 3 |

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
