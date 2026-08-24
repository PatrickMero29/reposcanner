# Vulnerability Scan Report

**Local-model findings:** 0
**Static (semgrep) findings:** 5

## Static Analysis Findings (semgrep)

Raw rule matches from the free, local pre-filter. These have **not** been reviewed by the AI engine — some may be false positives, and this section is what you get even with zero API budget.

| Severity | Count |
|---|---|
| high | 1 |
| medium | 4 |

## 1. [python.lang.security.use-defused-xml.use-defused-xml] The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks. These attacks can leak confidential data and "XML bombs" can cause denial of service.

- **File:** `hashcat-7.1.2\tools\virtualbox2hashcat.py` (lines 15-15)
- **Severity:** high
- **CWE:** CWE-611
- **Commit:** `9ca1824e4d52251a0a5b2f8066f8cf1ea6473552`

_Static rule match — not yet reviewed by the AI engine. Verify manually or re-run with AI analysis enabled._

---

## 2. [python.lang.security.audit.eval-detected.eval-detected] Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability. Ensure evaluated content is not definable by external sources.

- **File:** `Old MetaCTF\Untitled-1.py` (lines 18-18)
- **Severity:** medium
- **CWE:** CWE-95
- **Commit:** `9ca1824e4d52251a0a5b2f8066f8cf1ea6473552`

_Static rule match — not yet reviewed by the AI engine. Verify manually or re-run with AI analysis enabled._

---

## 3. [python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1] Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

- **File:** `hashcat-7.1.2\tools\mozilla2hashcat.py` (lines 120-120)
- **Severity:** medium
- **CWE:** CWE-327
- **Commit:** `9ca1824e4d52251a0a5b2f8066f8cf1ea6473552`

_Static rule match — not yet reviewed by the AI engine. Verify manually or re-run with AI analysis enabled._

---

## 4. [python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1] Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

- **File:** `hashcat-7.1.2\tools\mozilla2hashcat.py` (lines 122-122)
- **Severity:** medium
- **CWE:** CWE-327
- **Commit:** `9ca1824e4d52251a0a5b2f8066f8cf1ea6473552`

_Static rule match — not yet reviewed by the AI engine. Verify manually or re-run with AI analysis enabled._

---

## 5. [python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1] Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Use SHA256 or SHA3 instead.

- **File:** `hashcat-7.1.2\tools\mozilla2hashcat.py` (lines 145-145)
- **Severity:** medium
- **CWE:** CWE-327
- **Commit:** `9ca1824e4d52251a0a5b2f8066f8cf1ea6473552`

_Static rule match — not yet reviewed by the AI engine. Verify manually or re-run with AI analysis enabled._

---
