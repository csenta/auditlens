# AuditLens: Context-Aware Code Vulnerability Auditor with Proof-of-Exploit

A static application security testing (SAST) and reachability auditor designed to bridge the gap between static taint analysis and real exploitability.

---

## Why AuditLens?

Traditional SAST tools flag every dangerous function (`os.system()`, `cursor.execute()`) regardless of whether user input can reach it or whether proper sanitization exists along the execution path. This results in **alert fatigue** and high false-positive rates.

**AuditLens** performs **Source-to-Sink Taint Correlation & Reachability Verification**:
1. Identifies untrusted user input sources (`request.args`, `req.body`, `argv`).
2. Traces variables into dangerous execution sinks (`os.system`, `subprocess`, raw SQL queries, file opens).
3. Verifies whether intermediate sanitization (`shlex.quote`, parameterized queries, int casting) neutralizes the vulnerability.
4. For confirmed vulnerabilities, automatically synthesizes an actionable **Proof-of-Concept (PoC) reproduction curl command**.

---

## Vulnerabilities Detected

- **CWE-78: Command Injection**: Unescaped user input reaching shell execution contexts.
- **CWE-89: SQL Injection**: String concatenation or formatting inside raw database queries.
- **CWE-22: Path Traversal**: Unvalidated paths reaching filesystem read/write operations.
- **CWE-94: Code Injection / Eval**: Dynamic evaluation of user-supplied code.

---

## Quick Start

### 1. Installation
```bash
# Standard Python 3.10+ (No heavy binary dependencies required)
pip install -r requirements.txt
```

### 2. Audit a Source File or Repository
```bash
# Scan a single file:
python3 -m auditlens.cli examples/vulnerable_app.py

# Scan an entire repository and save Markdown report:
python3 -m auditlens.cli /path/to/codebase --out audit_report.md
```

---

## Sample Output

```markdown
# AuditLens Security Audit Report
**Target**: `examples/vulnerable_app.py`
**Total Candidates Audited**: 4
**Confirmed Vulnerabilities**: `2`
**Filtered False Positives**: `2`
**Needs Manual Review**: `0`

## Summary Table
| File | Line | Vulnerability Class | Verdict | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| `vulnerable_app.py` | 17 | CWE-78: Command Injection | 🚨 VULNERABLE | 95% |
| `vulnerable_app.py` | 25 | CWE-78: Command Injection | ✅ FILTERED (SAFE) | 90% |
| `vulnerable_app.py` | 33 | CWE-89: SQL Injection | 🚨 VULNERABLE | 95% |
| `vulnerable_app.py` | 41 | CWE-89: SQL Injection | ✅ FILTERED (SAFE) | 90% |

### 1. [CWE-78: Command Injection] at `examples/vulnerable_app.py:17`
- **Verdict**: `CONFIRMED_VULNERABLE` (Confidence: `95%`)
- **Analysis**: User input is directly concatenated or formatted into a shell execution context without escaping.
- **Dangerous Sink**: `os.system(f"ping -c 1 {host}")`
- **Input Source**: `request.args`

**Proof of Concept (PoC) Reproduction**:
```bash
curl -X POST 'http://localhost:5000/api' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'target=127.0.0.1; id #'
```
