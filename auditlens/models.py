"""
Data models for AuditLens code vulnerability auditor.
"""

from dataclasses import dataclass, field
from enum import Enum


class VulnClass(str, Enum):
    COMMAND_INJECTION = "CWE-78: Command Injection"
    SQL_INJECTION = "CWE-89: SQL Injection"
    PATH_TRAVERSAL = "CWE-22: Path Traversal"
    SSRF = "CWE-918: Server-Side Request Forgery"
    CODE_INJECTION = "CWE-94: Code Injection / Eval"


class AuditVerdict(str, Enum):
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"


@dataclass
class SourceSinkCandidate:
    vuln_class: VulnClass
    file_path: str
    line_number: int
    source_expr: str
    sink_expr: str
    code_context: str


@dataclass
class AuditFinding:
    candidate: SourceSinkCandidate
    verdict: AuditVerdict
    confidence: float
    explanation: str
    proof_of_concept: str | None = None
    remediation: str | None = None
