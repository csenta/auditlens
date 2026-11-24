"""
Reachability analyzer and sanitizer verification for AuditLens.
Evaluates whether user input flows into a dangerous sink without neutralizing sanitizers.
"""

import re
from auditlens.models import SourceSinkCandidate, VulnClass, AuditVerdict, AuditFinding


class ReachabilityAnalyzer:

    # Sanitizers categorized by vulnerability class
    SANITIZERS = {
        VulnClass.COMMAND_INJECTION: [
            r"shlex\.quote",
            r"shlex\.split",
            r"escapeshellcmd",
            r"escapeshellarg",
        ],
        VulnClass.SQL_INJECTION: [
            r",\s*\([^)]*\)",  # Parameterized tuple: cursor.execute(query, (param,))
            r",\s*\[[^\]]*\]",  # Parameterized list: cursor.execute(query, [param])
            r"int\s*\(",        # Integer casting
        ],
        VulnClass.PATH_TRAVERSAL: [
            r"os\.path\.basename",
            r"path\.basename",
            r"secure_filename",
        ],
    }

    # Dangerous formatting patterns (f-string, format, modulo, string concat)
    UNSAFE_FORMATTING = re.compile(
        r'(?:\bf["\'].*?\{[^}]+\}.*?["\']|%\s*(?:\([^)]+\)|\w+)|\.format\s*\(|\+\s*\w+)'
    )

    @classmethod
    def analyze_candidate(cls, candidate: SourceSinkCandidate) -> AuditFinding:
        context = candidate.code_context
        sink = candidate.sink_expr
        vuln_class = candidate.vuln_class

        # Strip single-line comments (# and //) so comments mentioning sanitizers don't mislead analysis
        code_without_comments = re.sub(r"#.*$", "", context, flags=re.MULTILINE)
        code_without_comments = re.sub(r"//.*$", "", code_without_comments, flags=re.MULTILINE)

        # 1. Check for neutralizing sanitizers in code statements
        sanitizer_patterns = cls.SANITIZERS.get(vuln_class, [])
        for pattern in sanitizer_patterns:
            if re.search(pattern, code_without_comments):
                clean_name = re.sub(r"\\b|\\", "", pattern)
                return AuditFinding(
                    candidate=candidate,
                    verdict=AuditVerdict.FALSE_POSITIVE,
                    confidence=0.9,
                    explanation=f"Sanitization detected matching '{clean_name}'. Taint path is neutralized.",
                    remediation="Existing sanitization appears adequate. Ensure edge cases like null bytes are handled.",
                )

        # 2. Check for explicit unsafe formatting in the sink
        is_unsafe_format = bool(cls.UNSAFE_FORMATTING.search(sink))

        if vuln_class == VulnClass.COMMAND_INJECTION:
            has_shell_true = "shell=True" in sink or "os.system" in sink
            if has_shell_true or is_unsafe_format:
                return AuditFinding(
                    candidate=candidate,
                    verdict=AuditVerdict.CONFIRMED_VULNERABLE,
                    confidence=0.95,
                    explanation="User input is directly concatenated or formatted into a shell execution context without escaping.",
                    proof_of_concept="; id # or & whoami",
                    remediation="Use subprocess.run(['command', arg], shell=False) or escape input with shlex.quote().",
                )

        elif vuln_class == VulnClass.SQL_INJECTION:
            if is_unsafe_format:
                return AuditFinding(
                    candidate=candidate,
                    verdict=AuditVerdict.CONFIRMED_VULNERABLE,
                    confidence=0.95,
                    explanation="Raw string interpolation/formatting detected in SQL execution without parameterized query placeholders.",
                    proof_of_concept="' OR '1'='1",
                    remediation="Use parameterized queries: cursor.execute('SELECT * FROM tbl WHERE id = %s', (user_id,))",
                )

        elif vuln_class == VulnClass.PATH_TRAVERSAL:
            if is_unsafe_format or "+" in sink:
                return AuditFinding(
                    candidate=candidate,
                    verdict=AuditVerdict.CONFIRMED_VULNERABLE,
                    confidence=0.9,
                    explanation="Path string constructed using unvalidated user input without os.path.basename or confinement checks.",
                    proof_of_concept="../../../../../etc/passwd",
                    remediation="Use os.path.basename() or verify os.path.abspath(target).startswith(allowed_dir).",
                )

        return AuditFinding(
            candidate=candidate,
            verdict=AuditVerdict.NEEDS_REVIEW,
            confidence=0.5,
            explanation="Taint flow detected between source and sink, but intermediate validation requires manual audit.",
            remediation="Review variable data flow between input source and execution sink.",
        )
