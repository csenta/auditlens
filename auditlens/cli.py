#!/usr/bin/env python3
"""
CLI for AuditLens: Context-Aware Code Vulnerability Auditor with Proof-of-Exploit Synthesis.
"""

import argparse
import os
import sys
from auditlens.scanner import CodeScanner
from auditlens.reachability import ReachabilityAnalyzer
from auditlens.poc_gen import PoCGenerator
from auditlens.models import AuditVerdict, AuditFinding


def format_markdown_report(findings: list[AuditFinding], target_path: str) -> str:
    confirmed = [f for f in findings if f.verdict == AuditVerdict.CONFIRMED_VULNERABLE]
    false_positives = [f for f in findings if f.verdict == AuditVerdict.FALSE_POSITIVE]
    needs_review = [f for f in findings if f.verdict == AuditVerdict.NEEDS_REVIEW]

    lines = [
        "# AuditLens Security Audit Report",
        f"**Target**: `{target_path}`",
        f"**Total Candidates Audited**: {len(findings)}",
        f"**Confirmed Vulnerabilities**: `{len(confirmed)}`",
        f"**Filtered False Positives**: `{len(false_positives)}`",
        f"**Needs Manual Review**: `{len(needs_review)}`",
        "",
        "---",
        "",
        "## Summary Table",
        "| File | Line | Vulnerability Class | Verdict | Confidence |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for f in findings:
        c = f.candidate
        status = "🚨 VULNERABLE" if f.verdict == AuditVerdict.CONFIRMED_VULNERABLE else (
            "✅ FILTERED (SAFE)" if f.verdict == AuditVerdict.FALSE_POSITIVE else "⚠️ REVIEW"
        )
        lines.append(f"| `{os.path.basename(c.file_path)}` | {c.line_number} | {c.vuln_class.value} | {status} | {f.confidence * 100:.0f}% |")

    lines.extend(["", "---", "", "## Confirmed Vulnerability Details"])
    if not confirmed:
        lines.append("No confirmed exploitable vulnerabilities detected.")
    else:
        for i, f in enumerate(confirmed, 1):
            c = f.candidate
            poc = PoCGenerator.generate_reproduction(f)
            lines.extend([
                f"### {i}. [{c.vuln_class.value}] at `{c.file_path}:{c.line_number}`",
                f"- **Verdict**: `{f.verdict.value}` (Confidence: `{f.confidence * 100:.0f}%`)",
                f"- **Analysis**: {f.explanation}",
                f"- **Dangerous Sink**: `{c.sink_expr}`",
                f"- **Input Source**: `{c.source_expr}`",
                "",
                "**Vulnerable Code Snippet**:",
                "```python",
                c.code_context.strip(),
                "```",
                "",
                "**Proof of Concept (PoC) Reproduction**:",
                "```bash",
                poc,
                "```",
                "",
                f"**Recommended Remediation**: {f.remediation}",
                "",
            ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="AuditLens: Context-Aware Code Vulnerability Auditor with Proof-of-Exploit."
    )
    parser.add_argument("target", help="Path to source file or project directory to audit")
    parser.add_argument("--out", help="Path to save output Markdown audit report")
    parser.add_argument(
        "--only-vulnerable",
        action="store_true",
        help="Only display confirmed vulnerabilities (filter out safe / false positives)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[!] Error: Target path '{args.target}' does not exist.")
        sys.exit(1)

    print(f"[*] Scanning '{args.target}' for source-to-sink taint candidates...")
    if os.path.isfile(args.target):
        candidates = CodeScanner.scan_file(args.target)
    else:
        candidates = CodeScanner.scan_directory(args.target)

    print(f"[*] Analyzing reachability and sanitization across {len(candidates)} candidates...")
    findings: list[AuditFinding] = []
    for c in candidates:
        finding = ReachabilityAnalyzer.analyze_candidate(c)
        findings.append(finding)

    confirmed_count = sum(1 for f in findings if f.verdict == AuditVerdict.CONFIRMED_VULNERABLE)
    print(f"[+] Audit completed: {confirmed_count} confirmed vulnerabilities found.")

    report_md = format_markdown_report(findings, args.target)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"[+] Saved Markdown report to: {args.out}")
    else:
        print("\n" + report_md)

    if confirmed_count > 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
