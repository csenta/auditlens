"""
Static source and sink scanner for AuditLens.
Scans source code for potential taint flows from user input sources to dangerous sinks.
"""

import os
import re
from auditlens.models import VulnClass, SourceSinkCandidate


class CodeScanner:

    # Sinks categorized by vulnerability class
    SINKS = [
        (
            VulnClass.COMMAND_INJECTION,
            re.compile(r"(?:os\.system|subprocess\.(?:Popen|run|call|check_output)|child_process\.exec)\s*\((?P<sink>.*)\)"),
        ),
        (
            VulnClass.SQL_INJECTION,
            re.compile(r"(?:cursor\.execute|db\.query|connection\.execute)\s*\((?P<sink>.*)\)"),
        ),
        (
            VulnClass.PATH_TRAVERSAL,
            re.compile(r"(?:open|fs\.readFile|fs\.readFileSync|send_file)\s*\((?P<sink>.*)\)"),
        ),
        (
            VulnClass.CODE_INJECTION,
            re.compile(r"(?:eval|exec)\s*\((?P<sink>.*)\)"),
        ),
    ]

    # User Input Sources
    SOURCES = re.compile(
        r"(?:request\.(?:args|form|values|json|get_json|params|headers|cookies)|req\.(?:query|body|params|headers)|sys\.argv|input\s*\()"
    )

    @classmethod
    def scan_file(cls, file_path: str) -> list[SourceSinkCandidate]:
        if not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        full_content = "".join(lines)
        # If file has no input sources anywhere, skip
        if not cls.SOURCES.search(full_content):
            return []

        candidates: list[SourceSinkCandidate] = []

        for line_idx, line in enumerate(lines, 1):
            for vuln_class, sink_pattern in cls.SINKS:
                match = sink_pattern.search(line)
                if match:
                    # Locate enclosing function boundary
                    func_start = line_idx - 1
                    while func_start > 0 and not lines[func_start].lstrip().startswith("def "):
                        func_start -= 1
                    
                    if not lines[func_start].lstrip().startswith("def "):
                        func_start = max(0, line_idx - 10)

                    # Look forward until next unindented def/class or max 15 lines
                    func_end = line_idx
                    while func_end < len(lines) and not (lines[func_end].startswith("def ") or lines[func_end].startswith("@")):
                        func_end += 1

                    context_block = "".join(lines[func_start:func_end])

                    source_match = cls.SOURCES.search(context_block)
                    if source_match:
                        candidates.append(
                            SourceSinkCandidate(
                                vuln_class=vuln_class,
                                file_path=file_path,
                                line_number=line_idx,
                                source_expr=source_match.group(0),
                                sink_expr=match.group(0).strip(),
                                code_context=context_block,
                            )
                        )

        return candidates

    @classmethod
    def scan_directory(cls, dir_path: str) -> list[SourceSinkCandidate]:
        candidates: list[SourceSinkCandidate] = []
        target_exts = {".py", ".js", ".ts", ".php"}

        for root, _, files in os.walk(dir_path):
            if any(ignored in root for ignored in ("node_modules", ".git", "venv", "__pycache__")):
                continue
            for file in files:
                if any(file.endswith(ext) for ext in target_exts):
                    path = os.path.join(root, file)
                    candidates.extend(cls.scan_file(path))

        return candidates
