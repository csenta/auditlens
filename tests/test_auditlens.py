"""
Unit tests for AuditLens code vulnerability auditor and reachability analyzer.
"""

import tempfile
import unittest
from auditlens.scanner import CodeScanner
from auditlens.reachability import ReachabilityAnalyzer
from auditlens.poc_gen import PoCGenerator
from auditlens.models import VulnClass, AuditVerdict


class TestAuditLens(unittest.TestCase):

    def test_vulnerable_command_injection(self):
        sample_code = """
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    ip = request.args.get('host')
    os.system(f"ping -c 1 {ip}")
    return "done"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(sample_code)
            f.flush()
            candidates = CodeScanner.scan_file(f.name)

        self.assertEqual(len(candidates), 1)
        finding = ReachabilityAnalyzer.analyze_candidate(candidates[0])
        self.assertEqual(finding.verdict, AuditVerdict.CONFIRMED_VULNERABLE)
        self.assertEqual(finding.candidate.vuln_class, VulnClass.COMMAND_INJECTION)

        poc = PoCGenerator.generate_reproduction(finding)
        self.assertIn("curl", poc)
        self.assertIn("; id", poc)

    def test_sanitized_command_injection_false_positive(self):
        sample_code = """
from flask import Flask, request
import os, shlex

app = Flask(__name__)

@app.route('/ping')
def ping():
    ip = request.args.get('host')
    safe_ip = shlex.quote(ip)
    os.system(f"ping -c 1 {safe_ip}")
    return "done"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(sample_code)
            f.flush()
            candidates = CodeScanner.scan_file(f.name)

        self.assertEqual(len(candidates), 1)
        finding = ReachabilityAnalyzer.analyze_candidate(candidates[0])
        self.assertEqual(finding.verdict, AuditVerdict.FALSE_POSITIVE)
        self.assertIn("shlex.quote", finding.explanation)

    def test_vulnerable_sql_injection(self):
        sample_code = """
from flask import Flask, request

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return "ok"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(sample_code)
            f.flush()
            candidates = CodeScanner.scan_file(f.name)

        self.assertEqual(len(candidates), 1)
        finding = ReachabilityAnalyzer.analyze_candidate(candidates[0])
        self.assertEqual(finding.verdict, AuditVerdict.CONFIRMED_VULNERABLE)
        self.assertEqual(finding.candidate.vuln_class, VulnClass.SQL_INJECTION)

    def test_parameterized_sql_injection_false_positive(self):
        sample_code = """
from flask import Flask, request

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return "ok"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(sample_code)
            f.flush()
            candidates = CodeScanner.scan_file(f.name)

        self.assertEqual(len(candidates), 1)
        finding = ReachabilityAnalyzer.analyze_candidate(candidates[0])
        self.assertEqual(finding.verdict, AuditVerdict.FALSE_POSITIVE)


if __name__ == "__main__":
    unittest.main()
