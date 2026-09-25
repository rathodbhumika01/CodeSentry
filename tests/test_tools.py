"""
Tests for the Code Sentry vulnerability scanner.
Run with: pytest
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import scan_vulnerabilities


def test_clean_code():
    code = """
def add(a, b):
    return a + b
"""
    findings = scan_vulnerabilities(code)
    assert findings == []


def test_detect_eval():
    code = """
user_input = input()
result = eval(user_input)
"""
    findings = scan_vulnerabilities(code)
    categories = [f["category"] for f in findings]
    assert "Code Injection" in categories


def test_detect_sql_injection():
    code = """
username = input()
query = f"SELECT * FROM users WHERE name='{username}'"
"""
    findings = scan_vulnerabilities(code)
    categories = [f["category"] for f in findings]
    assert "SQL Injection" in categories


def test_detect_shell_true():
    code = """
import subprocess
command = input("Enter command: ")
subprocess.run(command, shell=True)
"""
    findings = scan_vulnerabilities(code)
    categories = [f["category"] for f in findings]
    assert "Command Injection" in categories


def test_detect_pickle():
    code = """
import pickle
data = input()
obj = pickle.loads(data)
"""
    findings = scan_vulnerabilities(code)
    categories = [f["category"] for f in findings]
    assert "Insecure Deserialization" in categories


def test_detect_weak_hash():
    code = """
import hashlib
password = "admin123"
hash_value = hashlib.md5(password.encode()).hexdigest()
"""
    findings = scan_vulnerabilities(code)
    categories = [f["category"] for f in findings]
    assert "Weak Cryptography" in categories


def test_detect_hardcoded_credentials():
    code = """
API_KEY = "abc123secret"
"""
    findings = scan_vulnerabilities(code)
    categories = [f["category"] for f in findings]
    assert "Hardcoded Credentials" in categories


def test_detect_multiple_vulnerabilities():
    code = """
import pickle
import subprocess
import hashlib

password = "admin123"

data = input()
obj = pickle.loads(data)

command = input()
subprocess.run(command, shell=True)

hash_value = hashlib.md5(password.encode()).hexdigest()
"""
    findings = scan_vulnerabilities(code)
    assert len(findings) >= 4


def test_empty_code_does_not_crash():
    findings = scan_vulnerabilities("")
    assert findings == []