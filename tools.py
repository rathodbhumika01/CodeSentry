"""
Code Sentry - Security Scanner
Scans Python source code for common vulnerability patterns.
"""

import re


def scan_vulnerabilities(code: str) -> list:
    """
    Scan a code snippet for common security vulnerabilities.
    Returns a list of findings, where each finding is a dict with:
        - category: type of vulnerability
        - severity: HIGH, MEDIUM, or LOW
        - line: line number where it was found
        - description: short explanation
    """
    findings = []

    if not code or not code.strip():
        return findings

    lines = code.split("\n")

    patterns = [
        {
            "regex": r"\beval\s*\(",
            "category": "Code Injection",
            "severity": "HIGH",
            "description": "Use of eval() can execute arbitrary code if input is not trusted.",
        },
        {
            "regex": r"\bexec\s*\(",
            "category": "Code Injection",
            "severity": "HIGH",
            "description": "Use of exec() can execute arbitrary code if input is not trusted.",
        },
        {
            "regex": r"subprocess\.\w+\([^)]*shell\s*=\s*True",
            "category": "Command Injection",
            "severity": "HIGH",
            "description": "subprocess call with shell=True can allow command injection if input is user-controlled.",
        },
        {
            "regex": r"os\.system\s*\(",
            "category": "Command Injection",
            "severity": "HIGH",
            "description": "os.system() executes shell commands and is risky with untrusted input.",
        },
        {
            "regex": r"pickle\.loads?\s*\(",
            "category": "Insecure Deserialization",
            "severity": "HIGH",
            "description": "Unpickling untrusted data can lead to arbitrary code execution.",
        },
        {
            "regex": r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)",
            "category": "Insecure Deserialization",
            "severity": "MEDIUM",
            "description": "yaml.load() without SafeLoader can execute arbitrary code from YAML input.",
        },
        {
            "regex": r"hashlib\.md5\s*\(",
            "category": "Weak Cryptography",
            "severity": "MEDIUM",
            "description": "MD5 is a weak hash algorithm and should not be used for security purposes.",
        },
        {
            "regex": r"hashlib\.sha1\s*\(",
            "category": "Weak Cryptography",
            "severity": "MEDIUM",
            "description": "SHA1 is considered weak and should not be used for security purposes.",
        },
        {
            "regex": r"(?i)(password|api_key|secret|token)\s*=\s*[\"'][^\"']+[\"']",
            "category": "Hardcoded Credentials",
            "severity": "HIGH",
            "description": "Hardcoded credentials found in source code.",
        },
        {
            "regex": r"f[\"'].*SELECT.*\{.*\}.*[\"']",
            "category": "SQL Injection",
            "severity": "HIGH",
            "description": "Building SQL queries with f-strings and variable interpolation risks SQL injection.",
        },
        {
            "regex": r"(?:execute|cursor\.execute)\s*\([^)]*%\s*\(",
            "category": "SQL Injection",
            "severity": "HIGH",
            "description": "String formatting inside SQL execute() risks SQL injection.",
        },
        {
            "regex": r"\+.*SELECT|SELECT.*\+",
            "category": "SQL Injection",
            "severity": "MEDIUM",
            "description": "String concatenation used to build SQL query - risk of SQL injection.",
        },
    ]

    for line_num, line in enumerate(lines, start=1):
        for pattern in patterns:
            if re.search(pattern["regex"], line):
                findings.append(
                    {
                        "category": pattern["category"],
                        "severity": pattern["severity"],
                        "line": line_num,
                        "description": pattern["description"],
                    }
                )

    return findings