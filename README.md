# Code Sentry

Code Sentry is an AI-powered security code reviewer. You give it a piece of
code and a question, and it uses Google's Gemini model to decide whether the
code needs a security scan. If it does, Gemini calls a local vulnerability
scanner tool, then explains the findings in plain language along with an
overall risk verdict and suggested fixes.

## How it works

User -> main.py -> Gemini (decides if a scan is needed) -> scan_vulnerabilities() in tools.py -> Gemini explains the findings -> Final security report

The scanner never runs automatically just because risky-looking code is
detected in the Python source. Gemini itself decides, using tool/function
calling, whether to call the scanner.

## What the scanner detects

- Code injection (`eval`, `exec`)
- Command injection (`subprocess` with `shell=True`, `os.system`)
- Insecure deserialization (`pickle.loads`, unsafe `yaml.load`)
- Weak cryptography (MD5, SHA1)
- Hardcoded credentials (passwords, API keys, secrets, tokens)
- SQL injection (f-string queries, string concatenation, string formatting in `execute()`)

## Project structure

Code_Sentry/
- main.py - Main application, connects user input, Gemini, and the scanner
- tools.py - scan_vulnerabilities() implementation
- prompts.py - Gemini security-expert system prompt
- requirements.txt - Required Python packages
- README.md
- .gitignore
- tests/test_tools.py - Unit tests for the scanner

## Setup

1. Create and activate a virtual environment:
python -m venv venv
venv\Scripts\activate


2. Install dependencies:
pip install -r requirements.txt


3. Set your Gemini API key as an environment variable. Do not hardcode it anywhere in the source code.

Windows (PowerShell):
$env:GEMINI_API_KEY="AQ.Ab8RN6LzDoyz0sn5sx_8SYch6K-Owq2egxDQMsRw0NcL3JAzGA"


You can get a free API key from Google AI Studio: https://aistudio.google.com/apikey

## Usage

Run the application:
python main.py


You'll be asked for a security question, then asked to paste the code to review. Type `END` on its own line when you're done pasting the code.

### Example
Security question: Is this code safe to use in production?

Paste your code below. Type 'END' on its own line when done:
import subprocess
command = input("Enter command: ")
subprocess.run(command, shell=True)
END


Example output:
Overall Verdict: HIGH RISK

Finding: Command Injection (High Severity)
Location: Line 3 - subprocess.run(command, shell=True)

What is the issue?
The program takes input directly from the user and passes it to the system shell using shell=True.

How to fix it?
Avoid shell=True. Pass command arguments as a list of strings rather than a single raw string passed to a shell.


## Running the tests
pytest

This runs the scanner's unit tests, covering clean code, each vulnerability category individually, multiple vulnerabilities in one snippet, and empty input.

## Assumptions and notes

- The scanner uses pattern matching (regular expressions), not a full static-analysis engine, so it may miss some vulnerabilities and can occasionally flag safe code. It is meant to assist, not replace, a full manual security review.
- If the Gemini API returns a temporary server error (for example, the model being under high demand), the application automatically retries a few times with a short delay before giving up.
- No database, web server, or authentication is used - this is a local command-line Python application, not a full-stack project.

