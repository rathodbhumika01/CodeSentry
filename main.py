"""
Code Sentry - AI-powered security code reviewer.
Run with: python main.py
"""

import os
import sys
import time

from google import genai
from google.genai import types
from google.genai import errors

from tools import scan_vulnerabilities
from prompts import SYSTEM_PROMPT


def get_client() -> genai.Client:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY environment variable is not set.")
        print("Set it before running, for example on Windows PowerShell:")
        print('  $env:GEMINI_API_KEY="your_api_key_here"')
        sys.exit(1)
    return genai.Client(api_key=api_key)


def run_review(client: genai.Client, question: str, code: str) -> str:
    user_message = f"""Security question: {question}

Code to review:
{code}
"""

    config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=[scan_vulnerabilities],
    )

    chat = client.chats.create(model="gemini-3.8-flash", config=config)

    max_attempts = 6
    for attempt in range(1, max_attempts + 1):
        try:
            response = chat.send_message(user_message)
            return response.text
        except (errors.ServerError, errors.APIError, Exception) as e:
            if attempt == max_attempts:
                raise
            wait_seconds = 15
            print(f"Request failed ({type(e).__name__}). Attempt {attempt}/{max_attempts}. Retrying in {wait_seconds}s...")
            time.sleep(wait_seconds)


def main():
    print("=" * 40)
    print("        CODE SENTRY SECURITY REVIEW")
    print("=" * 40)

    client = get_client()

    question = input("\nSecurity question: ")
    print("\nPaste your code below. Type 'END' on its own line when done:")

    code_lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        code_lines.append(line)
    code = "\n".join(code_lines)

    print("\nReviewing your code, please wait...\n")

    result = run_review(client, question, code)

    print("=" * 40)
    print(result)
    print("=" * 40)


if __name__ == "__main__":
    main()