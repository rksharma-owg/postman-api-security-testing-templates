# NoSQL Injection Validation Payloads

These examples test strict typing and rejection of client-controlled query operators. Values
use unlikely canary strings and do not request data modification.

- Primary mapping: OWASP Web A03:2021 — Injection
- Examples: 12
- Expected secure result: schema-validation error or literal-string handling
- File: `nosqli_safe_tests.payload`

Use only against an authorized test environment.
