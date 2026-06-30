# JWT Validation Payloads

These examples test token parsing, algorithm allowlists, signature enforcement, and claim
validation without containing usable credentials.

- Primary mapping: OWASP API2:2023 — Broken Authentication
- Examples: 12
- Expected secure result: `401` or `403`, with no token details leaked
- File: `jwt_safe_tests.payload`

Use only against an authorized test environment.
