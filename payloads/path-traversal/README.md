# Path Traversal Validation Payloads

These examples reference a deliberately nonexistent canary filename. They test normalization and
root confinement without requesting operating-system or application secrets.

- Primary mapping: OWASP Web A01:2021 — Broken Access Control
- Examples: 12
- Expected secure result: reject traversal or resolve only inside the configured storage root
- File: `path_traversal_safe_tests.payload`

Use only against an authorized test environment.
