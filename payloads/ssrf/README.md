# SSRF Validation Payloads

These examples use the RFC-reserved `.invalid` top-level domain, which is guaranteed not to
resolve publicly. They test URL parsing without targeting cloud metadata or real internal hosts.

- Primary mapping: OWASP API7:2023 — Server Side Request Forgery
- Examples: 12
- Expected secure result: reject untrusted URLs or allow only explicitly approved destinations
- File: `ssrf_safe_tests.payload`

Use only against an authorized test environment.
