# Command Injection Validation Payloads

These examples use shell separators with `echo` or `printf` canaries only. They do not inspect
the host, launch an interactive shell, change files, or contact the network.

- Primary mapping: OWASP Web A03:2021 — Injection
- Examples: 12
- Expected secure result: literal handling or input rejection; no canary in command output
- File: `command_injection_safe_tests.payload`

Use only against an authorized test environment.
