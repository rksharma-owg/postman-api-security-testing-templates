# Payload Library

This directory contains non-destructive canary payloads for authorized API security testing.
Every category has at least 11 examples, a `metadata.json` index, and a category README.

## Categories

| Directory | Purpose | Primary mapping |
|---|---|---|
| `command-injection/` | Shell metacharacter and argument-boundary detection | OWASP Web A03:2021 |
| `fuzz/` | Type, length, encoding, and boundary handling | Context-dependent |
| `graphql/` | GraphQL validation, batching, aliases, and bounded depth | OWASP API4/API8:2023 |
| `jwt/` | Token parsing, algorithm, signature, and claim validation | OWASP API2:2023 |
| `nosqli/` | NoSQL operator and type-confusion handling | OWASP Web A03:2021 |
| `path-traversal/` | Path normalization using nonexistent canary files | OWASP Web A01:2021 |
| `sqli/` | SQL parser and boolean-response canaries | OWASP Web A03:2021 |
| `ssrf/` | URL validation using reserved, non-resolving domains | OWASP API7:2023 |
| `xss/` | Output-encoding canaries without data access or exfiltration | OWASP Web A03:2021 |

## Safety Rules

- Run tests only against systems you own or are explicitly authorized to assess.
- Examples use inert markers, nonexistent files, or RFC-reserved `.invalid` domains.
- No payload reads credentials, accesses cloud metadata, modifies data, launches a shell,
  or transmits browser/session data.
- Start with a single request and use conservative rate limits.
- The word “safe” means non-destructive by design, not risk-free in every environment.

Run `npm run validate:payloads` before committing changes.
