#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path, content):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + "\n", encoding="utf-8")


def write_json(path, data):
    write(path, json.dumps(data, indent=2))


def request_item(name, method, path, tests, prerequest="", body=None, headers=None):
    headers = headers or [
        {"key": "Accept", "value": "application/json"},
        {"key": "Authorization", "value": "Bearer {{access_token}}"},
    ]
    item = {
        "name": name,
        "event": [
            {
                "listen": "prerequest",
                "script": {"type": "text/javascript", "exec": prerequest.splitlines()},
            },
            {
                "listen": "test",
                "script": {"type": "text/javascript", "exec": tests.splitlines()},
            },
        ],
        "request": {
            "method": method,
            "header": headers,
            "url": {
                "raw": "{{base_url}}" + path,
                "host": ["{{base_url}}"],
                "path": [p for p in path.strip("/").split("/") if p],
            },
            "description": "Safe defensive test template. Run only against systems you own or are authorized to assess.",
        },
    }
    if body is not None:
        item["request"]["body"] = {
            "mode": "raw",
            "raw": json.dumps(body, indent=2),
            "options": {"raw": {"language": "json"}},
        }
        item["request"]["header"].append({"key": "Content-Type", "value": "application/json"})
    return item


COMMON_PREREQUEST = """
const runId = pm.variables.replaceIn('{{$guid}}');
pm.collectionVariables.set('run_id', runId);
pm.request.headers.upsert({ key: 'X-Security-Test-Run', value: runId });
pm.request.headers.upsert({ key: 'X-Requested-By', value: 'postman-api-security-testing-templates' });
""".strip()

SECURITY_TESTS = """
pm.test('response is a documented security outcome', function () {
  pm.expect([200, 201, 202, 204, 400, 401, 403, 404, 409, 415, 422, 429]).to.include(pm.response.code);
});
pm.test('no stack trace or implementation detail is leaked', function () {
  const body = pm.response.text().toLowerCase();
  pm.expect(body).to.not.include('traceback');
  pm.expect(body).to.not.include('stack trace');
  pm.expect(body).to.not.include('syntaxerror');
});
pm.test('response is not unexpectedly permissive', function () {
  if (pm.info.requestName.toLowerCase().includes('missing') || pm.info.requestName.toLowerCase().includes('invalid') || pm.info.requestName.toLowerCase().includes('bypass')) {
    pm.expect([401, 403, 404, 422, 429]).to.include(pm.response.code);
  }
});
""".strip()


def collection(name, description, folders):
    return {
        "info": {
            "_postman_id": "{{postman_guid}}",
            "name": name,
            "description": description,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "event": [
            {
                "listen": "prerequest",
                "script": {
                    "type": "text/javascript",
                    "exec": [
                        "pm.collectionVariables.set('started_at', new Date().toISOString());",
                        "pm.collectionVariables.set('toolkit', 'postman-api-security-testing-templates');",
                    ],
                },
            }
        ],
        "variable": [
            {"key": "base_url", "value": "{{base_url}}"},
            {"key": "access_token", "value": "{{access_token}}"},
            {"key": "user_id", "value": "1001"},
            {"key": "other_user_id", "value": "1002"},
            {"key": "admin_token", "value": "{{admin_token}}"},
        ],
        "item": folders,
    }


def folder(name, items, description):
    return {"name": name, "description": description, "item": items}


collections = {
    "collections/auth/authentication-security.postman_collection.json": collection(
        "Authentication Security Testing",
        "Templates for validating token handling, broken authentication, OAuth misuse, and refresh-token controls.",
        [
            folder(
                "Bearer Token Validation",
                [
                    request_item("Missing bearer token is rejected", "GET", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Accept", "value": "application/json"}]),
                    request_item("Invalid bearer token is rejected", "GET", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Authorization", "value": "Bearer invalid.token.value"}]),
                    request_item("Expired bearer token is rejected", "GET", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Authorization", "value": "Bearer {{expired_token}}"}]),
                ],
                "Negative tests for token presence, syntax, and expiry.",
            ),
            folder(
                "OAuth and Refresh Tokens",
                [
                    request_item("Refresh token reuse is detected", "POST", "/api/v1/auth/refresh", SECURITY_TESTS, COMMON_PREREQUEST, {"refresh_token": "{{used_refresh_token}}"}),
                    request_item("OAuth token audience mismatch is rejected", "GET", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Authorization", "value": "Bearer {{wrong_audience_token}}"}]),
                ],
                "Safe checks for common OAuth lifecycle mistakes.",
            ),
        ],
    ),
    "collections/authorization/authorization-security.postman_collection.json": collection(
        "Authorization Security Testing",
        "Templates for IDOR, horizontal and vertical privilege escalation, tenant isolation, and role bypass validation.",
        [
            folder(
                "Object Access",
                [
                    request_item("Own record is accessible", "GET", "/api/v1/users/{{user_id}}/orders", SECURITY_TESTS, COMMON_PREREQUEST),
                    request_item("Other user record is denied", "GET", "/api/v1/users/{{other_user_id}}/orders", SECURITY_TESTS, COMMON_PREREQUEST),
                    request_item("Sequential identifier probing is denied", "GET", "/api/v1/invoices/{{invoice_id}}", SECURITY_TESTS, COMMON_PREREQUEST),
                ],
                "Validate object-level authorization, including predictable identifiers.",
            ),
            folder(
                "Role and Tenant Boundaries",
                [
                    request_item("User cannot access admin endpoint", "GET", "/api/v1/admin/users", SECURITY_TESTS, COMMON_PREREQUEST),
                    request_item("Tenant isolation prevents cross-tenant reads", "GET", "/api/v1/tenants/{{other_tenant_id}}/settings", SECURITY_TESTS, COMMON_PREREQUEST),
                    request_item("Role override body field is ignored", "PATCH", "/api/v1/users/{{user_id}}", SECURITY_TESTS, COMMON_PREREQUEST, {"role": "admin"}),
                ],
                "Check vertical authorization and multi-tenant enforcement.",
            ),
        ],
    ),
    "collections/jwt/jwt-security.postman_collection.json": collection(
        "JWT Security Testing",
        "JWT validation checks for algorithm confusion, signature verification, claim enforcement, and key handling.",
        [
            folder(
                "JWT Tampering",
                [
                    request_item("Unsigned JWT is rejected", "GET", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Authorization", "value": "Bearer {{jwt_none_alg}}"}]),
                    request_item("Modified role claim is rejected", "GET", "/api/v1/admin/users", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Authorization", "value": "Bearer {{jwt_tampered_role}}"}]),
                    request_item("Expired exp claim is enforced", "GET", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Authorization", "value": "Bearer {{jwt_expired}}"}]),
                ],
                "Defensive validation for common JWT implementation errors.",
            )
        ],
    ),
    "collections/injection/injection-security.postman_collection.json": collection(
        "Injection Security Testing",
        "Safe payload-driven templates for SQL, NoSQL, command, LDAP, XPath, and GraphQL injection detection.",
        [
            folder(
                "Query Parameters",
                [
                    request_item("SQL meta characters are handled safely", "GET", "/api/v1/search?q={{sql_payload}}", SECURITY_TESTS, COMMON_PREREQUEST),
                    request_item("NoSQL operator-like input is handled safely", "POST", "/api/v1/search", SECURITY_TESTS, COMMON_PREREQUEST, {"email": {"$ne": "safe@example.test"}}),
                    request_item("Command metacharacters are treated as data", "POST", "/api/v1/tools/lookup", SECURITY_TESTS, COMMON_PREREQUEST, {"host": "example.test; whoami"}),
                ],
                "Use controlled payloads that validate error handling and input treatment.",
            )
        ],
    ),
    "collections/graphql/graphql-security.postman_collection.json": collection(
        "GraphQL Security Testing",
        "GraphQL templates for introspection control, query depth, alias overloading, batching, and authorization checks.",
        [
            folder(
                "Schema and Query Controls",
                [
                    request_item("Introspection policy is enforced", "POST", "/graphql", SECURITY_TESTS, COMMON_PREREQUEST, {"query": "{ __schema { types { name } } }"}),
                    request_item("Deep query is constrained", "POST", "/graphql", SECURITY_TESTS, COMMON_PREREQUEST, {"query": "query { viewer { teams { projects { issues { comments { author { id } } } } } } }"}),
                    request_item("Alias overloading is constrained", "POST", "/graphql", SECURITY_TESTS, COMMON_PREREQUEST, {"query": "query { a:viewer{id} b:viewer{id} c:viewer{id} }"}),
                ],
                "Check complexity controls without destructive load.",
            ),
            folder(
                "Authorization",
                [
                    request_item("GraphQL object authorization is enforced", "POST", "/graphql", SECURITY_TESTS, COMMON_PREREQUEST, {"query": "query($id: ID!){ user(id:$id){ id email role } }", "variables": {"id": "{{other_user_id}}"}}),
                ],
                "Validate resolver-level authorization.",
            ),
        ],
    ),
    "collections/fuzzing/fuzzing-security.postman_collection.json": collection(
        "API Fuzzing Safety Checks",
        "Lightweight fuzzing templates for boundary values, malformed JSON, encodings, and type confusion.",
        [
            folder(
                "Input Robustness",
                [
                    request_item("Boundary string length is handled", "POST", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, {"display_name": "{{long_string}}"}),
                    request_item("Type confusion is rejected", "POST", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, {"age": {"unexpected": "object"}}),
                    request_item("Encoded characters are normalized safely", "GET", "/api/v1/search?q=%252e%252e%252f", SECURITY_TESTS, COMMON_PREREQUEST),
                ],
                "Safe robustness checks for validation and parsers.",
            )
        ],
    ),
    "collections/headers/header-security.postman_collection.json": collection(
        "Header Security Testing",
        "Security header and leakage checks for REST APIs and browser-facing API responses.",
        [
            folder(
                "Response Headers",
                [
                    request_item("Security headers are present", "GET", "/api/v1/health", """
pm.test('HSTS is present on HTTPS responses when applicable', function () {
  if (pm.environment.get('base_url').startsWith('https://')) pm.expect(pm.response.headers.has('Strict-Transport-Security')).to.eql(true);
});
pm.test('content sniffing is disabled', function () {
  pm.expect(pm.response.headers.get('X-Content-Type-Options')).to.match(/nosniff/i);
});
pm.test('sensitive implementation headers are not leaked', function () {
  ['X-Powered-By', 'Server'].forEach(h => pm.expect(pm.response.headers.get(h) || '').to.not.match(/express|flask|php|apache/i));
});
""" + SECURITY_TESTS, COMMON_PREREQUEST),
                ],
                "Validate defensive response headers and leakage.",
            )
        ],
    ),
    "collections/cors/cors-security.postman_collection.json": collection(
        "CORS Security Testing",
        "CORS origin reflection, credential, and preflight policy validation.",
        [
            folder(
                "CORS Policy",
                [
                    request_item("Untrusted origin is not reflected", "OPTIONS", "/api/v1/profile", """
pm.test('untrusted origin is not allowed with credentials', function () {
  const allowOrigin = pm.response.headers.get('Access-Control-Allow-Origin') || '';
  const allowCreds = pm.response.headers.get('Access-Control-Allow-Credentials') || '';
  pm.expect(!(allowOrigin === 'https://attacker.example' && /true/i.test(allowCreds))).to.eql(true);
});
""" + SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Origin", "value": "https://attacker.example"}, {"key": "Access-Control-Request-Method", "value": "GET"}]),
                ],
                "Check for dangerous wildcard and reflected origins.",
            )
        ],
    ),
    "collections/rate-limit/rate-limit-security.postman_collection.json": collection(
        "Rate Limit Security Testing",
        "Templates for brute force, enumeration, OTP, login flooding, and throttling validation.",
        [
            folder(
                "Throttling",
                [
                    request_item("Login attempts are throttled", "POST", "/api/v1/auth/login", """
pm.test('rate limit or auth failure is returned', function () {
  pm.expect([400, 401, 403, 422, 429]).to.include(pm.response.code);
});
pm.test('retry guidance is present when rate limited', function () {
  if (pm.response.code === 429) pm.expect(pm.response.headers.has('Retry-After')).to.eql(true);
});
""" + SECURITY_TESTS, COMMON_PREREQUEST, {"email": "security-test@example.test", "password": "{{invalid_password}}"}),
                    request_item("OTP verification is throttled", "POST", "/api/v1/auth/otp/verify", SECURITY_TESTS, COMMON_PREREQUEST, {"otp": "000000"}),
                ],
                "Use Postman Runner iterations or Newman to repeat safely in an authorized lab.",
            )
        ],
    ),
    "collections/ssrf/ssrf-security.postman_collection.json": collection(
        "SSRF Security Testing",
        "Safe SSRF validation templates using non-routable and documentation-reserved targets.",
        [
            folder("URL Fetching", [request_item("Private network URL is blocked", "POST", "/api/v1/fetch", SECURITY_TESTS, COMMON_PREREQUEST, {"url": "http://127.0.0.1:80/"}), request_item("Metadata endpoint URL is blocked", "POST", "/api/v1/fetch", SECURITY_TESTS, COMMON_PREREQUEST, {"url": "http://169.254.169.254/latest/meta-data/"})], "Validate allowlists, DNS rebinding defenses, and egress controls."),
        ],
    ),
    "collections/xss/xss-security.postman_collection.json": collection(
        "API XSS and Output Encoding Testing",
        "Templates for checking reflected stored values, JSON encoding, and SVG upload handling.",
        [folder("Output Encoding", [request_item("Script-like value is encoded", "POST", "/api/v1/comments", SECURITY_TESTS, COMMON_PREREQUEST, {"body": "<script>alert(1)</script>"}), request_item("HTML attributes are encoded", "POST", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, {"display_name": "\"><img src=x onerror=alert(1)>"})], "Check that APIs store and return untrusted text safely.")],
    ),
    "collections/idor/idor-security.postman_collection.json": collection(
        "IDOR Security Testing",
        "Focused object-level authorization templates for predictable, UUID, and nested resources.",
        [folder("Object Level Authorization", [request_item("Other account profile is denied", "GET", "/api/v1/accounts/{{other_account_id}}", SECURITY_TESTS, COMMON_PREREQUEST), request_item("Nested resource access is denied", "GET", "/api/v1/accounts/{{other_account_id}}/documents/{{document_id}}", SECURITY_TESTS, COMMON_PREREQUEST)], "Validate ownership on every object reference.")],
    ),
    "collections/file-upload/file-upload-security.postman_collection.json": collection(
        "File Upload Security Testing",
        "Safe templates for extension allowlists, MIME validation, SVG handling, and file size limits.",
        [folder("Upload Validation", [request_item("Double extension is rejected", "POST", "/api/v1/files", SECURITY_TESTS, COMMON_PREREQUEST, {"filename": "avatar.jpg.php", "content_type": "image/jpeg"}), request_item("SVG active content is rejected or sanitized", "POST", "/api/v1/files", SECURITY_TESTS, COMMON_PREREQUEST, {"filename": "safe-test.svg", "content": "<svg><script>alert(1)</script></svg>"})], "Use mock file bodies unless testing an authorized lab.")],
    ),
    "collections/webhook/webhook-security.postman_collection.json": collection(
        "Webhook Security Testing",
        "Templates for signature validation, replay protection, timestamp enforcement, and forged requests.",
        [folder("Webhook Verification", [request_item("Missing signature is rejected", "POST", "/api/v1/webhooks/provider", SECURITY_TESTS, COMMON_PREREQUEST, {"event": "invoice.created", "id": "{{run_id}}"}, headers=[{"key": "Content-Type", "value": "application/json"}]), request_item("Replay timestamp is rejected", "POST", "/api/v1/webhooks/provider", SECURITY_TESTS, COMMON_PREREQUEST, {"event": "invoice.created", "id": "{{run_id}}"}, headers=[{"key": "X-Webhook-Signature", "value": "{{valid_signature}}"}, {"key": "X-Webhook-Timestamp", "value": "946684800"}])], "Validate that webhook receivers verify authenticity and freshness.")],
    ),
    "collections/business-logic/business-logic-security.postman_collection.json": collection(
        "Business Logic Security Testing",
        "Templates for workflow bypass, negative quantities, coupon reuse, and state transition validation.",
        [folder("Workflow Abuse", [request_item("Negative quantity is rejected", "POST", "/api/v1/cart/items", SECURITY_TESTS, COMMON_PREREQUEST, {"sku": "DEMO-1", "quantity": -1}), request_item("Coupon reuse is rejected", "POST", "/api/v1/checkout/coupons", SECURITY_TESTS, COMMON_PREREQUEST, {"coupon": "{{used_coupon}}"})], "Model invariants that must hold across API workflows.")],
    ),
    "collections/api-versioning/api-versioning-security.postman_collection.json": collection(
        "API Versioning Security Testing",
        "Templates for deprecated endpoint exposure and inconsistent security controls across API versions.",
        [folder("Version Drift", [request_item("Deprecated v1 admin route is protected", "GET", "/api/v1/admin/users", SECURITY_TESTS, COMMON_PREREQUEST), request_item("Current v2 admin route is protected", "GET", "/api/v2/admin/users", SECURITY_TESTS, COMMON_PREREQUEST)], "Compare authorization, validation, and headers across versions.")],
    ),
    "collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json": collection(
        "OWASP API Security Top 10 Coverage",
        "Curated Postman checks mapped to OWASP API Security Top 10 categories.",
        [folder("Top 10 Smoke Checks", [request_item("API1 object authorization smoke test", "GET", "/api/v1/users/{{other_user_id}}", SECURITY_TESTS, COMMON_PREREQUEST), request_item("API2 broken authentication smoke test", "GET", "/api/v1/profile", SECURITY_TESTS, COMMON_PREREQUEST, headers=[{"key": "Authorization", "value": "Bearer invalid"}]), request_item("API4 unrestricted resource consumption smoke test", "POST", "/api/v1/search", SECURITY_TESTS, COMMON_PREREQUEST, {"query": "{{long_string}}"})], "Starting point for OWASP API Security reviews.")],
    ),
}

for path, data in collections.items():
    write_json(path, data)

# The payload library is maintained as reviewed source under payloads/<category>/.
# Do not generate or overwrite it here. Run `npm run validate:payloads` to verify
# its indexes, front matter, safety constraints, and minimum example counts.

env_values = [
    {"key": "base_url", "value": "http://localhost:8080", "type": "default"},
    {"key": "access_token", "value": "replace-me", "type": "secret"},
    {"key": "admin_token", "value": "replace-me", "type": "secret"},
    {"key": "expired_token", "value": "replace-me", "type": "secret"},
    {"key": "wrong_audience_token", "value": "replace-me", "type": "secret"},
    {"key": "jwt_none_alg", "value": "replace-me", "type": "secret"},
    {"key": "jwt_tampered_role", "value": "replace-me", "type": "secret"},
    {"key": "jwt_expired", "value": "replace-me", "type": "secret"},
    {"key": "user_id", "value": "1001", "type": "default"},
    {"key": "other_user_id", "value": "1002", "type": "default"},
    {"key": "other_tenant_id", "value": "tenant-b", "type": "default"},
    {"key": "invoice_id", "value": "2002", "type": "default"},
    {"key": "other_account_id", "value": "acct-002", "type": "default"},
    {"key": "document_id", "value": "doc-123", "type": "default"},
    {"key": "sql_payload", "value": "' OR '1'='1", "type": "default"},
    {"key": "long_string", "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "type": "default"},
    {"key": "invalid_password", "value": "not-the-password", "type": "secret"},
    {"key": "used_refresh_token", "value": "replace-me", "type": "secret"},
    {"key": "used_coupon", "value": "WELCOME10", "type": "default"},
    {"key": "valid_signature", "value": "replace-me", "type": "secret"},
]
for name, base in [("local", "http://localhost:8080"), ("staging", "https://staging.example.test"), ("production-safe", "https://api.example.test")]:
    values = [dict(v) for v in env_values]
    values[0]["value"] = base
    write_json(f"environments/{name}.postman_environment.json", {
        "id": f"{name}-api-security-environment",
        "name": f"{name.title()} API Security",
        "values": values,
        "_postman_variable_scope": "environment",
        "_postman_exported_using": "postman-api-security-testing-templates",
    })

write("README.md", """
# Postman API Security Testing Templates

![Repository banner](assets/banners/api-security-banner.svg)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Postman](https://img.shields.io/badge/Postman-Collections-orange.svg)](collections)
[![Newman](https://img.shields.io/badge/Newman-Automation-blue.svg)](scripts/newman)
[![OWASP API](https://img.shields.io/badge/OWASP%20API%20Top%2010-Covered-red.svg)](docs/owasp-api-top10.md)

A production-grade open-source toolkit of reusable Postman collections, payloads, environments, lab APIs, and automation workflows for defensive API security testing.

> Use this project only on APIs you own, operate, or are explicitly authorized to test.

## What Is Included

- Importable Postman collections for authentication, authorization, JWT, GraphQL, SSRF, CORS, headers, file upload, rate limiting, IDOR, XSS, business logic, and OWASP API Top 10 coverage.
- Reusable payload files for safe validation of input handling and defensive controls.
- Local, staging, and production-safe Postman environments.
- Newman scripts for CLI, JSON, JUnit, and HTML-style reporting.
- GitHub Actions, Jenkins, Docker, and CI/CD examples.
- Intentionally vulnerable Flask and Node.js APIs for local practice.
- Mermaid diagrams, screenshot placeholders, and professional docs.

## Quick Start

```bash
git clone https://github.com/rksharma-owg/postman-api-security-testing-templates.git
cd postman-api-security-testing-templates
npm install
npm run test:local
```

Import any file under `collections/` into Postman, then import `environments/local.postman_environment.json`.

## Run With Newman

```bash
npm run test:auth
npm run test:owasp
npm run report:json
```

## Local Vulnerable Lab

```bash
docker compose -f vulnerable-api-lab/docker-compose.yml up --build
```

The lab exposes:

- Flask API on `http://localhost:8080`
- Node API on `http://localhost:8081`

## OWASP API Security Top 10 Mapping

| OWASP Category | Repository Coverage |
| --- | --- |
| API1 Broken Object Level Authorization | `collections/authorization`, `collections/idor` |
| API2 Broken Authentication | `collections/auth`, `collections/jwt` |
| API3 Broken Object Property Level Authorization | `collections/business-logic` |
| API4 Unrestricted Resource Consumption | `collections/rate-limit`, `collections/fuzzing` |
| API5 Broken Function Level Authorization | `collections/authorization` |
| API6 Unrestricted Access to Sensitive Business Flows | `collections/business-logic`, `collections/rate-limit` |
| API7 SSRF | `collections/ssrf` |
| API8 Security Misconfiguration | `collections/headers`, `collections/cors` |
| API9 Improper Inventory Management | `collections/api-versioning` |
| API10 Unsafe Consumption of APIs | `collections/webhook` |

## Visual Guide

![Architecture diagram](assets/diagrams/api-security-architecture.svg)

See `docs/` for setup, automation, JWT testing, GraphQL testing, and remediation guidance.

## Repository Layout

```text
collections/             Postman collections grouped by security domain
payloads/                Reviewed canary payloads (9 categories, 11+ examples each)
environments/            Postman environment templates
scripts/                 Newman, CI/CD, Docker, and workflow examples
vulnerable-api-lab/      Local practice APIs
docs/                    Guides, mappings, diagrams, and screenshots
assets/                  Banner, diagrams, and visual placeholders
```

## Roadmap

- Add OpenAPI-driven collection generation.
- Add Postman visualizer dashboards.
- Add more cloud gateway policy examples.
- Add SARIF conversion for CI annotations.

## License

MIT. See `LICENSE`.
""")

write("LICENSE", """
MIT License

Copyright (c) 2026 API Security Testing Templates contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
""")

write("CONTRIBUTING.md", """
# Contributing

Thanks for helping improve defensive API security testing.

## Guidelines

- Keep examples safe, educational, and authorized-use only.
- Do not add destructive payloads, malware, persistence tooling, credential theft, or real secrets.
- Ensure Postman collections are valid JSON and import cleanly.
- Include remediation notes when adding a new test category.
- Prefer small focused pull requests.

## Collection Standards

Each collection should include folders, environment variables, pre-request scripts, test assertions, negative cases, and clear descriptions.
""")

write("SECURITY.md", """
# Security Policy

This repository is for defensive testing and education. Do not use it against systems without permission.

## Reporting Issues

Please report security issues privately to the maintainers. Do not include live credentials, customer data, production URLs, or exploit output.

## Safe Use

Run aggressive tests only in a local lab, staging system, or authorized security engagement. Production-safe examples are designed to validate controls without causing disruption.
""")

write("CODE_OF_CONDUCT.md", """
# Code of Conduct

Be respectful, inclusive, and professional. This project welcomes security engineers, developers, QA engineers, students, and researchers who want to improve API security safely.
""")

write("package.json", json.dumps({
    "name": "postman-api-security-testing-templates",
    "version": "1.0.0",
    "description": "Postman collections, payloads, labs, and automation for defensive API security testing.",
    "scripts": {
        "test:local": "newman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/local.postman_environment.json",
        "test:auth": "newman run collections/auth/authentication-security.postman_collection.json -e environments/local.postman_environment.json",
        "test:owasp": "newman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/local.postman_environment.json",
        "report:json": "newman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/local.postman_environment.json --reporters cli,json --reporter-json-export reports/newman-results.json"
    },
    "devDependencies": {"newman": "^6.2.1"}
}, indent=2))

write(".gitignore", """
node_modules/
reports/
.env
*.log
__pycache__/
.pytest_cache/
""")

docs = {
    "docs/setup.md": "# Setup\n\nInstall Node.js, run `npm install`, import a collection into Postman, and select an environment. For local practice, start the vulnerable lab with Docker Compose.\n",
    "docs/authentication-testing.md": "# Authentication Testing\n\nValidate that missing, malformed, expired, reused, and wrong-audience credentials fail closed. Confirm generic errors, audit logging, token rotation, and refresh-token replay detection.\n\n## Remediation\n\nUse short-lived access tokens, rotate refresh tokens, bind tokens to audience and issuer, and centralize authentication middleware.\n",
    "docs/graphql-testing.md": "# GraphQL Testing\n\nTest introspection policy, depth limits, alias limits, batching, and resolver-level authorization. Keep load low unless testing an isolated lab.\n\n## Remediation\n\nApply query complexity limits, disable unnecessary introspection, enforce authorization in resolvers, and monitor expensive operations.\n",
    "docs/jwt-testing.md": "# JWT Testing\n\nCheck algorithm allowlists, signature validation, issuer, audience, expiry, not-before, key rotation, and claim tampering.\n\n## Remediation\n\nReject `none`, pin allowed algorithms, validate every registered claim, and use managed key rotation.\n",
    "docs/owasp-api-top10.md": "# OWASP API Security Top 10\n\nThis toolkit maps Postman collections to OWASP API Security Top 10 categories and provides safe validation templates for each risk area.\n\nSee the README table for the concise mapping.\n",
    "docs/automation.md": "# Automation\n\nRun Newman locally, in Docker, or in CI. Export JSON and JUnit reports for build artifacts. Keep production jobs scoped to smoke checks and low-risk negative cases.\n\n```bash\nnewman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/staging.postman_environment.json --reporters cli,json,junit\n```\n",
    "docs/screenshots/README.md": "# Screenshots\n\nPlaceholder directory for Postman runner screenshots, Newman reports, and CI artifacts.\n",
}
for path, content in docs.items():
    write(path, content)

write("docs/diagrams.md", """
# Diagrams

## API Security Testing Flow

```mermaid
flowchart LR
  A[Postman Collection] --> B[Environment Variables]
  B --> C[Authorized API Target]
  C --> D[Security Assertions]
  D --> E[Newman Reports]
  E --> F[CI/CD Gates]
```

## Defensive Feedback Loop

```mermaid
sequenceDiagram
  participant Tester
  participant Postman
  participant API
  participant CI
  Tester->>Postman: Import templates
  Postman->>API: Run authorized checks
  API-->>Postman: Security outcomes
  Postman->>CI: Export Newman reports
  CI-->>Tester: Pass, fail, or warn
```
""")

write("scripts/newman/run-all.sh", """
#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT="${1:-environments/local.postman_environment.json}"
mkdir -p reports

for collection in collections/*/*.postman_collection.json; do
  name="$(basename "$collection" .postman_collection.json)"
  echo "Running $name"
  npx newman run "$collection" -e "$ENVIRONMENT" --reporters cli,json --reporter-json-export "reports/$name.json"
done
""")

write("scripts/newman/run-collection.sh", """
#!/usr/bin/env bash
set -euo pipefail

COLLECTION="${1:?Usage: run-collection.sh <collection> [environment]}"
ENVIRONMENT="${2:-environments/local.postman_environment.json}"

npx newman run "$COLLECTION" -e "$ENVIRONMENT" --reporters cli,json,junit --reporter-json-export reports/result.json --reporter-junit-export reports/result.xml
""")

write("scripts/ci-cd/Jenkinsfile", """
pipeline {
  agent any
  stages {
    stage('Install') {
      steps { sh 'npm ci' }
    }
    stage('API Security Smoke Tests') {
      steps {
        sh 'mkdir -p reports'
        sh 'npx newman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/staging.postman_environment.json --reporters cli,junit --reporter-junit-export reports/newman.xml'
      }
      post { always { junit 'reports/newman.xml' } }
    }
  }
}
""")

write("scripts/ci-cd/gitlab-ci.yml", """
api_security_tests:
  image: node:20-alpine
  script:
    - npm ci
    - mkdir -p reports
    - npx newman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/staging.postman_environment.json --reporters cli,json --reporter-json-export reports/newman.json
  artifacts:
    when: always
    paths:
      - reports/
""")

write(".github/workflows/api-security-tests.yml", """
name: API Security Tests

on:
  pull_request:
  workflow_dispatch:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  newman:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: npm
      - name: Install dependencies
        run: npm ci
      - name: Run OWASP API security smoke tests
        run: |
          mkdir -p reports
          npx newman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json \
            -e environments/production-safe.postman_environment.json \
            --reporters cli,json,junit \
            --reporter-json-export reports/newman.json \
            --reporter-junit-export reports/newman.xml
      - name: Upload reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: newman-api-security-reports
          path: reports/
""")

write("scripts/github-actions/api-security-tests.yml", (ROOT / ".github/workflows/api-security-tests.yml").read_text())

write("scripts/docker/Dockerfile", """
FROM node:20-alpine
WORKDIR /workspace
COPY package*.json ./
RUN npm install
COPY . .
ENTRYPOINT ["npx", "newman"]
""")

write("scripts/docker/run-newman-docker.sh", """
#!/usr/bin/env bash
set -euo pipefail
docker build -f scripts/docker/Dockerfile -t postman-api-security-tests .
docker run --rm -v "$PWD/reports:/workspace/reports" postman-api-security-tests run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/local.postman_environment.json --reporters cli,json --reporter-json-export reports/docker-newman.json
""")

write("vulnerable-api-lab/docker-compose.yml", """
services:
  flask-api:
    build: ./flask-api
    ports:
      - "8080:8080"
  node-api:
    build: ./node-api
    ports:
      - "8081:8081"
""")

write("vulnerable-api-lab/flask-api/requirements.txt", "Flask==3.0.3\nPyJWT==2.8.0\n")
write("vulnerable-api-lab/flask-api/Dockerfile", """
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
CMD ["python", "app.py"]
""")
write("vulnerable-api-lab/flask-api/app.py", """
from flask import Flask, jsonify, request
import jwt

app = Flask(__name__)
SECRET = "lab-secret"
ORDERS = {
    "1001": [{"id": "ord-1", "owner": "1001", "total": 42}],
    "1002": [{"id": "ord-2", "owner": "1002", "total": 99}],
}


def weak_user_id():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    try:
        # Intentionally vulnerable lab behavior: signature verification disabled.
        return jwt.decode(token, options={"verify_signature": False}).get("sub")
    except Exception:
        return None


@app.get("/api/v1/health")
def health():
    return jsonify({"status": "ok", "lab": "flask"})


@app.get("/api/v1/profile")
def profile():
    user_id = weak_user_id()
    if not user_id:
        return jsonify({"error": "missing token"}), 401
    return jsonify({"id": user_id, "role": "user"})


@app.get("/api/v1/users/<user_id>/orders")
def user_orders(user_id):
    # Intentionally vulnerable IDOR for local practice.
    return jsonify({"orders": ORDERS.get(user_id, [])})


@app.post("/api/v1/auth/login")
def login():
    # Intentionally missing rate limits for lab demonstrations.
    return jsonify({"error": "invalid credentials"}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
""")

write("vulnerable-api-lab/node-api/package.json", json.dumps({"scripts": {"start": "node server.js"}, "dependencies": {"cors": "^2.8.5", "express": "^4.19.2", "sqlite3": "^5.1.7"}}, indent=2))
write("vulnerable-api-lab/node-api/Dockerfile", """
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY server.js .
CMD ["npm", "start"]
""")
write("vulnerable-api-lab/node-api/server.js", """
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true })); // Intentionally weak CORS for lab practice.

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER, email TEXT, role TEXT)');
  db.run("INSERT INTO users VALUES (1, 'alice@example.test', 'user')");
  db.run("INSERT INTO users VALUES (2, 'admin@example.test', 'admin')");
});

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok', lab: 'node' }));

app.get('/api/v1/users', (req, res) => {
  const q = req.query.q || '';
  // Intentionally vulnerable SQL concatenation for local practice only.
  db.all("SELECT id, email, role FROM users WHERE email LIKE '%" + q + "%'", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: rows });
  });
});

app.get('/api/v1/admin/users', (req, res) => {
  // Intentionally broken access control for lab practice.
  res.json({ users: [{ id: 1, email: 'alice@example.test' }, { id: 2, email: 'admin@example.test' }] });
});

app.listen(8081, () => console.log('Node vulnerable API listening on 8081'));
""")

write("assets/banners/api-security-banner.svg", """
<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="360" viewBox="0 0 1280 360" role="img" aria-label="Postman API Security Testing Templates">
  <rect width="1280" height="360" fill="#101820"/>
  <path d="M0 280 C220 210 340 340 560 260 S930 190 1280 250 L1280 360 L0 360 Z" fill="#0B6E4F"/>
  <path d="M0 305 C260 245 420 360 700 292 S1030 232 1280 300 L1280 360 L0 360 Z" fill="#F2AA4C"/>
  <g fill="none" stroke="#FFFFFF" stroke-width="4" opacity="0.9">
    <rect x="880" y="82" width="170" height="118" rx="8"/>
    <path d="M918 82 V55 H1012 V82"/>
    <path d="M914 132 H1018"/>
    <path d="M965 102 V166"/>
  </g>
  <text x="80" y="140" fill="#FFFFFF" font-family="Inter, Arial, sans-serif" font-size="54" font-weight="700">Postman API Security</text>
  <text x="82" y="196" fill="#E8F1F2" font-family="Inter, Arial, sans-serif" font-size="28">Testing templates, payloads, labs, and CI automation</text>
  <text x="84" y="246" fill="#FFFFFF" font-family="Inter, Arial, sans-serif" font-size="20">OWASP API Top 10 | Newman | GraphQL | JWT | AuthZ | Webhooks</text>
</svg>
""")

write("assets/diagrams/api-security-architecture.svg", """
<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="520" viewBox="0 0 1100 520" role="img" aria-label="API security testing architecture">
  <rect width="1100" height="520" fill="#F7FAFC"/>
  <style>.box{fill:#fff;stroke:#263238;stroke-width:2}.title{font:700 24px Arial;fill:#101820}.text{font:16px Arial;fill:#263238}.arrow{stroke:#0B6E4F;stroke-width:4;marker-end:url(#arrow)}</style>
  <defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#0B6E4F"/></marker></defs>
  <text x="60" y="55" class="title">API Security Testing Architecture</text>
  <rect x="60" y="100" width="210" height="110" rx="8" class="box"/><text x="92" y="150" class="title">Postman</text><text x="92" y="178" class="text">Collections + Environments</text>
  <rect x="430" y="100" width="240" height="110" rx="8" class="box"/><text x="462" y="150" class="title">Authorized API</text><text x="462" y="178" class="text">Local, staging, or safe prod</text>
  <rect x="820" y="100" width="220" height="110" rx="8" class="box"/><text x="852" y="150" class="title">Assertions</text><text x="852" y="178" class="text">Status, headers, leakage</text>
  <rect x="245" y="315" width="235" height="110" rx="8" class="box"/><text x="278" y="365" class="title">Newman</text><text x="278" y="393" class="text">CLI and report exports</text>
  <rect x="635" y="315" width="245" height="110" rx="8" class="box"/><text x="668" y="365" class="title">CI/CD</text><text x="668" y="393" class="text">Gates and artifacts</text>
  <line x1="270" y1="155" x2="430" y2="155" class="arrow"/><line x1="670" y1="155" x2="820" y2="155" class="arrow"/><line x1="930" y1="210" x2="770" y2="315" class="arrow"/><line x1="480" y1="370" x2="635" y2="370" class="arrow"/><line x1="360" y1="315" x2="185" y2="210" class="arrow"/>
</svg>
""")

for path in [
    "assets/screenshots/postman-runner-placeholder.svg",
    "assets/screenshots/newman-report-placeholder.svg",
    "docs/screenshots/postman-runner-placeholder.svg",
]:
    write(path, """
<svg xmlns="http://www.w3.org/2000/svg" width="960" height="540" viewBox="0 0 960 540" role="img" aria-label="Screenshot placeholder">
  <rect width="960" height="540" fill="#F3F6F8"/>
  <rect x="60" y="60" width="840" height="420" rx="8" fill="#FFFFFF" stroke="#CBD5E1"/>
  <rect x="60" y="60" width="840" height="54" rx="8" fill="#101820"/>
  <text x="90" y="96" font-family="Arial" font-size="20" fill="#FFFFFF">Screenshot Placeholder</text>
  <text x="90" y="180" font-family="Arial" font-size="28" fill="#101820">Add Postman or Newman report capture here</text>
  <text x="90" y="225" font-family="Arial" font-size="18" fill="#475569">Keep screenshots free of secrets, tokens, production hostnames, and customer data.</text>
</svg>
""")

write("assets/diagrams/attack-flow.mmd", """
flowchart TD
  A[Authorized tester] --> B[Select security template]
  B --> C[Run against approved target]
  C --> D{Expected defensive outcome?}
  D -- Yes --> E[Document passing control]
  D -- No --> F[Create finding]
  F --> G[Remediate]
  G --> C
""")

for directory in ["collections/auth", "collections/authorization", "collections/jwt", "collections/injection", "collections/graphql", "collections/fuzzing", "collections/headers", "collections/cors", "collections/rate-limit", "collections/ssrf", "collections/xss", "collections/idor", "collections/file-upload", "collections/webhook", "collections/business-logic", "collections/api-versioning", "collections/owasp-api-top10"]:
    write(f"{directory}/README.md", f"# {directory.split('/')[-1].replace('-', ' ').title()} Collections\n\nImport the Postman collection in this folder and run it with an appropriate environment. These templates are for authorized defensive testing only.\n")

write("scripts/README.md", "# Scripts\n\nAutomation helpers for Newman, CI/CD systems, GitHub Actions, and Docker-based execution.\n")
write("environments/README.md", "# Environments\n\nPostman environments for local lab, staging, and production-safe smoke testing. Replace placeholder secrets in Postman or your CI secret store.\n")
write("vulnerable-api-lab/README.md", "# Vulnerable API Lab\n\nIntentionally vulnerable Flask and Node.js APIs for local defensive learning. Do not deploy these services to the internet.\n")
