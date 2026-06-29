# Automation

Run Newman locally, in Docker, or in CI. Export JSON and JUnit reports for build artifacts. Keep production jobs scoped to smoke checks and low-risk negative cases.

```bash
newman run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/staging.postman_environment.json --reporters cli,json,junit
```
