
#!/usr/bin/env bash
set -euo pipefail
docker build -f scripts/docker/Dockerfile -t postman-api-security-tests .
docker run --rm -v "$PWD/reports:/workspace/reports" postman-api-security-tests run collections/owasp-api-top10/owasp-api-top10-security.postman_collection.json -e environments/local.postman_environment.json --reporters cli,json --reporter-json-export reports/docker-newman.json
