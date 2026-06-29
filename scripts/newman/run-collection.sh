
#!/usr/bin/env bash
set -euo pipefail

COLLECTION="${1:?Usage: run-collection.sh <collection> [environment]}"
ENVIRONMENT="${2:-environments/local.postman_environment.json}"

npx newman run "$COLLECTION" -e "$ENVIRONMENT" --reporters cli,json,junit --reporter-json-export reports/result.json --reporter-junit-export reports/result.xml
