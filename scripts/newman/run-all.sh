
#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT="${1:-environments/local.postman_environment.json}"
mkdir -p reports

for collection in collections/*/*.postman_collection.json; do
  name="$(basename "$collection" .postman_collection.json)"
  echo "Running $name"
  npx newman run "$collection" -e "$ENVIRONMENT" --reporters cli,json --reporter-json-export "reports/$name.json"
done
