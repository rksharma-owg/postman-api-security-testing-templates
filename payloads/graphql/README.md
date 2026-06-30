# GraphQL Validation Payloads

These bounded queries test parser behavior, introspection policy, aliases, batching, directives,
and depth controls without mutations or large amplification.

- Primary mapping: OWASP API4:2023 and API8:2023
- Examples: 12
- Expected secure result: policy-consistent data or a GraphQL validation error
- File: `graphql_safe_tests.payload`

Replace `canaryField` with a harmless field from the authorized test schema where necessary.
