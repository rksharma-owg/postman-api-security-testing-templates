# Authentication Testing

Validate that missing, malformed, expired, reused, and wrong-audience credentials fail closed. Confirm generic errors, audit logging, token rotation, and refresh-token replay detection.

## Remediation

Use short-lived access tokens, rotate refresh tokens, bind tokens to audience and issuer, and centralize authentication middleware.
