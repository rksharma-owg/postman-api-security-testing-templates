# JWT Testing

Check algorithm allowlists, signature validation, issuer, audience, expiry, not-before, key rotation, and claim tampering.

## Remediation

Reject `none`, pin allowed algorithms, validate every registered claim, and use managed key rotation.
