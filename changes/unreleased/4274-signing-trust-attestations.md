---
section: Added
issues: [#4282]
---
- **Signing keys can store an out-of-band OpenPGP trust attestation** (#4282). Challenge, verify, and get live at `/api/v1/signing/keys/{id}/trust-attestation`. A valid detached signature is recorded as `signature_valid` (not a PKI trust decision); replacing an existing issuer is refused. SHA-1/MD5 signatures, weak issuer keys, and revoked/expired issuers are rejected.
