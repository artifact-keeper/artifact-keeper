---
section: Added
issues: [#4274]
---
- **Signing keys can store an out-of-band OpenPGP trust attestation** (#4274). Challenge, verify, and get live at `/api/v1/signing/keys/{id}/trust-attestation`. A valid detached signature is recorded as `signature_valid` (not a PKI trust decision); replacing an existing issuer is refused.
