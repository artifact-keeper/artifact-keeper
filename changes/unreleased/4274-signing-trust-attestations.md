---
section: Added
issues: [#4274]
---
- **Signing keys can store a verified out-of-band trust attestation** (#4274). An external root key can sign an Artifact Keeper signing key; challenge, verify, and get live at `/api/v1/signing/keys/{id}/trust-attestation`.
