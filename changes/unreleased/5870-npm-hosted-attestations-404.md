---
section: Fixed
issues: [#5870]
---
- **npm attestation lookups on hosted repositories answer `404` instead of `501`** (#5870). pnpm asks `/-/npm/v1/attestations/{pkg}@{ver}` for every resolved version; the `501` made it retry each one and logged every request at ERROR. Hosted versions have no attestations, so `404` is the right answer. A Virtual with no Remote member answers the same way.
