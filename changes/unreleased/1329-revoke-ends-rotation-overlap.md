---
section: Changed
issues: [#1329]
---
- **Revoking a signing key now sets its `expires_at` to the time of revocation** (#1329). A revoked key used to keep `expires_at: null` in the signing-key API. Revocation now stamps it (an earlier expiry is kept), and that is what ends a rotated-out key's co-signing overlap immediately.
