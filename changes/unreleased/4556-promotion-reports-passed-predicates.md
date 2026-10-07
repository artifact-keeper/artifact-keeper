---
section: Changed
issues: [#4556]
---
- **Promotion `gate_results` also list every scan-policy predicate that was checked and held, with the reason** (#4556). A successful promotion reported only the scan and unscanned rules, so a UI could not show that the attestation was verified, the license allowed or the channel allowed: those predicates were evaluated but only their failures were recorded. Single and bulk promotion now add one passed `policy-predicate` entry per configured conda or origin predicate that held, its reason carrying the predicate token, for example `Policy 'release-gate' [conda.license]: license 'mit' is allowed` or `Policy 'release-gate' [conda.attestation]: attestation is verified: verified CEP-27 attestation (sigstore-key, identity ci, issuer key:...)`. Failures are reported exactly as before.
