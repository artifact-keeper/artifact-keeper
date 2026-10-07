---
section: Security
issues: [#4511]
---
- **CI OIDC token exchange now refuses an assertion whose `nbf` (not before) is in the future** (#4511). `POST /api/v1/auth/ci/token` checked the signature, `iss`, `aud` and `exp` of an exchanged CI token but not `nbf`, so a token that was not valid yet was accepted. This applied to every provider type (`gitlab`, `github`, `generic`, `kubernetes`) and both key sources. The claim is now checked with the same 60-second clock-skew leeway as `exp`: a token whose `nbf` is further in the future is refused with 401, and ordinary clock skew between the CI issuer and Artifact Keeper is still tolerated. Tokens without an `nbf` claim are unaffected.
