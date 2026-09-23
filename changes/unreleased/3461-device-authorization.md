---
section: Added
issues: [#3461]
---
- **Headless clients can authorize with the Artifact Keeper device grant** (#3461). Clients request a short-lived user code at `/api/v1/auth/device/code`, an interactive user approves it without exposing their credential to the client, and the client redeems the device code exactly once for AK-native access and refresh tokens. Requested action scopes and repository access are capped by the approving session, refresh families participate in replay detection and revocation, and the flow remains available when the separate web frontend is disabled.
