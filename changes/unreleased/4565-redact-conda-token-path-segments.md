---
section: Fixed
issues: [#4565, #4555, #544]
---
- **Conda token-channel URLs no longer write the token to request logs and traces** (#4565, #4555, #544). The `http_request` span's `uri` field redacted secret query parameters but kept the path as sent, so the bearer token in `/conda/t/<token>/<repo>/...` and in rattler's `/t/<token>/conda/<repo>/...` (pixi `--conda-token`) was logged in clear. That path segment is now recorded as `[REDACTED]`; the rest of the path is kept. Only paths that start with one of those two prefixes are changed. Rotate any token that was used through these URLs if your logs or trace backend may have been read by someone who should not hold it.
