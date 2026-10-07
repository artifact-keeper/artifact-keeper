---
section: Fixed
issues: [#4467]
---
- **`PATCH /api/v1/repositories/{key}` now applies `upstream_url` instead of returning 200 and ignoring it** (#4467). Rotating credentials embedded in a Remote's upstream URL, or repointing a Remote, silently did nothing, and since #4462 redacts the URL in responses a client could not tell. The new URL is validated exactly as on create (SSRF guard, scheme and host checks, per-format rules), and the response redacts userinfo and sets `upstream_url_has_credentials`. Moving the URL to a different origin (scheme, host or port) while upstream-auth credentials are configured is refused with 409, so stored credentials are never sent to a host they were not configured for: remove them (`PUT .../upstream-auth` with `auth_type: "none"`), change the URL, then configure credentials for the new upstream. Content already cached from the old upstream stays cached and is served until it expires or is purged.
