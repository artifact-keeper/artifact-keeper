---
section: Fixed
issues: [#5479]
---
- **Nexus migration source connections work with a trailing slash, refuse `api_token`, and test with a Nexus message** (#5479). A source URL ending in `/` made every Nexus request a `//` path that Nexus answers with 404, so the URL is now trimmed when the connection is created and again when the Nexus client is built, which also fixes rows already stored with the slash. Nexus has no API-key auth and the client used to drop the token for empty Basic credentials, so the anonymous status check passed and every later call failed: creating a Nexus connection with `auth_type` `api_token` now answers 400 naming `basic_auth` (a Nexus user token goes in as its name code and pass code). Existing `api_token` Nexus connections stop testing green and report the same message until they are recreated with `basic_auth`. The connection test names the source type and the base URL it probed, with any `user:password@` stripped, instead of always saying Artifactory.
