---
section: Fixed
issues: [#5871]
---
- **Hosted Maven downloads carry an ETag and answer If-None-Match with 304** (#5871). A hosted artifact was served with no validator, so Gradle and Maven re-downloaded SNAPSHOT and changing modules in full on every check. The exact path and the SNAPSHOT alias now send the artifact's SHA-256 as a strong `ETag` with `Cache-Control: no-cache`, and a matching `If-None-Match` gets a 304 with no body. The conditional check runs after the download gate, so a quarantined or policy-blocked artifact still answers 403.
