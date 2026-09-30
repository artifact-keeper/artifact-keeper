---
section: Fixed
issues: [#3926]
---
- **Artifactory migrations no longer fail artifacts that take longer than 30 seconds to download** (#3926). The Artifactory source client used a 30 s whole-request timeout that also covered the response body, so every artifact larger than about 30 s of source bandwidth failed with "error decoding response body". Streamed downloads are now bounded by a connect timeout and a read-idle timeout (a stalled source is still cut off), while the buffered API calls and connection tests keep a whole-request ceiling (300 s). All three are tunable for Artifactory and Nexus sources with `MIGRATION_SOURCE_READ_TIMEOUT_SECS`, `MIGRATION_SOURCE_CONNECT_TIMEOUT_SECS` and `MIGRATION_SOURCE_BUFFERED_TIMEOUT_SECS`.
