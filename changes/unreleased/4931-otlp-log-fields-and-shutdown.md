---
section: Fixed
issues: [#4931]
---
- **OTLP log records and shutdown now carry enough context and fit inside a container stop grace period** (#4931). The `Request completed` event copies `method`, redacted `uri` and `status` onto its own fields, so it remains identifiable in an OTLP log backend even when logs are not joined to traces. Shutdown flushes spans, logs and metrics concurrently against one shared 5 s deadline instead of letting each provider apply its own timeout, and `artifact_keeper.virtual.member_count` is exported as an integer rather than a string.
