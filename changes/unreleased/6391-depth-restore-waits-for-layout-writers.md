---
section: Fixed
issues: [#6391]
---
- **Depth-bearing restores now wait for an in-flight repository layout writer instead of failing with a conflict** (#6391). A strict restore took the RPM layout lock with a non-blocking probe, so a short-lived artifact writer could make a valid restore fail on an otherwise idle repository. The restore now waits for the lock before it owns any rows.
