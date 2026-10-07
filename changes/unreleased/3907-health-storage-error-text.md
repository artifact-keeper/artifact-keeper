---
section: Security
issues: [#3907]
---
- **The detailed health payload no longer echoes the raw filesystem storage error** (#3907). When the storage path could not be resolved or the probe write failed, the storage check's message interpolated the underlying I/O error (`Storage path not accessible: {e}`, `Storage write failed: {e}`), which carries the OS error text tied to the configured storage path. The message is now the fixed text alone (`Storage path not accessible` / `Storage write failed`) and the raw error is logged server-side at warn. Both phrasings join the raw-error-body gate (#3718) so they cannot return.
