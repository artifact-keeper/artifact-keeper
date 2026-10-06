---
section: Security
issues: [#4098, #4343]
---
- **A quarantine hold on one member of a virtual repository is no longer bypassed by serving the same file from a lower-priority member** (#4098, #4343). When a virtual npm, PyPI or VS Code repository walked its members for a proxied package, a member that answered with a quarantine hold (409) was skipped and the walk went on to the next member, which could serve the very file the hold was withholding. The walk now stops at the hold, as the shared virtual resolver already did.
