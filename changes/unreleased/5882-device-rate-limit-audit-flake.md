---
section: Fixed
issues: [#5882]
---

- The device flow per-user rate-limit test and two MCP registry integration tests now wait for their fire-and-forget audit rows to land instead of sleeping a fixed 300 ms, so they no longer fail on a loaded runner (#5882).
