---
section: Fixed
issues: [#5820]
---
- **The streaming-invariant test accounts for the npm audit read removed by #5778** (#5820). npm now reads upstream audit advisories through the proxy's capped JSON helper, so `npm.rs` has one fewer buffer site exempt from streaming. The test's allowlist is lowered from 6 to 5 for `npm.rs` and from 33 to 32 in total, which turns main's Backend Integration Tests green again. Test-only; no runtime change.
