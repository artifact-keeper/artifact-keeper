---
section: Changed
issues: [#4255, #4250, #4310, #4309, #4354, #4353, #4006]
---
- **Test suites hardened against the flakes seen during the 1.11.0 cycle** (#4255, #4310, #4354, #4006). The system-stats proxy-cache test asserts inside one repeatable-read snapshot, so concurrent writers no longer skew its deltas (#4250); the `upload_service` tests run in the serial database group, because the staging reaper they call purges every test's chunks (#4309); the OCI commit-time PATCH rejection test no longer races request authentication against a 200 ms budget (#4353). The `rcgen` dev-dependency moves to 0.14 with the test OIDC issuer updated to its API (#4006). No shipped behaviour changes.
