---
section: Fixed
issues: [#5182]
---
- **The pre-push hook can pass on a clean checkout again** (#5182). It ran plain `cargo test`, which many unit tests cannot pass because they rely on `cargo nextest` running one process per test, and it said no database was needed when the presigned-redirect tests need one. So it failed on every checkout and contributors had to bypass it. The hook now runs `cargo check` by default, which needs only cargo. Setting `AK_PRE_PUSH_TESTS=1` adds the unit tests under `cargo nextest` with a required database, and the hook stops with instructions if either is missing. CI still runs the unit tests on every PR, and `CONTRIBUTING.md` and `TESTING.md` now say what is needed.
