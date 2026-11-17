---
section: Changed
issues: [#6143]
---
- **The backend unit-test build no longer generates code for the whole router in every CI shard** (#6143). One test helper was declared `pub async fn` and called `create_router`. rustc builds a `pub async fn` and everything it calls into every test binary that compiles it, whether or not a test calls it, so each of the five unit-test legs built every handler. Test code now uses `pub(crate) async fn`, and `scripts/ci/test-shards.py check` refuses the old form. Test-only change: production builds and binaries are unaffected.
