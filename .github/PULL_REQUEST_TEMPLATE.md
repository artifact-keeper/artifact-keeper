## Summary
<!-- What does this PR do and why? -->

## Regression test (required for `fix/*` PRs)
<!--
Hardening Core (https://github.com/orgs/artifact-keeper/projects/2) requires
every bug-fix PR to land with a regression test that fails on `main` and
passes on this PR. Choose one that fits the bug:
  - unit test (closest to the buggy logic)
  - integration test (requires DB/storage/etc.)
  - end-to-end test in artifact-keeper-test (exercises the user flow)

For non-fix PRs (feat/, chore/, docs/, ci/, refactor/) check N/A.
Reviewers should not approve fix/* PRs without a checked box.
-->
- [ ] This PR is a `fix/*` AND adds/updates a test that would have caught the bug
- [ ] N/A — this is not a bug fix

## Test Checklist
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated (if applicable)
- [ ] E2E tests added/updated (if applicable)
- [ ] Manually tested locally
- [ ] No regressions in existing tests

## API Changes
- [ ] New endpoints have `#[utoipa::path]` annotations
- [ ] Request/response types have `#[derive(ToSchema)]`
- [ ] OpenAPI spec validates: `cargo test --lib test_openapi_spec_is_valid`
- [ ] Migration is reversible (if applicable)
- [ ] N/A - no API changes
