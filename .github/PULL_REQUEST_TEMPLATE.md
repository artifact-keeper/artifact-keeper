## Summary
<!-- What does this PR do and why? -->

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
