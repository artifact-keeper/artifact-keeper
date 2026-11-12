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

## End-to-end proof (bug fixes)
<!--
A bug PR (its linked issue is type:bug, its title type is `fix`, or its branch
is fix/*) also needs an end-to-end proof in artifact-keeper-test. Declare it
with ONE line, outside this comment (see CONTRIBUTING.md, "End-to-end proof
for bug fixes"):

  E2E: artifact-keeper-test#N              a test PR that adds or extends a
                                           tier or suite; it names this issue
                                           and has a `## Validation` section
                                           with a RED and a GREEN line
  E2E: tier <name>                         an existing tier that covers it
  E2E: suite tests/<area>/<file>.sh        an existing suite that goes red on
                                           the bug and names the issue
  E2E-Exempt: <category>: <reason>         plus the label no-e2e-required.
      Categories: test-only, build-ci, deps, docs, internal-unreachable (name
      the unit/integration test), race-window (name the barrier/failpoint/
      stress test), embargoed: GHSA-... (harmless facet only until disclosure)

Flake fixes: the `ci` or `testing` label and
  Flake-Proof: <how reproduced>; <N> consecutive passes under <load>
A PR into release/X.Y.x cites a test PR against artifact-keeper-test's
release/X.Y.x. Titles of type test/ci/docs/chore/build, or a diff only in
docs/.github/scripts, are exempt ONLY when no linked issue is type:bug.
-->

## Changelog
<!--
User-facing changes add ONE new file, changes/unreleased/<issue-number>-<slug>.md,
instead of editing CHANGELOG.md (format: changes/README.md). CI-only changes need none.
-->
- [ ] Added a fragment under `changes/unreleased/`
- [ ] N/A — no user-facing change

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
