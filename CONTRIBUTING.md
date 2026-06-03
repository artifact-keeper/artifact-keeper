# Contributing to Artifact Keeper

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/artifact-keeper.git`
3. Enable the git hooks: `./scripts/setup-hooks.sh` (one time, see [Git hooks](#git-hooks))
4. Create a feature branch: `git checkout -b feat/your-feature` (use `fix/`, `chore/`, or `docs/` as appropriate)
5. Make your changes
6. Run the same checks CI runs (see [What CI checks](#what-ci-checks))
7. Commit and push to your fork
8. Open a Pull Request against `main`, referencing an issue (`Closes #N`)

## Git hooks

Run `./scripts/setup-hooks.sh` once after cloning (or `./scripts/dev.sh setup`). It points
git at the version-controlled hooks in `.githooks/`, which require only git and cargo, no
extra tooling to install:

- **pre-commit** runs `cargo fmt --all -- --check` when Rust files are staged (instant).
- **pre-push** runs `cargo check --workspace --all-targets` and `cargo test --workspace --lib`
  with `SQLX_OFFLINE=true`, so compile errors and unit-test failures are caught before they
  reach a red PR. No database needed.

The hooks are fast local feedback, not a substitute for CI. Bypass once with
`git commit --no-verify` / `git push --no-verify` only when you genuinely need to.

## What CI checks

Every PR must be fully green before merge. The pipeline (`.github/workflows/ci.yml` and
related workflows) enforces, in order of how fast you can reproduce each locally:

| Gate | What it runs | Reproduce locally |
| --- | --- | --- |
| Formatting | `cargo fmt --all -- --check` | `cargo fmt --all -- --check` (pre-commit hook) |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | same command |
| Migration slots | migration files must have unique numeric prefixes | `ls backend/migrations/ \| tail` |
| Unit tests | `cargo test --workspace --lib` | same command (pre-push hook) |
| Shell tests | dtrack-init regression test | `./docker/test-init-dtrack.sh` |
| Coverage floor | `cargo llvm-cov --workspace --lib --fail-under-lines 50` | `cargo llvm-cov --workspace --lib --summary-only` |
| New-code coverage | new/changed lines must be >= 70% covered (skipped under 10 new lines) | add tests for the lines you changed |
| Duplication | jscpd over changed `.rs` files, <= 3% | `jscpd --min-lines 10 --threshold 3 --format rust <files>` |
| Integration tests | `cargo test --workspace` (needs Postgres) | `./scripts/dev.sh start` then `cargo test --workspace` |
| Smoke E2E | docker compose up + smoke profile | `./scripts/run-e2e-tests.sh` |
| Security audit | `cargo audit` on the dependency tree | `cargo audit` |
| Linked issue | PR body must reference an issue (`Closes #N`) | n/a (PR body) |
| CodeQL | static analysis | n/a (runs in CI) |

The fmt/clippy/unit-test gates are the ones the hooks cover. The coverage, duplication, and
linked-issue gates run only in CI, so check those before pushing a large change. Do not use
"push and see if CI passes" as a workflow, and do not bypass a failing gate with `--admin`.

## Development Setup

### Prerequisites

- Rust 1.75+
- PostgreSQL 16
- Docker & Docker Compose (for integration tests)

### Running Locally

```bash
# Start dependencies
docker compose up -d postgres opensearch

# Run the backend
cargo run

# Run tests
cargo test --workspace --lib
```

## What to Contribute

- **Bug reports** — File an issue with steps to reproduce
- **Bug fixes** — Open a PR referencing the issue
- **New package format handlers** — See the WASM plugin system and [example plugin](https://github.com/artifact-keeper/artifact-keeper-example-plugin)
- **Documentation improvements** — Docs live in `site/src/content/docs/`
- **Feature requests** — Open a discussion in [GitHub Discussions](https://github.com/artifact-keeper/artifact-keeper/discussions)

## Guidelines

- Keep PRs focused on a single change
- Follow existing code style (`cargo fmt` enforces this)
- Add tests for new functionality
- Update documentation if your change affects user-facing behavior

## Regression-test contract for bug fixes

Every PR that fixes a bug must land with a regression test that fails on
`main` and passes on the PR. This is enforced by checkbox in the PR
template and by reviewer policy: `fix/*` PRs are not approved without
the box checked.

The test can live wherever fits the bug:

- **Unit test** in the same crate as the fixed code, when the bug is
  in pure logic.
- **Integration test** in the same repo, when the bug requires a real
  database, storage backend, or HTTP client.
- **End-to-end test** in
  [`artifact-keeper-test`](https://github.com/artifact-keeper/artifact-keeper-test),
  when the bug surfaces only when the deployed system is exercised
  through its native client (`mvn`, `npm`, `docker pull`, etc.).

For PRs that aren't bug fixes (`feat/`, `chore/`, `docs/`, `ci/`,
`refactor/`), check the "N/A" box on the template.

This is part of [Hardening Core](https://github.com/orgs/artifact-keeper/projects/2),
the stability program tracking the work to make every release deploy
clean from a fresh helm install.

## Reporting Security Issues

Please do **not** open a public issue for security vulnerabilities. Instead, email the maintainers directly or use GitHub's private vulnerability reporting.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
