# Contributing to Artifact Keeper

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/artifact-keeper.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run checks: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --lib`
6. Commit and push to your fork
7. Open a Pull Request against `main`

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

## Reporting Security Issues

Please do **not** open a public issue for security vulnerabilities. Instead, email the maintainers directly or use GitHub's private vulnerability reporting.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
