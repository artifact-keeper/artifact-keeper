---
section: Added
issues: [#5985]
---
- **Hosted Homebrew bottle repositories** (#5985). A `homebrew` repository accepts bottles built by `brew bottle` under `/homebrew/{repo}/bottles/`, checks that each archive really holds `INSTALL_RECEIPT.json` for the formula name and version in its filename, and serves them back under the single-dash name `brew` downloads (the `--` name `brew bottle` writes is accepted too). `/homebrew/{repo}/api/formula.json` and `/api/formula/{name}.json` render the formula JSON (newest version, every platform tag, `sha256`, `cellar`) on demand, so a published or deleted bottle shows up with no index step. Remote and virtual Homebrew repositories are not supported yet and answer `501`, and the JSON is served unsigned rather than as `formula.jws.json`. See `docs/homebrew.md`.
