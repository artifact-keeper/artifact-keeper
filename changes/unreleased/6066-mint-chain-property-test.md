---
section: Changed
issues: [#6066]
---
- **Development and CI: the token-minting Lean model is now checked against the Rust** (#6066). `formal/ArtifactKeeper/Auth/MintRepoCeiling.lean` proves a chain of token mints never widens the repositories a token reaches, but had no paired Rust test, and the Lean job runs only when `formal/` changes, so removing the empty-allowlist refusal in `mint_repo_ceiling` passed CI. A property test now runs chains of mints through the real ceiling, the selector each mint stores and its read-back as the new token's scope; with the refusal removed it fails with the model's counterexample.
