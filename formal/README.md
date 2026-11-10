# Formal models

Small Lean 4 models of the backend's pure decision rules, with machine-checked
proofs of the guarantees those rules are meant to give.

A model here is a hand-written copy of one Rust function, not a translation of
it. A proof says the *rule* is sound; it does not say the Rust still matches the
rule. Each model therefore names the exact Rust it mirrors, and should be
re-read whenever that Rust changes.

## Layout

```
formal/
  lakefile.toml               Lake package (no dependencies, no Mathlib)
  lean-toolchain              pinned Lean version
  ArtifactKeeper.lean         root: imports every model
  ArtifactKeeper/<Area>/<Rule>.lean
```

`<Area>` follows the backend's own grouping (`Scan`, `Auth`, `Storage`, ...).

## Models

| Model | Mirrors | Result |
|---|---|---|
| `AgeGate/PolicyRelaxation.lean` | `AgeGatePolicy::is_relaxed_by` (`backend/src/services/age_gate_service.rs`) | Holds over time: any run of individually allowed changes to an enabled gate leaves it enabled, in the same mode, with a minimum age that never drops. |
| `Auth/MintRepoCeiling.lean` | `AuthExtension::mint_repo_ceiling` (`backend/src/api/middleware/auth.rs`) and `AccessScope::grants` (`backend/src/models/access_scope.rs`) | Holds over time: through any chain of mints, a token reaches only repositories the original credential reached. Shows the empty-allowlist refusal is load-bearing: without it, "restricted to nothing" mints "unrestricted". |
| `Scan/ScanState.lean` | `classify_scan_state` and `ScanState::is_unscanned` (`backend/src/services/scan_state.rs`) | The original fall-through passes a row with an unrecognised status (counterexample included). With the fall-through closed, the gate is passed exactly when a scan completed or every row is "not applicable". |

## Checking

```bash
brew install elan-init        # once; elan reads lean-toolchain
cd formal && lake build --wfail
```

`--wfail` turns warnings into errors, so a proof left as `sorry` fails the build.

## Adding a model

1. Pick a rule that is already a pure function (no database, no I/O).
2. Copy it branch for branch into `ArtifactKeeper/<Area>/<Rule>.lean`; say in
   the module doc comment which Rust function and file it mirrors.
3. State the guarantee the rule exists for as a theorem and prove it.
4. If the guarantee is false, keep the counterexample as a theorem (`by decide`)
   rather than weakening the statement, then model the fix and prove that.
5. Add the import to `ArtifactKeeper.lean` and a row to the table above.
