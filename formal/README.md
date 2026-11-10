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
| `AgeGate/CheckDecision.lean` | `decide_age_gate_check` (`backend/src/services/age_gate_service.rs`) | A version is served exactly when it is not rejected and either meets the threshold or carries a manual approval the current policy still honours. A rejection always blocks; below the threshold an automatic approval, or one bound to another identity, never serves. |
| `AgeGate/PolicyRelaxation.lean` | `AgeGatePolicy::is_relaxed_by` (`backend/src/services/age_gate_service.rs`) | Holds over time: any run of individually allowed changes to an enabled gate leaves it enabled, in the same mode, with a minimum age that never drops. |
| `Auth/MintRepoCeiling.lean` | `AuthExtension::mint_repo_ceiling` (`backend/src/api/middleware/auth.rs`) and `AccessScope::grants` (`backend/src/models/access_scope.rs`) | Holds over time: through any chain of mints, a token reaches only repositories the original credential reached. Shows the empty-allowlist refusal is load-bearing: without it, "restricted to nothing" mints "unrestricted". |
| `Curation/RuleEvaluation.lean` | `CurationService::evaluate_rules` (`backend/src/services/curation_service.rs`) | First-match evaluation shared by PyPI, npm, conda and every curated format: the first applicable rule decides, rules below a matching block cannot unblock, and no applicable rule gives the default. States the cost of skipping undecidable rules: a constraint that blocks every version still admits a request that names no version. |
| `Quarantine/DownloadGate.lean` | `check_download_allowed`, `admin_quarantine_allowed` (`backend/src/services/quarantine_service.rs`) | A rejection never downloads; a hold with no expiry never lapses; a timed hold blocks for exactly its window and, once lapsed, stays lapsed; quarantine-now always blocks and is refused on a rejection. Records that an unrecognised status downloads (safe only while the column constraint holds). |
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
