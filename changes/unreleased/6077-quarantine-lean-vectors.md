---
section: Changed
issues: [#6077]
---
- **Development and CI: the quarantine download gate is checked against answers generated from its Lean model** (#6077). `lake exe ak-oracle emit quarantine_download_gate` in `formal/` writes the model's answer for every status, every ordering of expiry and current time, and the admin quarantine check to `formal/vectors/quarantine_download_gate.txt`. A Rust test replays every line through `check_download_allowed` and `admin_quarantine_allowed`, and the Lean job regenerates the file and fails on any difference, so a Rust change that departs from the model fails a test even when the theorems' property tests still pass.
