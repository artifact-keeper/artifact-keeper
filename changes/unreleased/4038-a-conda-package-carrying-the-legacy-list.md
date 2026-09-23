---
section: Fixed
issues: [#4038]
---
- **A conda package carrying the legacy list spelling of `run_exports` is now served back as the CEP-12 dict, not the bare list** (#4038). A recipe may declare `run_exports` as a bare list of specs — conda-build's own `write_run_exports` defines that spelling as weak exports (`{"weak": [...]}`) — and packages built before conda-build normalised it carry the list verbatim in `info/run_exports.json`. CEP-12 requires the per-package member of a channel's `run_exports.json` to be a dict, so the bare list was served to clients in a shape they cannot parse as run exports. Ingest now normalises the list to `{"weak": [...]}` on the way into `artifact_metadata`, exactly as conda-build does when writing the package, and the `run_exports.json` read path applies the same rule, so packages already hosted with the list spelling are corrected without a republish. The dict spelling passes through untouched, and a package with no run exports still serves `{}`.
