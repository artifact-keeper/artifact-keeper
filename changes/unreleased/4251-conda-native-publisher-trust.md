---
section: Fixed
issues: [#4251]
---
- **Publisher-trust curation rules now apply to `conda_native` repositories** (#4251). The publisher-trust evaluator only recognized the `conda` format, so a rule on a `conda_native` staging or proxy repository evaluated to "not applicable": it saved and looked active, but checked nothing. `conda_native` now maps to the same publisher family as `conda`. Its packages are judged the same way: on the cert-bound owner of a verified CEP-27 attestation, or on the self-asserted `about.json` maintainer under `match: metadata`. An untrusted publisher is flagged or blocked, and a trusted one is allowed.
