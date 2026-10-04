---
section: Fixed
issues: [#3866]
---
- **CycloneDX SBOMs emit compound SPDX license expressions as `expression`, so Dependency-Track evaluates them against license policy** (#3866). A component license such as `MIT AND PSF-2.0` or `Apache-2.0 WITH LLVM-exception` was written as a free-form `license.name`, which Dependency-Track stores as an unresolved license name: every license policy then failed on that component even when each operand was approved, and names over 255 characters were truncated. A string that parses as a compound SPDX expression (`AND`, `OR`, `WITH`, parentheses) is now emitted as `{"expression": ...}`; known single SPDX identifiers still use `license.id`, and free-form text such as `Public Domain` or `GPL v2 or later` still uses `license.name`, so arbitrary strings never reach `license.id` (#1474). SBOMs already imported into Dependency-Track must be regenerated and re-imported to pick this up.
