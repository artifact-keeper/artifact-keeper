---
section: Security
issues: [#5468, #5469, #5470]
---
- **MCPB bundle uploads refuse ambiguous or unsafe archive entries before anything is stored** (#5468, #5469, #5470). A bundle was stored verbatim after only its `manifest.json` was read, so an archive with two `manifest.json` entries (the last one won), a manifest repeating a JSON key (the last value won), an entry named `../x`, `/etc`, `C:/x` or with a backslash, a symlink or device entry, a non-UTF-8 entry name, or an entry whose central-directory and local-header names differ was accepted and served to clients that unpack it. `PUT .../bundles/{file}.mcpb` now answers `400 mcp_bundle_invalid` with a detail naming the defect (for example `duplicate entry manifest.json`, `unsafe entry name: ../x`, `symlink entry: link`, `entry 3 name is not UTF-8`, `central/local header name mismatch for entry 3`) and stores no bundle row, facts or object. The accepted archive rules are listed under MCPB bundles in `docs/mcp-registry.md`.
