---
section: Added
issues: [#4429]
---
- **New guide for Bazel module registries, `docs/bazel.md`, including how virtual repositories shadow upstream modules** (#4429). When any hosted member of a Bazel virtual repository publishes a module name, the virtual stops consulting its remote members for that name (the same dependency-confusion guard npm uses, #1217), so every BCR version of that module disappears and transitive dependencies on an upstream version fail to resolve. The guide explains the rule, shows the failure, and recommends distinct names for internal modules (or Bazel's own `single_version_override` / `archive_override` for patching a public module) instead of reusing a public name.
