---
section: Added
issues: [#3070]
---
- **Repository responses now carry `format_key` for WASM-plugin-backed repositories** (#3070). A plugin repository is stored as `format: "generic"` plus a plugin key, and until now no read path returned that key, so API consumers could not tell a plugin repository from a plain generic one after creating it. Create, get, update and the repository listing now include `format_key` whenever the stored key names a handler other than the built-in one for `format`; plain repositories omit the field.
